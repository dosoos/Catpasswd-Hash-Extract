//! 7-Zip extractor (`$7z$`, hashcat 11600).
//!
//! Parses the 7z start header + next header property tree far enough to locate
//! the AES-256 coder (method id 06F10701), read its NumCyclesPower / salt / IV
//! properties, the packed stream size, unpack size and CRC. Field layout matches
//! 7z2hashcat / John `7z2john`.
//!
//! When the next header is a `kEncodedHeader` (id 0x17), its property tree
//! describes a *compressed* header (typically LZMA/LZMA2). The pack stream is
//! read and decompressed before the real `kHeader` is parsed — exactly what
//! `7z2john` does. Without that step the AES coder is invisible and extraction
//! falsely reports "no AES coder found".

use lzma_rs::decompress::raw::{Lzma2Decoder, LzmaDecoder, LzmaParams, LzmaProperties};
use std::io::Cursor;

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use super::util::{hex_encode, read_u32_le, read_u64_le};
use crate::models::HashResult;

const FORMAT: &str = "7z";
const SIG_HEADER_LEN: u64 = 32;
const AES_CODER_ID: &[u8] = &[0x06, 0xF1, 0x07, 0x01];
const LZMA1_ID: &[u8] = &[0x03, 0x01, 0x01];
const LZMA2_ID: &[u8] = &[0x21];
const PPMD_ID: &[u8] = &[0x03, 0x04, 0x01];
const BZIP2_ID: &[u8] = &[0x04, 0x02, 0x02];
const DEFLATE_ID: &[u8] = &[0x04, 0x01, 0x08];
const COPY_ID: &[u8] = &[0x00];

/// Maximum ciphertext embedded in the hash line. Header-encrypted archives are
/// tiny; large data-encrypted payloads are truncated with a warning.
const EMBED_CAP: usize = 8 * 1024 * 1024;

pub fn extract(path: &Path, source_name: &str) -> HashResult {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => return HashResult::err(FORMAT, source_name, format!("cannot open file: {e}")),
    };

    let mut sig = [0u8; 32];
    if let Err(e) = file.read_exact(&mut sig) {
        return HashResult::err(FORMAT, source_name, format!("cannot read start header: {e}"));
    }

    let next_off = match read_u64_le(&sig, 12) {
        Some(v) => v,
        None => return HashResult::err(FORMAT, source_name, "truncated 7z start header"),
    };
    let next_size = match read_u64_le(&sig, 20) {
        Some(v) => v as usize,
        None => return HashResult::err(FORMAT, source_name, "truncated 7z start header"),
    };
    if next_size == 0 {
        return HashResult::warn(FORMAT, source_name, "7z archive has no header (empty?)");
    }

    let nheader = match read_at(&mut file, SIG_HEADER_LEN + next_off, next_size) {
        Ok(b) => b,
        Err(e) => return HashResult::err(FORMAT, source_name, format!("cannot read header: {e}")),
    };

    let streams = match resolve_streams(&mut file, &nheader) {
        Ok(s) => s,
        Err(ResolveError::Unsupported(msg)) => {
            return HashResult::warn(FORMAT, source_name, msg);
        }
        Err(ResolveError::Failed(msg)) => {
            return HashResult::err(FORMAT, source_name, msg);
        }
    };

    build_line(&mut file, source_name, streams)
}

/// Outcome of locating the archive's real StreamsInfo.
enum ResolveError {
    /// Layout is understood but cannot yield a hash (no encryption, unsupported
    /// coder, etc.) — surfaced as a warning.
    Unsupported(String),
    /// A decode/I/O step that should have succeeded failed — surfaced as an error.
    Failed(String),
}

/// Parse the next header, transparently decompressing a `kEncodedHeader` whose
/// coder is a plain compressor (LZMA/LZMA2/COPY). If the encoded header is
/// itself AES-encrypted (header-encrypted archive), its descriptor is returned
/// directly — that descriptor's pack stream is the encrypted header that goes
/// into the hash line.
fn resolve_streams(file: &mut File, nheader: &[u8]) -> Result<StreamsInfo, ResolveError> {
    let unsupported = || {
        ResolveError::Unsupported(
            "7z header could not be parsed or contains no encryption (unsupported layout)".into(),
        )
    };

    let id = *nheader.first().ok_or_else(unsupported)?;
    if id != 0x17 {
        // kHeader (0x01) or anything else: parse directly.
        return parse_next_header(nheader).ok_or_else(unsupported);
    }

    // kEncodedHeader: first parse its descriptor (PackInfo/UnpackInfo describing
    // the compressed real header).
    let enc = parse_next_header(nheader).ok_or_else(unsupported)?;

    // Header-encrypted archive: the AES coder is in the descriptor itself. The
    // descriptor's pack stream is exactly the encrypted header hashcat wants.
    let has_aes = enc
        .folders
        .iter()
        .any(|f| f.coders.iter().any(|c| c.id == AES_CODER_ID));
    if has_aes {
        return Ok(enc);
    }

    // Header is only compressed, not encrypted. Decompress the real kHeader and
    // parse it instead.
    let real = decode_encoded_header(file, &enc)?;
    parse_next_header(&real).ok_or_else(unsupported)
}

/// Read and decompress the pack stream described by a `kEncodedHeader`
/// descriptor, returning the bytes of the real `kHeader`.
fn decode_encoded_header(file: &mut File, enc: &StreamsInfo) -> Result<Vec<u8>, ResolveError> {
    let folder = enc
        .folders
        .first()
        .ok_or_else(|| ResolveError::Failed("encoded header has no folder".into()))?;

    let pack_size = enc
        .pack_sizes
        .first()
        .copied()
        .ok_or_else(|| ResolveError::Failed("encoded header has no pack size".into()))?
        as usize;
    let unpack_size = enc.unpack_sizes.last().copied().unwrap_or(0) as usize;

    let data_off = SIG_HEADER_LEN + enc.pack_pos;
    let packed = read_at(file, data_off, pack_size)
        .map_err(|e| ResolveError::Failed(format!("read encoded header stream failed: {e}")))?;

    // Header encoding in practice uses a single LZMA/LZMA2/COPY coder. Feed
    // each stage's output into the next.
    let mut current: Vec<u8> = packed;
    for coder in &folder.coders {
        current = match coder.id.as_slice() {
            COPY_ID => current,
            LZMA1_ID => lzma1_decompress(&current, &coder.props, unpack_size)?,
            LZMA2_ID => lzma2_decompress(&current, unpack_size)?,
            other => {
                return Err(ResolveError::Failed(format!(
                    "unsupported encoded-header coder: {}",
                    hex_encode(other)
                )));
            }
        };
    }

    Ok(current)
}

fn lzma1_decompress(
    data: &[u8],
    props: &[u8],
    unpack_size: usize,
) -> Result<Vec<u8>, ResolveError> {
    if props.len() < 5 {
        return Err(ResolveError::Failed(
            "LZMA coder properties too short".into(),
        ));
    }
    let b0 = props[0] as u32;
    if b0 >= 225 {
        return Err(ResolveError::Failed("invalid LZMA properties".into()));
    }
    let lc = b0 % 9;
    let remainder = b0 / 9;
    let lp = remainder % 5;
    let pb = remainder / 5;
    let dict_size = read_u32_le(props, 1)
        .ok_or_else(|| ResolveError::Failed("bad LZMA dict size".into()))?;

    let params = LzmaParams::new(
        LzmaProperties { lc, lp, pb },
        dict_size,
        Some(unpack_size as u64),
    );
    let mut decoder = LzmaDecoder::new(params, None)
        .map_err(|e| ResolveError::Failed(format!("LZMA decoder init: {e}")))?;

    let mut input = Cursor::new(data);
    let mut out = Vec::with_capacity(unpack_size);
    decoder
        .decompress(&mut input, &mut out)
        .map_err(|e| ResolveError::Failed(format!("LZMA decompress failed: {e}")))?;
    Ok(out)
}

fn lzma2_decompress(data: &[u8], unpack_size: usize) -> Result<Vec<u8>, ResolveError> {
    let mut input = Cursor::new(data);
    let mut out = Vec::with_capacity(unpack_size);
    let mut decoder = Lzma2Decoder::new();
    decoder
        .decompress(&mut input, &mut out)
        .map_err(|e| ResolveError::Failed(format!("LZMA2 decompress failed: {e}")))?;
    Ok(out)
}

fn build_line(file: &mut File, source_name: &str, s: StreamsInfo) -> HashResult {
    let folder = match s.folders.first() {
        Some(f) => f,
        None => return HashResult::warn(FORMAT, source_name, "7z: no folders in header"),
    };

    let mut out_index = 0usize;
    let mut aes_index = None;
    for (i, coder) in folder.coders.iter().enumerate() {
        if coder.id == AES_CODER_ID {
            aes_index = Some((i, out_index));
            break;
        }
        out_index += coder.num_out as usize;
    }

    let (aes_coder_index, aes_out_index) = match aes_index {
        Some(v) => v,
        None => {
            return HashResult::warn(
                FORMAT,
                source_name,
                "7z archive is not AES-encrypted (no AES coder found)",
            )
        }
    };

    let coder = &folder.coders[aes_coder_index];
    let props = match parse_aes_props(&coder.props) {
        Some(p) => p,
        None => return HashResult::err(FORMAT, source_name, "7z: malformed AES coder properties"),
    };

    let pack_size = s.pack_sizes.first().copied().unwrap_or(0);
    let unpack_size = s.unpack_sizes.get(aes_out_index).copied().unwrap_or(0);
    let crc = digest_for_stream(&s, 0);

    let data_off = SIG_HEADER_LEN + s.pack_pos;
    let want = (pack_size as usize).min(EMBED_CAP);
    let data = match read_at(file, data_off, want) {
        Ok(b) => b,
        Err(e) => return HashResult::err(FORMAT, source_name, format!("read data failed: {e}")),
    };

    let (type_of_data, extra_fields) =
        match compression_fields(folder, aes_coder_index, &s, aes_out_index) {
            Ok(v) => v,
            Err(msg) => return HashResult::warn(FORMAT, source_name, msg),
        };

    let mut line = format!(
        "$7z${type_of_data}${cost}${slen}${salt}${ivlen}${iv}${crc}${psize}${usize_}${data}",
        cost = props.num_cycles_power,
        slen = props.salt.len(),
        salt = hex_encode(&props.salt),
        ivlen = props.iv_len,
        iv = hex_encode(&props.iv),
        crc = crc,
        psize = pack_size,
        usize_ = unpack_size,
        data = hex_encode(&data),
    );
    line.push_str(&extra_fields);

    let mut res = HashResult::ok(FORMAT, source_name, line, Some(11600));
    if crc == 0 {
        res = res.with_warning("no CRC found in 7z header; verification field is 0");
    }
    if (pack_size as usize) > EMBED_CAP {
        res = res.with_warning("7z ciphertext truncated in hash line (very large payload)");
    }
    res
}

/// Map post-AES coders to hashcat data-type + trailing `$crc_len$attrs` fields.
fn compression_fields(
    folder: &Folder,
    aes_coder_index: usize,
    streams: &StreamsInfo,
    aes_out_index: usize,
) -> Result<(u32, String), &'static str> {
    let after_aes = &folder.coders[aes_coder_index + 1..];
    if after_aes.is_empty() {
        return Ok((0, String::new()));
    }

    let mut compression_type = 0u32;
    let mut compression_attrs = String::new();
    let mut preprocessor_type = 0u32;
    let mut preprocessor_attrs = String::new();
    let mut compressor_count = 0u32;
    let mut preprocessor_count = 0u32;

    for coder in after_aes {
        if coder.id == COPY_ID {
            continue;
        }
        let (kind, is_preprocessor) = coder_kind(&coder.id)?;
        let attrs = hex_encode(&coder.props);
        if is_preprocessor {
            preprocessor_count += 1;
            if preprocessor_count == 1 {
                preprocessor_type = kind;
                preprocessor_attrs = attrs;
            } else {
                preprocessor_attrs
                    .push_str(&format!(",{}_{}", (kind << 4) + preprocessor_count, attrs));
            }
        } else {
            compressor_count += 1;
            if compressor_count == 1 {
                compression_type = kind;
                if preprocessor_count == 0 {
                    compression_attrs = attrs;
                } else {
                    compression_attrs =
                        format!(",{}_{}", (kind << 4) + compressor_count, attrs);
                }
            } else {
                compression_attrs
                    .push_str(&format!(",{}_{}", (kind << 4) + compressor_count, attrs));
            }
        }
    }

    if compression_type == 0 && preprocessor_type == 0 {
        // Only COPY coders after AES (stored, no compression): same as AES alone.
        return Ok((0, String::new()));
    }

    let type_of_data = (preprocessor_type << 4) | compression_type;
    let crc_len = streams
        .substream_file_sizes
        .first()
        .copied()
        .or_else(|| streams.unpack_sizes.get(aes_out_index + 1).copied())
        .unwrap_or(0);

    let mut extra = format!("${crc_len}");
    if !compression_attrs.is_empty() {
        extra.push('$');
        extra.push_str(&compression_attrs);
    }
    if !preprocessor_attrs.is_empty() {
        extra.push('$');
        extra.push_str(&preprocessor_attrs);
    }

    Ok((type_of_data, extra))
}

fn coder_kind(id: &[u8]) -> Result<(u32, bool), &'static str> {
    if id == LZMA1_ID {
        Ok((1, false))
    } else if id == LZMA2_ID {
        Ok((2, false))
    } else if id == PPMD_ID {
        Ok((3, false))
    } else if id == BZIP2_ID {
        Ok((6, false))
    } else if id == DEFLATE_ID {
        Ok((7, false))
    } else if id == &[0x03] {
        Ok((3, true)) // BCJ
    } else if id == &[0x33] {
        Ok((2, true)) // BCJ2
    } else {
        Err("7z uses an unsupported post-AES coder")
    }
}

fn digest_for_stream(streams: &StreamsInfo, index: usize) -> u32 {
    if let Some(Some(crc)) = streams.folder_crcs.get(index) {
        return *crc;
    }
    streams.substream_crcs.get(index).copied().unwrap_or(0)
}

struct AesProps {
    num_cycles_power: u8,
    salt: Vec<u8>,
    /// Stored IV length from coder properties (hash field).
    iv_len: usize,
    /// IV padded to 16 bytes for the hex field.
    iv: Vec<u8>,
}

fn parse_aes_props(props: &[u8]) -> Option<AesProps> {
    let default_iv = [0u8; 16];
    if props.is_empty() {
        return Some(AesProps {
            num_cycles_power: 19,
            salt: Vec::new(),
            iv_len: 16,
            iv: default_iv.to_vec(),
        });
    }

    let b0 = props[0];
    let num_cycles_power = b0 & 0x3f;
    let mut salt = Vec::new();
    let iv_raw;

    if b0 & 0xc0 != 0 {
        let b1 = *props.get(1)?;
        let salt_size = ((b0 >> 7) & 1) as usize + (b1 >> 4) as usize;
        let iv_size = ((b0 >> 6) & 1) as usize + (b1 & 0x0f) as usize;
        let mut p = 2usize;
        salt = props.get(p..p + salt_size)?.to_vec();
        p += salt_size;
        iv_raw = props.get(p..p + iv_size)?.to_vec();
    } else {
        iv_raw = default_iv.to_vec();
    }

    let iv_len = if iv_raw.is_empty() { 16 } else { iv_raw.len() };
    let mut iv = iv_raw;
    if iv.len() < 16 {
        iv.resize(16, 0);
    } else {
        iv.truncate(16);
    }

    Some(AesProps {
        num_cycles_power,
        salt,
        iv_len,
        iv,
    })
}

// ---------------------- 7z header property parser ----------------------

struct StreamsInfo {
    pack_pos: u64,
    pack_sizes: Vec<u64>,
    folders: Vec<Folder>,
    unpack_sizes: Vec<u64>,
    folder_crcs: Vec<Option<u32>>,
    substream_crcs: Vec<u32>,
    substream_file_sizes: Vec<u64>,
}

struct Folder {
    coders: Vec<Coder>,
}

struct Coder {
    id: Vec<u8>,
    props: Vec<u8>,
    num_out: u64,
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.buf.get(self.pos..self.pos + n)?;
        self.pos += n;
        Some(s)
    }
    /// 7z variable-length number.
    fn number(&mut self) -> Option<u64> {
        let first = self.u8()?;
        let mut mask = 0x80u8;
        let mut value: u64 = 0;
        for i in 0..8 {
            if first & mask == 0 {
                let high = (first & mask.wrapping_sub(1)) as u64;
                value |= high << (8 * i);
                return Some(value);
            }
            let b = self.u8()? as u64;
            value |= b << (8 * i);
            mask >>= 1;
        }
        Some(value)
    }
}

fn parse_next_header(buf: &[u8]) -> Option<StreamsInfo> {
    let mut r = Reader::new(buf);
    let id = r.u8()?;
    match id {
        0x17 => parse_streams_info(&mut r), // kEncodedHeader (header-encrypted)
        0x01 => parse_header(&mut r),       // kHeader
        _ => None,
    }
}

fn parse_header(r: &mut Reader) -> Option<StreamsInfo> {
    loop {
        let id = r.u8()?;
        match id {
            0x00 => return None, // kEnd, no main streams info encountered
            0x04 => return parse_streams_info(r), // kMainStreamsInfo
            0x02 => {
                // kArchiveProperties: skip until kEnd
                skip_until_end(r)?;
            }
            _ => return None,
        }
    }
}

fn parse_streams_info(r: &mut Reader) -> Option<StreamsInfo> {
    let mut pack_pos = 0u64;
    let mut pack_sizes = Vec::new();
    let mut folders = Vec::new();
    let mut unpack_sizes = Vec::new();
    let mut folder_crcs = Vec::new();
    let mut substream_crcs = Vec::new();
    let mut substream_file_sizes = Vec::new();

    loop {
        let id = r.u8()?;
        match id {
            0x00 => break, // kEnd
            0x06 => {
                // kPackInfo
                pack_pos = r.number()?;
                let num = r.number()? as usize;
                loop {
                    let pid = r.u8()?;
                    match pid {
                        0x00 => break,
                        0x09 => {
                            for _ in 0..num {
                                pack_sizes.push(r.number()?);
                            }
                        }
                        0x0A => skip_digests(r, num)?,
                        _ => return None,
                    }
                }
            }
            0x07 => {
                // kUnpackInfo
                let folder_id = r.u8()?;
                if folder_id != 0x0B {
                    return None;
                }
                let num_folders = r.number()? as usize;
                let external = r.u8()?;
                if external != 0 {
                    return None; // folders stored elsewhere; unsupported
                }
                let mut total_out = 0usize;
                for _ in 0..num_folders {
                    let folder = parse_folder(r)?;
                    total_out += folder.coders.iter().map(|c| c.num_out as usize).sum::<usize>();
                    folders.push(folder);
                }
                let cus = r.u8()?;
                if cus != 0x0C {
                    return None;
                }
                for _ in 0..total_out {
                    unpack_sizes.push(r.number()?);
                }
                loop {
                    let pid = r.u8()?;
                    match pid {
                        0x00 => break,
                        0x0A => folder_crcs = read_digests(r, num_folders)?,
                        _ => return None,
                    }
                }
            }
            0x08 => {
                parse_substreams(
                    r,
                    &folders,
                    &unpack_sizes,
                    &folder_crcs,
                    &mut substream_crcs,
                    &mut substream_file_sizes,
                )?;
            }
            _ => return None,
        }
    }

    Some(StreamsInfo {
        pack_pos,
        pack_sizes,
        folders,
        unpack_sizes,
        folder_crcs,
        substream_crcs,
        substream_file_sizes,
    })
}

fn parse_folder(r: &mut Reader) -> Option<Folder> {
    let num_coders = r.number()? as usize;
    let mut coders = Vec::with_capacity(num_coders);
    let mut total_in = 0u64;
    let mut total_out = 0u64;
    for _ in 0..num_coders {
        let flag = r.u8()?;
        let id_size = (flag & 0x0f) as usize;
        let id = r.bytes(id_size)?.to_vec();
        let (num_in, num_out) = if flag & 0x10 != 0 {
            (r.number()?, r.number()?)
        } else {
            (1, 1)
        };
        let props = if flag & 0x20 != 0 {
            let size = r.number()? as usize;
            r.bytes(size)?.to_vec()
        } else {
            Vec::new()
        };
        total_in += num_in;
        total_out += num_out;
        coders.push(Coder { id, props, num_out });
    }

    let num_bind_pairs = total_out.saturating_sub(1);
    for _ in 0..num_bind_pairs {
        let _in_index = r.number()?;
        let _out_index = r.number()?;
    }

    let num_packed = total_in.saturating_sub(num_bind_pairs);
    if num_packed > 1 {
        for _ in 0..num_packed {
            let _idx = r.number()?;
        }
    }

    Some(Folder { coders })
}

fn parse_substreams(
    r: &mut Reader,
    folders: &[Folder],
    unpack_sizes: &[u64],
    folder_crcs: &[Option<u32>],
    substream_crcs: &mut Vec<u32>,
    substream_file_sizes: &mut Vec<u64>,
) -> Option<()> {
    let mut num_unpack_per_folder: Vec<u64> = vec![1; folders.len()];
    let mut saw_sizes = false;

    loop {
        let id = r.u8()?;
        match id {
            0x00 => {
                if !saw_sizes {
                    for (i, _folder) in folders.iter().enumerate() {
                        if num_unpack_per_folder[i] == 1 {
                            if let Some(size) = folder_main_unpack_size_for_index(
                                unpack_sizes,
                                folders,
                                i,
                            ) {
                                substream_file_sizes.push(size);
                            }
                        }
                    }
                }
                return Some(());
            }
            0x0D => {
                for slot in num_unpack_per_folder.iter_mut() {
                    *slot = r.number()?;
                }
            }
            0x09 => {
                saw_sizes = true;
                let mut unpack_index = 0usize;
                for (i, &count) in num_unpack_per_folder.iter().enumerate() {
                    let mut sum = 0u64;
                    for j in 1..count {
                        let size = r.number()?;
                        if j == 1 {
                            substream_file_sizes.push(size);
                        }
                        sum += size;
                    }
                    if count >= 1 {
                        if let Some(folder_size) =
                            folder_main_unpack_size_for_index(unpack_sizes, folders, i)
                        {
                            if folder_size >= sum {
                                let last = folder_size - sum;
                                if count == 1 {
                                    substream_file_sizes.push(last);
                                }
                            }
                        }
                    }
                    unpack_index += count as usize;
                    let _ = unpack_index;
                }
            }
            0x0A => {
                let mut digest_slots = 0usize;
                for (i, &count) in num_unpack_per_folder.iter().enumerate() {
                    let has_folder_crc = folder_crcs
                        .get(i)
                        .and_then(|c| c.as_ref())
                        .is_some();
                    if count != 1 || !has_folder_crc {
                        digest_slots += count as usize;
                    }
                }

                let all_defined = r.u8()?;
                if all_defined == 0 {
                    let bytes = (digest_slots + 7) / 8;
                    let defined = r.bytes(bytes)?;
                    let mut bit = 0usize;
                    for i in 0..num_unpack_per_folder.len() {
                        let count = num_unpack_per_folder[i] as usize;
                        let has_folder_crc = folder_crcs
                            .get(i)
                            .and_then(|c| c.as_ref())
                            .is_some();
                        if count == 1 && has_folder_crc {
                            continue;
                        }
                        for _ in 0..count {
                            if defined[bit / 8] & (0x80 >> (bit % 8)) != 0 {
                                substream_crcs.push(read_crc(r)?);
                            }
                            bit += 1;
                        }
                    }
                } else {
                    for i in 0..num_unpack_per_folder.len() {
                        let count = num_unpack_per_folder[i] as usize;
                        let has_folder_crc = folder_crcs
                            .get(i)
                            .and_then(|c| c.as_ref())
                            .is_some();
                        if count == 1 && has_folder_crc {
                            continue;
                        }
                        for _ in 0..count {
                            substream_crcs.push(read_crc(r)?);
                        }
                    }
                }
            }
            _ => return None,
        }
    }
}

fn folder_main_unpack_size_for_index(
    unpack_sizes: &[u64],
    folders: &[Folder],
    folder_index: usize,
) -> Option<u64> {
    let mut index = 0usize;
    for (i, folder) in folders.iter().enumerate() {
        let outs: usize = folder.coders.iter().map(|c| c.num_out as usize).sum();
        if i == folder_index {
            return unpack_sizes.get(index + outs - 1).copied();
        }
        index += outs;
    }
    None
}

fn read_crc(r: &mut Reader) -> Option<u32> {
    let b = r.bytes(4)?;
    read_u32_le(b, 0)
}

fn read_digests(r: &mut Reader, num: usize) -> Option<Vec<Option<u32>>> {
    let all_defined = r.u8()?;
    let mut out = vec![None; num];
    if all_defined == 0 {
        let bytes = (num + 7) / 8;
        let defined = r.bytes(bytes)?;
        let mut defined_idx = 0usize;
        for i in 0..num {
            if defined[i / 8] & (0x80 >> (i % 8)) != 0 {
                out[i] = Some(read_crc(r)?);
                defined_idx += 1;
            }
        }
        let _ = defined_idx;
    } else {
        for slot in out.iter_mut() {
            *slot = Some(read_crc(r)?);
        }
    }
    Some(out)
}

fn skip_digests(r: &mut Reader, num: usize) -> Option<()> {
    let all_defined = r.u8()?;
    let count = if all_defined == 0 {
        let bytes = (num + 7) / 8;
        let defined = r.bytes(bytes)?;
        (0..num)
            .filter(|i| defined[i / 8] & (0x80 >> (i % 8)) != 0)
            .count()
    } else {
        num
    };
    r.bytes(count * 4)?;
    Some(())
}

fn skip_until_end(r: &mut Reader) -> Option<()> {
    loop {
        let id = r.u8()?;
        if id == 0x00 {
            return Some(());
        }
        let size = r.number()? as usize;
        r.bytes(size)?;
    }
}

fn read_at(file: &mut File, off: u64, len: usize) -> std::io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(off))?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_props_parse_with_salt_and_iv() {
        let b0 = 0xc0 | 19;
        let mut props = vec![b0, 0x0f];
        props.push(0xAA);
        props.extend_from_slice(&[0u8; 16]);
        let p = parse_aes_props(&props).unwrap();
        assert_eq!(p.num_cycles_power, 19);
        assert_eq!(p.salt.len(), 1);
        assert_eq!(p.iv_len, 16);
        assert_eq!(p.iv.len(), 16);
    }

    #[test]
    fn aes_props_default_when_empty() {
        let p = parse_aes_props(&[]).unwrap();
        assert_eq!(p.num_cycles_power, 19);
        assert!(p.salt.is_empty());
        assert_eq!(p.iv_len, 16);
        assert_eq!(p.iv, [0u8; 16]);
    }

    #[test]
    fn aes_props_iv_padded_to_16() {
        // b0: salt+iv flags, cycles=19; b1: salt=1 byte, iv=8 bytes
        let mut props = vec![0xc0 | 19, 0x07];
        props.push(0x11);
        props.extend_from_slice(&[0x22; 8]);
        let p = parse_aes_props(&props).unwrap();
        assert_eq!(p.iv_len, 8);
        assert_eq!(p.iv.len(), 16);
        assert_eq!(&p.iv[8..], &[0u8; 8]);
    }

    #[test]
    fn sevenz_number_encoding() {
        let mut r = Reader::new(&[0x40, 0xFF]);
        assert_eq!(r.number(), Some(64));

        let mut r2 = Reader::new(&[0x80, 0x01]);
        assert_eq!(r2.number(), Some(1));
    }

    #[test]
    fn live_archives_match_7z2hashcat_layout() {
        use std::path::Path;

        let dir = std::env::var("SEVENZ_TEST_DIR").ok();
        let Some(dir) = dir else {
            return;
        };

        let data = Path::new(&dir).join("enc_data.7z");
        if !data.is_file() {
            return;
        }

        let res = extract(&data, "enc_data.7z");
        assert!(res.error.is_none(), "{:?}", res.error);
        let line = res.hash_line;
        assert!(
            line.starts_with("$7z$2$19$0$$16$"),
            "unexpected prefix: {line}"
        );
        assert!(line.ends_with("$28$00"), "unexpected suffix: {line}");

        let header = Path::new(&dir).join("enc_header.7z");
        if header.is_file() {
            let res = extract(&header, "enc_header.7z");
            assert!(res.error.is_none(), "{:?}", res.error);
            assert!(
                res.hash_line.starts_with("$7z$0$"),
                "header-encrypted prefix: {}",
                res.hash_line
            );
        }
    }

    // Regression: a data-encrypted 7z whose next header is an LZMA-compressed
    // kEncodedHeader (not header-encrypted). The AES coders live inside the
    // decompressed real header and must be found there. Compared byte-for-byte
    // against John the Ripper's 7z2john output.
    #[test]
    fn lzma_encoded_header_matches_7z2john() {
        use std::path::Path;
        let path = std::env::var("SEVENZ_LZMA_ENC_HEADER").ok();
        let Some(path) = path else { return };
        let path = Path::new(&path);
        if !path.is_file() {
            return;
        }

        let expected = "$7z$0$19$0$$16$8c2536eea1f16cc736e49ea9ca1fbe02$2259142691$128$113$bb55a9f8db6ef58238b8596ca3903188863a81b4f8dbe455b82ad60ee227df81118a9bed0e77913e4be70b62634881d1838a5a11966786917eb4b0f7c390efe3bc0076f2c83b0a2a9ce36e4661a3ea6ffa3e61f2835dd24bb9688ae67720002b8cf5cb1bb58e676a62cb957eb002de585cb8492a647b42ecfbdb73db8076a291";

        let res = extract(path, "sample.tgz");
        assert!(res.error.is_none(), "error: {:?}", res.error);
        assert!(res.warnings.is_empty(), "warnings: {:?}", res.warnings);
        assert_eq!(res.hash_line, expected);
    }
}
