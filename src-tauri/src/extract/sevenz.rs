//! 7-Zip extractor (`$7z$`, hashcat 11600).
//!
//! Parses the 7z start header + next header property tree far enough to locate
//! the AES-256 coder (method id 06F10701), read its NumCyclesPower / salt / IV
//! properties, the packed stream size, unpack size and CRC. Implemented from
//! the public 7z format description.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use super::util::{hex_encode, read_u32_le, read_u64_le};
use crate::models::HashResult;

const FORMAT: &str = "7z";
const SIG_HEADER_LEN: u64 = 32;
const AES_CODER_ID: &[u8] = &[0x06, 0xF1, 0x07, 0x01];

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

    let streams = match parse_next_header(&nheader) {
        Some(s) => s,
        None => {
            return HashResult::warn(
                FORMAT,
                source_name,
                "7z header could not be parsed or contains no encryption (unsupported layout)",
            )
        }
    };

    build_line(&mut file, source_name, streams)
}

fn build_line(file: &mut File, source_name: &str, s: StreamsInfo) -> HashResult {
    // Locate the AES coder within the first folder.
    let folder = match s.folders.first() {
        Some(f) => f,
        None => return HashResult::warn(FORMAT, source_name, "7z: no folders in header"),
    };

    let mut out_index = 0usize;
    let mut aes: Option<(&Coder, usize)> = None;
    for coder in &folder.coders {
        if coder.id == AES_CODER_ID {
            aes = Some((coder, out_index));
            break;
        }
        out_index += coder.num_out as usize;
    }

    let (coder, aes_out_index) = match aes {
        Some(v) => v,
        None => {
            return HashResult::warn(
                FORMAT,
                source_name,
                "7z archive is not AES-encrypted (no AES coder found)",
            )
        }
    };

    let props = match parse_aes_props(&coder.props) {
        Some(p) => p,
        None => return HashResult::err(FORMAT, source_name, "7z: malformed AES coder properties"),
    };

    let pack_size = s.pack_sizes.first().copied().unwrap_or(0);
    let unpack_size = s.unpack_sizes.get(aes_out_index).copied().unwrap_or(0);
    let crc = s.crcs.first().copied().unwrap_or(0);

    // Read the (encrypted) packed data from 32 + pack_pos.
    let data_off = SIG_HEADER_LEN + s.pack_pos;
    let want = (pack_size as usize).min(EMBED_CAP);
    let data = match read_at(file, data_off, want) {
        Ok(b) => b,
        Err(e) => return HashResult::err(FORMAT, source_name, format!("read data failed: {e}")),
    };

    let line = format!(
        "$7z$0${cost}${slen}${salt}${ivlen}${iv}${crc}${psize}${usize_}${data}",
        cost = props.num_cycles_power,
        slen = props.salt.len(),
        salt = hex_encode(&props.salt),
        ivlen = props.iv.len(),
        iv = hex_encode(&props.iv),
        crc = crc,
        psize = pack_size,
        usize_ = unpack_size,
        data = hex_encode(&data),
    );

    let mut res = HashResult::ok(FORMAT, source_name, line, Some(11600));
    if crc == 0 {
        res = res.with_warning("no CRC found in 7z header; verification field is 0");
    }
    if folder.coders.len() > 1 {
        res = res.with_warning(
            "7z folder chains AES with another coder (e.g. compression); \
             the extended hashcat fields for that coder are not emitted",
        );
    }
    if (pack_size as usize) > EMBED_CAP {
        res = res.with_warning("7z ciphertext truncated in hash line (very large payload)");
    }
    res
}

struct AesProps {
    num_cycles_power: u8,
    salt: Vec<u8>,
    iv: Vec<u8>,
}

fn parse_aes_props(props: &[u8]) -> Option<AesProps> {
    let b0 = *props.first()?;
    let num_cycles_power = b0 & 0x3f;
    let mut salt = Vec::new();
    let mut iv = Vec::new();
    if b0 & 0xc0 != 0 {
        let b1 = *props.get(1)?;
        let salt_size = ((b0 >> 7) & 1) as usize + (b1 >> 4) as usize;
        let iv_size = ((b0 >> 6) & 1) as usize + (b1 & 0x0f) as usize;
        let mut p = 2usize;
        salt = props.get(p..p + salt_size)?.to_vec();
        p += salt_size;
        iv = props.get(p..p + iv_size)?.to_vec();
    }
    Some(AesProps {
        num_cycles_power,
        salt,
        iv,
    })
}

// ---------------------- 7z header property parser ----------------------

struct StreamsInfo {
    pack_pos: u64,
    pack_sizes: Vec<u64>,
    folders: Vec<Folder>,
    unpack_sizes: Vec<u64>,
    crcs: Vec<u32>,
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
    let mut crcs = Vec::new();

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
                        0x0A => skip_digests(r, num_folders)?,
                        _ => return None,
                    }
                }
            }
            0x08 => {
                // kSubStreamsInfo: parse for CRCs, skip the rest we don't need.
                parse_substreams(r, &folders, &mut crcs)?;
            }
            _ => return None,
        }
    }

    Some(StreamsInfo {
        pack_pos,
        pack_sizes,
        folders,
        unpack_sizes,
        crcs,
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

    // Bind pairs: (total_out - 1) of them.
    let num_bind_pairs = total_out.saturating_sub(1);
    for _ in 0..num_bind_pairs {
        let _in_index = r.number()?;
        let _out_index = r.number()?;
    }

    // Packed streams: total_in - num_bind_pairs. If more than one, explicit
    // indices follow.
    let num_packed = total_in.saturating_sub(num_bind_pairs);
    if num_packed > 1 {
        for _ in 0..num_packed {
            let _idx = r.number()?;
        }
    }

    Some(Folder { coders })
}

fn parse_substreams(r: &mut Reader, folders: &[Folder], crcs: &mut Vec<u32>) -> Option<()> {
    let mut num_unpack_per_folder: Vec<u64> = vec![1; folders.len()];
    loop {
        let id = r.u8()?;
        match id {
            0x00 => return Some(()),
            0x0D => {
                // kNumUnpackStream
                for slot in num_unpack_per_folder.iter_mut() {
                    *slot = r.number()?;
                }
            }
            0x09 => {
                // kSize: sizes for streams (all but last per folder)
                for &count in &num_unpack_per_folder {
                    for _ in 1..count {
                        let _ = r.number()?;
                    }
                }
            }
            0x0A => {
                // kCRC over the streams whose CRC is not already known.
                let total: u64 = num_unpack_per_folder.iter().sum();
                let all_defined = r.u8()?;
                let count = total as usize;
                if all_defined == 0 {
                    // bit vector of defined flags
                    let bytes = (count + 7) / 8;
                    let defined = r.bytes(bytes)?;
                    for i in 0..count {
                        if defined[i / 8] & (0x80 >> (i % 8)) != 0 {
                            crcs.push(read_crc(r)?);
                        }
                    }
                } else {
                    for _ in 0..count {
                        crcs.push(read_crc(r)?);
                    }
                }
            }
            _ => return None,
        }
    }
}

fn read_crc(r: &mut Reader) -> Option<u32> {
    let b = r.bytes(4)?;
    read_u32_le(b, 0)
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
    fn aes_props_parse() {
        // b0 = 0xc0 | 19 (numcycles) ; salt/iv present.
        // b0: bit7=1(salt+1) bit6=1(iv+1) low6=19
        let b0 = 0xc0 | 19;
        // b1: high nibble = extra salt (0 => salt=1), low nibble = extra iv (0x0f => iv=16-1? )
        // salt_size = 1 + 0 = 1 ; iv_size = 1 + 15 = 16
        let mut props = vec![b0, 0x0f];
        props.push(0xAA); // salt (1 byte)
        props.extend_from_slice(&[0u8; 16]); // iv (16 bytes)
        let p = parse_aes_props(&props).unwrap();
        assert_eq!(p.num_cycles_power, 19);
        assert_eq!(p.salt.len(), 1);
        assert_eq!(p.iv.len(), 16);
    }

    #[test]
    fn sevenz_number_encoding() {
        // 0x40 has the high bit clear, so the value is the low 6 bits = 64,
        // consuming a single byte.
        let mut r = Reader::new(&[0x40, 0xFF]);
        assert_eq!(r.number(), Some(64));

        // 0x80 0x01 => high bit set, so read one extra byte (0x01) => 1.
        let mut r2 = Reader::new(&[0x80, 0x01]);
        assert_eq!(r2.number(), Some(1));
    }
}
