//! ZIP extractor: WinZip AES (`$zip2$`) and traditional ZipCrypto (`$pkzip$`).
//!
//! Implemented from the PKWARE APPNOTE local-file-header layout and the
//! WinZip AES extra-field (0x9901) specification. Output follows John the
//! Ripper `zip2john` shapes. Current Jumbo `ZIP` / `winzip_common_valid`
//! requires the AES DF field to be inline lowercase hex of length `Le*2`
//! — the old `ZFILE*path*…` pointer form is rejected ("No password hashes
//! loaded"). hashcat mode is unset for ZIP in this stage.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use super::util::{hex_encode, read_u16_le, read_u32_le};
use crate::models::HashResult;

const FORMAT: &str = "zip";

const LFH_SIG: [u8; 4] = [b'P', b'K', 0x03, 0x04];
const CDH_SIG: [u8; 4] = [b'P', b'K', 0x01, 0x02];
const EOCD_SIG: [u8; 4] = [b'P', b'K', 0x05, 0x06];
/// ZIP64 EOCD locator signature
const ZIP64_EOCD_LOC_SIG: [u8; 4] = [b'P', b'K', 0x06, 0x07];
/// ZIP64 EOCD signature
const ZIP64_EOCD_SIG: [u8; 4] = [b'P', b'K', 0x06, 0x06];

/// Warn when the inline `$zip2$` DF hex would be very large (John still loads it).
const LARGE_INLINE_WARN: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
struct Entry {
    local_header_offset: u64,
    data_offset: u64,
    method: u16,
    version_needed: u16,
    /// General purpose bit flag from central directory.
    flags: u16,
    /// Last modification time (MS-DOS format, from central directory).
    mtime: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    encrypted: bool,
    /// Present when the entry uses WinZip AES (extra field 0x9901).
    aes: Option<AesInfo>,
}

#[derive(Debug, Clone)]
struct AesInfo {
    /// 1 = AES-128, 2 = AES-192, 3 = AES-256.
    strength: u8,
    /// Real compression method hidden behind method 99.
    actual_method: u16,
}

pub fn extract(path: &Path, source_name: &str) -> HashResult {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => return HashResult::err(FORMAT, source_name, format!("cannot open file: {e}")),
    };

    let entries = match scan_entries(&mut file) {
        Ok(e) => e,
        Err(e) => return HashResult::err(FORMAT, source_name, format!("ZIP parse error: {e}")),
    };

    if entries.is_empty() {
        return HashResult::warn(FORMAT, source_name, "no ZIP local file headers found");
    }

    let encrypted: Vec<&Entry> = entries.iter().filter(|e| e.encrypted).collect();
    if encrypted.is_empty() {
        return HashResult::warn(FORMAT, source_name, "ZIP is not password-encrypted");
    }

    // Prefer WinZip AES when present; otherwise fall back to ZipCrypto.
    if let Some(entry) = encrypted.iter().copied().find(|e| e.aes.is_some()) {
        return build_zip2(&mut file, source_name, entry);
    }

    // ZipCrypto: prefer a stored (uncompressed) entry with non-zero content,
    // then any non-zero entry by smallest compressed size.
    let mut candidates: Vec<&Entry> = encrypted;
    candidates.sort_by_key(|e| {
        (
            e.uncompressed_size == 0,      // zero-length files last
            e.method != 0,                  // stored before deflated
            e.compressed_size,              // smallest first
        )
    });
    build_pkzip(&mut file, source_name, candidates[0])
}

/// Scan ZIP entries via Central Directory — the authoritative source for
/// sizes/offsets, even when entries use streaming data descriptors.
fn scan_entries(file: &mut File) -> std::io::Result<Vec<Entry>> {
    let file_len = file.seek(SeekFrom::End(0))?;
    let (cd_offset, cd_size, entry_count) = find_central_directory(file, file_len)?;

    let mut entries = Vec::with_capacity(entry_count as usize);
    let mut pos = cd_offset;
    let cd_end = cd_offset + cd_size;

    for _ in 0..entry_count {
        if pos + 46 > cd_end {
            break;
        }
        file.seek(SeekFrom::Start(pos))?;
        let mut sig = [0u8; 4];
        file.read_exact(&mut sig)?;
        if sig != CDH_SIG {
            break;
        }
        let mut hdr = [0u8; 42];
        file.read_exact(&mut hdr)?;

        // Central directory header layout (after signature):
        //   ver_made(2) ver_needed(2) flags(2) method(2) mtime(2) mdate(2)
        //   crc(4) comp_size(4) uncomp_size(4) name_len(2) extra_len(2) comment_len(2)
        //   disk(2) int_attr(2) ext_attr(4) local_offset(4)
        let version_needed = read_u16_le(&hdr, 2).unwrap_or(0);
        let flags = read_u16_le(&hdr, 4).unwrap_or(0);
        let method = read_u16_le(&hdr, 6).unwrap_or(0);
        let mtime = read_u16_le(&hdr, 8).unwrap_or(0);
        let crc32 = read_u32_le(&hdr, 12).unwrap_or(0);
        let compressed_size = read_u32_le(&hdr, 16).unwrap_or(0) as u64;
        let uncompressed_size = read_u32_le(&hdr, 20).unwrap_or(0) as u64;
        let name_len = read_u16_le(&hdr, 24).unwrap_or(0) as usize;
        let extra_len_cd = read_u16_le(&hdr, 26).unwrap_or(0) as usize;
        let comment_len = read_u16_le(&hdr, 28).unwrap_or(0) as usize;
        let local_header_offset = read_u32_le(&hdr, 38).unwrap_or(0) as u64;

        // After the 46-byte fixed header comes: filename (name_len), extra (extra_len_cd), comment.
        // Skip the filename first, then read the central-directory extra field for ZIP64 sizes.
        let mut comp_size = compressed_size;
        let mut uncomp_size = uncompressed_size;
        let mut local_off = local_header_offset;
        file.seek(SeekFrom::Current(name_len as i64))?;
        if extra_len_cd > 0 {
            let mut cd_extra = vec![0u8; extra_len_cd];
            file.read_exact(&mut cd_extra)?;
            // ZIP64 extra field 0x0001 carries true 64-bit sizes when originals were 0xFFFFFFFF.
            apply_zip64_extra(&cd_extra, &mut comp_size, &mut uncomp_size, &mut local_off);
        }

        let encrypted = (flags & 0x0001) != 0;

        // Now read the *local* header at local_off to get the local extra field
        // (which is where the WinZip AES 0x9901 record actually lives) and
        // compute the data offset.
        let mut aes = None;
        let mut data_offset = 0u64;
        file.seek(SeekFrom::Start(local_off))?;
        let mut lsig = [0u8; 4];
        if file.read_exact(&mut lsig).is_ok() && lsig == LFH_SIG {
            let mut lhdr = [0u8; 26];
            if file.read_exact(&mut lhdr).is_ok() {
                let lname_len = read_u16_le(&lhdr, 22).unwrap_or(0) as u64;
                let lextra_len = read_u16_le(&lhdr, 24).unwrap_or(0) as usize;
                data_offset = local_off + 30 + lname_len + lextra_len as u64;
                // Skip the filename before reading the extra field.
                file.seek(SeekFrom::Current(lname_len as i64))?;
                if lextra_len > 0 {
                    let mut lextra = vec![0u8; lextra_len];
                    if file.read_exact(&mut lextra).is_ok() {
                        aes = parse_aes_extra(&lextra);
                    }
                }
            }
        }

        entries.push(Entry {
            local_header_offset: local_off,
            data_offset,
            method,
            version_needed,
            flags,
            mtime,
            crc32,
            compressed_size: comp_size,
            uncompressed_size: uncomp_size,
            encrypted,
            aes,
        });

        pos = pos + 46 + name_len as u64 + extra_len_cd as u64 + comment_len as u64;
    }

    Ok(entries)
}

/// Find the EOCD record (and optional ZIP64 locator/EOCD) and return
/// (cd_offset, cd_size, entry_count).
fn find_central_directory(file: &mut File, file_len: u64) -> std::io::Result<(u64, u64, u64)> {
    // EOCD is 22 bytes + comment (max 65535). Scan backwards from EOF.
    let max_scan = file_len.saturating_sub(22).min(65535 + 22);
    let mut buf = vec![0u8; max_scan as usize];
    let start = file_len - max_scan;
    file.seek(SeekFrom::Start(start))?;
    file.read_exact(&mut buf)?;

    let eocd_rel = buf
        .windows(4)
        .rposition(|w| w == EOCD_SIG)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "EOCD not found"))?;
    let eocd_off = start + eocd_rel as u64;

    file.seek(SeekFrom::Start(eocd_off + 4))?;
    let mut eocd = [0u8; 18];
    file.read_exact(&mut eocd)?;

    let disk_num = read_u16_le(&eocd, 0).unwrap_or(0) as u64;
    let _disk_cd = read_u16_le(&eocd, 2).unwrap_or(0);
    let _entries_disk = read_u16_le(&eocd, 4).unwrap_or(0) as u64;
    let entry_count = read_u16_le(&eocd, 6).unwrap_or(0) as u64;
    let cd_size = read_u32_le(&eocd, 8).unwrap_or(0) as u64;
    let cd_offset = read_u32_le(&eocd, 12).unwrap_or(0) as u64;
    let comment_len = read_u16_le(&eocd, 16).unwrap_or(0) as u64;

    // If values look like ZIP64 placeholders, check for ZIP64 EOCD locator.
    let need_zip64 = entry_count == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_offset == 0xFFFF_FFFF;
    if need_zip64 && eocd_off >= 20 {
        // ZIP64 EOCD locator is 20 bytes immediately before the EOCD when present.
        file.seek(SeekFrom::Start(eocd_off - 20))?;
        let mut loc = [0u8; 20];
        if file.read_exact(&mut loc).is_ok() && loc[0..4] == ZIP64_EOCD_LOC_SIG {
            let zip64_eocd_off = u64::from_le_bytes(loc[8..16].try_into().unwrap());
            file.seek(SeekFrom::Start(zip64_eocd_off))?;
            let mut zsig = [0u8; 4];
            if file.read_exact(&mut zsig).is_ok() && zsig == ZIP64_EOCD_SIG {
                let mut zhdr = [0u8; 52];
                if file.read_exact(&mut zhdr).is_ok() {
                    // Fields after 4-byte sig + 8-byte record size:
                    // ver_made(2) ver_needed(2) disk(4) disk_cd(4)
                    // entries_disk(8) entries_total(8) cd_size(8) cd_offset(8)
                    let _rec_size = u64::from_le_bytes(zhdr[4..12].try_into().unwrap());
                    // entries_total at offset 24 from sig, i.e. 24-4=20 in zhdr
                    let entries_total = u64::from_le_bytes(zhdr[20..28].try_into().unwrap());
                    let z_cd_size = u64::from_le_bytes(zhdr[28..36].try_into().unwrap());
                    let z_cd_offset = u64::from_le_bytes(zhdr[36..44].try_into().unwrap());
                    if entries_total != 0 {
                        return Ok((z_cd_offset, z_cd_size, entries_total));
                    }
                }
            }
        }
    }

    // Sanity: avoid returning empty result on bad scans
    if entry_count == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "central directory has zero entries",
        ));
    }

    let _ = (disk_num, comment_len);
    Ok((cd_offset, cd_size, entry_count))
}

/// Apply ZIP64 extra field (0x0001) overrides. The field contains original
/// uncomp_size (8), comp_size (8), local_header_offset (8), disk_start (4)
/// *only* for those positions where the CD header value was the 0xFF* sentinel.
fn apply_zip64_extra(extra: &[u8], comp_size: &mut u64, uncomp_size: &mut u64, local_off: &mut u64) {
    let mut i = 0usize;
    while i + 4 <= extra.len() {
        let id = read_u16_le(extra, i).unwrap_or(0xffff);
        let size = read_u16_le(extra, i + 2).unwrap_or(0) as usize;
        let body_start = i + 4;
        if id == 0x0001 {
            let mut p = body_start;
            if *uncomp_size == 0xFFFF_FFFF && p + 8 <= body_start + size {
                *uncomp_size = u64::from_le_bytes(extra[p..p + 8].try_into().unwrap());
                p += 8;
            }
            if *comp_size == 0xFFFF_FFFF && p + 8 <= body_start + size {
                *comp_size = u64::from_le_bytes(extra[p..p + 8].try_into().unwrap());
                p += 8;
            }
            if *local_off == 0xFFFF_FFFF && p + 8 <= body_start + size {
                *local_off = u64::from_le_bytes(extra[p..p + 8].try_into().unwrap());
            }
            return;
        }
        i = body_start + size;
    }
}

fn parse_aes_extra(extra: &[u8]) -> Option<AesInfo> {
    let mut i = 0usize;
    while i + 4 <= extra.len() {
        let id = read_u16_le(extra, i)?;
        let size = read_u16_le(extra, i + 2)? as usize;
        let body_start = i + 4;
        if id == 0x9901 && body_start + 7 <= extra.len() {
            // version(2) vendor(2) strength(1) actual_method(2)
            let strength = extra[body_start + 4];
            let actual_method = read_u16_le(extra, body_start + 5)?;
            return Some(AesInfo {
                strength,
                actual_method,
            });
        }
        i = body_start + size;
    }
    None
}

fn salt_len_for(strength: u8) -> Option<usize> {
    match strength {
        1 => Some(8),
        2 => Some(12),
        3 => Some(16),
        _ => None,
    }
}

fn build_zip2(file: &mut File, source_name: &str, entry: &Entry) -> HashResult {
    let aes = entry.aes.as_ref().expect("aes entry");
    let salt_len = match salt_len_for(aes.strength) {
        Some(s) => s,
        None => {
            return HashResult::err(
                FORMAT,
                source_name,
                format!("unknown WinZip AES strength {}", aes.strength),
            )
        }
    };

    // WinZip AES payload: salt | pwv(2) | ciphertext | auth(10)
    let overhead = salt_len as u64 + 2 + 10;
    if entry.compressed_size < overhead {
        return HashResult::err(
            FORMAT,
            source_name,
            "AES entry too small to contain salt/verifier/auth",
        );
    }
    let real_len = entry.compressed_size - overhead;

    let salt = match read_at(file, entry.data_offset, salt_len) {
        Ok(b) => b,
        Err(e) => return HashResult::err(FORMAT, source_name, format!("read salt failed: {e}")),
    };
    let pwv = match read_at(file, entry.data_offset + salt_len as u64, 2) {
        Ok(b) => b,
        Err(e) => return HashResult::err(FORMAT, source_name, format!("read verifier failed: {e}")),
    };
    let auth_off = entry.data_offset + salt_len as u64 + 2 + real_len;
    let auth = match read_at(file, auth_off, 10) {
        Ok(b) => b,
        Err(e) => return HashResult::err(FORMAT, source_name, format!("read auth failed: {e}")),
    };

    // John Jumbo requires DF = lowercase hex of exactly real_len bytes (no ZFILE).
    let data_off = entry.data_offset + salt_len as u64 + 2;
    let df = match read_at(file, data_off, real_len as usize) {
        Ok(b) => hex_encode(&b),
        Err(e) => return HashResult::err(FORMAT, source_name, format!("read data failed: {e}")),
    };

    let line = format!(
        "$zip2$*0*{mode}*0*{salt}*{pwv}*{len:x}*{df}*{auth}*$/zip2$",
        mode = aes.strength,
        salt = hex_encode(&salt),
        pwv = hex_encode(&pwv),
        len = real_len,
        df = df,
        auth = hex_encode(&auth),
    );

    let mut res = HashResult::ok(FORMAT, source_name, line, None);
    if real_len > LARGE_INLINE_WARN {
        res = res.with_warning(format!(
            "AES ciphertext is {real_len} bytes; the John hash line embeds it inline (~{} MiB hex)",
            (real_len * 2) / (1024 * 1024)
        ));
    }
    if aes.actual_method != 0 && aes.actual_method != 8 {
        res = res.with_warning(format!(
            "unusual inner compression method {}",
            aes.actual_method
        ));
    }
    res
}

fn build_pkzip(file: &mut File, source_name: &str, entry: &Entry) -> HashResult {
    if entry.compressed_size == 0 {
        return HashResult::err(
            FORMAT,
            source_name,
            "ZipCrypto entry has unknown size (streamed); cannot extract",
        );
    }

    // ZipCrypto prepends a 12-byte encryption header before the compressed data.
    // We need at least those 12 bytes to extract the check-word.
    if entry.compressed_size < 12 {
        return HashResult::err(
            FORMAT,
            source_name,
            "ZipCrypto entry too small for 12-byte encryption header",
        );
    }

    let data = match read_at(file, entry.data_offset, entry.compressed_size as usize) {
        Ok(b) => b,
        Err(e) => return HashResult::err(FORMAT, source_name, format!("read data failed: {e}")),
    };

    // check_bytes: number of known plaintext bytes used to verify a candidate
    // password. 1 when only the high byte of the CRC is known (version >= 2.0
    // *or* the data descriptor bit is set, meaning CRC/sizes came after the
    // encrypted stream); otherwise 2 (both CRC high word bytes).
    let has_data_descriptor = (entry.flags & 0x0008) != 0;
    let check_bytes = if entry.version_needed >= 20 || has_data_descriptor {
        1
    } else {
        2
    };

    // The "magic" / check word in $pkzip$ format is the MS-DOS modification
    // time from the local file header (big-endian hex). The ZipCrypto 12-byte
    // encryption header ends with (crc_high_byte, mtime_high_byte), so John
    // uses the mtime as the known 2-byte verification value.
    let cs = format!("{:04x}", entry.mtime);

    // Data offset relative to the start of the local file header record.
    let data_off_rel = entry.data_offset - entry.local_header_offset;

    let line = format!(
        "$pkzip$1*{cb}*2*0*{clen:x}*{dlen:x}*{crc:08x}*{off:x}*{doff:x}*{method:x}*{clen2:x}*{cs}*{data}*$/pkzip$",
        cb = check_bytes,
        clen = entry.compressed_size,
        dlen = entry.uncompressed_size,
        crc = entry.crc32,
        off = entry.local_header_offset,
        doff = data_off_rel,
        method = entry.method,
        clen2 = entry.compressed_size,
        cs = cs,
        data = hex_encode(&data),
    );

    HashResult::ok(FORMAT, source_name, line, None)
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
    fn salt_len_mapping() {
        assert_eq!(salt_len_for(1), Some(8));
        assert_eq!(salt_len_for(2), Some(12));
        assert_eq!(salt_len_for(3), Some(16));
        assert_eq!(salt_len_for(4), None);
    }

    #[test]
    fn parses_aes_extra_field() {
        // id=0x9901 size=7 version=1 vendor="AE" strength=3 method=0
        let extra = [
            0x01, 0x99, 0x07, 0x00, 0x01, 0x00, b'A', b'E', 0x03, 0x00, 0x00,
        ];
        let aes = parse_aes_extra(&extra).expect("aes parsed");
        assert_eq!(aes.strength, 3);
        assert_eq!(aes.actual_method, 0);
    }

    #[test]
    fn large_inline_warn_threshold() {
        assert!(LARGE_INLINE_WARN >= 1024 * 1024);
    }
}
