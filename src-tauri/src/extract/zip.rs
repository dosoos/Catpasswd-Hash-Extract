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

/// Warn when the inline `$zip2$` DF hex would be very large (John still loads it).
const LARGE_INLINE_WARN: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
struct Entry {
    local_header_offset: u64,
    data_offset: u64,
    method: u16,
    version_needed: u16,
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

    let entries = match scan_local_headers(&mut file) {
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

    // ZipCrypto: prefer a stored (uncompressed) entry, then the smallest.
    let mut candidates: Vec<&Entry> = encrypted;
    candidates.sort_by_key(|e| (e.method != 0, e.compressed_size));
    build_pkzip(&mut file, source_name, candidates[0])
}

fn scan_local_headers(file: &mut File) -> std::io::Result<Vec<Entry>> {
    let mut entries = Vec::new();
    let mut pos: u64 = 0;

    loop {
        let mut sig = [0u8; 4];
        file.seek(SeekFrom::Start(pos))?;
        if let Err(e) = file.read_exact(&mut sig) {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                break;
            }
            return Err(e);
        }
        if sig == CDH_SIG {
            break; // reached central directory
        }
        if sig != LFH_SIG {
            break; // not a local header; stop scanning
        }

        // Read the rest of the fixed 30-byte header (26 more bytes).
        let mut hdr = [0u8; 26];
        if file.read_exact(&mut hdr).is_err() {
            break;
        }
        let flags = read_u16_le(&hdr, 2).unwrap_or(0);
        let method = read_u16_le(&hdr, 4).unwrap_or(0);
        let version_needed = read_u16_le(&hdr, 0).unwrap_or(0);
        let crc32 = read_u32_le(&hdr, 10).unwrap_or(0);
        let compressed_size = read_u32_le(&hdr, 14).unwrap_or(0) as u64;
        let uncompressed_size = read_u32_le(&hdr, 18).unwrap_or(0) as u64;
        let name_len = read_u16_le(&hdr, 22).unwrap_or(0) as usize;
        let extra_len = read_u16_le(&hdr, 24).unwrap_or(0) as usize;

        let name_off = pos + 30;
        let extra_off = name_off + name_len as u64;
        let data_off = extra_off + extra_len as u64;

        // Parse the extra field looking for the WinZip AES header (0x9901).
        let mut aes = None;
        if extra_len > 0 {
            let mut extra = vec![0u8; extra_len];
            file.seek(SeekFrom::Start(extra_off))?;
            if file.read_exact(&mut extra).is_ok() {
                aes = parse_aes_extra(&extra);
            }
        }

        let encrypted = (flags & 0x0001) != 0;

        // A zero compressed size with the data-descriptor bit set means the
        // real size lives after the data / in the central directory, which we
        // do not read here. Record the entry but we cannot safely advance.
        let has_data_descriptor = (flags & 0x0008) != 0;

        entries.push(Entry {
            local_header_offset: pos,
            data_offset: data_off,
            method,
            version_needed,
            crc32,
            compressed_size,
            uncompressed_size,
            encrypted,
            aes,
        });

        if compressed_size == 0 && has_data_descriptor {
            // Cannot reliably find the next header; stop after this entry.
            break;
        }
        pos = data_off + compressed_size;
    }

    Ok(entries)
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

    let data = match read_at(file, entry.data_offset, entry.compressed_size as usize) {
        Ok(b) => b,
        Err(e) => return HashResult::err(FORMAT, source_name, format!("read data failed: {e}")),
    };

    // check_bytes: 1 if the writer needed >= 2.0 to extract, else 2 (per the
    // common convention used by zip2john-compatible output).
    let check_bytes = if entry.version_needed >= 20 { 1 } else { 2 };
    let cs = format!("{:04x}", (entry.crc32 >> 16) & 0xffff);

    // Data offset relative to the start of the local file header record.
    let data_off_rel = entry.data_offset - entry.local_header_offset;

    let line = format!(
        "$pkzip$1*{cb}*2*0*{clen:x}*{dlen:x}*{crc:08x}*{off:x}*{doff:x}*{method}*{clen2:x}*{cs}*{data}*$/pkzip$",
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
