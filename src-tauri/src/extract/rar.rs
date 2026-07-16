//! RAR extractor.
//!
//! - RAR5 (`$rar5$`, hashcat 13000): parses the block format with variable
//!   length integers and reads the file-encryption record (salt, IV, password
//!   check) or the archive-encryption header for header-encrypted (`-hp`)
//!   archives.
//! - RAR3 (`$RAR3$`, hashcat 12500): header-encrypted (`-hp`) archives fully;
//!   file-data encryption (`-p`) is only detected and reported.
//!
//! Implemented from the public RAR5 archive-format documentation.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::util::{hex_encode, read_u16_le, read_u32_le};
use crate::models::HashResult;

const FORMAT: &str = "rar";

/// The encryption metadata lives near the archive start; reading a bounded
/// prefix is enough and keeps memory bounded for large archives.
const MAX_SCAN: u64 = 2 * 1024 * 1024;

fn read_prefix(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let len = file.metadata().map(|m| m.len()).unwrap_or(MAX_SCAN);
    let cap = len.min(MAX_SCAN) as usize;
    let mut buf = vec![0u8; cap];
    let n = file.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

/// Read a RAR5 variable-length integer at `pos`. Returns (value, bytes_read).
fn read_vint(buf: &[u8], pos: usize) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    let mut i = pos;
    loop {
        if i >= buf.len() || shift >= 64 {
            return None;
        }
        let byte = buf[i];
        i += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Some((result, i - pos))
}

// ----------------------------- RAR5 -----------------------------

pub fn extract_rar5(path: &Path, source_name: &str) -> HashResult {
    let buf = match read_prefix(path) {
        Ok(b) => b,
        Err(e) => return HashResult::err(FORMAT, source_name, format!("cannot read file: {e}")),
    };

    match scan_rar5(&buf) {
        Some(Rar5Enc::File { salt, iv, pswcheck, kdf_count }) => {
            let line = format!(
                "$rar5$16${}${}${}$8${}",
                hex_encode(&salt),
                kdf_count,
                hex_encode(&iv),
                hex_encode(&pswcheck),
            );
            HashResult::ok(FORMAT, source_name, line, Some(13000))
        }
        Some(Rar5Enc::Archive { salt, pswcheck, kdf_count }) => {
            // Header-encrypted (-hp): there is no per-file IV in the archive
            // encryption header. We emit a $rar5$ line with a zero IV
            // placeholder; verification is via the password-check value.
            let line = format!(
                "$rar5$16${}${}${}$8${}",
                hex_encode(&salt),
                kdf_count,
                hex_encode(&[0u8; 16]),
                hex_encode(&pswcheck),
            );
            HashResult::ok(FORMAT, source_name, line, Some(13000)).with_warning(
                "RAR5 header-encrypted (-hp): zero-IV placeholder used; \
                 verify against your cracker",
            )
        }
        None => HashResult::warn(
            FORMAT,
            source_name,
            "RAR5 archive is not password-encrypted (no encryption record found)",
        ),
    }
}

enum Rar5Enc {
    File {
        salt: [u8; 16],
        iv: [u8; 16],
        pswcheck: [u8; 8],
        kdf_count: u8,
    },
    Archive {
        salt: [u8; 16],
        pswcheck: [u8; 8],
        kdf_count: u8,
    },
}

fn scan_rar5(buf: &[u8]) -> Option<Rar5Enc> {
    // Skip the 8-byte signature "Rar!\x1a\x07\x01\x00".
    let mut pos = 8usize;
    while pos + 4 <= buf.len() {
        // 4-byte header CRC32 (ignored), then vint header size.
        let p0 = pos + 4;
        let (header_size, n) = read_vint(buf, p0)?;
        let header_start = p0 + n;
        let header_end = header_start.checked_add(header_size as usize)?;
        if header_end > buf.len() {
            break;
        }

        let mut p = header_start;
        let (htype, n) = read_vint(buf, p)?;
        p += n;
        let (hflags, n) = read_vint(buf, p)?;
        p += n;

        let mut extra_size = 0u64;
        if hflags & 0x0001 != 0 {
            let (v, n) = read_vint(buf, p)?;
            extra_size = v;
            p += n;
        }
        let mut data_size = 0u64;
        if hflags & 0x0002 != 0 {
            let (v, n) = read_vint(buf, p)?;
            data_size = v;
            p += n;
        }

        match htype {
            4 => {
                // Archive encryption header (header-encrypted archive).
                if let Some(enc) = parse_rar5_archive_enc(buf, p) {
                    return Some(enc);
                }
            }
            2 => {
                // File header: look for a file-encryption record (type 1) in
                // the extra area located at the end of the header.
                let extra_start = header_end.checked_sub(extra_size as usize)?;
                if let Some(enc) = parse_rar5_file_enc(buf, extra_start, header_end) {
                    return Some(enc);
                }
            }
            _ => {}
        }

        pos = header_end + data_size as usize;
    }
    None
}

fn parse_rar5_archive_enc(buf: &[u8], mut p: usize) -> Option<Rar5Enc> {
    let (_ver, n) = read_vint(buf, p)?;
    p += n;
    let (enc_flags, n) = read_vint(buf, p)?;
    p += n;
    let kdf_count = *buf.get(p)?;
    p += 1;
    let salt: [u8; 16] = buf.get(p..p + 16)?.try_into().ok()?;
    p += 16;
    if enc_flags & 0x0001 == 0 {
        return None; // no password check value present
    }
    let check = buf.get(p..p + 12)?;
    let pswcheck: [u8; 8] = check[..8].try_into().ok()?;
    Some(Rar5Enc::Archive {
        salt,
        pswcheck,
        kdf_count,
    })
}

fn parse_rar5_file_enc(buf: &[u8], extra_start: usize, header_end: usize) -> Option<Rar5Enc> {
    let mut q = extra_start;
    while q < header_end {
        let (rec_size, n) = read_vint(buf, q)?;
        let body = q + n;
        let (rec_type, n2) = read_vint(buf, body)?;
        let mut r = body + n2;
        if rec_type == 1 {
            let (_ver, n) = read_vint(buf, r)?;
            r += n;
            let (flags, n) = read_vint(buf, r)?;
            r += n;
            let kdf_count = *buf.get(r)?;
            r += 1;
            let salt: [u8; 16] = buf.get(r..r + 16)?.try_into().ok()?;
            r += 16;
            let iv: [u8; 16] = buf.get(r..r + 16)?.try_into().ok()?;
            r += 16;
            if flags & 0x0001 == 0 {
                return None;
            }
            let check = buf.get(r..r + 12)?;
            let pswcheck: [u8; 8] = check[..8].try_into().ok()?;
            return Some(Rar5Enc::File {
                salt,
                iv,
                pswcheck,
                kdf_count,
            });
        }
        q = body + rec_size as usize;
    }
    None
}

// ----------------------------- RAR3 -----------------------------

pub fn extract_rar3(path: &Path, source_name: &str) -> HashResult {
    let buf = match read_prefix(path) {
        Ok(b) => b,
        Err(e) => return HashResult::err(FORMAT, source_name, format!("cannot read file: {e}")),
    };

    // Skip the 7-byte RAR3 signature/marker.
    let mut pos = 7usize;
    let mut saw_encrypted_file = false;

    while pos + 7 <= buf.len() {
        let head_type = buf[pos + 2];
        let head_flags = match read_u16_le(&buf, pos + 3) {
            Some(v) => v,
            None => break,
        };
        let head_size = match read_u16_le(&buf, pos + 5) {
            Some(v) => v as usize,
            None => break,
        };
        if head_size < 7 {
            break;
        }
        let add_size = if head_flags & 0x8000 != 0 {
            read_u32_le(&buf, pos + 7).unwrap_or(0) as usize
        } else {
            0
        };

        if head_type == 0x73 && (head_flags & 0x0080) != 0 {
            // Archive header with encrypted-headers (-hp): the 8-byte salt is
            // the tail of the header block; the encrypted verification block
            // follows the header.
            let salt_off = pos + head_size - 8;
            let enc_off = pos + head_size + add_size;
            if let (Some(salt), Some(enc)) = (
                buf.get(salt_off..salt_off + 8),
                buf.get(enc_off..enc_off + 16),
            ) {
                let line = format!("$RAR3$*0*{}*{}", hex_encode(salt), hex_encode(enc));
                return HashResult::ok(FORMAT, source_name, line, Some(12500)).with_warning(
                    "RAR3 header-encrypted (-hp) output is best-effort",
                );
            }
        }

        if head_type == 0x74 && (head_flags & 0x0004) != 0 {
            saw_encrypted_file = true;
        }

        let advance = head_size + add_size;
        if advance == 0 {
            break;
        }
        pos += advance;
    }

    if saw_encrypted_file {
        return HashResult::warn(
            FORMAT,
            source_name,
            "RAR3 file-data encryption (-p) detected but is only partially supported",
        );
    }

    HashResult::warn(FORMAT, source_name, "RAR3 archive is not password-encrypted")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vint_single_byte() {
        assert_eq!(read_vint(&[0x0f], 0), Some((15, 1)));
    }

    #[test]
    fn vint_multi_byte() {
        // 0x80 0x01 => 0b0000001_0000000 = 128
        assert_eq!(read_vint(&[0x80, 0x01], 0), Some((128, 2)));
    }
}
