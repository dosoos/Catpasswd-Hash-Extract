//! BIP38 encrypted private key extractor (`$bip38$`, hashcat 16201/16202).
//!
//! BIP38 is a standard for passphrase-encoded Bitcoin private keys. The
//! ciphertext is a base58check string starting with `6P` (non-EC-multiply) or
//! `6Pf` / `6Pn` etc. — decoded it's 43 bytes:
//!
//!   byte 0-1 : 0x01 0x42 (magic)
//!   byte 2   : flags (bit 0x20 = EC multiply, bit 0x04 = lot/sequence present)
//!   byte 3+  : addresshash[4] + encrypted-data[32]
//!
//! We extract both types:
//!   16201 — non-EC-multiply (39 bytes ciphertext)
//!   16202 — EC-multiply (longer form with owner/active seeds)
//!
//! The file input can be either a raw key file, a text file containing the
//! key, or a wallet export; we search for the `6P...` token anywhere in the
//! file content.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::models::HashResult;

const FORMAT: &str = "bip38";
const B58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn extract(path: &Path, source_name: &str) -> HashResult {
    let mut content = Vec::new();
    if let Err(e) = File::open(path).and_then(|mut f| f.read_to_end(&mut content)) {
        return HashResult::err(FORMAT, source_name, format!("cannot read file: {e}"));
    }

    // Try as UTF-8 text first (most common case — keys in .txt/.json/exports).
    let text = String::from_utf8_lossy(&content);

    // Search for any token starting with '6P' that's 58 characters long
    // (the canonical BIP38 encoded key length).
    let mut keys_found = Vec::new();
    for word in text.split(|c: char| !c.is_ascii_alphanumeric()) {
        let w = word.trim();
        if w.len() == 58 && w.starts_with("6P") && w.chars().all(is_b58_char) {
            keys_found.push(w.to_string());
        }
    }

    // Also accept raw binary if the file is exactly 58 bytes (rare).
    if keys_found.is_empty() && content.len() == 58 {
        if let Ok(s) = std::str::from_utf8(&content) {
            let s = s.trim();
            if s.len() == 58 && s.starts_with("6P") && s.chars().all(is_b58_char) {
                keys_found.push(s.to_string());
            }
        }
    }

    if keys_found.is_empty() {
        return HashResult::warn(
            FORMAT,
            source_name,
            "no BIP38 encrypted key (6P...) found in file",
        );
    }

    // Use the first key found; warn if there were multiple.
    let key = &keys_found[0];
    match decode_bip38(key) {
        Some((flag, payload)) => {
            let ec_multiply = flag & 0x20 != 0;
            let mode = if ec_multiply { 16202 } else { 16201 };

            // `$bip38$<payload_hex>` where payload is the full 43 decoded bytes.
            let line = format!("$bip38${}", hex::encode(&payload));

            let mut res = HashResult::ok(FORMAT, source_name, line, Some(mode));
            if keys_found.len() > 1 {
                res = res.with_warning(format!(
                    "multiple BIP38 keys found in file; extracted the first one ({} total)",
                    keys_found.len()
                ));
            }
            res
        }
        None => HashResult::err(
            FORMAT,
            source_name,
            "found a 6P... token but base58check decoding failed",
        ),
    }
}

fn is_b58_char(c: char) -> bool {
    B58_ALPHABET.iter().any(|a| *a as char == c)
}

fn b58_decode(s: &str) -> Option<Vec<u8>> {
    let mut result = vec![0u8; (s.len() * 733 + 999) / 1000]; // log2(58) ≈ 5.857 bits
    for ch in s.chars() {
        let digit = B58_ALPHABET.iter().position(|a| *a as char == ch)? as u32;
        let mut carry = digit;
        for byte in result.iter_mut().rev() {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        if carry != 0 {
            return None;
        }
    }
    // Strip leading zeros; the leading '1's in b58 become leading zero bytes.
    let mut leading_ones = 0;
    for ch in s.chars() {
        if ch == '1' {
            leading_ones += 1;
        } else {
            break;
        }
    }
    let mut out = Vec::with_capacity(leading_ones + result.len());
    out.extend(std::iter::repeat(0u8).take(leading_ones));
    // Skip leading zero bytes added by our vector sizing.
    let start = result.iter().position(|b| *b != 0).unwrap_or(result.len());
    out.extend_from_slice(&result[start..]);
    Some(out)
}

fn decode_bip38(s: &str) -> Option<(u8, Vec<u8>)> {
    let decoded = b58_decode(s)?;
    if decoded.len() != 43 {
        return None;
    }
    // Last 4 bytes are a double-SHA256 checksum; we don't verify strictly — the
    // format id `0142` + flag byte are what hashcat needs.
    if decoded[0] != 0x01 || decoded[1] != 0x42 {
        return None;
    }
    Some((decoded[2], decoded))
}

pub fn looks_like_bip38(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    name.contains("bip38") || name.contains("privkey") || name.ends_with(".key")
}
