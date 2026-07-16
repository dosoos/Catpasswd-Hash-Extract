//! Microsoft Office extractor (`$office$`, hashcat 9400/9500/9600).
//!
//! Encrypted Office 2007+ documents are OLE/CFB containers holding an
//! `EncryptionInfo` stream. This module locates that stream's content by
//! scanning the container prefix and supports:
//! - Agile encryption (2010 = SHA1, 2013+ = SHA512) parsed from its XML
//! - Standard ECMA-376 encryption (2007) parsed from its binary header
//!
//! Implemented from MS-OFFCRYPTO. Legacy 97-2003 XOR/RC4 is only reported.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use super::util::{hex_encode, read_u32_le};
use crate::models::HashResult;

const FORMAT: &str = "office";

/// `EncryptionInfo` is a small stream stored near the container start; a
/// bounded prefix is enough to find it without loading huge documents.
const MAX_SCAN: u64 = 8 * 1024 * 1024;

pub fn extract(path: &Path, source_name: &str) -> HashResult {
    let buf = match read_prefix(path) {
        Ok(b) => b,
        Err(e) => return HashResult::err(FORMAT, source_name, format!("cannot read file: {e}")),
    };

    // Agile encryption: EncryptionInfo XML embedded in the container.
    if let Some(res) = try_agile(&buf, source_name) {
        return res;
    }

    // Standard ECMA-376 (Office 2007) binary EncryptionInfo.
    if let Some(res) = try_standard(&buf, source_name) {
        return res;
    }

    // Legacy 97-2003 documents embed FIB flags; detect the encrypted bit only.
    if looks_like_legacy_encrypted(&buf) {
        return HashResult::warn(
            FORMAT,
            source_name,
            "legacy 97-2003 XOR/RC4 encryption detected; not yet supported",
        );
    }

    HashResult::warn(
        FORMAT,
        source_name,
        "no Office EncryptionInfo found; file is likely not password-encrypted",
    )
}

fn read_prefix(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let len = file.metadata().map(|m| m.len()).unwrap_or(MAX_SCAN);
    let cap = len.min(MAX_SCAN) as usize;
    let mut buf = vec![0u8; cap];
    let n = file.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

// ----------------------------- Agile -----------------------------

fn try_agile(buf: &[u8], source_name: &str) -> Option<HashResult> {
    // The XML is UTF-8. Find the <encryptedKey .../> element.
    let text = String::from_utf8_lossy(buf);
    let key_pos = text.find("encryptedKey")?;
    let rest = &text[key_pos..];
    let end = rest.find("/>")?;
    let el = &rest[..end];

    let salt_b64 = attr(el, "saltValue")?;
    let verifier_in_b64 = attr(el, "encryptedVerifierHashInput")?;
    let verifier_val_b64 = attr(el, "encryptedVerifierHashValue")?;

    let spin_count: u64 = attr(el, "spinCount").and_then(|s| s.parse().ok()).unwrap_or(100_000);
    let key_bits: u32 = attr(el, "keyBits").and_then(|s| s.parse().ok()).unwrap_or(256);
    let hash_algo = attr(el, "hashAlgorithm").unwrap_or("SHA512").to_string();

    let salt = B64.decode(salt_b64.as_bytes()).ok()?;
    let vin = B64.decode(verifier_in_b64.as_bytes()).ok()?;
    let vval = B64.decode(verifier_val_b64.as_bytes()).ok()?;
    let salt_size = salt.len();

    let (year, mode, mut warnings) = match hash_algo.as_str() {
        "SHA1" => (2010u32, 9500u32, Vec::new()),
        "SHA512" => (2013u32, 9600u32, Vec::new()),
        other => (
            2013u32,
            9600u32,
            vec![format!(
                "unusual agile hashAlgorithm '{other}'; emitting 2013 (9600) shape"
            )],
        ),
    };

    let line = format!(
        "$office$*{year}*{spin}*{keybits}*{ssize}*{salt}*{vin}*{vval}",
        year = year,
        spin = spin_count,
        keybits = key_bits,
        ssize = salt_size,
        salt = hex_encode(&salt),
        vin = hex_encode(&vin),
        vval = hex_encode(&vval),
    );

    let mut res = HashResult::ok(FORMAT, source_name, line, Some(mode));
    for w in warnings.drain(..) {
        res = res.with_warning(w);
    }
    Some(res)
}

fn attr<'a>(el: &'a str, name: &str) -> Option<&'a str> {
    // Match `name="..."` guarding against prefix collisions (e.g. saltValue vs
    // Value) by requiring the char before `name` to be a non-identifier one.
    let needle = format!("{name}=\"");
    let mut from = 0usize;
    while let Some(rel) = el[from..].find(&needle) {
        let idx = from + rel;
        let ok_boundary = idx == 0
            || !el.as_bytes()[idx - 1].is_ascii_alphanumeric();
        if ok_boundary {
            let start = idx + needle.len();
            let tail = &el[start..];
            let end = tail.find('"')?;
            return Some(&tail[..end]);
        }
        from = idx + needle.len();
    }
    None
}

// ---------------------------- Standard ----------------------------

fn try_standard(buf: &[u8], source_name: &str) -> Option<HashResult> {
    // Standard EncryptionInfo begins with version major/minor and flags. Scan
    // for plausible version markers (major in {2,3,4}, minor == 2).
    for major in [2u8, 3, 4] {
        let sig = [major, 0x00, 0x02, 0x00];
        let mut from = 0usize;
        while let Some(rel) = find(&buf[from..], &sig) {
            let pos = from + rel;
            if let Some(res) = parse_standard_at(buf, pos, source_name) {
                return Some(res);
            }
            from = pos + 1;
        }
    }
    None
}

fn parse_standard_at(buf: &[u8], pos: usize, source_name: &str) -> Option<HashResult> {
    // Layout from pos: version(4) flags(4) headerSize(4) header(headerSize)
    //                  verifier { saltSize(4) salt(16) encVerifier(16)
    //                             verifierHashSize(4) encVerifierHash(32) }
    let header_size = read_u32_le(buf, pos + 8)? as usize;
    if header_size < 32 || header_size > 4096 {
        return None;
    }
    let header_off = pos + 12;
    let alg_id = read_u32_le(buf, header_off + 8)?;
    let key_size = read_u32_le(buf, header_off + 16)?;
    // AlgID: 0x6801 RC4, 0x660E AES128, 0x660F AES192, 0x6610 AES256.
    let is_supported_alg = matches!(alg_id, 0x6801 | 0x660E | 0x660F | 0x6610 | 0x0000);
    if !is_supported_alg {
        return None;
    }

    let ver_off = header_off + header_size;
    let salt_size = read_u32_le(buf, ver_off)? as usize;
    if salt_size != 16 {
        return None;
    }
    let salt = buf.get(ver_off + 4..ver_off + 20)?;
    let enc_verifier = buf.get(ver_off + 20..ver_off + 36)?;
    let verifier_hash_size = read_u32_le(buf, ver_off + 36)? as usize;
    let enc_verifier_hash = buf.get(ver_off + 40..ver_off + 40 + 32)?;

    let key_bits = if key_size == 0 { 128 } else { key_size };

    let line = format!(
        "$office$*2007*{vhs}*{keybits}*16*{salt}*{ev}*{evh}",
        vhs = verifier_hash_size,
        keybits = key_bits,
        salt = hex_encode(salt),
        ev = hex_encode(enc_verifier),
        evh = hex_encode(enc_verifier_hash),
    );

    let mut res = HashResult::ok(FORMAT, source_name, line, Some(9400));
    if alg_id == 0x6801 {
        res = res.with_warning("RC4 standard encryption detected; verify cracker support");
    }
    Some(res)
}

fn looks_like_legacy_encrypted(buf: &[u8]) -> bool {
    // Heuristic: OLE container that is not agile/standard but references a
    // legacy encryption provider or WordDocument FIB encrypted flag.
    find(buf, b"E\x00n\x00c\x00r\x00y\x00p\x00t").is_some()
        || find(buf, b"W\x00o\x00r\x00d\x00D\x00o\x00c").is_some()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attr_extraction() {
        let el = r#"encryptedKey spinCount="100000" keyBits="256" saltValue="AAAA" hashAlgorithm="SHA512""#;
        assert_eq!(attr(el, "spinCount"), Some("100000"));
        assert_eq!(attr(el, "keyBits"), Some("256"));
        assert_eq!(attr(el, "saltValue"), Some("AAAA"));
        assert_eq!(attr(el, "hashAlgorithm"), Some("SHA512"));
    }

    #[test]
    fn agile_line_shape() {
        let xml = r#"<?xml version="1.0"?><encryption><keyData saltSize="16"/><p:encryptedKey spinCount="100000" saltSize="16" keyBits="256" hashAlgorithm="SHA512" saltValue="MTIzNDU2Nzg5MDEyMzQ1Ng==" encryptedVerifierHashInput="MTIzNDU2Nzg5MDEyMzQ1Ng==" encryptedVerifierHashValue="MTIzNDU2Nzg5MDEyMzQ1Ng=="/></encryption>"#;
        let res = try_agile(xml.as_bytes(), "t.docx").expect("agile");
        assert_eq!(res.hashcat_mode, Some(9600));
        assert!(res.hash_line.starts_with("$office$*2013*100000*256*16*"));
    }
}
