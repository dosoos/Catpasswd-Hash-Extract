//! Microsoft Office extractor (`$office$` / `$oldoffice$`).
//!
//! - Office 2007+ (OLE/CFB `EncryptionInfo`): Agile XML and Standard binary
//!   → `$office$*…` (hashcat 9400/9500/9600)
//! - Excel 97–2003 (BIFF `FILEPASS` in `Workbook`/`Book`): RC4 / CryptoAPI
//!   → `$oldoffice$*…` (hashcat 9700/9800), matching John `office2john.py`
//!
//! Implemented from MS-OFFCRYPTO / MS-XLS. Legacy XOR obfuscation is reported
//! but not emitted as a crackable hash line.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use super::util::{hex_encode, read_u16_le, read_u32_le};
use crate::models::HashResult;

const FORMAT: &str = "office";

/// `EncryptionInfo` is a small stream stored near the container start; a
/// bounded prefix is enough to find it without loading huge documents.
const MAX_SCAN: u64 = 8 * 1024 * 1024;

/// Cap Workbook stream read for FILEPASS / second-block extraction.
const MAX_WORKBOOK_STREAM: usize = 64 * 1024 * 1024;

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

    // Excel 97–2003: BIFF FILEPASS inside Workbook/Book (John $oldoffice$).
    match try_oldoffice_xls(path, source_name) {
        Ok(Some(res)) => return res,
        Ok(None) => {}
        Err(e) => {
            return HashResult::err(FORMAT, source_name, format!("OLE/XLS parse error: {e}"));
        }
    }

    HashResult::warn(
        FORMAT,
        source_name,
        "no Office EncryptionInfo / FILEPASS found; file is likely not password-encrypted",
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

// ------------------------ Excel 97–2003 (XLS) ------------------------

/// Scan BIFF records in `Workbook`/`Book` for `FILEPASS` (0x2F), matching
/// John `office2john.py` → `$oldoffice$`.
fn try_oldoffice_xls(path: &Path, source_name: &str) -> Result<Option<HashResult>, String> {
    let mut comp = cfb::open(path).map_err(|e| e.to_string())?;

    let stream_name = ["Workbook", "Book", "/Workbook", "/Book"]
        .into_iter()
        .find(|n| comp.is_stream(n));

    let Some(stream_name) = stream_name else {
        return Ok(None);
    };

    let mut stream = comp
        .open_stream(stream_name)
        .map_err(|e| e.to_string())?;
    let mut data = Vec::new();
    stream
        .by_ref()
        .take(MAX_WORKBOOK_STREAM as u64)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;

    Ok(parse_xls_filepass(&data, source_name))
}

fn parse_xls_filepass(stream: &[u8], source_name: &str) -> Option<HashResult> {
    let mut pos = 0usize;
    while pos + 4 <= stream.len() {
        let rec_type = read_u16_le(stream, pos)?;
        let length = read_u16_le(stream, pos + 2)? as usize;
        let data_off = pos + 4;
        if data_off.saturating_add(length) > stream.len() {
            break;
        }
        let data = &stream[data_off..data_off + length];
        let after = data_off + length;

        if rec_type == 0x002f {
            // FILEPASS
            if length == 4 {
                return Some(HashResult::warn(
                    FORMAT,
                    source_name,
                    "Excel 95 XOR obfuscation detected; not crackable with $oldoffice$",
                ));
            }
            if data.len() >= 2 && data[0] == 0x00 && data[1] == 0x00 {
                return Some(HashResult::warn(
                    FORMAT,
                    source_name,
                    "Excel XOR obfuscation detected; not crackable with $oldoffice$",
                ));
            }
            // RC4 encryption header: 01 00 01 00 01 00 | salt(16) | verifier(16) | hash(16)
            if data.len() >= 6 + 48
                && data[0..6] == [0x01, 0x00, 0x01, 0x00, 0x01, 0x00]
            {
                let body = &data[6..];
                let salt = &body[0..16];
                let verifier = &body[16..32];
                let verifier_hash = &body[32..48];
                let line = format!(
                    "$oldoffice$0*{}*{}*{}",
                    hex_encode(salt),
                    hex_encode(verifier),
                    hex_encode(verifier_hash),
                );
                return Some(HashResult::ok(FORMAT, source_name, line, Some(9700)));
            }
            // RC4 CryptoAPI: 01 00 {02|03|04} 00 …
            if data.len() >= 4
                && data[0] == 0x01
                && data[1] == 0x00
                && matches!(data[2], 0x02 | 0x03 | 0x04)
                && data[3] == 0x00
            {
                return parse_xls_cryptoapi(data, stream, after, source_name);
            }
            return Some(HashResult::warn(
                FORMAT,
                source_name,
                "unrecognized Excel FILEPASS encryption header",
            ));
        }

        pos = after;
    }
    None
}

fn parse_xls_cryptoapi(
    data: &[u8],
    workbook: &[u8],
    after_filepass: usize,
    source_name: &str,
) -> Option<HashResult> {
    // Skip unused(2); then major, minor, flags, headerLength — same layout as
    // office2john find_rc4_passinfo_xls CryptoAPI branch.
    if data.len() < 12 {
        return None;
    }
    let mut off = 2usize; // unused
    let _major = read_u16_le(data, off)?;
    off += 2;
    let _minor = read_u16_le(data, off)?;
    off += 2;
    let _flags = read_u32_le(data, off)?;
    off += 4;
    let mut header_length = read_u32_le(data, off)? as usize;
    off += 4;

    // Header fields: Flags(4) SizeExtra(4) AlgID(4) AlgHashID(4) KeySize(4)
    // ProviderType(4) Reserved1(4) Reserved2(4) CSPName (remainder of header)
    if off + 8 > data.len() {
        return None;
    }
    off += 4; // skipFlags
    header_length = header_length.saturating_sub(4);
    off += 4; // sizeExtra
    header_length = header_length.saturating_sub(4);
    let _alg_id = read_u32_le(data, off)?;
    off += 4;
    header_length = header_length.saturating_sub(4);
    let _alg_hash = read_u32_le(data, off)?;
    off += 4;
    header_length = header_length.saturating_sub(4);
    let key_size = read_u32_le(data, off)?;
    off += 4;
    header_length = header_length.saturating_sub(4);
    off += 4; // providerType
    header_length = header_length.saturating_sub(4);
    off += 4; // unused
    header_length = header_length.saturating_sub(4);
    off += 4; // unused
    header_length = header_length.saturating_sub(4);
    if header_length > data.len().saturating_sub(off) {
        return None;
    }
    off += header_length; // CSPName (UTF-16)

    let typ = match key_size {
        40 => 3u32,
        128 => 4u32,
        56 => 5u32,
        other => {
            return Some(HashResult::warn(
                FORMAT,
                source_name,
                format!("Excel CryptoAPI RC4 unsupported keySize {other}"),
            ));
        }
    };

    let salt_size = read_u32_le(data, off)? as usize;
    off += 4;
    if salt_size != 16 || off + 16 + 16 + 4 + 20 > data.len() {
        return None;
    }
    let salt = &data[off..off + 16];
    off += 16;
    let enc_verifier = &data[off..off + 16];
    off += 16;
    let verifier_hash_size = read_u32_le(data, off)? as usize;
    off += 4;
    if verifier_hash_size != 20 || off + 20 > data.len() {
        return None;
    }
    let enc_verifier_hash = &data[off..off + 20];

    let mut line = format!(
        "$oldoffice${typ}*{}*{}*{}",
        hex_encode(salt),
        hex_encode(enc_verifier),
        hex_encode(enc_verifier_hash),
    );

    // Type 3 (40-bit): John appends 32 bytes from the second 1024-byte block.
    if typ == 3 {
        if after_filepass > 1024 {
            return Some(HashResult::warn(
                FORMAT,
                source_name,
                "Excel CryptoAPI type-3 FILEPASS past first block; cannot read second block",
            ));
        }
        let block2 = 1024usize;
        if workbook.len() < block2 + 32 {
            return Some(HashResult::warn(
                FORMAT,
                source_name,
                "Excel Workbook too short for type-3 second block",
            ));
        }
        line.push('*');
        line.push_str(&hex_encode(&workbook[block2..block2 + 32]));
    }

    let mode = if typ <= 1 { 9700 } else { 9800 };
    Some(HashResult::ok(FORMAT, source_name, line, Some(mode)))
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

    #[test]
    fn xls_rc4_filepass_type0() {
        // BIFF FILEPASS: type=0x2f, len=54, RC4 header + salt/verifier/hash
        let mut stream = Vec::new();
        stream.extend_from_slice(&0x002fu16.to_le_bytes());
        stream.extend_from_slice(&54u16.to_le_bytes());
        stream.extend_from_slice(&[0x01, 0x00, 0x01, 0x00, 0x01, 0x00]);
        stream.extend_from_slice(&[0x11; 16]); // salt
        stream.extend_from_slice(&[0x22; 16]); // verifier
        stream.extend_from_slice(&[0x33; 16]); // verifierHash
        let res = parse_xls_filepass(&stream, "t.xls").expect("filepass");
        assert_eq!(res.hashcat_mode, Some(9700));
        assert!(res.hash_line.starts_with("$oldoffice$0*"));
        assert!(res.hash_line.contains(&"11".repeat(16)));
        assert!(res.hash_line.contains(&"22".repeat(16)));
        assert!(res.hash_line.contains(&"33".repeat(16)));
    }

    #[test]
    fn xls_xor_filepass_warns() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&0x002fu16.to_le_bytes());
        stream.extend_from_slice(&6u16.to_le_bytes());
        stream.extend_from_slice(&[0x00, 0x00, 0xab, 0xcd, 0xef, 0x01]);
        let res = parse_xls_filepass(&stream, "t.xls").expect("xor");
        assert!(res.hash_line.is_empty());
        assert!(res.warnings.iter().any(|w| w.contains("XOR")));
    }
}
