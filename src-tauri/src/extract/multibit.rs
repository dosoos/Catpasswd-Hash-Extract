//! MultiBit wallet extractor (`$multibit$`, hashcat 11400).
//!
//! Supports three MultiBit layouts per John `multibit2john.py`:
//!
//! - **v1 — MultiBit Classic `.key`**: an OpenSSL-style `Salted__` prefix
//!   followed by 8 bytes salt then ciphertext. Output:
//!   `$multibit$1*<salt_hex>*<enc_hex>`  (enc = bytes[16:48] of decoded blob)
//!
//! - **v2 — MultiBit HD**: file is the raw encrypted data; output contains
//!   both an IV-and-block form and a no-IV (hardcoded IV) form (three hex
//!   segments): `$multibit$2*<iv_hex>*<block_iv_hex>*<block_noiv_hex>`
//!
//! - **v3 — bitcoinj/MultiBit `.wallet` protobuf**: scrypt-encrypted protobuf
//!   wallet. Output: `$multibit$3*<n>*<r>*<p>*<salt_hex>*<enc_last32_hex>`
//!   (this is the same layout Coinomi uses — hashcat mode 11400).

use std::fs::File;
use std::io::Read;
use std::path::Path;

use base64::Engine;

use crate::models::HashResult;

const FORMAT: &str = "multibit";

pub fn extract(path: &Path, source_name: &str) -> HashResult {
    let mut data = Vec::new();
    if let Err(e) = File::open(path).and_then(|mut f| f.read_to_end(&mut data)) {
        return HashResult::err(FORMAT, source_name, format!("cannot read file: {e}"));
    }

    if data.len() < 16 {
        return HashResult::err(FORMAT, source_name, "file too small for a MultiBit wallet");
    }

    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let looks_like_wallet_protobuf =
        name.contains("wallet") || data.windows(20).any(|w| w.starts_with(b"org.bitcoin.production"));

    if looks_like_wallet_protobuf {
        // Try bitcoinj / MultiBit .wallet protobuf (v3).
        if let Some(line) = try_protobuf_v3(&data) {
            return HashResult::ok(FORMAT, source_name, line, Some(11400));
        }
    }

    // v1 / v2 path: strip whitespace, try base64 decode.
    let pdata: Vec<u8> = data.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    if pdata.len() < 64 {
        return HashResult::err(FORMAT, source_name, "short file for a MultiBit key");
    }

    let b64 = base64::engine::general_purpose::STANDARD;
    if let Ok(decoded) = b64.decode(&pdata[..pdata.len().min(64)]) {
        if decoded.starts_with(b"Salted__") {
            return build_v1(&decoded, source_name);
        }
    }
    // v2 MultiBit HD.
    build_v2(&data, source_name)
}

fn build_v1(decoded: &[u8], source_name: &str) -> HashResult {
    // OpenSSL Salted__<8-byte salt><ciphertext...>
    if decoded.len() < 48 {
        return HashResult::err(
            FORMAT,
            source_name,
            "MultiBit v1 decoded data too short",
        );
    }
    let salt = &decoded[8..16];
    let enc = &decoded[16..48]; // two AES blocks
    let line = format!(
        "$multibit$1*{salt}*{enc}",
        salt = hex::encode(salt),
        enc = hex::encode(enc),
    );
    HashResult::ok(FORMAT, source_name, line, Some(11400))
}

fn build_v2(data: &[u8], source_name: &str) -> HashResult {
    if data.len() < 32 {
        return HashResult::err(
            FORMAT,
            source_name,
            "MultiBit v2 wallet too short",
        );
    }
    let iv = &data[..16];
    let block_iv = &data[16..32];
    let block_noiv = &data[..16];
    let line = format!(
        "$multibit$2*{iv}*{biv}*{bnoiv}",
        iv = hex::encode(iv),
        biv = hex::encode(block_iv),
        bnoiv = hex::encode(block_noiv),
    );
    HashResult::ok(FORMAT, source_name, line, Some(11400))
}

fn try_protobuf_v3(data: &[u8]) -> Option<String> {
    // bitcoinj wallet protobuf (field numbers match multibit2john/coinomi2john):
    //   Wallet.encryption_type        = field 1, varint → expect 2 (ENCRYPTED_SCRYPT_AES)
    //   Wallet.encryption_parameters  = field 4, sub-message (salt, n, r, p)
    //   Wallet.key                    = field 2 (repeated), sub-message
    //     key.type                    = field 1, varint → ENCRYPTED_SCRYPT_AES=2 or DETERMINISTIC_KEY
    //     key.encrypted_data          = field 3, sub-message
    //       encrypted_data.encrypted_private_key = field 2, bytes (48 bytes)
    let mut p = 0usize;
    let mut encryption_type: Option<u64> = None;
    let mut salt: Option<Vec<u8>> = None;
    let mut n: Option<u64> = None;
    let mut r: Option<u64> = None;
    let mut pp: Option<u64> = None;
    let mut found_key: Option<Vec<u8>> = None;

    while p < data.len() {
        let tag = read_varint(data, &mut p)?;
        let field_num = tag >> 3;
        let wire_type = tag & 0x07;
        match field_num {
            1 if wire_type == 0 => encryption_type = Some(read_varint(data, &mut p)?),
            2 if wire_type == 2 => {
                let len = read_varint(data, &mut p)? as usize;
                if p + len > data.len() {
                    return None;
                }
                let sub = &data[p..p + len];
                p += len;
                if found_key.is_none() {
                    if let Some(epk) = parse_wallet_key(sub) {
                        found_key = Some(epk);
                    }
                }
            }
            4 if wire_type == 2 => {
                let len = read_varint(data, &mut p)? as usize;
                if p + len > data.len() {
                    return None;
                }
                let sub = &data[p..p + len];
                p += len;
                let (s, nn, rr, pv) = parse_encryption_params(sub)?;
                salt = Some(s);
                n = nn;
                r = rr;
                pp = pv;
            }
            _ => skip_field(data, &mut p, wire_type)?,
        }
    }

    if encryption_type? != 2 {
        return None;
    }
    let epk = found_key?;
    if epk.len() != 48 {
        return None;
    }
    let last32 = &epk[epk.len() - 32..];
    Some(format!(
        "$multibit$3*{n}*{r}*{p}*{salt}*{enc}",
        n = n?,
        r = r?,
        p = pp?,
        salt = hex::encode(salt.as_ref()?),
        enc = hex::encode(last32),
    ))
}

fn parse_wallet_key(data: &[u8]) -> Option<Vec<u8>> {
    let mut p = 0usize;
    let mut _key_type: Option<u64> = None;
    while p < data.len() {
        let tag = read_varint(data, &mut p)?;
        let field_num = tag >> 3;
        let wire_type = tag & 0x07;
        match field_num {
            1 if wire_type == 0 => _key_type = Some(read_varint(data, &mut p)?),
            3 if wire_type == 2 => {
                // encrypted_data sub-message
                let len = read_varint(data, &mut p)? as usize;
                if p + len > data.len() {
                    return None;
                }
                let sub = &data[p..p + len];
                // inside: field 2 = encrypted_private_key bytes
                let mut sp = 0usize;
                while sp < sub.len() {
                    let stag = read_varint(sub, &mut sp)?;
                    let sfield = stag >> 3;
                    let swire = stag & 0x07;
                    if sfield == 2 && swire == 2 {
                        let elen = read_varint(sub, &mut sp)? as usize;
                        if sp + elen > sub.len() {
                            return None;
                        }
                        return Some(sub[sp..sp + elen].to_vec());
                    }
                    skip_field(sub, &mut sp, swire);
                }
                return None;
            }
            _ => skip_field(data, &mut p, wire_type)?,
        }
    }
    None
}

fn parse_encryption_params(data: &[u8]) -> Option<(Vec<u8>, Option<u64>, Option<u64>, Option<u64>)> {
    let mut p = 0usize;
    let mut salt = None;
    let mut n = None;
    let mut r = None;
    let mut pp = None;
    while p < data.len() {
        let tag = read_varint(data, &mut p)?;
        let field_num = tag >> 3;
        let wire_type = tag & 0x07;
        match field_num {
            1 if wire_type == 2 => {
                let len = read_varint(data, &mut p)? as usize;
                if p + len > data.len() {
                    return None;
                }
                salt = Some(data[p..p + len].to_vec());
                p += len;
            }
            2 if wire_type == 0 => n = Some(read_varint(data, &mut p)?),
            3 if wire_type == 0 => r = Some(read_varint(data, &mut p)?),
            4 if wire_type == 0 => pp = Some(read_varint(data, &mut p)?),
            _ => skip_field(data, &mut p, wire_type)?,
        }
    }
    Some((salt?, n, r, pp))
}

fn read_varint(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= data.len() {
            return None;
        }
        let b = data[*pos];
        *pos += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

fn skip_field(data: &[u8], pos: &mut usize, wire_type: u64) -> Option<()> {
    match wire_type {
        0 => {
            let _ = read_varint(data, pos)?;
        }
        1 => {
            if *pos + 8 > data.len() {
                return None;
            }
            *pos += 8;
        }
        2 => {
            let len = read_varint(data, pos)? as usize;
            if *pos + len > data.len() {
                return None;
            }
            *pos += len;
        }
        5 => {
            if *pos + 4 > data.len() {
                return None;
            }
            *pos += 4;
        }
        _ => return None,
    }
    Some(())
}

pub fn looks_like_multibit(head: &[u8], path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    // Java serialized-object magic is a strong indicator of MultiBit Classic .key.
    if head.len() >= 4 && head.starts_with(&[0xAC, 0xED, 0x00, 0x05]) {
        return name.ends_with(".key") || name.contains("multibit");
    }
    // bitcoinj protobuf wallet starts with 0x0a tag.
    if name.ends_with(".wallet") && !head.is_empty() && head[0] == 0x0a {
        return true;
    }
    name.ends_with(".key")
        && (name.contains("multibit")
            || !(name.contains("bip38") || name.contains("privkey")))
}
