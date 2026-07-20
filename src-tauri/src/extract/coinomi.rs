//! Coinomi wallet extractor.
//!
//! Coinomi `.coinomi` files are protobuf-serialized wallets encrypted with
//! scrypt+AES. Output matches John `coinomi2john.py` byte-for-byte:
//!
//! `$multibit$3*<n>*<r>*<p>*<salt_hex>*<enc_private_key_last32_hex>`
//!
//! Note: the output uses the `$multibit$3*` prefix (hashcat mode 11400) because
//! that kernel already supports the same scrypt layout Coinomi uses. We set
//! `format = "coinomi"` for display and the matching hashcat mode.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::models::HashResult;

const FORMAT: &str = "coinomi";

pub fn extract(path: &Path, source_name: &str) -> HashResult {
    let mut data = Vec::new();
    if let Err(e) = File::open(path).and_then(|mut f| f.read_to_end(&mut data)) {
        return HashResult::err(FORMAT, source_name, format!("cannot read file: {e}"));
    }

    // Quick heuristic: Coinomi protobuf starts with field 1 (encryption_type,
    // varint) encoded as 0x08.
    if data.is_empty() {
        return HashResult::err(FORMAT, source_name, "empty Coinomi wallet file");
    }

    match parse_coinomi_protobuf(&data) {
        Some(rec) => {
            // last 32 bytes of encrypted_private_key
            let enc_last32 = if rec.encrypted_private_key.len() >= 32 {
                &rec.encrypted_private_key[rec.encrypted_private_key.len() - 32..]
            } else {
                return HashResult::err(
                    FORMAT,
                    source_name,
                    "encrypted master key too short",
                );
            };
            let line = format!(
                "$multibit$3*{n}*{r}*{p}*{salt}*{enc}",
                n = rec.n,
                r = rec.r,
                p = rec.p,
                salt = hex::encode(&rec.salt),
                enc = hex::encode(enc_last32),
            );
            HashResult::ok(FORMAT, source_name, line, Some(11400))
        }
        None => HashResult::err(
            FORMAT,
            source_name,
            "could not parse Coinomi wallet (not encrypted or unknown layout)",
        ),
    }
}

struct CoinomiRec {
    encrypted_private_key: Vec<u8>,
    salt: Vec<u8>,
    n: u64,
    r: u64,
    p: u64,
}

/// Minimal protobuf wire-format parser that picks out the fields we need:
///
///   Wallet.encryption_type          = field 1, varint  → expect ENCRYPTED_SCRYPT_AES (2)
///   Wallet.master_key               = field 3, sub-message
///     master_key.encrypted_data     = field 1, sub-message
///       encrypted_data.encrypted_private_key = field 2, length-delimited bytes
///   Wallet.encryption_parameters    = field 6, sub-message
///     encryption_parameters.salt    = field 1, length-delimited bytes
///     encryption_parameters.n       = field 2, varint
///     encryption_parameters.r       = field 3, varint
///     encryption_parameters.p       = field 4, varint
fn parse_coinomi_protobuf(data: &[u8]) -> Option<CoinomiRec> {
    let mut p = 0usize;
    let mut encryption_type: Option<u64> = None;
    let mut encrypted_private_key: Option<Vec<u8>> = None;
    let mut salt: Option<Vec<u8>> = None;
    let mut n: Option<u64> = None;
    let mut r: Option<u64> = None;
    let mut p_val: Option<u64> = None;

    while p < data.len() {
        let tag = read_varint(data, &mut p)?;
        let field_num = tag >> 3;
        let wire_type = tag & 0x07;
        match field_num {
            1 => {
                // encryption_type
                if wire_type == 0 {
                    encryption_type = Some(read_varint(data, &mut p)?);
                } else {
                    skip_field(data, &mut p, wire_type)?;
                }
            }
            3 => {
                // master_key sub-message
                if wire_type == 2 {
                    let len = read_varint(data, &mut p)? as usize;
                    if p + len > data.len() {
                        return None;
                    }
                    let sub = &data[p..p + len];
                    p += len;
                    if let Some(epk) = parse_master_key(sub) {
                        encrypted_private_key = Some(epk);
                    }
                } else {
                    skip_field(data, &mut p, wire_type)?;
                }
            }
            6 => {
                // encryption_parameters sub-message
                if wire_type == 2 {
                    let len = read_varint(data, &mut p)? as usize;
                    if p + len > data.len() {
                        return None;
                    }
                    let sub = &data[p..p + len];
                    p += len;
                    let (s, nn, rr, pp) = parse_encryption_params(sub)?;
                    salt = Some(s);
                    n = nn;
                    r = rr;
                    p_val = pp;
                } else {
                    skip_field(data, &mut p, wire_type)?;
                }
            }
            _ => skip_field(data, &mut p, wire_type)?,
        }
    }

    if encryption_type != Some(2) {
        // 2 = ENCRYPTED_SCRYPT_AES
        return None;
    }
    Some(CoinomiRec {
        encrypted_private_key: encrypted_private_key?,
        salt: salt?,
        n: n?,
        r: r?,
        p: p_val?,
    })
}

fn parse_master_key(data: &[u8]) -> Option<Vec<u8>> {
    let mut p = 0usize;
    while p < data.len() {
        let tag = read_varint(data, &mut p)?;
        let field_num = tag >> 3;
        let wire_type = tag & 0x07;
        if field_num == 1 && wire_type == 2 {
            // encrypted_data sub-message
            let len = read_varint(data, &mut p)? as usize;
            if p + len > data.len() {
                return None;
            }
            let sub = &data[p..p + len];
            // inside encrypted_data: field 2 = encrypted_private_key (bytes)
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
        skip_field(data, &mut p, wire_type);
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
            // varint
            let _ = read_varint(data, pos)?;
        }
        1 => {
            // 64-bit
            if *pos + 8 > data.len() {
                return None;
            }
            *pos += 8;
        }
        2 => {
            // length-delimited
            let len = read_varint(data, pos)? as usize;
            if *pos + len > data.len() {
                return None;
            }
            *pos += len;
        }
        5 => {
            // 32-bit
            if *pos + 4 > data.len() {
                return None;
            }
            *pos += 4;
        }
        _ => return None,
    }
    Some(())
}

pub fn looks_like_coinomi(head: &[u8], path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase() == "coinomi")
        .unwrap_or(false)
        || (head.starts_with(b"\x08") && path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase() == "wallet")
            .unwrap_or(false))
}
