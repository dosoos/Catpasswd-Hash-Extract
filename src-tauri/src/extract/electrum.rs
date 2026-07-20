//! Electrum wallet extractor (`$electrum$`, hashcat 16600).
//!
//! Supports Electrum 1.x, 2.x through 4.x wallet formats. Output lines are
//! byte-for-byte compatible with John `electrum2john.py`.
//!
//! Format variants (all `*`-separated):
//!
//! - v1 (Electrum 1.x / upgraded old seed):   `$electrum$1*<iv_hex>*<enc_hex>`
//! - v2 (Electrum 2.x bip32 xprv):            `$electrum$2*<iv_hex>*<enc_hex>`
//! - v3 (imported private keys):              `$electrum$3*<iv_hex>*<enc_hex>`
//! - v4 (Electrum 2.8+ ECIES full):           `$electrum$4*<ephemeral_pubkey_hex>*<all_but_mac_hex>*<mac_hex>`
//! - v5 (Electrum 2.8+ ECIES truncated):      `$electrum$5*...`
//!
//! The encrypted blob is a base64-encoded value decoded to raw bytes; the
//! relevant IV and ciphertext slices are hexified for the hash line.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use base64::Engine;
use serde_json::Value;

use crate::models::HashResult;

const FORMAT: &str = "electrum";

pub fn extract(path: &Path, source_name: &str) -> HashResult {
    let mut raw = Vec::new();
    if let Err(e) = File::open(path).and_then(|mut f| f.read_to_end(&mut raw)) {
        return HashResult::err(FORMAT, source_name, format!("cannot read file: {e}"));
    }

    // Electrum 2.8+ ECIES wallets: whole file is base64 and decodes to BIE1 magic.
    {
        let b64 = base64::engine::general_purpose::STANDARD;
        if let Ok(decoded) = b64.decode(&raw) {
            if decoded.starts_with(b"BIE1") {
                return process_electrum28(&decoded, false, source_name);
            }
        }
    }

    // Try UTF-8 JSON / Python literal.
    let content = match std::str::from_utf8(&raw) {
        Ok(s) => s,
        Err(_) => {
            return HashResult::err(
                FORMAT,
                source_name,
                "Electrum wallet is not valid UTF-8 (corrupt or unsupported)",
            )
        }
    };

    // First try JSON (2.x+).
    if let Ok(v) = serde_json::from_str::<Value>(content) {
        if let Some(line) = process_json(&v) {
            return HashResult::ok(FORMAT, source_name, line, Some(16600));
        }
    }

    // Fall back to Python-literal Electrum 1.x.
    if let Some(line) = process_py_literal(content) {
        return HashResult::ok(FORMAT, source_name, line, Some(16600));
    }

    HashResult::warn(
        FORMAT,
        source_name,
        "Electrum wallet unrecognized format (unencrypted or unsupported layout)",
    )
}

fn process_electrum28(decoded: &[u8], truncate: bool, _source_name: &str) -> HashResult {
    // Layout (per electrum2john lines 42-54):
    //   decoded[0:4]   = 'BIE1'
    //   decoded[4:37]  = ephemeral_pubkey (33 bytes compressed)
    //   decoded[37:-32]= ciphertext
    //   decoded[-32:]  = mac
    if decoded.len() < 37 + 32 {
        return HashResult::err(FORMAT, _source_name, "Electrum 2.8+ wallet too small");
    }
    let ephemeral_pubkey = &decoded[4..37];
    let mac = &decoded[decoded.len() - 32..];
    let version: u8;
    let all_but_mac: &[u8];
    if truncate || decoded.len() - 32 > 16384 {
        // Truncated: skip 4-byte magic + 33-byte pubkey, take up to 1024 bytes
        // of ciphertext.
        let start = 37;
        let end = (start + 1024).min(decoded.len() - 32);
        all_but_mac = &decoded[..end];
        version = 5;
    } else {
        all_but_mac = &decoded[..decoded.len() - 32];
        version = 4;
    }
    let line = format!(
        "$electrum${v}*{pk}*{abm}*{mac}",
        v = version,
        pk = hex::encode(ephemeral_pubkey),
        abm = hex::encode(all_but_mac),
        mac = hex::encode(mac),
    );
    HashResult::ok(FORMAT, _source_name, line, Some(16600))
}

fn process_json(v: &Value) -> Option<String> {
    // Not encrypted?
    if v.get("use_encryption").and_then(|b| b.as_bool()) == Some(false) {
        return None;
    }

    // Upgraded 1.x → 2.x ("old" wallet type): seed lives under keystore.
    if v.get("wallet_type").and_then(|w| w.as_str()) == Some("old") {
        if let Some(ks) = v.get("keystore") {
            if let Some(seed_b64) = ks.get("seed").and_then(|s| s.as_str()) {
                return build_electrum1_from_seed_b64(seed_b64);
            }
        }
    }

    // 2.x / 3.x / 4.x keystore path.
    if let Some(ks) = v.get("keystore") {
        if let Some(line) = process_keystore(ks) {
            return Some(line);
        }
    }
    // Multi-sig wallets have x1/, x2/, ... blocks.
    for i in 1..=16 {
        let key = format!("x{i}/");
        if let Some(x) = v.get(&key) {
            if let Some(line) = process_keystore(x) {
                return Some(line);
            }
        } else {
            break;
        }
    }
    // 2.0–2.6 "imported" accounts layout.
    if let Some(accs) = v.get("accounts").and_then(|a| a.get("/x")).and_then(|a| a.get("imported")) {
        if let Some(obj) = accs.as_object() {
            for (_k, val) in obj {
                if let Some(arr) = val.as_array() {
                    if arr.len() >= 2 {
                        if let Some(privkey_b64) = arr[1].as_str() {
                            if let Some(line) = build_electrum3_from_privkey_b64(privkey_b64) {
                                return Some(line);
                            }
                        }
                    }
                }
            }
        }
    }
    // 2.0–2.6 master_private_keys fallback.
    if let Some(mpks) = v.get("master_private_keys").and_then(|m| m.as_object()) {
        if let Some((_k, val)) = mpks.into_iter().next() {
            if let Some(xprv_b64) = val.as_str() {
                if let Some(line) = build_electrum2_from_xprv_b64(xprv_b64) {
                    return Some(line);
                }
            }
        }
    }
    None
}

fn process_keystore(ks: &Value) -> Option<String> {
    let ks_type = ks.get("type").and_then(|t| t.as_str())?;
    match ks_type {
        "bip32" => {
            let xprv = ks.get("xprv").and_then(|x| x.as_str())?;
            build_electrum2_from_xprv_b64(xprv)
        }
        "old" => {
            let seed = ks.get("seed").and_then(|s| s.as_str())?;
            build_electrum1_from_seed_b64(seed)
        }
        "imported" => {
            let keypairs = ks.get("keypairs").and_then(|k| k.as_object())?;
            for (_pubkey, privkey_val) in keypairs.into_iter() {
                if let Some(privkey_b64) = privkey_val.as_str() {
                    if let Some(line) = build_electrum3_from_privkey_b64(privkey_b64) {
                        return Some(line);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

fn build_electrum1_from_seed_b64(seed_b64: &str) -> Option<String> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let seed_data = b64.decode(seed_b64).ok()?;
    if seed_data.len() != 64 {
        return None;
    }
    let iv = &seed_data[..16];
    let enc = &seed_data[16..32];
    Some(format!(
        "$electrum$1*{iv}*{enc}",
        iv = hex::encode(iv),
        enc = hex::encode(enc),
    ))
}

fn build_electrum2_from_xprv_b64(xprv_b64: &str) -> Option<String> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let data = b64.decode(xprv_b64).ok()?;
    if data.len() != 128 {
        return None;
    }
    let iv = &data[..16];
    let enc = &data[16..32];
    Some(format!(
        "$electrum$2*{iv}*{enc}",
        iv = hex::encode(iv),
        enc = hex::encode(enc),
    ))
}

fn build_electrum3_from_privkey_b64(privkey_b64: &str) -> Option<String> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let data = b64.decode(privkey_b64).ok()?;
    if data.len() != 80 {
        return None;
    }
    let iv = &data[data.len() - 32..data.len() - 16];
    let enc = &data[data.len() - 16..];
    Some(format!(
        "$electrum$3*{iv}*{enc}",
        iv = hex::encode(iv),
        enc = hex::encode(enc),
    ))
}

fn process_py_literal(content: &str) -> Option<String> {
    // Electrum 1.x uses Python repr() — look for `seed_version` and `seed = '...'`.
    // Quick-and-dirty extraction without full Python parsing.
    if !content.contains("seed_version") {
        return None;
    }
    let seed = extract_py_str_field(content, "seed")?;
    build_electrum1_from_seed_b64(&seed)
}

fn extract_py_str_field(content: &str, field: &str) -> Option<String> {
    let needle = format!("'{field}'");
    let idx = content.find(&needle)?;
    let after = &content[idx + needle.len()..];
    let colon = after.find(':')?;
    let after_colon = after[colon + 1..].trim_start();
    if after_colon.starts_with('\'') || after_colon.starts_with('"') {
        let q = after_colon.chars().next()?;
        let start = after_colon[1..].find(q)?;
        Some(after_colon[1..1 + start].to_string())
    } else {
        None
    }
}

pub fn looks_like_electrum(_head: &[u8], path: &Path) -> bool {
    // Electrum wallets may be base64 or JSON — fall back to filename heuristics.
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name == "default_wallet" || name.contains("electrum") || name.starts_with("wallet_") {
        return true;
    }
    if name.ends_with(".json")
        && super::util::basename(path)
            .to_ascii_lowercase()
            .contains("wallet")
    {
        return true;
    }
    false
}
