//! Blockchain.com wallet extractor (`$blockchain$`, hashcat 17100/20600).
//!
//! Supports the three Blockchain.com wallet layouts handled by John
//! `blockchain2john.py`:
//!
//! - **v1** (legacy): raw encrypted blob — output `$blockchain$<len>$<hex>`
//!   where `<hex>` is the hex of the entire file.
//! - **v1 base64**: file contains only a base64-encoded encrypted blob —
//!   output `$blockchain$<len>$<hex-of-decoded-bytes>`.
//! - **v2/v3/v4**: JSON with `pbkdf2_iterations` and `payload` (base64) —
//!   output `$blockchain$v2$<iterations>$<len>$<hex-of-decoded-payload>`.
//!
//! Detection is opportunistic: we try v2/v3/v4 JSON first; if the file looks
//! like JSON but lacks those fields we fall back to v1; otherwise the whole
//! file is treated as the v1 encrypted blob.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use base64::Engine;
use serde_json::Value;

use crate::models::HashResult;

const FORMAT: &str = "blockchain";

pub fn extract(path: &Path, source_name: &str) -> HashResult {
    let mut raw = Vec::new();
    if let Err(e) = File::open(path).and_then(|mut f| f.read_to_end(&mut raw)) {
        return HashResult::err(FORMAT, source_name, format!("cannot read file: {e}"));
    }

    // Try v2/v3/v4 JSON layout first (presence of pbkdf2_iterations is the tell).
    if let Ok(content) = std::str::from_utf8(&raw) {
        if let Ok(v) = serde_json::from_str::<Value>(content) {
            if let Some(iter) = v.get("pbkdf2_iterations").and_then(|i| i.as_u64()) {
                if let Some(payload_b64) = v.get("payload").and_then(|p| p.as_str()) {
                    let b64 = base64::engine::general_purpose::STANDARD;
                    match b64.decode(payload_b64) {
                        Ok(decoded) => {
                            let line = format!(
                                "$blockchain$v2${iter}${len}${hex}",
                                iter = iter,
                                len = decoded.len(),
                                hex = hex::encode(&decoded),
                            );
                            return HashResult::ok(FORMAT, source_name, line, Some(17100));
                        }
                        Err(e) => {
                            return HashResult::err(
                                FORMAT,
                                source_name,
                                format!("blockchain v2 payload base64 decode failed: {e}"),
                            )
                        }
                    }
                }
            }
        }
    }

    // Try v1 base64-only: if the file is pure printable base64 and decodes
    // to binary with plausible length, use that.
    let trimmed: Vec<u8> = raw.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    let b64 = base64::engine::general_purpose::STANDARD;
    if let Ok(decoded) = b64.decode(&trimmed) {
        if decoded.len() > 16 && !decoded.starts_with(b"{") {
            let line = format!(
                "$blockchain${len}${hex}",
                len = decoded.len(),
                hex = hex::encode(&decoded),
            );
            return HashResult::ok(FORMAT, source_name, line, Some(17100));
        }
    }

    // v1 raw: hex of entire file contents.
    let line = format!(
        "$blockchain${len}${hex}",
        len = raw.len(),
        hex = hex::encode(&raw),
    );
    HashResult::ok(FORMAT, source_name, line, Some(17100))
}

pub fn looks_like_blockchain(head: &[u8], path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name.contains("blockchain") || name.contains("wallet.aes") {
        return true;
    }
    if !head.starts_with(b"{") {
        return false;
    }
    name.ends_with(".json") && name.contains("wallet")
}
