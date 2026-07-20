//! MetaMask / browser extension wallet vault extractor (`$metamask$`, hashcat 26600).
//!
//! MetaMask stores an encrypted vault in the browser extension's local storage
//! (LevelDB). The vault JSON contains `data` (ciphertext), `iv` (AES-GCM nonce),
//! `salt` (PBKDF2 salt) and KDF parameters in `keyMetadata`.
//!
//! Output is byte-for-byte compatible with hashcat mode **26600** (MetaMask
//! Wallet, PBKDF2-HMAC-SHA256 + AES-256-GCM), matching the token structure in
//! hashcat's `src/modules/module_26600.c`:
//!
//! `$metamask$<iterations>$<iv_base64>$<ciphertext_base64>`
//!
//! - `<iterations>`: PBKDF2 iteration count (older vaults = 10000, newer = 12
//!   or 600000 depending on MetaMask version).
//! - `<iv_base64>`: base64 of the 16-byte IV (GCM nonce, padded to 16 bytes if
//!   the vault stores a 12-byte nonce). Must be exactly 24 base64 characters.
//! - `<ciphertext_base64>`: base64 of the AES-GCM ciphertext (includes the
//!   16-byte auth tag appended by MetaMask).
//!
//! We unwrap several common container layouts:
//!   1. Direct vault: `{ "data": "...", "iv": "...", "salt": "...", "keyMetadata": {...} }`
//!   2. Nested under `vault` key: `{ "vault": { "data": ... } }`
//!   3. Storage dump: `{ "data": { "KeyringController:vault": "<json string>" } }`
//!   4. Storage dump: `{ "KeyringController": { "vault": "<json string>" } }`

use std::fs::File;
use std::io::Read;
use std::path::Path;

use base64::Engine;
use serde_json::Value;

use crate::models::HashResult;

const FORMAT: &str = "metamask";
const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;

pub fn extract(path: &Path, source_name: &str) -> HashResult {
    let mut content = String::new();
    if let Err(e) = File::open(path).and_then(|mut f| f.read_to_string(&mut content)) {
        return HashResult::err(FORMAT, source_name, format!("cannot read file: {e}"));
    }

    let value: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            return HashResult::err(
                FORMAT,
                source_name,
                format!("invalid JSON — not a MetaMask vault: {e}"),
            )
        }
    };

    // Unwrap container layers to get to the actual vault object.
    let vault = unwrap_vault(value);

    extract_from_vault(&vault, source_name)
}

fn unwrap_vault(v: Value) -> Value {
    // { "data": { "KeyringController:vault": "<json string>" } }
    if let Some(inner_str) = v
        .get("data")
        .and_then(|d| d.get("KeyringController:vault"))
        .and_then(|s| s.as_str())
    {
        if let Ok(parsed) = serde_json::from_str::<Value>(inner_str) {
            return parsed;
        }
    }
    // { "KeyringController": { "vault": "<json string>" } }
    if let Some(inner_str) = v
        .get("KeyringController")
        .and_then(|k| k.get("vault"))
        .and_then(|s| s.as_str())
    {
        if let Ok(parsed) = serde_json::from_str::<Value>(inner_str) {
            return parsed;
        }
    }
    // Top-level "vault" key — may be an object directly or a JSON string.
    if let Some(vault_val) = v.get("vault") {
        match vault_val {
            Value::Object(obj) if obj.contains_key("data") && obj.contains_key("iv") => {
                return Value::Object(obj.clone());
            }
            Value::String(s) => {
                if let Ok(parsed) = serde_json::from_str::<Value>(s) {
                    return parsed;
                }
            }
            _ => {}
        }
    }
    v
}

fn extract_from_vault(v: &Value, source_name: &str) -> HashResult {
    let data_b64 = match v.get("data").and_then(|d| d.as_str()) {
        Some(s) => s,
        None => {
            return HashResult::err(
                FORMAT,
                source_name,
                "MetaMask vault missing 'data' field",
            )
        }
    };
    let iv_b64 = match v.get("iv").and_then(|i| i.as_str()) {
        Some(s) => s,
        None => return HashResult::err(FORMAT, source_name, "MetaMask vault missing 'iv'"),
    };
    let salt_b64 = match v.get("salt").and_then(|s| s.as_str()) {
        Some(s) => s,
        None => return HashResult::err(FORMAT, source_name, "MetaMask vault missing 'salt'"),
    };

    // Iterations: default 10000; read from keyMetadata.params.iterations.
    let iterations = v
        .get("keyMetadata")
        .and_then(|k| k.get("params"))
        .and_then(|p| p.get("iterations"))
        .and_then(|i| i.as_u64())
        .or_else(|| {
            v.get("keyMetadata")
                .and_then(|k| k.get("iterations"))
                .and_then(|i| i.as_u64())
        })
        .or_else(|| v.get("iterations").and_then(|i| i.as_u64()))
        .unwrap_or(10000);

    // Decode salt and validate 32 bytes (hashcat requirement).
    let salt_bytes = match B64.decode(salt_b64) {
        Ok(b) => b,
        Err(_) => {
            return HashResult::err(
                FORMAT,
                source_name,
                "MetaMask vault salt is not valid base64",
            )
        }
    };
    if salt_bytes.len() != 32 {
        return HashResult::err(
            FORMAT,
            source_name,
            format!(
                "MetaMask vault salt decodes to {} bytes (expected 32)",
                salt_bytes.len()
            ),
        );
    }

    // IV: hashcat expects 16 bytes (24 base64 chars). MetaMask stores a 12-byte
    // GCM nonce in some versions; we zero-pad to 16 bytes then re-encode.
    let mut iv_bytes = match B64.decode(iv_b64) {
        Ok(b) => b,
        Err(_) => {
            return HashResult::err(
                FORMAT,
                source_name,
                "MetaMask vault iv is not valid base64",
            )
        }
    };
    let mut warning: Option<String> = None;
    if iv_bytes.len() == 12 {
        let mut padded = [0u8; 16];
        padded[..12].copy_from_slice(&iv_bytes);
        iv_bytes = padded.to_vec();
        warning = Some("IV was 12 bytes (GCM nonce), zero-padded to 16 bytes for hashcat -m 26600".to_string());
    } else if iv_bytes.len() != 16 {
        return HashResult::err(
            FORMAT,
            source_name,
            format!(
                "MetaMask vault iv decodes to {} bytes (expected 12 or 16)",
                iv_bytes.len()
            ),
        );
    }
    let iv_out_b64 = B64.encode(&iv_bytes);

    // Validate ciphertext is valid base64 (don't re-encode — pass through raw so
    // the auth tag MetaMask appends at the end is preserved verbatim).
    if B64.decode(data_b64).is_err() {
        return HashResult::err(
            FORMAT,
            source_name,
            "MetaMask vault data is not valid base64",
        );
    }

    // Canonical hashcat 26600 line, matching module_26600.c module_hash_encode exactly:
    //   Default rounds (10000): $metamask$<salt_b64>$<iv_b64>$<ct_b64>
    //   Custom rounds:          $metamask$rounds=<N>$<salt_b64>$<iv_b64>$<ct_b64>
    //
    // Fields:
    //   signature = "$metamask$"
    //   optional rounds prefix "rounds=N$" (only when iterations != 10000)
    //   token[1] = salt (32 bytes, base64)
    //   token[2] = iv   (16 bytes, base64, exactly 24 chars)
    //   token[3] = ciphertext (base64, includes 16-byte GCM tag appended)
    let line = if iterations != 10000 {
        format!(
            "$metamask$rounds={iter}${salt}${iv}${ct}",
            iter = iterations,
            salt = salt_b64,
            iv = iv_out_b64,
            ct = data_b64,
        )
    } else {
        format!(
            "$metamask${salt}${iv}${ct}",
            salt = salt_b64,
            iv = iv_out_b64,
            ct = data_b64,
        )
    };

    let mut res = HashResult::ok(FORMAT, source_name, line, Some(26600));
    if let Some(w) = warning {
        res = res.with_warning(w);
    }
    res
}

pub fn looks_like_metamask(head: &[u8], path: &Path) -> bool {
    if !head.starts_with(b"{") {
        return false;
    }
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    name.contains("metamask")
        || name.contains("vault")
        || name.contains("keyring")
        || name.ends_with(".ldb")
}
