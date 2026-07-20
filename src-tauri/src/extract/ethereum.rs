//! Ethereum keystore extractor (v3 UTC/JSON, presale).
//!
//! Parses the standard Ethereum wallet JSON (Geth, parity, Mist, ethers,
//! MyEtherWallet, etc.), supporting both scrypt and pbkdf2 key derivation,
//! plus the older pre-sale format. Output lines are byte-for-byte compatible
//! with John the Ripper's `ethereum2john.py` and target hashcat mode 15700
//! (v3) / 16300 (pre-sale).
//!
//! Field layout (matching ethereum2john exactly):
//!
//! - scrypt:   `$ethereum$s*<n>*<r>*<p>*<salt>*<ciphertext>*<mac>`
//! - pbkdf2:   `$ethereum$p*<c>*<salt>*<ciphertext>*<mac>`
//! - presale:  `$ethereum$w*<encseed>*<ethaddr>*<bkp-32hex>`

use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde_json::Value;

use crate::models::HashResult;

const FORMAT: &str = "ethereum";

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
                format!("invalid JSON — not an Ethereum keystore: {e}"),
            )
        }
    };

    // Presale format (distinct field set, has `encseed` + `ethaddr` + `bkp`).
    if is_presale(&value) {
        return extract_presale(&value, source_name);
    }

    extract_v3(&value, source_name)
}

fn is_presale(v: &Value) -> bool {
    v.get("encseed").is_some() && v.get("ethaddr").is_some()
}

fn extract_v3(v: &Value, source_name: &str) -> HashResult {
    let crypto = v
        .get("crypto")
        .or_else(|| v.get("Crypto"));
    let Some(crypto) = crypto else {
        return HashResult::err(
            FORMAT,
            source_name,
            "Ethereum keystore has no 'crypto' field (not a v3 wallet)",
        );
    };

    let cipher = match crypto.get("cipher").and_then(|c| c.as_str()) {
        Some(c) => c,
        None => {
            return HashResult::err(
                FORMAT,
                source_name,
                "Ethereum keystore missing 'cipher' field",
            )
        }
    };
    if cipher != "aes-128-ctr" {
        return HashResult::err(
            FORMAT,
            source_name,
            format!("unexpected cipher '{cipher}' (expected aes-128-ctr)"),
        );
    }

    let kdf = match crypto.get("kdf").and_then(|k| k.as_str()) {
        Some(k) => k,
        None => {
            return HashResult::err(
                FORMAT,
                source_name,
                "Ethereum keystore missing 'kdf' field",
            )
        }
    };

    let ciphertext = match crypto.get("ciphertext").and_then(|c| c.as_str()) {
        Some(c) => c.to_lowercase(),
        None => {
            return HashResult::err(
                FORMAT,
                source_name,
                "Ethereum keystore missing 'ciphertext'",
            )
        }
    };

    let mac = match crypto.get("mac").and_then(|m| m.as_str()) {
        Some(m) => m.to_lowercase(),
        None => return HashResult::err(FORMAT, source_name, "Ethereum keystore missing 'mac'"),
    };

    let kdfparams = match crypto.get("kdfparams") {
        Some(p) => p,
        None => {
            return HashResult::err(
                FORMAT,
                source_name,
                "Ethereum keystore missing 'kdfparams'",
            )
        }
    };

    let line = match kdf {
        "scrypt" => {
            let n = match kdfparams.get("n").and_then(|x| x.as_u64()) {
                Some(v) => v,
                None => {
                    return HashResult::err(
                        FORMAT,
                        source_name,
                        "Ethereum scrypt keystore: missing 'n'",
                    )
                }
            };
            let r = match kdfparams.get("r").and_then(|x| x.as_u64()) {
                Some(v) => v,
                None => {
                    return HashResult::err(
                        FORMAT,
                        source_name,
                        "Ethereum scrypt keystore: missing 'r'",
                    )
                }
            };
            let p = match kdfparams.get("p").and_then(|x| x.as_u64()) {
                Some(v) => v,
                None => {
                    return HashResult::err(
                        FORMAT,
                        source_name,
                        "Ethereum scrypt keystore: missing 'p'",
                    )
                }
            };
            let salt = match kdfparams.get("salt").and_then(|s| s.as_str()) {
                Some(s) => s.to_lowercase(),
                None => {
                    return HashResult::err(
                        FORMAT,
                        source_name,
                        "Ethereum keystore: missing salt",
                    )
                }
            };
            // `$ethereum$s*n*r*p*salt*ciphertext*mac`
            let line = format!(
                "$ethereum$s*{n}*{r}*{p}*{salt}*{ciphertext}*{mac}",
            );
            // John the Ripper and hashcat (-m 15700) both hard-code scrypt salt
            // to exactly 64 hex chars (32 bytes). Libraries like eth_account/
            // web3.py may generate 16-byte (32 hex) salts which are spec-valid
            // per Web3 Secret Storage but won't load in stock crackers — the
            // user needs to re-generate the keystore with a 32-byte salt.
            let mut res = HashResult::ok(FORMAT, source_name, line, Some(15700));
            if salt.len() != 64 {
                res = res.with_warning(format!(
                    "scrypt salt is {} hex chars ({} bytes); stock John/hashcat require 64 hex chars (32 bytes) for scrypt wallets — keystores from Geth/Mist/MyEtherWallet use 32-byte salt and work out of the box",
                    salt.len(),
                    salt.len() / 2,
                ));
            }
            return res;
        }
        "pbkdf2" => {
            let c = match kdfparams.get("c").and_then(|x| x.as_u64()) {
                Some(v) => v,
                None => {
                    return HashResult::err(
                        FORMAT,
                        source_name,
                        "Ethereum pbkdf2 keystore: missing 'c'",
                    )
                }
            };
            let prf = kdfparams.get("prf").and_then(|s| s.as_str()).unwrap_or("");
            if prf != "hmac-sha256" {
                return HashResult::err(
                    FORMAT,
                    source_name,
                    format!("unexpected pbkdf2 prf '{prf}' (expected hmac-sha256)"),
                );
            }
            let salt = match kdfparams.get("salt").and_then(|s| s.as_str()) {
                Some(s) => s.to_lowercase(),
                None => {
                    return HashResult::err(
                        FORMAT,
                        source_name,
                        "Ethereum keystore: missing salt",
                    )
                }
            };
            // `$ethereum$p*c*salt*ciphertext*mac`
            format!(
                "$ethereum$p*{c}*{salt}*{ciphertext}*{mac}",
            )
        }
        other => {
            return HashResult::err(
                FORMAT,
                source_name,
                format!("Ethereum keystore: unsupported KDF '{other}'"),
            )
        }
    };

    HashResult::ok(FORMAT, source_name, line, Some(15700))
}

/// Pre-sale wallet (`encseed` + `ethaddr` + `bkp`). hashcat mode 16300.
fn extract_presale(v: &Value, source_name: &str) -> HashResult {
    let encseed = match v.get("encseed").and_then(|s| s.as_str()) {
        Some(s) => s.to_string(),
        None => return HashResult::err(FORMAT, source_name, "presale: missing encseed"),
    };
    let ethaddr = match v.get("ethaddr").and_then(|s| s.as_str()) {
        Some(s) => s.to_lowercase(),
        None => return HashResult::err(FORMAT, source_name, "presale: missing ethaddr"),
    };
    let bkp = match v.get("bkp").and_then(|s| s.as_str()) {
        Some(s) => s,
        None => return HashResult::err(FORMAT, source_name, "presale: missing bkp"),
    };
    // ethereum2john writes `bkp[:32]` hex (16 bytes = 32 hex chars).
    let bkp32 = if bkp.len() >= 32 {
        bkp[..32].to_string()
    } else {
        bkp.to_string()
    };

    // `$ethereum$w*encseed*ethaddr*bkp32`
    let line = format!("$ethereum$w*{encseed}*{ethaddr}*{bkp32}");

    HashResult::ok(FORMAT, source_name, line, Some(16300))
}

/// Heuristic: quick magic check before we try to parse JSON.
pub fn looks_like_keystore(head: &[u8], path: &Path) -> bool {
    if !head.starts_with(b"{") {
        return false;
    }
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    // UTC--* is the canonical keystore naming convention.
    if name.starts_with("utc--") {
        return true;
    }
    if name.ends_with(".json")
        && (name.contains("wallet") || name.contains("key") || name.contains("keystore"))
    {
        return true;
    }
    false
}
