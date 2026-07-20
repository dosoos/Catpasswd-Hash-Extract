//! Monero wallet keys extractor (`$monero$`, hashcat 11800).
//!
//! Monero wallets store two files: `<name>.keys` and `<name>`. The `.keys`
//! file is the encrypted key container. Output line matches John
//! `monero2john.py` byte-for-byte:
//!
//! `$monero$0*<hex_of_entire_.keys_file>`
//!
//! The hashcat 11800 kernel parses the binary blob internally; no field
//! splitting is done at extraction time.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::models::HashResult;

const FORMAT: &str = "monero";
const MONERO_MAGIC: &[u8] = b"Monero .keys file";

pub fn extract(path: &Path, source_name: &str) -> HashResult {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => return HashResult::err(FORMAT, source_name, format!("cannot open file: {e}")),
    };

    let mut buf = Vec::new();
    if let Err(e) = file.read_to_end(&mut buf) {
        return HashResult::err(FORMAT, source_name, format!("cannot read file: {e}"));
    }

    if buf.len() < 32 {
        return HashResult::err(FORMAT, source_name, "file too small to be a Monero wallet");
    }

    if !buf.starts_with(MONERO_MAGIC) {
        return HashResult::warn(
            FORMAT,
            source_name,
            "file is not a Monero .keys wallet (bad magic)",
        );
    }

    // $monero$0*<hex of entire file>
    let line = format!("$monero$0*{}", hex::encode(&buf));

    HashResult::ok(FORMAT, source_name, line, Some(11800))
}

pub fn looks_like_monero(head: &[u8], path: &Path) -> bool {
    if head.len() >= MONERO_MAGIC.len() && head.starts_with(MONERO_MAGIC) {
        return true;
    }
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase() == "keys")
        .unwrap_or(false)
}
