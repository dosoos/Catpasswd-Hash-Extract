//! Bitcoin Core wallet.dat extractor (`$bitcoin$`, hashcat 11300).
//!
//! Modern Bitcoin Core (0.21+) uses SQLite for wallet storage; older versions
//! used Berkeley DB. We handle both containers and extract the `mkey` record
//! which holds the encrypted master key, salt, and derivation parameters.
//!
//! Output line is byte-for-byte compatible with John the Ripper's
//! `bitcoin2john.py`:
//!
//! `$bitcoin$<master_hex_len>$<master_hex>$<salt_hex_len>$<salt_hex>$<rounds>$2$00$2$00`
//!
//! - `<master_hex>` is the **last 64 hex characters** (32 bytes / two AES
//!   blocks) of the encrypted master key.
//! - `<salt_hex>` is the full KDF salt (8 bytes for standard wallets, 18
//!   bytes for legacy Nexus wallets).
//! - `<rounds>` is the iteration count from the wallet.
//!
//! References:
//! - John `run/bitcoin2john.py`
//! - Bitcoin Core src/wallet/walletdb.cpp (BDB) and src/wallet/sqlite.cpp (SQLite)

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::models::HashResult;
use super::util::{read_u32_le, read_u64_le};

const FORMAT: &str = "bitcoin";

// Berkeley DB magic number 0x00061561 is stored in **native byte order** on
// the host that wrote the file. On x86 (little-endian) it serialises to
// 61 15 06 00. We accept both endian layouts.
const BDB_MAGIC_LE: &[u8] = &[0x61, 0x15, 0x06, 0x00];
const BDB_MAGIC_BE: &[u8] = &[0x00, 0x06, 0x15, 0x61];
// SQLite header magic.
const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";

pub fn extract(path: &Path, source_name: &str) -> HashResult {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => return HashResult::err(FORMAT, source_name, format!("cannot open file: {e}")),
    };

    let mut magic = [0u8; 16];
    if let Err(e) = file.read_exact(&mut magic) {
        return HashResult::err(FORMAT, source_name, format!("cannot read header: {e}"));
    }

    if magic.starts_with(SQLITE_MAGIC) {
        return extract_sqlite(&mut file, source_name);
    }
    if magic.starts_with(BDB_MAGIC_LE) || magic.starts_with(BDB_MAGIC_BE) {
        return extract_bdb(&mut file, source_name);
    }
    HashResult::err(
        FORMAT,
        source_name,
        "not a recognized Bitcoin wallet file (neither Berkeley DB nor SQLite)",
    )
}

struct MkeyRec {
    encrypted_key: Vec<u8>,
    salt: Vec<u8>,
    iterations: u32,
}

fn build_line(rec: MkeyRec, source_name: &str) -> HashResult {
    if rec.salt.len() != 8 && rec.salt.len() != 18 {
        return HashResult::err(
            FORMAT,
            source_name,
            format!(
                "unsupported salt size {} (expected 8 or 18 bytes)",
                rec.salt.len()
            ),
        );
    }

    let expected_key_len = if rec.salt.len() == 8 { 48 } else { 80 };
    if rec.encrypted_key.len() != expected_key_len {
        return HashResult::err(
            FORMAT,
            source_name,
            format!(
                "unsupported master key size {} bytes (expected {})",
                rec.encrypted_key.len(),
                expected_key_len
            ),
        );
    }

    // Last two AES blocks (32 bytes = 64 hex chars) are enough for cracking.
    let total = rec.encrypted_key.len();
    let master_hex = hex::encode(&rec.encrypted_key[total - 32..]);
    let salt_hex = hex::encode(&rec.salt);

    // Exact format from bitcoin2john.py line 279:
    //   "$bitcoin$%s$%s$%s$%s$%s$2$00$2$00\n" %
    //     (len(cry_master), cry_master, len(cry_salt), cry_salt, cry_rounds)
    let line = format!(
        "$bitcoin${ml}${m}${sl}${s}${r}$2$00$2$00",
        ml = master_hex.len(),
        m = master_hex,
        sl = salt_hex.len(),
        s = salt_hex,
        r = rec.iterations,
    );

    HashResult::ok(FORMAT, source_name, line, Some(11300))
}

// ---------------------------------------------------------------------------
// SQLite wallet (Bitcoin Core 0.21+)
// ---------------------------------------------------------------------------

fn extract_sqlite(file: &mut File, source_name: &str) -> HashResult {
    // Seek back to start and read the whole file. We don't pull in rusqlite as
    // a dependency; instead we parse the SQLite record format just enough to
    // find the `mkey` row in the `main` table.
    if file.seek(SeekFrom::Start(0)).is_err() {
        return HashResult::err(FORMAT, source_name, "cannot seek to start of file");
    }
    let mut data = Vec::new();
    if let Err(e) = file.read_to_end(&mut data) {
        return HashResult::err(FORMAT, source_name, format!("cannot read SQLite file: {e}"));
    }

    match scan_sqlite_for_mkey(&data) {
        Some(rec) => build_line(rec, source_name),
        None => HashResult::warn(
            FORMAT,
            source_name,
            "SQLite wallet does not contain an encrypted mkey record (wallet may be unencrypted or unsupported)",
        ),
    }
}

fn scan_sqlite_for_mkey(data: &[u8]) -> Option<MkeyRec> {
    // Primary: scan for the raw mkey value blob pattern (same logic as BDB,
    // works across SQLite page/cell formatting).
    if let Some(rec) = scan_blob_for_mkey_pattern(data) {
        return Some(rec);
    }

    // Fallback: find the 'mkey' literal (the key column value) and attempt to
    // parse the following blob across a range of offsets (SQLite serial types
    // and cell headers can put small prefix bytes between key and value).
    let needle = b"mkey";
    let mut pos = 0usize;
    while pos + needle.len() < data.len() {
        if &data[pos..pos + needle.len()] == needle {
            for skip in 1..=64 {
                let start = pos + needle.len() + skip;
                if start >= data.len() {
                    break;
                }
                if let Some(rec) = parse_mkey_value(&data[start..]) {
                    return Some(rec);
                }
            }
        }
        pos += 1;
    }
    None
}

// ---------------------------------------------------------------------------
// Berkeley DB wallet (Bitcoin Core < 0.21)
// ---------------------------------------------------------------------------

fn extract_bdb(file: &mut File, source_name: &str) -> HashResult {
    if file.seek(SeekFrom::Start(0)).is_err() {
        return HashResult::err(FORMAT, source_name, "cannot seek to start of file");
    }
    let mut data = Vec::new();
    if let Err(e) = file.read_to_end(&mut data) {
        return HashResult::err(FORMAT, source_name, format!("cannot read Berkeley DB file: {e}"));
    }

    // Primary approach: brute-force scan the entire file for the unique mkey
    // value blob pattern (0x30/0x50 prefix + method=0 + sane iterations). This
    // is robust against varying BDB page layouts, key/data separation, byte
    // order, and BDB version differences — it does not depend on finding the
    // "mkey" literal at all.
    if let Some(rec) = scan_blob_for_mkey_pattern(&data) {
        return build_line(rec, source_name);
    }

    // Fallback: locate the 'mkey' key string (used as the Berkeley DB key in
    // the "main" database) and try parse_mkey_value across a wider window in
    // case the value is stored with non-trivial prefix bytes on this BDB
    // version.
    let mut pos = 0usize;
    while pos + 4 < data.len() {
        if &data[pos..pos + 4] == b"mkey" {
            for skip in 1..=64 {
                let vstart = pos + 4 + skip;
                if vstart >= data.len() {
                    break;
                }
                if let Some(rec) = parse_mkey_value(&data[vstart..]) {
                    return build_line(rec, source_name);
                }
            }
        }
        pos += 1;
    }

    HashResult::warn(
        FORMAT,
        source_name,
        "Berkeley DB wallet has no encrypted mkey (wallet may be unencrypted)",
    )
}

fn scan_blob_for_mkey_pattern(data: &[u8]) -> Option<MkeyRec> {
    // Brute-force scan the entire file for the canonical mkey value blob
    // pattern (Bitcoin serialization). Two salt lengths are seen in the wild:
    //
    //   Standard wallet:  0x30 (enc_len=48) | <48 bytes enc> | 0x08 (salt_len=8) | <8 bytes salt> | u32 method=0 | u32 iters
    //   Nexus legacy:     0x50 (enc_len=80) | <80 bytes enc> | 0x12 (salt_len=18)| <18 bytes salt>| u32 method=0 | u32 iters
    //
    // This works regardless of the surrounding database page structure (BDB or
    // SQLite), because the mkey value itself has this exact byte layout and is
    // stored as an opaque blob. Finding method=0 followed by a sane iteration
    // count eliminates essentially all false positives.
    let mut p = 0usize;
    while p + 4 < data.len() {
        if let Some(rec) = try_match_mkey_at(data, p) {
            return Some(rec);
        }
        p += 1;
    }
    None
}

fn try_match_mkey_at(data: &[u8], p: usize) -> Option<MkeyRec> {
    let enc_len = *data.get(p)? as usize;
    // Only 48 (standard) and 80 (Nexus legacy) are expected.
    if enc_len != 48 && enc_len != 80 {
        return None;
    }
    let expected_salt_len = if enc_len == 48 { 8usize } else { 18 };

    let mut off = p + 1;
    if off + enc_len > data.len() {
        return None;
    }
    let encrypted_key = data[off..off + enc_len].to_vec();
    off += enc_len;

    let salt_len_byte = *data.get(off)? as usize;
    if salt_len_byte != expected_salt_len {
        return None;
    }
    off += 1;
    if off + expected_salt_len > data.len() {
        return None;
    }
    let salt = data[off..off + expected_salt_len].to_vec();
    off += expected_salt_len;

    let method = read_u32_le(data, off)?;
    if method != 0 {
        return None;
    }
    off += 4;
    let iterations = read_u32_le(data, off)?;
    if iterations < 1000 || iterations > 1_000_000_000 {
        return None;
    }

    Some(MkeyRec {
        encrypted_key,
        salt,
        iterations,
    })
}

// ---------------------------------------------------------------------------
// Shared: parse the mkey value blob (Bitcoin serialization / varint format)
// ---------------------------------------------------------------------------

fn parse_mkey_value(data: &[u8]) -> Option<MkeyRec> {
    let mut p = 0usize;

    // 1. compact_size: length of encrypted_key
    let enc_len = read_compact_size(data, &mut p)?;
    if enc_len < 32 || enc_len > 256 {
        return None;
    }
    if p + enc_len as usize > data.len() {
        return None;
    }
    let encrypted_key = data[p..p + enc_len as usize].to_vec();
    p += enc_len as usize;

    // 2. compact_size: length of salt
    let salt_len = read_compact_size(data, &mut p)?;
    if salt_len != 8 && salt_len != 18 {
        return None;
    }
    if p + salt_len as usize > data.len() {
        return None;
    }
    let salt = data[p..p + salt_len as usize].to_vec();
    p += salt_len as usize;

    // 3. u32 LE nDerivationMethod
    let method = read_u32_le(data, p)?;
    p += 4;
    if method != 0 {
        return None; // unknown KDF
    }

    // 4. u32 LE nDerivationIterations
    let iterations = read_u32_le(data, p)?;
    if iterations < 1000 || iterations > 1_000_000_000 {
        return None;
    }

    Some(MkeyRec {
        encrypted_key,
        salt,
        iterations,
    })
}

/// Bitcoin's compact size (varint) reader — matches BCDataStream.read_compact_size.
/// Updates `pos` past the consumed bytes on success.
fn read_compact_size(data: &[u8], pos: &mut usize) -> Option<u64> {
    if *pos >= data.len() {
        return None;
    }
    let first = data[*pos];
    *pos += 1;
    match first {
        253 => {
            if *pos + 2 > data.len() {
                return None;
            }
            let v = u16::from_le_bytes([data[*pos], data[*pos + 1]]) as u64;
            *pos += 2;
            Some(v)
        }
        254 => {
            if *pos + 4 > data.len() {
                return None;
            }
            let v = u32::from_le_bytes([
                data[*pos],
                data[*pos + 1],
                data[*pos + 2],
                data[*pos + 3],
            ]) as u64;
            *pos += 4;
            Some(v)
        }
        255 => {
            let v = read_u64_le(data, *pos)?;
            *pos += 8;
            Some(v)
        }
        n => Some(n as u64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_size_single_byte() {
        let data = [0x08, 0x30];
        let mut pos = 0;
        assert_eq!(read_compact_size(&data, &mut pos), Some(8));
        assert_eq!(pos, 1);
    }

    #[test]
    fn compact_size_253_two_bytes() {
        let data = [253u8, 0x30, 0x00];
        let mut pos = 0;
        assert_eq!(read_compact_size(&data, &mut pos), Some(0x30));
        assert_eq!(pos, 3);
    }

    #[test]
    fn bdb_magics_recognized_in_both_endianness() {
        assert_eq!(&[0x61, 0x15, 0x06, 0x00], BDB_MAGIC_LE);
        assert_eq!(&[0x00, 0x06, 0x15, 0x61], BDB_MAGIC_BE);
    }

    #[test]
    fn builds_canonical_line_matching_john() {
        // Fabricate a valid mkey record and verify line shape matches
        // bitcoin2john output exactly.
        let enc_key = vec![0xABu8; 48];
        let salt = vec![0xCDu8; 8];
        let rec = MkeyRec {
            encrypted_key: enc_key,
            salt,
            iterations: 12345,
        };
        let res = build_line(rec, "t");
        assert!(res.error.is_none(), "{:?}", res.error);
        // Last 64 hex chars of 48-byte key (32 bytes = 64 hex of 0xAB).
        let expected_master = "ab".repeat(32);
        let expected_salt = "cd".repeat(8);
        assert_eq!(
            res.hash_line,
            format!(
                "$bitcoin$64${m}$16${s}$12345$2$00$2$00",
                m = expected_master,
                s = expected_salt
            )
        );
        assert_eq!(res.hashcat_mode, Some(11300));
    }

    #[test]
    fn parses_standard_mkey_value_blob() {
        // Build a canonical mkey value blob:
        //   0x30 (len=48) | 48 bytes 0xEE |
        //   0x08 (len=8)  |  8 bytes 0xFF |
        //   0x00 00 00 00 (method=0) | 0x40 0x10 0x00 0x00 (iter=4160)
        let mut blob = Vec::new();
        blob.push(0x30);
        blob.extend_from_slice(&[0xEE; 48]);
        blob.push(0x08);
        blob.extend_from_slice(&[0xFF; 8]);
        blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        blob.extend_from_slice(&4160u32.to_le_bytes());

        let rec = parse_mkey_value(&blob).expect("parse failed");
        assert_eq!(rec.encrypted_key.len(), 48);
        assert_eq!(rec.salt.len(), 8);
        assert_eq!(rec.iterations, 4160);
    }

    #[test]
    fn mkey_pattern_scanner_finds_canonical_blob() {
        let mut data = vec![0u8; 200];
        // Build pattern at offset 20: 0x30 <48*0xEE> 0x08 <8*0xFF> 0 4160
        let mut off = 20usize;
        data[off] = 0x30;
        off += 1;
        for b in &mut data[off..off + 48] {
            *b = 0xEE;
        }
        off += 48;
        data[off] = 0x08;
        off += 1;
        for b in &mut data[off..off + 8] {
            *b = 0xFF;
        }
        off += 8;
        data[off..off + 4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        off += 4;
        data[off..off + 4].copy_from_slice(&4160u32.to_le_bytes());

        let rec = scan_blob_for_mkey_pattern(&data).expect("pattern not found");
        assert_eq!(rec.iterations, 4160);
        assert_eq!(rec.salt.len(), 8);
        assert_eq!(rec.encrypted_key.len(), 48);
    }

    #[test]
    fn mkey_pattern_scanner_finds_nexus_legacy_blob() {
        // Nexus legacy: 80-byte key (0x50), 18-byte salt (0x12)
        let mut data = vec![0u8; 200];
        let mut off = 30usize;
        data[off] = 0x50;
        off += 1;
        for b in &mut data[off..off + 80] {
            *b = 0xAA;
        }
        off += 80;
        data[off] = 0x12;
        off += 1;
        for b in &mut data[off..off + 18] {
            *b = 0xBB;
        }
        off += 18;
        data[off..off + 4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        off += 4;
        data[off..off + 4].copy_from_slice(&50000u32.to_le_bytes());

        let rec = scan_blob_for_mkey_pattern(&data).expect("nexus pattern not found");
        assert_eq!(rec.iterations, 50000);
        assert_eq!(rec.salt.len(), 18);
        assert_eq!(rec.encrypted_key.len(), 80);
    }

    #[test]
    fn builds_canonical_line_for_nexus_legacy() {
        let enc_key = vec![0xABu8; 80];
        let salt = vec![0xCDu8; 18];
        let rec = MkeyRec {
            encrypted_key: enc_key,
            salt,
            iterations: 50000,
        };
        let res = build_line(rec, "t");
        assert!(res.error.is_none(), "{:?}", res.error);
        // Last 32 bytes of 80-byte key = 64 hex chars of 0xAB.
        let expected_master = "ab".repeat(32);
        let expected_salt = "cd".repeat(18);
        assert_eq!(
            res.hash_line,
            format!(
                "$bitcoin$64${m}$36${s}$50000$2$00$2$00",
                m = expected_master,
                s = expected_salt
            )
        );
        assert_eq!(res.hashcat_mode, Some(11300));
    }
}
