//! Format detection from magic bytes (primary) and file extension (fallback).

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Zip,
    Rar3,
    Rar5,
    SevenZip,
    Office,
    Pdf,
    // v2 — crypto wallets
    Ethereum,
    Bitcoin,
    Electrum,
    Monero,
    MetaMask,
    Bip38,
    Blockchain,
    MultiBit,
    Coinomi,
    Unknown,
}

impl Format {
    /// Stable lowercase id used in `HashResult.format`. Part of the format
    /// contract for exporters; extractors set the matching id themselves.
    #[allow(dead_code)]
    pub fn id(&self) -> &'static str {
        match self {
            Format::Zip => "zip",
            Format::Rar3 | Format::Rar5 => "rar",
            Format::SevenZip => "7z",
            Format::Office => "office",
            Format::Pdf => "pdf",
            Format::Ethereum => "ethereum",
            Format::Bitcoin => "bitcoin",
            Format::Electrum => "electrum",
            Format::Monero => "monero",
            Format::MetaMask => "metamask",
            Format::Bip38 => "bip38",
            Format::Blockchain => "blockchain",
            Format::MultiBit => "multibit",
            Format::Coinomi => "coinomi",
            Format::Unknown => "unknown",
        }
    }

    /// Human-facing label used in `FileMeta.format_label`.
    pub fn label(&self) -> &'static str {
        match self {
            Format::Zip => "ZIP",
            Format::Rar3 => "RAR",
            Format::Rar5 => "RAR5",
            Format::SevenZip => "7-Zip",
            Format::Office => "Microsoft Office",
            Format::Pdf => "PDF",
            Format::Ethereum => "Ethereum Keystore",
            Format::Bitcoin => "Bitcoin Core (wallet.dat)",
            Format::Electrum => "Electrum Wallet",
            Format::Monero => "Monero Wallet",
            Format::MetaMask => "MetaMask / Browser Wallet Vault",
            Format::Bip38 => "BIP38 Encrypted Private Key",
            Format::Blockchain => "Blockchain.com Wallet",
            Format::MultiBit => "MultiBit Wallet",
            Format::Coinomi => "Coinomi Wallet",
            Format::Unknown => "unknown",
        }
    }
}

const RAR5_MAGIC: &[u8] = b"Rar!\x1a\x07\x01\x00";
const RAR3_MAGIC: &[u8] = b"Rar!\x1a\x07\x00";
const SEVENZIP_MAGIC: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
const OLE_MAGIC: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
// Berkeley DB magic 0x00061561 in native byte order (LE on x86, BE on big-endian hosts).
const BDB_MAGIC_LE: &[u8] = &[0x61, 0x15, 0x06, 0x00]; // little-endian (Bitcoin Core on x86)
const BDB_MAGIC_BE: &[u8] = &[0x00, 0x06, 0x15, 0x61]; // big-endian
const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0"; // Bitcoin Core 0.21+ wallet
const MONERO_MAGIC: &[u8] = b"Monero .keys file";

fn starts_with(buf: &[u8], magic: &[u8]) -> bool {
    buf.len() >= magic.len() && &buf[..magic.len()] == magic
}

/// Detect from the leading bytes of the file. Magic wins; extension is a
/// fallback only when the magic is inconclusive.
pub fn detect(head: &[u8], path: &Path) -> Format {
    // Order matters: RAR5 is a superset prefix of RAR3, so check RAR5 first.
    if starts_with(head, RAR5_MAGIC) {
        return Format::Rar5;
    }
    if starts_with(head, RAR3_MAGIC) {
        return Format::Rar3;
    }
    if starts_with(head, SEVENZIP_MAGIC) {
        return Format::SevenZip;
    }
    if starts_with(head, OLE_MAGIC) {
        return Format::Office;
    }
    if starts_with(head, b"%PDF") {
        return Format::Pdf;
    }
    // ZIP local header / central dir / spanning markers.
    if starts_with(head, b"PK\x03\x04")
        || starts_with(head, b"PK\x05\x06")
        || starts_with(head, b"PK\x07\x08")
    {
        // But ZIP is also the container for docx/xlsx/pptx — handled as zip archive.
        return Format::Zip;
    }

    // ---- v2 wallet formats ----

    // Bitcoin Core wallet: Berkeley DB (old) or SQLite (0.21+).
    if starts_with(head, SQLITE_MAGIC)
        || starts_with(head, BDB_MAGIC_LE)
        || starts_with(head, BDB_MAGIC_BE)
    {
        // SQLite might not be Bitcoin — check filename for wallet.dat-ish names.
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !starts_with(head, SQLITE_MAGIC)
            || name.contains("wallet")
            || name.ends_with(".dat")
        {
            return Format::Bitcoin;
        }
    }
    // Monero .keys magic
    if starts_with(head, MONERO_MAGIC) {
        return Format::Monero;
    }
    // Java serialization stream magic → MultiBit classic .key
    if starts_with(head, &[0xAC, 0xED, 0x00, 0x05]) && super::multibit::looks_like_multibit(head, path) {
        return Format::MultiBit;
    }
    // JSON-starting files — delegate to JSON-aware heuristics (filename +
    // lightweight content sniff done in the Ethereum/Electrum/MetaMask/Blockchain
    // helpers). We only resolve to a definite format if the helper is confident,
    // otherwise fall through to extension detection.
    if starts_with(head, b"{") || starts_with(head, b"[") {
        if super::ethereum::looks_like_keystore(head, path) {
            return Format::Ethereum;
        }
        if super::metamask::looks_like_metamask(head, path) {
            return Format::MetaMask;
        }
        if super::blockchain::looks_like_blockchain(head, path) {
            return Format::Blockchain;
        }
        if super::coinomi::looks_like_coinomi(head, path) {
            return Format::Coinomi;
        }
        if super::electrum::looks_like_electrum(head, path) {
            return Format::Electrum;
        }
    }
    // Monero .keys by extension even if magic offset differs
    if super::monero::looks_like_monero(head, path) {
        return Format::Monero;
    }
    // BIP38 by filename heuristic (content is scanned at extract time regardless).
    if super::bip38::looks_like_bip38(path) {
        return Format::Bip38;
    }

    detect_by_extension(path)
}

fn detect_by_extension(path: &Path) -> Format {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    match ext.as_deref() {
        Some("zip") | Some("jar") | Some("apk") | Some("docx") | Some("xlsx") | Some("pptx") => {
            Format::Zip
        }
        Some("rar") => Format::Rar3,
        Some("7z") => Format::SevenZip,
        Some("pdf") => Format::Pdf,
        Some("doc") | Some("xls") | Some("ppt") => Format::Office,
        // Wallet extensions
        Some("dat") if name.contains("wallet") => Format::Bitcoin,
        Some("json") => {
            // Filename-based JSON wallet guesses (no magic, plain JSON).
            if name.starts_with("utc--") {
                Format::Ethereum
            } else if name.contains("metamask") || name.contains("vault") || name.contains("keyring") {
                Format::MetaMask
            } else if name.contains("blockchain") || name.contains("wallet.aes") {
                Format::Blockchain
            } else if name == "default_wallet" || name.contains("electrum") {
                Format::Electrum
            } else {
                Format::Unknown
            }
        }
        Some("keys") => Format::Monero,
        Some("coinomi") => Format::Coinomi,
        Some("key") => {
            if name.contains("bip38") || name.contains("privkey") {
                Format::Bip38
            } else {
                Format::MultiBit
            }
        }
        _ => Format::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn detects_zip_magic() {
        assert_eq!(detect(b"PK\x03\x04rest", Path::new("a.bin")), Format::Zip);
    }

    #[test]
    fn detects_rar5_before_rar3() {
        assert_eq!(detect(b"Rar!\x1a\x07\x01\x00", Path::new("a.rar")), Format::Rar5);
        assert_eq!(detect(b"Rar!\x1a\x07\x00", Path::new("a.rar")), Format::Rar3);
    }

    #[test]
    fn detects_sevenzip_magic() {
        assert_eq!(
            detect(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00], Path::new("a.bin")),
            Format::SevenZip
        );
    }

    #[test]
    fn detects_ole_as_office() {
        assert_eq!(
            detect(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], Path::new("a.doc")),
            Format::Office
        );
    }

    #[test]
    fn detects_pdf_magic() {
        assert_eq!(detect(b"%PDF-1.7", Path::new("a.bin")), Format::Pdf);
    }

    #[test]
    fn detects_bitcoin_bdb_magic() {
        // Little-endian BDB magic (x86 Bitcoin Core).
        assert_eq!(
            detect(&[0x61, 0x15, 0x06, 0x00, 0, 0, 0], Path::new("wallet.dat")),
            Format::Bitcoin
        );
        // Big-endian BDB magic.
        assert_eq!(
            detect(&[0x00, 0x06, 0x15, 0x61, 0, 0, 0], Path::new("wallet.dat")),
            Format::Bitcoin
        );
    }

    #[test]
    fn detects_bitcoin_sqlite_wallet() {
        let mut head = SQLITE_MAGIC.to_vec();
        head.extend_from_slice(&[0u8; 8]);
        assert_eq!(detect(&head, Path::new("wallet.dat")), Format::Bitcoin);
    }

    #[test]
    fn detects_ethereum_utc_filename() {
        assert_eq!(
            detect(b"{\"version\":3}", Path::new("UTC--2024-01-01--abcdef")),
            Format::Ethereum
        );
    }

    #[test]
    fn detects_monero_magic() {
        assert_eq!(
            detect(b"Monero .keys file\x00\x00", Path::new("wallet.keys")),
            Format::Monero
        );
    }

    #[test]
    fn falls_back_to_extension() {
        assert_eq!(detect(b"garbage", Path::new("a.7z")), Format::SevenZip);
        assert_eq!(detect(b"garbage", Path::new("mystery")), Format::Unknown);
    }
}
