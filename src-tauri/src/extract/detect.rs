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
            Format::Unknown => "unknown",
        }
    }
}

const RAR5_MAGIC: &[u8] = b"Rar!\x1a\x07\x01\x00";
const RAR3_MAGIC: &[u8] = b"Rar!\x1a\x07\x00";
const SEVENZIP_MAGIC: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
const OLE_MAGIC: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

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
        // Encrypted Office 2007+ and legacy 97-2003 are OLE/CFB containers.
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
        return Format::Zip;
    }

    detect_by_extension(path)
}

fn detect_by_extension(path: &Path) -> Format {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());
    match ext.as_deref() {
        Some("zip") | Some("jar") | Some("apk") | Some("docx") | Some("xlsx") | Some("pptx") => {
            Format::Zip
        }
        Some("rar") => Format::Rar3,
        Some("7z") => Format::SevenZip,
        Some("pdf") => Format::Pdf,
        Some("doc") | Some("xls") | Some("ppt") => Format::Office,
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
    fn falls_back_to_extension() {
        assert_eq!(detect(b"garbage", Path::new("a.7z")), Format::SevenZip);
        assert_eq!(detect(b"garbage", Path::new("mystery")), Format::Unknown);
    }
}
