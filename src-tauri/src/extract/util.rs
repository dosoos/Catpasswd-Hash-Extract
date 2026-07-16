//! Small byte-parsing helpers shared by the format extractors.

use std::path::Path;

/// Lowercase hex encoding of a byte slice.
pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Read a little-endian u16 at `off`, or `None` if out of bounds.
pub fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    if end > buf.len() {
        return None;
    }
    Some(u16::from_le_bytes([buf[off], buf[off + 1]]))
}

/// Read a little-endian u32 at `off`, or `None` if out of bounds.
pub fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    if end > buf.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
    ]))
}

/// Read a little-endian u64 at `off`, or `None` if out of bounds.
pub fn read_u64_le(buf: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    if end > buf.len() {
        return None;
    }
    Some(u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ]))
}

/// Basename (file name component) as a String, falling back to the raw path.
pub fn basename(path: &Path) -> String {
    path.file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| path.to_string_lossy().into_owned())
}
