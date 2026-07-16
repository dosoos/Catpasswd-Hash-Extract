use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct HashResult {
    pub format: String,
    pub source_name: String,
    pub hash_line: String,
    pub hashcat_mode: Option<u32>,
    pub warnings: Vec<String>,
    pub error: Option<String>,
}

impl HashResult {
    /// Successful extraction with a crack-ready hash line.
    pub fn ok(
        format: &str,
        source_name: &str,
        hash_line: String,
        hashcat_mode: Option<u32>,
    ) -> Self {
        Self {
            format: format.to_string(),
            source_name: source_name.to_string(),
            hash_line,
            hashcat_mode,
            warnings: Vec::new(),
            error: None,
        }
    }

    /// Fatal (for this file) extraction failure. Meta is still shown by the UI.
    pub fn err(format: &str, source_name: &str, message: impl Into<String>) -> Self {
        Self {
            format: format.to_string(),
            source_name: source_name.to_string(),
            hash_line: String::new(),
            hashcat_mode: None,
            warnings: Vec::new(),
            error: Some(message.into()),
        }
    }

    /// Non-fatal note, e.g. "not encrypted". No hash line produced.
    pub fn warn(format: &str, source_name: &str, message: impl Into<String>) -> Self {
        Self {
            format: format.to_string(),
            source_name: source_name.to_string(),
            hash_line: String::new(),
            hashcat_mode: None,
            warnings: vec![message.into()],
            error: None,
        }
    }

    /// Attach an additional warning and return self (builder style).
    pub fn with_warning(mut self, message: impl Into<String>) -> Self {
        self.warnings.push(message.into());
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FileMeta {
    pub name: String,
    pub format_label: String,
    pub size: u64,
    pub modified_ms: Option<u64>,
    pub crc32: String,
    pub md5: String,
    pub sha256: String,
    pub sha512: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InspectResult {
    pub meta: FileMeta,
    pub hash: HashResult,
}

/// A physical disk as shown in the Disk tab (mirrors the Disk Management view).
#[derive(Debug, Clone, Serialize)]
pub struct DiskInfo {
    pub index: u32,
    /// Display name, e.g. `"Disk 0"`.
    pub name: String,
    /// Best-effort layout: `"GPT"` / `"MBR"` / `"Basic"` / `"Dynamic"`.
    pub layout: String,
    /// Total capacity in bytes.
    pub size: u64,
    /// Best-effort status, e.g. `"Online"`.
    pub status: String,
    /// Partitions and unallocated gaps in on-disk order.
    pub partitions: Vec<PartitionInfo>,
}

/// A partition or an unallocated gap within a [`DiskInfo`].
#[derive(Debug, Clone, Serialize)]
pub struct PartitionInfo {
    /// Stable id, `"{disk}:{part}"`, used by the UI to request inspection.
    pub id: String,
    pub disk_index: u32,
    /// Index within the disk's partition list (unallocated gaps included).
    pub partition_index: u32,
    /// Byte offset from the start of the disk.
    pub offset: u64,
    /// Size in bytes.
    pub size: u64,
    /// Drive letter without a colon, e.g. `"C"`, or `None`.
    pub letter: Option<String>,
    /// Volume label, or `""` when unknown.
    pub label: String,
    /// File system name, e.g. `"NTFS"`, or `None`.
    pub file_system: Option<String>,
    /// `"primary" | "extended" | "logical" | "unallocated" | "efi" | "recovery" | "unknown"`.
    pub kind: String,
    /// Best-effort short status text, e.g. `"Healthy"`.
    pub status: String,
    /// Whether the UI may offer this entry for inspection.
    pub selectable: bool,
}
