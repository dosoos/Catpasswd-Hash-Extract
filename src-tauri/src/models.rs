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
