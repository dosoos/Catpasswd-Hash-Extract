//! Unified detect -> extract -> `HashResult` pipeline.
//!
//! Every format extractor takes `path: &Path` and `source_name: &str` and
//! returns a [`HashResult`] (never `Result`): recoverable problems are placed
//! in `warnings`/`error` so the UI can always show file metadata plus a
//! message. `inspect_path` only returns `Err` for genuine IO failures.

pub mod bitlocker;
pub mod detect;
pub mod office;
pub mod pdf;
pub mod rar;
pub mod sevenz;
pub mod util;
pub mod zip;

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crc32fast::Hasher as Crc32;
use md5::{Digest, Md5};
use sha2::{Sha256, Sha512};

use crate::models::{FileMeta, HashResult, InspectResult};
use detect::Format;
use util::basename;

/// How many leading bytes are enough to identify every supported magic.
const HEAD_LEN: usize = 16;

/// Inspect a file: gather metadata + whole-file digests, detect the format,
/// and run the matching extractor.
pub fn inspect_path(path: &Path) -> Result<InspectResult, String> {
    let source_name = basename(path);

    let metadata = std::fs::metadata(path).map_err(|e| format!("cannot stat file: {e}"))?;
    if !metadata.is_file() {
        return Err(format!("not a regular file: {}", path.display()));
    }
    let size = metadata.len();
    let modified_ms = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .or_else(|| {
            // Some filesystems report times before the epoch; treat as unknown.
            let _ = SystemTime::now();
            None
        });

    let digests = compute_digests(path).map_err(|e| format!("cannot read file: {e}"))?;

    let format = detect::detect(&digests.head, path);

    let meta = FileMeta {
        name: source_name.clone(),
        format_label: format.label().to_string(),
        size,
        modified_ms,
        crc32: digests.crc32,
        md5: digests.md5,
        sha256: digests.sha256,
        sha512: digests.sha512,
    };

    let hash = dispatch(format, path, &source_name);

    Ok(InspectResult { meta, hash })
}

fn dispatch(format: Format, path: &Path, source_name: &str) -> HashResult {
    match format {
        Format::Zip => zip::extract(path, source_name),
        Format::Rar3 => rar::extract_rar3(path, source_name),
        Format::Rar5 => rar::extract_rar5(path, source_name),
        Format::SevenZip => sevenz::extract(path, source_name),
        Format::Office => office::extract(path, source_name),
        Format::Pdf => pdf::extract(path, source_name),
        Format::Unknown => HashResult::warn(
            "unknown",
            source_name,
            "unrecognized file format; no extractor available",
        ),
    }
}

struct Digests {
    head: Vec<u8>,
    crc32: String,
    md5: String,
    sha256: String,
    sha512: String,
}

fn compute_digests(path: &Path) -> std::io::Result<Digests> {
    let mut file = File::open(path)?;
    let mut crc = Crc32::new();
    let mut md5 = Md5::new();
    let mut sha256 = Sha256::new();
    let mut sha512 = Sha512::new();

    let mut head = Vec::with_capacity(HEAD_LEN);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        if head.len() < HEAD_LEN {
            let take = HEAD_LEN - head.len();
            head.extend_from_slice(&chunk[..take.min(chunk.len())]);
        }
        crc.update(chunk);
        md5.update(chunk);
        sha256.update(chunk);
        sha512.update(chunk);
    }

    Ok(Digests {
        head,
        crc32: format!("{:08x}", crc.finalize()),
        md5: hex::encode(md5.finalize()),
        sha256: hex::encode(sha256.finalize()),
        sha512: hex::encode(sha512.finalize()),
    })
}
