//! Disk source: enumerate physical disks/partitions and extract BitLocker
//! hashes from a selected volume.
//!
//! The public surface mirrors the file pipeline: [`inspect_volume`] returns the
//! same [`InspectResult`] contract (`FileMeta` + `HashResult`) so the UI and
//! exporters treat volumes exactly like files. All real work is Windows-only;
//! other platforms return a clear error.

use crate::models::{DiskInfo, InspectResult};

#[cfg(windows)]
mod win;

/// Enumerate physical disks and their partitions (Disk-Management style).
pub fn list_disks() -> Result<Vec<DiskInfo>, String> {
    #[cfg(windows)]
    {
        win::list_disks()
    }
    #[cfg(not(windows))]
    {
        Err("Disk enumeration is only available on Windows".to_string())
    }
}

/// Inspect the partition at `partition_index` on disk `disk_index` and extract a
/// BitLocker hash if the volume is password-protected.
pub fn inspect_volume(disk_index: u32, partition_index: u32) -> Result<InspectResult, String> {
    #[cfg(windows)]
    {
        win::inspect_volume(disk_index, partition_index)
    }
    #[cfg(not(windows))]
    {
        let _ = (disk_index, partition_index);
        Err("Volume inspection is only available on Windows".to_string())
    }
}
