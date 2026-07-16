mod disk;
mod extract;
mod models;

use std::path::Path;

use models::{DiskInfo, InspectResult};

/// Inspect a file at `path`: compute metadata + whole-file digests, detect the
/// format, and extract a crack-oriented `HashResult`.
#[tauri::command]
fn inspect_file(path: String) -> Result<InspectResult, String> {
    extract::inspect_path(Path::new(&path))
}

/// Write exported hash text to a user-chosen path (from the save dialog).
#[tauri::command]
fn write_text_file(path: String, contents: String) -> Result<(), String> {
    std::fs::write(Path::new(&path), contents).map_err(|e| format!("cannot write file: {e}"))
}

/// Enumerate physical disks and their partitions for the Disk tab.
#[tauri::command]
fn list_disks() -> Result<Vec<DiskInfo>, String> {
    disk::list_disks()
}

/// Inspect a selected partition and extract a BitLocker hash if present.
#[tauri::command]
fn inspect_volume(disk_index: u32, partition_index: u32) -> Result<InspectResult, String> {
    disk::inspect_volume(disk_index, partition_index)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            inspect_file,
            write_text_file,
            list_disks,
            inspect_volume
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
