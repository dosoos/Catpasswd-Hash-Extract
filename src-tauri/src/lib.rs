mod disk;
mod extract;
mod hash_cache;
mod models;

use std::io::Write;
use std::path::Path;

use models::{DiskInfo, InspectResult};

/// Inspect a file at `path`: compute metadata + whole-file digests, detect the
/// format, and extract a crack-oriented `HashResult`.
#[tauri::command]
fn inspect_file(path: String) -> Result<InspectResult, String> {
    extract::inspect_path(Path::new(&path))
}

/// Export the cached hash line for `token` to `path`. The full line never
/// crosses IPC — important for formats whose hash embeds the whole source file
/// (hundreds of MB). Buffered so large writes don't materialize one giant
/// allocation beyond the cached line.
#[tauri::command]
fn export_hash(token: String, path: String) -> Result<(), String> {
    let contents = hash_cache::get_line(&token)
        .ok_or_else(|| "hash is no longer cached; re-inspect the file and export again".to_string())?;
    let file =
        std::fs::File::create(Path::new(&path)).map_err(|e| format!("cannot create file: {e}"))?;
    let mut writer = std::io::BufWriter::new(file);
    writer
        .write_all(contents.as_bytes())
        .and_then(|()| writer.flush())
        .map_err(|e| format!("cannot write file: {e}"))
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
        .setup(|app| {
            use tauri::Manager;
            let title = format!(
                "Catpasswd Hash Extract v{}",
                env!("CARGO_PKG_VERSION")
            );
            if let Some(window) = app.get_webview_window("main") {
                window.set_title(&title)?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            inspect_file,
            export_hash,
            list_disks,
            inspect_volume
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
