mod extract;
mod models;

use std::path::Path;

use models::InspectResult;

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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![inspect_file, write_text_file])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
