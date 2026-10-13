use std::path::PathBuf;

// Find a file by name under start_path. Never follows links; unreadable entries are skipped.
pub fn traverse_path(start_path: &str, file: &str) -> Result<PathBuf, String> {
    walkdir::WalkDir::new(start_path)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .find(|e| e.file_type().is_file() && e.file_name() == file)
        .map(|e| e.into_path())
        .ok_or_else(|| format!("{} not found", file))
}
