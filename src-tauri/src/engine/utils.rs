use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::io::prelude::*;
use std::time::{Duration, SystemTime};
use neuralav_engine::is_reparse_point;

static DATA_DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

// Set once at startup from Tauri's app data dir; creates it when missing.
pub fn init_data_dir(dir: PathBuf) -> std::io::Result<()> {
    fs::create_dir_all(&dir)?;
    let _ = DATA_DIR.set(dir);
    Ok(())
}

// The data dir. No fallback: a shared temp path could be pre-planted by another user.
pub fn data_dir() -> PathBuf {
    DATA_DIR.get().cloned().expect("data dir not initialised")
}

fn db_path(base: &Path) -> PathBuf { base.join("database.csv") }
fn noti_path(base: &Path) -> PathBuf { base.join("notification.csv") }
fn quarantine_dir(base: &Path) -> PathBuf { base.join("Quarantine") }

// Run a program by absolute path; kill it if it outlives `timeout`.
fn run_with_timeout(program: &str, args: &[&str], timeout: Duration) -> Result<(bool, String), String> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("{} unavailable: {}", program, e))?;
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() < timeout => std::thread::sleep(Duration::from_millis(100)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{} timed out", program));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let text = format!("{} {}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    Ok((out.status.success(), text.trim().to_string()))
}

// Flush the OS DNS cache with the platform's own tool, by absolute path. Never elevates.
pub fn flush_dns() -> String {
    if cfg!(target_os = "macos") {
        // dscacheutil exits 0 without touching mDNSResponder's cache; the real flush needs root.
        return "Not supported without administrator rights (macOS needs `sudo killall -HUP mDNSResponder`)".to_string();
    }
    let (program, args): (String, &[&str]) = if cfg!(windows) {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        (format!("{}\\System32\\ipconfig.exe", root), &["/flushdns"])
    } else {
        ("/usr/bin/resolvectl".to_string(), &["flush-caches"])
    };
    match run_with_timeout(&program, args, Duration::from_secs(10)) {
        // ipconfig can report failure on stdout with exit code 0.
        Ok((true, text)) if !text.contains("Could not") => "DNS cache flushed".to_string(),
        Ok((_, text)) => format!("DNS flush failed (may need administrator rights or systemd-resolved): {}", text),
        Err(e) => format!("DNS flush failed: {}", e),
    }
}

pub struct CleanReport {
    pub files: u64,
    pub bytes: u64,
    pub skipped: u64,
}

#[cfg(unix)]
fn owned_by_me(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.uid() == unsafe { libc::geteuid() }
}
#[cfg(not(unix))]
fn owned_by_me(_: &fs::Metadata) -> bool {
    true
}

// Delete regular files under `dir` not modified for `max_age`.
// Never follows or deletes symlinks/junctions/reparse points; skips files owned by other users.
// ponytail: path-based unlink keeps a narrow TOCTOU on shared dirs; use dirfd/unlinkat (cap-std) if that matters.
pub fn clean_dir(dir: &Path, max_age: Duration) -> CleanReport {
    let mut report = CleanReport { files: 0, bytes: 0, skipped: 0 };
    let cutoff = SystemTime::now() - max_age;
    let walk = walkdir::WalkDir::new(dir)
        .min_depth(1)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !is_reparse_point(e));
    for entry in walk {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => { report.skipped += 1; continue; }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => { report.skipped += 1; continue; }
        };
        if meta.modified().map(|m| m > cutoff).unwrap_or(true) {
            continue;
        }
        if !owned_by_me(&meta) {
            report.skipped += 1;
            continue;
        }
        match fs::remove_file(entry.path()) {
            Ok(_) => { report.files += 1; report.bytes += meta.len(); }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => report.skipped += 1,
        }
    }
    report
}

// Allow only an absolute, canonical dir whose own name is a temp dir (Temp, tmp, macOS `T`).
pub fn is_safe_temp(dir: &Path) -> bool {
    let canon = match dir.canonicalize() {
        Ok(c) => c,
        Err(_) => return false,
    };
    let name = canon.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    dir.is_absolute() && canon.parent().is_some() && matches!(name.as_str(), "temp" | "tmp" | "t")
}

// Clean the current user's temp dir of files older than 7 days. No elevation.
pub fn clean_temp() -> String {
    let dir = std::env::temp_dir();
    if !is_safe_temp(&dir) {
        return format!("Refusing to clean unexpected temp dir: {}", dir.display());
    }
    let r = clean_dir(&dir, Duration::from_secs(7 * 24 * 3600));
    format!(
        "Freed {:.1} MB from {} files; {} skipped (in use, denied or owned by another user)",
        r.bytes as f64 / 1_048_576.0,
        r.files,
        r.skipped
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("neuralav-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn age(path: &Path, days: u64) {
        let past = SystemTime::now() - Duration::from_secs(days * 24 * 3600);
        fs::File::options().write(true).open(path).unwrap().set_modified(past).unwrap();
    }

    #[test]
    fn clean_dir_removes_only_old_regular_files() {
        let dir = scratch("clean");
        fs::create_dir_all(dir.join("sub")).unwrap();
        let old = dir.join("sub/old.tmp");
        let new = dir.join("new.tmp");
        fs::write(&old, b"old").unwrap();
        fs::write(&new, b"new").unwrap();
        age(&old, 30);

        // Links to old files and dirs outside must not be followed.
        let outside = scratch("outside");
        let outside_file = outside.join("victim.txt");
        fs::write(&outside_file, b"keep").unwrap();
        age(&outside_file, 30);
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside_file, dir.join("link")).unwrap();
            std::os::unix::fs::symlink(&outside, dir.join("dirlink")).unwrap();
        }

        let r = clean_dir(&dir, Duration::from_secs(7 * 24 * 3600));
        assert_eq!(r.files, 1);
        assert_eq!(r.bytes, 3);
        assert!(!old.exists());
        assert!(new.exists());
        assert!(outside_file.exists());

        fs::remove_dir_all(&dir).unwrap();
        fs::remove_dir_all(&outside).unwrap();
    }

    #[test]
    fn is_safe_temp_rejects_non_temp_dirs() {
        assert!(!is_safe_temp(Path::new("/")));
        assert!(!is_safe_temp(Path::new(".")));
        assert!(!is_safe_temp(Path::new("tmp")));
        assert!(!is_safe_temp(&scratch("documents")));
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            assert!(!is_safe_temp(Path::new(&home)));
        }
        let ok = scratch("x").join("Temp");
        fs::create_dir_all(&ok).unwrap();
        assert!(is_safe_temp(&ok));
        fs::remove_dir_all(ok.parent().unwrap()).unwrap();
    }

    #[test]
    fn del_quarantine_removes_db_row() {
        let base = scratch("delq");
        let src = base.join("evil, one.bin");
        fs::write(&src, b"x").unwrap();
        // Names with commas are refused rather than corrupting the csv.
        assert!(quarantine(&base, src.to_str().unwrap()).is_err());
        let src = base.join("evil.bin");
        fs::write(&src, b"x").unwrap();
        quarantine(&base, src.to_str().unwrap()).unwrap();
        add_file(&base, src.to_str().unwrap(), "Sig,Name");
        assert_eq!(read_db(&base).len(), 1);
        assert_eq!(read_db(&base)[0][1], "Sig Name");
        assert_eq!(del_quarantine(&base, "evil.bin"), "File deleted");
        assert!(read_db(&base).iter().all(|r| r[0] != "evil.bin"));
        assert!(!quarantine_entry(&base, "evil.bin").unwrap().exists());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn delete_file_in_quarantine_removes_db_row() {
        let base = scratch("delf");
        let src = base.join("a.bin");
        fs::write(&src, b"x").unwrap();
        quarantine(&base, src.to_str().unwrap()).unwrap();
        add_file(&base, src.to_str().unwrap(), "Sig");
        delete_file(&base, quarantine_entry(&base, "a.bin").unwrap().to_str().unwrap()).unwrap();
        assert!(read_db(&base).iter().all(|r| r[0] != "a.bin"));
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn quarantine_restore_round_trip_with_comma_in_path() {
        let base = scratch("rt");
        let dir = base.join("my, dir");
        fs::create_dir_all(&dir).unwrap();
        let src = dir.join("m.bin");
        fs::write(&src, b"payload").unwrap();
        let sp = src.to_str().unwrap();
        quarantine(&base, sp).unwrap();
        add_file(&base, sp, "Sig");
        assert!(!src.exists());
        assert_eq!(read_db(&base)[0][2], sp);
        assert_eq!(restore_file(&base, "m.bin"), "File restored");
        assert_eq!(fs::read(&src).unwrap(), b"payload");
        assert!(read_db(&base).iter().all(|r| r[0] != "m.bin"));
        let noti = read_noti(&base);
        assert!(noti.iter().any(|r| r.len() == 3 && r[1] == "Restored" && r[2] == sp));
        fs::remove_dir_all(&base).unwrap();
    }
}

// Quarantine file path for a bare name; None if the name could escape the folder
// or would break the comma/line-based csv.
pub fn quarantine_entry(base: &Path, name: &str) -> Option<PathBuf> {
    if name.is_empty() || name.contains(['/', '\\', ':', ',', '\n', '\r']) || name.contains("..") {
        return None;
    }
    Some(quarantine_dir(base).join(format!("{}.txt", name)))
}

// Move a file; rename first, copy + remove when rename fails (cross-volume).
fn move_file(from: &Path, to: &Path) -> Result<(), String> {
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
    fs::copy(from, to).map_err(|e| format!("Unable to move file: {}", e))?;
    fs::remove_file(from).map_err(|e| format!("Unable to remove original: {}", e))
}

// Quarantine a file
pub fn quarantine(base: &Path, filepath: &str) -> Result<(), String> {
    // The DB is line-based; a newline in the path would restore to a different path.
    if filepath.contains(['\n', '\r']) {
        return Err("Invalid file path".to_string());
    }
    let filename = Path::new(filepath)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid file name")?;
    let dest = quarantine_entry(base, filename).ok_or("Invalid file name")?;
    fs::create_dir_all(quarantine_dir(base)).map_err(|e| format!("Unable to create directory: {}", e))?;
    if dest.exists() {
        return Err("A quarantined file with this name already exists".to_string());
    }
    move_file(Path::new(filepath), &dest)?;
    add_noti(base, filepath, "Quarantined");
    Ok(())
}

// Restore a file from quarantine
pub fn restore_file(base: &Path, filename: &str) -> String {
    let is_quarantined = match quarantine_entry(base, filename) {
        Some(p) => p,
        None => return "Invalid file name".to_string(),
    };
    if !is_quarantined.exists() { return "File not in quarantine".to_string(); }
    let mut filepath = String::new();
    for line in read_db(base) {
        if line.len() > 2 && line[0] == filename {
            filepath = line[2].to_string();
        }
    }
    if filepath.is_empty() { return "File not in database".to_string(); }
    if Path::new(&filepath).exists() { return "Destination already exists".to_string(); }
    if let Err(e) = move_file(&is_quarantined, Path::new(&filepath)) { return e; }
    delete_row(base, filename);
    add_noti(base, filepath.as_str(), "Restored");
    "File restored".to_string()
}

// Delete a file from the system
pub fn delete_file(base: &Path, filepath: &str) -> Result<(), String> {
    let path = Path::new(filepath);
    if !path.exists() {
        return Err("File not found".to_string());
    }
    if let Err(e) = fs::remove_file(filepath) {
        return Err(format!("Unable to delete file: {}", e));
    }
    if path.parent() == Some(quarantine_dir(base).as_path()) {
        if let Some(name) = path.file_stem().and_then(|n| n.to_str()) {
            delete_row(base, name);
        }
    }
    add_noti(base, filepath, "Deleted");
    Ok(())
}

pub fn del_quarantine(base: &Path, filename: &str) -> String {
    let path = match quarantine_entry(base, filename) {
        Some(p) => p,
        None => return "Invalid file name".to_string(),
    };
    if !path.exists() {
        return "File not in quarantine".to_string();
    }
    if let Err(e) = fs::remove_file(&path) {
        return format!("Unable to delete file: {}", e);
    }
    delete_row(base, filename);
    add_noti(base, &path.to_string_lossy(), "Deleted");
    "File deleted".to_string()
}

// Fields must not hold line breaks; the path is always the last field and may hold commas.
fn clean(field: &str) -> String {
    field.replace(['\n', '\r'], " ")
}

// Append one line to a csv, creating its folder and file when missing.
fn append_line(path: &Path, line: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::OpenOptions::new().append(true).create(true).open(path)?.write_all(line.as_bytes())
}

// Read a csv into rows of 3 fields (the last may contain commas); a missing file is an empty table.
fn read_csv(path: &Path) -> Vec<Vec<String>> {
    let contents = fs::read_to_string(path).unwrap_or_default();
    contents.lines().map(|l| l.splitn(3, ',').map(String::from).collect()).collect()
}

// read database csv file and convert data to array of list: name, classification, original path
pub fn read_db(base: &Path) -> Vec<Vec<String>> {
    read_csv(&db_path(base))
}

// find file in database and delete row
pub fn delete_row(base: &Path, filename: &str) {
    let db = db_path(base);
    let contents = fs::read_to_string(&db).unwrap_or_default();
    let mut new_contents = String::new();
    for line in contents.lines() {
        let first = line.split(',').next().unwrap_or("");
        if first != filename || first.is_empty() {
            new_contents.push_str(line);
            new_contents.push('\n');
        }
    }
    let _ = fs::write(db, new_contents.trim_end());
}

// Add notification to csv: time, action, path
pub fn add_noti(base: &Path, filepath: &str, action: &str) {
    let time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let _ = append_line(&noti_path(base), &format!("{},{},{}\n", time, action, clean(filepath)));
}

// read notification csv file and convert data to array of list: time, action, path
pub fn read_noti(base: &Path) -> Vec<Vec<String>> {
    read_csv(&noti_path(base))
}

// Add a quarantined file to the database csv: name, classification, original path
pub fn add_file(base: &Path, filepath: &str, classification: &str) {
    let filename = Path::new(filepath).file_name().map(|n| n.to_string_lossy()).unwrap_or_default();
    let class = clean(classification).replace(',', " ");
    let _ = append_line(&db_path(base), &format!("{},{},{}\n", filename, class, clean(filepath)));
}
