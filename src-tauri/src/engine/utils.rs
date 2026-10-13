use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::io::prelude::*;
use sysinfo::{System, SystemExt};
use std::time::{Duration, SystemTime};
use serde_json::Value;

const DB: &str = "C:/neural-av/database.csv";

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

#[cfg(windows)]
fn is_reparse_point(entry: &walkdir::DirEntry) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    entry.metadata().map(|m| m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0).unwrap_or(true)
}
#[cfg(not(windows))]
fn is_reparse_point(_: &walkdir::DirEntry) -> bool {
    false
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
}

fn format_system_time(time: SystemTime) -> String {
    let formatted_time = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    formatted_time.to_string()
}
// return the metadata of the file in String
pub fn meta(filepath: &str) -> String {


    let metadata = std::fs::metadata(filepath).unwrap();
    let create = metadata.created().unwrap();
    let modified = metadata.modified().unwrap();
    let size = metadata.len();

    let mut result = String::new();
    result.push_str("Created at: ");
    result.push_str(&format_system_time(create));
    result.push_str("\n");
    result.push_str("Modifiedat: ");
    result.push_str(&format_system_time(modified));
    result.push_str("\n");
    result.push_str("Size of file: ");
    result.push_str(&size.to_string());
    result

}

/*// Check if a file exists
pub fn check(hash: &str) -> bool {
    let path: &str = "database.csv";
    //open database
    let mut file = fs::OpenOptions::new().read(true).open(path).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let lines: Vec<&str> = contents.split("\n").collect();
    for line in lines {
        let line_vec: Vec<&str> = line.split(",").collect();
        if line_vec[0] == hash {
            return true;
        }
    }
    return false;
}*/

const QUARANTINE_DIR: &str = "C:/neural-av/Quarantine";

// Quarantine file path for a bare name; None if the name could escape the folder.
pub fn quarantine_entry(name: &str) -> Option<PathBuf> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains(':') || name.contains("..") {
        return None;
    }
    Some(Path::new(QUARANTINE_DIR).join(format!("{}.txt", name)))
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
pub fn quarantine(filepath: &str) -> Result<(), String> {
    let filename = Path::new(filepath)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Invalid file name")?;
    let dest = quarantine_entry(filename).ok_or("Invalid file name")?;
    fs::create_dir_all(QUARANTINE_DIR).map_err(|e| format!("Unable to create directory: {}", e))?;
    if dest.exists() {
        return Err("A quarantined file with this name already exists".to_string());
    }
    move_file(Path::new(filepath), &dest)?;
    add_noti(filepath, "Quarantined");
    Ok(())
}

// Restore a file from quarantine
pub fn restore_file(filename: &str) -> String {
    let is_quarantined = match quarantine_entry(filename) {
        Some(p) => p,
        None => return "Invalid file name".to_string(),
    };
    if is_quarantined.exists() == false {return "File not in quarantine".to_string(); }
    let mut filepath = String::new();
    for line in read_db() {
        if line.len() > 2 && line[0] == filename {
            filepath = line[2].to_string();
        }
    }
    if filepath.is_empty() {return "File not in database".to_string(); }
    if Path::new(&filepath).exists() {return "Destination already exists".to_string(); }
    if let Err(e) = move_file(&is_quarantined, Path::new(&filepath)) {return e; }
    delete_row(filename);
    add_noti(filepath.as_str(), "Restored");
    return "File restored".to_string();

}

// Delete a file from the system
pub fn delete_file(filepath: &str) -> Result<(), String> {
    println!("Deleting file: {}", filepath);

    let path = Path::new(filepath);
    if path.exists() == false {
        return Err("File not found".to_string());
    }
    if let Err(e) = fs::remove_file(filepath) {
        return Err(format!("Unable to delete file: {}", e));
    }
    if filepath.contains("Quarantine") == true {
        let binding = filepath.replace("C:\\neural-av\\Quarantine\\", "");
        let filename :&str = binding.as_str();
        let filename2 = filename.replace(".txt", "");
        println!("{}", filename2);
        delete_row(filename2.as_str());
    }
    add_noti(filepath, "Deleted");
    Ok(())
}

pub fn del_quarantine(filename: &str) -> String {
    let path = match quarantine_entry(filename) {
        Some(p) => p,
        None => return "Invalid file name".to_string(),
    };
    if path.exists() == false {
        return "File not in quarantine".to_string();
    }
    if let Err(e) = fs::remove_file(&path) {
        return format!("Unable to delete file: {}", e);
    }
    add_noti(&path.to_string_lossy(), "Deleted");
    "File deleted".to_string()
}

/*//md5 hash a file
pub fn hash(filepath: &str) -> String {
    let mut file = fs::File::open(filepath).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let mut hasher = sha2::Sha256::new();
    hasher.update(contents);
    let result = hasher.finalize();
    let result = format!("{:x}", result);
    result
}*/
// Check if a database csv file exists
pub fn check_db() -> bool {
    let path = Path::new(DB);
    path.exists()
}

// Create a database csv file
pub fn create_db() {
    let path = Path::new(DB);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)
        .unwrap();
    file.write_all(b"").expect("Unable to write data");

    //create quarantine folder if not exist
    let quarantine_path = Path::new("Quarantine");
    if quarantine_path.exists() == false {
        fs::create_dir("Quarantine").expect("Unable to create directory");
    }

    //create notification csv if not exist
    let notfile_path = Path::new("notification.csv");
    if notfile_path.exists() == false {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(notfile_path)
            .unwrap();
        file.write_all(b"").expect("Unable to write data");
    }
    
}

// read database csv file and convert data to array of list
pub fn read_db() -> Vec<Vec<String>> {
    let path = Path::new(DB);
    let mut file = fs::OpenOptions::new().read(true).open(path).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let lines: Vec<&str> = contents.split("\n").collect();
    let mut result: Vec<Vec<String>> = Vec::new();
    for line in lines {
        let line_vec: Vec<&str> = line.split(",").collect();
        let mut line_vec2: Vec<String> = Vec::new();
        for item in line_vec {
            line_vec2.push(item.to_string());
        }
        result.push(line_vec2);
    }
    result
}


// find file in database and delete row
pub fn delete_row(filename: &str) {
    let path = Path::new(DB);
    let mut file = fs::OpenOptions::new().read(true).open(path).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let lines: Vec<&str> = contents.split("\n").collect();
    let mut new_contents = String::new();
    for line in lines {
        let line_vec: Vec<&str> = line.split(",").collect();
        if line_vec[0] != filename || line_vec[0] == "" {
            new_contents.push_str(line);
            new_contents.push_str("\n");
        }
    }
    new_contents = new_contents.trim_end().to_string();
    fs::remove_file(path).expect("Unable to delete file");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)
        .unwrap();
    file.write_all(new_contents.as_bytes()).expect("Unable to write data");
    
}
  
//add notification to csv
pub fn add_noti(filepath: &str, action: &str) {
    let path = Path::new("C:/neural-av/notification.csv");
    // add time to the second
    let time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let mut file = fs::OpenOptions::new().append(true).open(path).unwrap();
    let mut contents = String::new();
    contents.push_str(time.to_string().as_str());
    contents.push_str(",");
    contents.push_str(filepath);
    contents.push_str(",");
    contents.push_str(action);
    contents.push_str("\n");
    file.write_all(contents.as_bytes())
        .expect("Unable to write data");
}

// read notification csv file and convert data to array of list
pub fn read_noti() -> Vec<Vec<String>> {
    let path = Path::new("C:/neural-av/notification.csv");
    let mut file = fs::OpenOptions::new().read(true).open(path).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let lines: Vec<&str> = contents.split("\n").collect();
    let mut result: Vec<Vec<String>> = Vec::new();
    for line in lines {
        let line_vec: Vec<&str> = line.split(",").collect();
        let mut line_vec2: Vec<String> = Vec::new();
        for item in line_vec {
            line_vec2.push(item.to_string());
        }
        result.push(line_vec2);
    }
    result
}


// Add a file to csv with permissions
pub fn add_file(filepath: &str, _classification: &str) {

    //open database
    let path = Path::new(DB);
    let mut file = fs::OpenOptions::new().read(true).open(path).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    //get filename from the last slash of the filepath  
    let mut filename = String::new();
    let mut last_slash = 0;
    for (i, c) in filepath.chars().enumerate() {
        if c == '\\' {
            last_slash = i;
        }
    }
    for (i, c) in filepath.chars().enumerate() {
        if i > last_slash {
            filename.push(c);
        }
    }

    //add filename, classification, hash, filepath to database
    let mut file = fs::OpenOptions::new().append(true).open(path).unwrap();
    let mut contents = String::new();
    contents.push_str(filename.as_str());
    contents.push_str(",");
    contents.push_str(_classification);
    contents.push_str(",");
    contents.push_str(filepath);
    contents.push_str("\n");
    file.write_all(contents.as_bytes())
        .expect("Unable to write data");

}

// get memory usage and return as a 2 decimal float
pub fn memory() -> f32 {
    let mut system = System::new_all();
    system.refresh_all();

    let mem = system.used_memory();
    let total_mem = system.total_memory();
    let mem = mem as f32 / total_mem as f32 * 100.0;
    return mem
}

pub fn security() -> f32 {
    let path = Path::new(DB);
    let mut file = fs::OpenOptions::new().read(true).open(path).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let lines: Vec<&str> = contents.split("\n").collect();
    let mut result: Vec<String> = Vec::new();
    for line in lines {
        result.push(line.to_string());
    }
    let data = result.len() as f32;
    let data = 100.0 - data / 10.0;
    return data
}

pub fn vt_statistics() -> Vec<Vec<String>> {
    let path = Path::new("C:/neural-av/statistics.json");
    let mut file = fs::OpenOptions::new().read(true).open(path).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    let v: Value = serde_json::from_str(&contents).unwrap();
    let mut result: Vec<Vec<String>> = Vec::new();
    for (key, value) in v["results"].as_object().unwrap() {
        let mut line_vec: Vec<String> = Vec::new();
        line_vec.push(key.to_string());
        line_vec.push(value["category"].to_string());
        line_vec.push(value["engine_name"].to_string());
        line_vec.push(value["engine_version"].to_string());
        line_vec.push(value["result"].to_string());
        line_vec.push(value["method"].to_string());
        line_vec.push(value["engine_update"].to_string());
        result.push(line_vec);
    }
    result    
}



