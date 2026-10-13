#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod engine;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use neuralav_engine::{Engine, EngineConfig};
use neuralav_proto::{Layer, Status, Verdict};
use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::TrayIconBuilder;
use tauri::{Manager, State};

// Paths returned by scans; destructive commands only act on these.
static SCANNED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

fn scanned() -> std::sync::MutexGuard<'static, BTreeSet<String>> {
    SCANNED.lock().unwrap_or_else(|e| e.into_inner())
}

fn main() {
    let run = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            engine::utils::init_data_dir(app.path().app_data_dir()?)?;
            // Bundled rules first (Tauri resource dir), then env var / exe dir / dev tree.
            let cfg = app
                .path()
                .resource_dir()
                .ok()
                .map(|d| d.join("rules"))
                .filter(|d| d.is_dir())
                .map(EngineConfig::new)
                .unwrap_or_else(EngineConfig::discover);
            app.manage(Arc::new(Engine::load(cfg).map_err(|e| format!("engine: {e}"))?));
            let quit = MenuItemBuilder::with_id("quit", "Quit").build(app)?;
            let show = MenuItemBuilder::with_id("show", "Show").build(app)?;
            let hide = MenuItemBuilder::with_id("hide", "Hide").build(app)?;
            let menu = MenuBuilder::new(app).items(&[&show, &hide, &quit]).build()?;
            TrayIconBuilder::new()
                .icon(tauri::include_image!("icons/nav-ico.png"))
                .menu(&menu)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "quit" => app.exit(0),
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "hide" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.hide();
                        }
                    }
                    _ => {}
                })
                .build(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            optimize,
            quarantine_file,
            clean,
            remote_delete,
            restore,
            get_quarantine,
            del_quarantine,
            get_noti,
            get_drives,
            remote_inference,
            scan_path,
            process_stats
        ])
        .run(tauri::generate_context!());
    if let Err(e) = run {
        eprintln!("error while running tauri application: {e}");
        std::process::exit(1);
    }
}

type Eng<'a> = State<'a, Arc<Engine>>;

// JS-facing identity: "Malicious" | "Suspicious" | "Harmless" (or "Error: ...").
fn identity(v: &Verdict) -> String {
    if let Some(e) = &v.error {
        return format!("Error: {}", e);
    }
    match v.status {
        Status::Malicious => "Malicious",
        Status::Suspicious => "Suspicious",
        Status::Clean => "Harmless",
    }
    .to_string()
}

// "label,text"; commas are stripped from both fields so the frontend can split on ",".
fn class_string(v: &Verdict) -> String {
    let (label, text) = match (&v.error, v.status, v.reasons.first()) {
        (Some(e), _, _) => ("Error".to_string(), e.clone()),
        (None, Status::Clean, _) => ("None".to_string(), "Nothing detected".to_string()),
        (None, _, Some(r)) => match r.layer {
            Layer::Hash => ("Known malware".to_string(), r.detail.clone()),
            Layer::Signature => (r.detail.clone(), format!("Matched rule {}", r.detail)),
            Layer::Model => (r.detail.clone(), "Statistical match; suspicious but not confirmed malicious".to_string()),
        },
        (None, _, None) => ("Unknown".to_string(), "Flagged without a reason".to_string()),
    };
    format!("{},{}", label.replace(',', " "), text.replace(',', " "))
}

// Runs a blocking scan off the UI thread; a panic inside becomes an error string.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| format!("Error: {}", e))
}

// Destructive commands only act on non-empty paths that a scan flagged Malicious.
fn check_scanned(path: &str) -> Result<(), String> {
    if path.is_empty() || !scanned().contains(path) {
        return Err("Path was not scanned".to_string());
    }
    Ok(())
}

#[tauri::command]
fn get_drives() -> Vec<String> {
    ('A'..='Z')
        .map(|c| format!("{}:\\", c))
        .filter(|d| Path::new(d).exists())
        .collect()
}

// Scans a tree on a blocking thread. Calls `row` per verdict; only Malicious paths enter SCANNED.
fn scan_rows(engine: &Engine, root: &Path, row: impl Fn(&Verdict, String) -> Vec<String>) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    engine.scan_tree(root, |v| {
        let id = identity(&v);
        if v.status == Status::Malicious {
            scanned().insert(v.path.clone());
        }
        rows.push(row(&v, id));
    });
    rows
}

// Result row: path, identity, "label,text" (or "Safe" for a fully scanned clean file), size in bytes ("" if unreadable), sha256 ("" if not computed).
fn scan_row(v: &Verdict, id: String) -> Vec<String> {
    let class = if v.error.is_none() && v.status == Status::Clean { "Safe".to_string() } else { class_string(v) };
    let size = std::fs::symlink_metadata(&v.path).map(|m| m.len().to_string()).unwrap_or_default();
    vec![v.path.clone(), id, class, size, v.sha256.clone()]
}

static CPU_LAST: Mutex<Option<(std::time::Instant, f64)>> = Mutex::new(None);

#[derive(serde::Serialize)]
struct ProcStats {
    rss_bytes: Option<u64>,
    cpu_percent: Option<f64>,
}

// Core process only; the WebView renders in separate OS processes that this does not count.
#[cfg(unix)]
fn cpu_seconds() -> Option<f64> {
    let mut u: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut u) } != 0 {
        return None;
    }
    let t = |v: libc::timeval| v.tv_sec as f64 + v.tv_usec as f64 / 1e6;
    Some(t(u.ru_utime) + t(u.ru_stime))
}
#[cfg(not(unix))]
fn cpu_seconds() -> Option<f64> {
    None // ponytail: Windows needs GetProcessTimes (no windows bindings dep yet)
}

#[cfg(target_os = "macos")]
fn rss_bytes() -> Option<u64> {
    let mut ti: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    let n = unsafe { libc::proc_pidinfo(libc::getpid(), libc::PROC_PIDTASKINFO, 0, &mut ti as *mut _ as *mut libc::c_void, size) };
    (n == size).then_some(ti.pti_resident_size)
}
#[cfg(target_os = "linux")]
fn rss_bytes() -> Option<u64> {
    let pages: u64 = std::fs::read_to_string("/proc/self/statm").ok()?.split_whitespace().nth(1)?.parse().ok()?;
    let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).ok()?;
    pages.checked_mul(page)
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn rss_bytes() -> Option<u64> {
    None // ponytail: Windows needs GetProcessMemoryInfo
}

#[tauri::command]
fn process_stats() -> ProcStats {
    let now = std::time::Instant::now();
    let cpu = cpu_seconds();
    let mut last = CPU_LAST.lock().unwrap_or_else(|e| e.into_inner());
    let cpu_percent = match (cpu, *last) {
        (Some(c), Some((t, c0))) => {
            let wall = now.duration_since(t).as_secs_f64();
            (wall > 0.0).then(|| ((c - c0) / wall * 100.0).max(0.0))
        }
        _ => None,
    };
    if let Some(c) = cpu {
        *last = Some((now, c));
    }
    ProcStats { rss_bytes: rss_bytes(), cpu_percent }
}

#[tauri::command]
async fn remote_inference(engine: Eng<'_>, drive: String) -> Result<Vec<Vec<String>>, String> {
    let engine = engine.inner().clone();
    blocking(move || scan_rows(&engine, Path::new(&drive), scan_row)).await
}

// Read-only scan of a picked file or folder. The path is canonicalized first; links inside a tree are not followed.
// Malicious paths enter SCANNED.
#[tauri::command]
async fn scan_path(engine: Eng<'_>, path: String) -> Result<Vec<Vec<String>>, String> {
    let engine = engine.inner().clone();
    blocking(move || scan_path_rows(&engine, &path)).await?
}

fn scan_path_rows(engine: &Engine, path: &str) -> Result<Vec<Vec<String>>, String> {
    let root = std::fs::canonicalize(path).map_err(|e| format!("Cannot open {}: {}", path, e))?;
    Ok(scan_rows(engine, &root, scan_row))
}

#[tauri::command]
async fn optimize() -> String {
    tauri::async_runtime::spawn_blocking(engine::utils::flush_dns)
        .await
        .unwrap_or_else(|e| format!("DNS flush failed: {}", e))
}

#[tauri::command]
async fn clean() -> String {
    tauri::async_runtime::spawn_blocking(engine::utils::clean_temp)
        .await
        .unwrap_or_else(|e| format!("Clean up failed: {}", e))
}

// Quarantines a path that already passed the SCANNED gate.
fn quarantine_scanned(filepath: &str, classification: &str) -> String {
    match engine::utils::quarantine(&engine::utils::data_dir(), filepath, classification) {
        Ok(()) => {
            scanned().remove(filepath);
            engine::utils::add_file(&engine::utils::data_dir(), filepath, classification);
            "File quarantined".to_string()
        }
        Err(e) => e,
    }
}

#[tauri::command]
fn quarantine_file(filepath: &str, classification: &str) -> String {
    match check_scanned(filepath) {
        Ok(()) => quarantine_scanned(filepath, classification),
        Err(e) => e,
    }
}

#[tauri::command]
fn get_quarantine() -> Vec<Vec<String>> {
    let result = engine::utils::read_db(&engine::utils::data_dir());
    return result;
}

#[tauri::command]
fn get_noti() -> Vec<Vec<String>> {
    let result = engine::utils::read_noti(&engine::utils::data_dir());
    return result;
}

#[tauri::command]
fn restore(filename: &str) -> String {
    let result = engine::utils::restore_file(&engine::utils::data_dir(), filename);
    return result;
}

#[tauri::command]
fn remote_delete(filepath: &str, classification: &str) -> String {
    match check_scanned(filepath) {
        Ok(()) => delete_scanned(filepath, classification),
        Err(e) => e,
    }
}

// Deletes a path that already passed the SCANNED gate.
fn delete_scanned(filepath: &str, classification: &str) -> String {
    match engine::utils::delete_file(&engine::utils::data_dir(), filepath, classification) {
        Ok(()) => {
            scanned().remove(filepath);
            "File deleted".to_string()
        }
        Err(e) => e,
    }
}

#[tauri::command]
fn del_quarantine(filename: &str) -> String {
    return engine::utils::del_quarantine(&engine::utils::data_dir(), filename);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(status: Status, reasons: Vec<(Layer, &str)>, error: Option<&str>) -> Verdict {
        Verdict {
            path: "p".into(),
            sha256: String::new(),
            status,
            reasons: reasons.into_iter().map(|(layer, d)| neuralav_proto::Reason { layer, detail: d.into() }).collect(),
            error: error.map(String::from),
        }
    }

    #[test]
    fn identity_maps_status_and_error() {
        assert_eq!(identity(&verdict(Status::Malicious, vec![], None)), "Malicious");
        assert_eq!(identity(&verdict(Status::Suspicious, vec![], None)), "Suspicious");
        assert_eq!(identity(&verdict(Status::Clean, vec![], None)), "Harmless");
        // A file that was not fully scanned must never read as Harmless.
        assert_eq!(identity(&verdict(Status::Clean, vec![], Some("boom"))), "Error: boom");
    }

    #[test]
    fn class_string_branches_on_status() {
        assert_eq!(class_string(&verdict(Status::Clean, vec![], None)), "None,Nothing detected");
        assert_eq!(class_string(&verdict(Status::Clean, vec![], Some("a,b"))), "Error,a b");
        assert_eq!(
            class_string(&verdict(Status::Malicious, vec![(Layer::Signature, "EICAR_Test_File")], None)),
            "EICAR_Test_File,Matched rule EICAR_Test_File"
        );
        assert_eq!(
            class_string(&verdict(Status::Malicious, vec![(Layer::Hash, "known bad x")], None)),
            "Known malware,known bad x"
        );
        assert_eq!(class_string(&verdict(Status::Suspicious, vec![], None)), "Unknown,Flagged without a reason");
        assert_eq!(
            class_string(&verdict(Status::Suspicious, vec![(Layer::Model, "Static model 0.97")], None)),
            "Static model 0.97,Statistical match; suspicious but not confirmed malicious"
        );
    }

    #[test]
    fn process_stats_reports_rss_and_cpu_delta() {
        let _ = process_stats();
        std::hint::black_box((0..5_000_000u64).sum::<u64>());
        let s = process_stats();
        assert!(s.rss_bytes.is_none_or(|b| b > 0));
        assert!(s.cpu_percent.is_none_or(|c| c >= 0.0));
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        assert!(s.rss_bytes.is_some());
    }

    #[test]
    fn scanned_gate_rejects_unscanned_and_empty_paths() {
        assert!(check_scanned("").is_err());
        assert!(check_scanned("/tests/never-scanned").is_err());
        scanned().insert("/tests/flagged".to_string());
        assert!(check_scanned("/tests/flagged").is_ok());
        scanned().insert(String::new());
        assert!(check_scanned("").is_err());
        scanned().remove("/tests/flagged");
        scanned().remove("");
    }

    #[test]
    fn destructive_commands_refuse_unscanned_paths() {
        assert_eq!(remote_delete("/tests/never-scanned", "x"), "Path was not scanned");
        assert_eq!(quarantine_file("/tests/never-scanned", "x"), "Path was not scanned");
    }

    // Two halves, so this source file is not itself an EICAR file.
    fn eicar() -> Vec<u8> {
        let a = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-";
        let b = r"ANTIVIRUS-TEST-FILE!$H+H*";
        format!("{a}{b}").into_bytes()
    }

    #[test]
    fn scan_path_flags_eicar_in_a_folder_and_a_file_and_gates_it() {
        let engine = Engine::load(EngineConfig::discover()).expect("engine");
        let dir = std::env::temp_dir().join(format!("neuralav-scan-path-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        let bad = dir.join("sub").join("eicar.txt");
        let good = dir.join("clean.txt");
        std::fs::write(&bad, eicar()).unwrap();
        std::fs::write(&good, b"hello").unwrap();
        let bad = std::fs::canonicalize(&bad).unwrap().to_string_lossy().into_owned();
        let good = std::fs::canonicalize(&good).unwrap().to_string_lossy().into_owned();

        let rows = scan_path_rows(&engine, &dir.to_string_lossy()).unwrap();
        assert_eq!(rows.len(), 2);
        let find = |p: &str| rows.iter().find(|r| r[0] == p).unwrap().clone();
        assert_eq!(find(&bad)[1], "Malicious");
        assert!(find(&bad)[2].starts_with("EICAR"), "{:?}", find(&bad));
        let hello = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert_eq!(find(&good), vec![good.clone(), "Harmless".to_string(), "Safe".to_string(), "5".to_string(), hello.to_string()]);
        assert_eq!(find(&bad)[3], eicar().len().to_string());
        assert_eq!(find(&bad)[4].len(), 64);
        assert!(check_scanned(&bad).is_ok());
        assert!(check_scanned(&good).is_err());

        scanned().remove(&bad);
        let one = scan_path_rows(&engine, &bad).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0][1], "Malicious");
        assert!(check_scanned(&bad).is_ok());
        scanned().remove(&bad);

        assert!(scan_path_rows(&engine, "/tests/does-not-exist").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
