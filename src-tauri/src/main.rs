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

const FOLDER: &str = "C:\\Users\\muhds\\Desktop\\Test";

// Paths returned by scans; destructive commands only act on these.
static SCANNED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

fn scanned() -> std::sync::MutexGuard<'static, BTreeSet<String>> {
    SCANNED.lock().unwrap_or_else(|e| e.into_inner())
}

// All regular files under root; unreadable entries are skipped.
fn list_files(root: &str) -> Vec<String> {
    walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_string_lossy().into_owned())
        .collect()
}

fn main() {
    let run = tauri::Builder::default()
        .setup(|app| {
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
            identify,
            classify,
            optimize,
            quarantine,
            quarantine_file,
            clean,
            memory,
            delete_file,
            delete_q,
            remote_delete,
            restore,
            get_quarantine,
            del_quarantine,
            get_noti,
            multiscan,
            get_drives,
            remote_scan,
            remote_inference,
            metafunc
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
            Layer::Yara => (r.detail.clone(), format!("Matched rule {}", r.detail)),
        },
        (None, _, None) => ("Unknown".to_string(), "Flagged without a reason".to_string()),
    };
    format!("{},{}", label.replace(',', " "), text.replace(',', " "))
}

// Runs a blocking scan off the UI thread; a panic inside becomes an error string.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| format!("Error: {}", e))
}

// Scans a file found by name under FOLDER. Malicious paths enter SCANNED.
fn scan_one(engine: &Engine, filename: &str) -> Verdict {
    let v = match engine::func::traverse_path(FOLDER, filename) {
        Ok(path) => engine.scan_file(&path),
        Err(e) => Verdict { path: filename.to_string(), sha256: String::new(), status: Status::Clean, reasons: Vec::new(), error: Some(e) },
    };
    if v.status == Status::Malicious {
        scanned().insert(v.path.clone());
    }
    v
}

// Destructive commands only act on non-empty paths that a scan flagged Malicious.
fn check_scanned(path: &str) -> Result<(), String> {
    if path.is_empty() || !scanned().contains(path) {
        return Err("Path was not scanned".to_string());
    }
    Ok(())
}

// Resolves a bare name under FOLDER, then applies the SCANNED gate.
fn gated_path(name: &str) -> Result<String, String> {
    let path = engine::func::traverse_path(FOLDER, name)?.to_string_lossy().into_owned();
    check_scanned(&path)?;
    Ok(path)
}

#[tauri::command]
async fn identify(engine: Eng<'_>, filename: String) -> Result<String, String> {
    let engine = engine.inner().clone();
    Ok(blocking(move || identity(&scan_one(&engine, &filename))).await.unwrap_or_else(|e| e))
}

#[tauri::command]
async fn classify(engine: Eng<'_>, filename: String) -> Result<String, String> {
    let engine = engine.inner().clone();
    Ok(blocking(move || {
        let v = scan_one(&engine, &filename);
        match &v.error {
            Some(e) => format!("Error: {}", e),
            None => class_string(&v),
        }
    })
    .await
    .unwrap_or_else(|e| e))
}

#[tauri::command]
fn get_drives() -> Vec<String> {
    ('A'..='Z')
        .map(|c| format!("{}:\\", c))
        .filter(|d| Path::new(d).exists())
        .collect()
}

#[tauri::command]
fn remote_scan(drive: &str) -> Vec<String> {
    list_files(drive)
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

#[tauri::command]
async fn remote_inference(engine: Eng<'_>, drive: String) -> Result<Vec<Vec<String>>, String> {
    let engine = engine.inner().clone();
    blocking(move || scan_rows(&engine, Path::new(&drive), |v, id| vec![v.path.clone(), id])).await
}

#[tauri::command]
async fn multiscan(engine: Eng<'_>, directory: String) -> Result<Vec<Vec<String>>, String> {
    let rel = Path::new(&directory);
    if rel.has_root() || rel.components().any(|c| !matches!(c, std::path::Component::Normal(_))) {
        return Ok(Vec::new());
    }
    let dir = Path::new(FOLDER).join(rel);
    let engine = engine.inner().clone();
    blocking(move || {
        scan_rows(&engine, &dir, |v, id| {
            let class = if v.error.is_none() && v.status == Status::Clean { "Safe".to_string() } else { class_string(v) };
            vec![v.path.clone(), id, class]
        })
    })
    .await
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

#[tauri::command]
fn quarantine(file: &str, _classification: &str) -> String {
    let filepath = match gated_path(file) {
        Ok(p) => p,
        Err(e) => return e,
    };
    quarantine_scanned(&filepath, _classification)
}

// Quarantines a path that already passed the SCANNED gate.
fn quarantine_scanned(filepath: &str, classification: &str) -> String {
    match engine::utils::quarantine(filepath) {
        Ok(()) => {
            scanned().remove(filepath);
            engine::utils::add_file(filepath, classification);
            "File quarantined".to_string()
        }
        Err(e) => e,
    }
}

#[tauri::command]
fn quarantine_file(filepath: &str, _classification: &str) -> String {
    match check_scanned(filepath) {
        Ok(()) => quarantine_scanned(filepath, _classification),
        Err(e) => e,
    }
}

#[tauri::command]
fn get_quarantine() -> Vec<Vec<String>> {
    let result = engine::utils::read_db();
    return result;
}

#[tauri::command]
fn get_noti() -> Vec<Vec<String>> {
    let result = engine::utils::read_noti();
    return result;
}

#[tauri::command]
fn restore(filename: &str) -> String {
    let result = engine::utils::restore_file(filename);
    return result;
}

#[tauri::command]
fn remote_delete(filepath: &str) -> String {
    match check_scanned(filepath) {
        Ok(()) => delete_scanned(filepath),
        Err(e) => e,
    }
}

// Deletes a path that already passed the SCANNED gate.
fn delete_scanned(filepath: &str) -> String {
    match engine::utils::delete_file(filepath) {
        Ok(()) => {
            scanned().remove(filepath);
            "File deleted".to_string()
        }
        Err(e) => e,
    }
}

#[tauri::command]
fn delete_file(filepath: &str) -> String {
    match gated_path(filepath) {
        Ok(p) => delete_scanned(&p),
        Err(e) => e,
    }
}

#[tauri::command]
fn delete_q(filepath: &str) -> String {
    let quarantine = match std::fs::canonicalize("C:/neural-av/Quarantine") {
        Ok(q) => q,
        Err(_) => return "Invalid path".to_string(),
    };
    let parent = Path::new(filepath).parent().and_then(|p| std::fs::canonicalize(p).ok());
    if parent.as_ref() != Some(&quarantine) {
        return "Invalid path".to_string();
    }
    return match engine::utils::delete_file(filepath) {
        Ok(()) => "File deleted".to_string(),
        Err(e) => e,
    };
}

#[tauri::command]
fn del_quarantine(filename: &str) -> String {
    return engine::utils::del_quarantine(filename);
}

#[tauri::command]
fn memory() -> f32 {
    let result = engine::utils::memory();
    return result;
}

#[tauri::command]
fn metafunc(filepath: &str) -> String {
    match engine::func::traverse_path(FOLDER, filepath) {
        Ok(p) => engine::utils::meta(&p.to_string_lossy()),
        Err(e) => e,
    }
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
            class_string(&verdict(Status::Malicious, vec![(Layer::Yara, "EICAR_Test_File")], None)),
            "EICAR_Test_File,Matched rule EICAR_Test_File"
        );
        assert_eq!(
            class_string(&verdict(Status::Malicious, vec![(Layer::Hash, "known bad x")], None)),
            "Known malware,known bad x"
        );
        assert_eq!(class_string(&verdict(Status::Suspicious, vec![], None)), "Unknown,Flagged without a reason");
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
    fn delete_and_quarantine_commands_refuse_unscanned_paths() {
        // An empty or unresolvable name must not act on anything.
        assert!(delete_file("").ends_with("not found"));
        assert!(quarantine("", "x").ends_with("not found"));
        assert_eq!(remote_delete("/tests/never-scanned"), "Path was not scanned");
        assert_eq!(quarantine_file("/tests/never-scanned", "x"), "Path was not scanned");
    }
}
