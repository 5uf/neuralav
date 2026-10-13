#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod engine;

use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::TrayIconBuilder;
use tauri::Manager;

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
    
    std::thread::spawn(|| {
        engine::engine();
    });

    tauri::Builder::default()
        .setup(|app| {
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
            security,
            vt_stats,
            delete_file,
            delete_q,
            remote_delete,
            restore,
            get_quarantine,
            del_quarantine,
            get_noti,
            traverse,
            multiscan,
            get_drives,
            remote_scan,
            remote_inference,
            metafunc
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[tauri::command]
fn identify(filename: &str) -> String {
    let path = engine::func::traverse_path(FOLDER, filename);
    match engine::python::identify(&path.to_string_lossy()) {
        Ok(result) => result,
        Err(e) => format!("Error: {:?}", e),
    }
}

#[tauri::command]
fn classify(filename: &str) -> String {
    let path = engine::func::traverse_path(FOLDER, filename);
    match engine::python::classify(&path.to_string_lossy()) {
        Ok(class) => class,
        Err(e) => format!("Error: {:?}", e),
    }
}

#[tauri::command]
fn traverse(filepath: &str) -> Vec<PathBuf> {
    let path = engine::func::traverse_all(filepath);
    return path;
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

#[tauri::command]
fn remote_inference(drive: &str) -> Vec<Vec<String>> {
    let mut inference: Vec<Vec<String>> = Vec::new();
    for path in list_files(drive) {
        let identity = match engine::python::identify(&path) {
            Ok(i) => i,
            Err(e) => format!("Error: {:?}", e),
        };
        if identity == "Malicious" {
            scanned().insert(path.clone());
        }
        inference.push(vec![path, identity]);
    }
    return inference;
}

#[tauri::command]
fn multiscan(directory: &str) -> Vec<Vec<String>> {
    let rel = Path::new(directory);
    if rel.has_root() || rel.components().any(|c| !matches!(c, std::path::Component::Normal(_))) {
        return Vec::new();
    }
    let dir = Path::new(FOLDER).join(rel);
    let paths = engine::func::traverse_all(dir.to_str().unwrap());
    let mut result: Vec<Vec<String>> = Vec::new();
    for file in paths {
        let path = file.to_string_lossy().into_owned();
        let mut class = "Safe".to_string();
        let identity = match engine::python::identify(&path) {
            Ok(i) => i,
            Err(e) => format!("Error: {:?}", e),
        };
        if identity == "Malicious" {
            class = match engine::python::classify(&path) {
                Ok(c) => c,
                Err(e) => format!("Error: {:?}", e),
            };
        }
        if identity == "Malicious" {
            scanned().insert(path.clone());
        }
        result.push(vec![path, identity, class]);
    }
    return result;
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
    let file = engine::func::traverse_path(FOLDER, file);
    let filepath = file.to_str().unwrap();
    println!("{}", filepath);
    return match engine::utils::quarantine(filepath) {
        Ok(()) => {
            engine::utils::add_file(filepath, _classification);
            "File quarantined".to_string()
        }
        Err(e) => e,
    };
}

#[tauri::command]
fn quarantine_file(filepath: &str, _classification: &str) -> String {
    if !scanned().contains(filepath) {
        return "Path was not scanned".to_string();
    }
    return match engine::utils::quarantine(filepath) {
        Ok(()) => {
            scanned().remove(filepath);
            engine::utils::add_file(filepath, _classification);
            "File quarantined".to_string()
        }
        Err(e) => e,
    };
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
    if !scanned().contains(filepath) {
        return "Path was not scanned".to_string();
    }
    return match engine::utils::delete_file(filepath) {
        Ok(()) => {
            scanned().remove(filepath);
            "File deleted".to_string()
        }
        Err(e) => e,
    };
}

#[tauri::command]
fn delete_file(filepath: &str) -> String {
    let path = engine::func::traverse_path(FOLDER, filepath);
    return match engine::utils::delete_file(path.to_str().unwrap()) {
        Ok(()) => "File deleted".to_string(),
        Err(e) => e,
    };
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
fn security() -> f32 {
    let result = engine::utils::security();
    return result;
}

#[tauri::command]
fn vt_stats() -> Vec<Vec<String>> {
    let result = engine::utils::vt_statistics();
    return result;
}

#[tauri::command]
fn metafunc(filepath: &str) -> String {
    let filepath = engine::func::traverse_path(FOLDER, filepath);
    let result = engine::utils::meta(filepath.to_str().unwrap());
    return result;
}


/*fn warmup() {
    if !utils::check_db() {utils::create_db();}
    engine::python::warmup();
}*/
