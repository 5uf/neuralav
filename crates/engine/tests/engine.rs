use neuralav_engine::{Engine, EngineConfig};
use neuralav_proto::{Layer, Status};
use std::path::{Path, PathBuf};

// Two halves, so this source file is not itself an EICAR file.
fn eicar() -> Vec<u8> {
    let a = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-";
    let b = "ANTIVIRUS-TEST-FILE!$H+H*";
    format!("{a}{b}").into_bytes()
}

fn sha256(path: &Path) -> String {
    // independent of the engine: shell out to the platform hasher via std only is overkill; use sha2 directly
    use sha2::{Digest, Sha256};
    Sha256::digest(std::fs::read(path).unwrap()).iter().map(|b| format!("{b:02x}")).collect()
}

fn shipped_rules() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("rules")
}

/// Rules dir with the given hash lists (None = file missing) and optionally the eicar rule.
fn rules_dir(known_bad: Option<&str>, allow: Option<&str>, yara: bool) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("yara")).unwrap();
    std::fs::create_dir_all(dir.path().join("hashes")).unwrap();
    if yara {
        std::fs::copy(shipped_rules().join("yara/eicar.yar"), dir.path().join("yara/eicar.yar")).unwrap();
    }
    if let Some(t) = known_bad {
        std::fs::write(dir.path().join("hashes/known_bad.txt"), t).unwrap();
    }
    if let Some(t) = allow {
        std::fs::write(dir.path().join("hashes/allowlist.txt"), t).unwrap();
    }
    dir
}

fn load_err(dir: &tempfile::TempDir) -> String {
    match Engine::load(EngineConfig::new(dir.path())) {
        Ok(_) => panic!("load should fail"),
        Err(e) => e,
    }
}

/// Engine with temp hash lists, so results are deterministic.
fn engine_with(known_bad: &str, allow: &str, max: Option<u64>) -> (Engine, tempfile::TempDir) {
    let dir = rules_dir(Some(known_bad), Some(allow), true);
    let mut cfg = EngineConfig::new(dir.path());
    if let Some(m) = max {
        cfg.max_file_size = m;
    }
    (Engine::load(cfg).unwrap(), dir)
}

fn benign(dir: &Path) -> PathBuf {
    let mut x: u64 = 0x9E3779B97F4A7C15;
    let data: Vec<u8> = (0..4096)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x & 0x7f) as u8 | 0x20
        })
        .collect();
    let p = dir.join("benign.bin");
    std::fs::write(&p, data).unwrap();
    p
}

#[test]
fn eicar_is_malicious_via_yara() {
    let (e, _r) = engine_with("", "", None);
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("eicar.com");
    std::fs::write(&p, eicar()).unwrap();
    let v = e.scan_file(&p);
    assert_eq!(v.status, Status::Malicious, "{v:?}");
    assert!(v.reasons.iter().any(|r| r.layer == Layer::Yara && r.detail == "EICAR_Test_File"));
    assert!(v.error.is_none());
}

#[test]
fn benign_file_is_clean() {
    let (e, _r) = engine_with("", "", None);
    let d = tempfile::tempdir().unwrap();
    let v = e.scan_file(&benign(d.path()));
    assert_eq!(v.status, Status::Clean, "{v:?}");
    assert_eq!(v.sha256.len(), 64);
}

#[test]
fn known_bad_hash_is_malicious_via_hash() {
    let d = tempfile::tempdir().unwrap();
    let p = benign(d.path());
    let (e, _r) = engine_with(&format!("# comment\n{} test-sample # trailing\n", sha256(&p).to_uppercase()), "", None);
    let v = e.scan_file(&p);
    assert_eq!(v.status, Status::Malicious, "{v:?}");
    assert_eq!(v.reasons[0].layer, Layer::Hash);
    assert!(v.reasons[0].detail.contains("test-sample"));
}

#[test]
fn allowlist_overrides_known_bad_and_yara() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("eicar.com");
    std::fs::write(&p, eicar()).unwrap();
    let h = sha256(&p);
    let (e, _r) = engine_with(&format!("{h}\n"), &format!("{h} ok\n"), None);
    let v = e.scan_file(&p);
    assert_eq!(v.status, Status::Clean, "{v:?}");
    assert_eq!(v.reasons[0].layer, Layer::Hash);
}

#[test]
fn oversized_file_is_an_error_not_clean() {
    let (e, _r) = engine_with("", "", Some(10));
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("eicar.com");
    std::fs::write(&p, eicar()).unwrap();
    let v = e.scan_file(&p);
    // YARA never ran, so the file must not look Clean: the error makes the UI and CLI report it.
    assert!(v.error.as_deref().is_some_and(|e| e.contains("not fully scanned") && e.contains("size limit")), "{v:?}");
    assert!(v.reasons.is_empty());
}

#[test]
fn missing_file_reports_error() {
    let (e, _r) = engine_with("", "", None);
    let v = e.scan_file(Path::new("/nonexistent/neuralav-test"));
    assert!(v.error.is_some());
}

#[cfg(unix)]
#[test]
fn scan_tree_does_not_follow_symlinked_dir() {
    let (e, _r) = engine_with("", "", None);
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("eicar.com"), eicar()).unwrap();
    let root = tempfile::tempdir().unwrap();
    benign(root.path());
    std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();
    let mut seen = Vec::new();
    e.scan_tree(root.path(), |v| seen.push(v));
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(seen.iter().all(|v| v.status == Status::Clean && !v.path.contains("eicar")));
}

#[test]
fn load_fails_without_signature_rules() {
    let d = rules_dir(Some(""), Some(""), false);
    assert!(load_err(&d).contains("no signature rules"));
}

#[test]
fn load_fails_when_a_hash_list_is_missing() {
    let e = load_err(&rules_dir(None, Some(""), true));
    assert!(e.contains("known_bad.txt"), "{e}");
    let e = load_err(&rules_dir(Some(""), None, true));
    assert!(e.contains("allowlist.txt"), "{e}");
}

#[test]
fn load_accepts_empty_hash_lists() {
    assert!(Engine::load(EngineConfig::new(rules_dir(Some(""), Some(""), true).path())).is_ok());
}

#[test]
fn bad_hash_line_names_file_and_line() {
    let good = "a".repeat(64);
    let e = load_err(&rules_dir(Some(&format!("{good} ok\n# c\nnot-a-hash\n")), Some(""), true));
    assert!(e.contains("known_bad.txt:3"), "{e}");
    let e = load_err(&rules_dir(Some(""), Some(&format!("{}g\n", "a".repeat(63))), true));
    assert!(e.contains("allowlist.txt:1"), "{e}");
    let e = load_err(&rules_dir(Some(&"a".repeat(63)), Some(""), true));
    assert!(e.contains("known_bad.txt:1"), "{e}");
}

#[cfg(unix)]
#[test]
fn symlink_and_fifo_are_errors_not_clean() {
    let (e, _r) = engine_with("", "", None);
    let d = tempfile::tempdir().unwrap();
    let target = benign(d.path());
    let link = d.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let v = e.scan_file(&link);
    assert!(v.error.as_deref().is_some_and(|m| m.contains("not a regular file")), "{v:?}");

    let fifo = d.path().join("fifo");
    assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    let v = e.scan_file(&fifo); // must return, not block on open
    assert!(v.error.as_deref().is_some_and(|m| m.contains("not a regular file")), "{v:?}");
}

#[cfg(unix)]
#[test]
fn scan_tree_reports_symlink_root_as_error() {
    let (e, _r) = engine_with("", "", None);
    let real = tempfile::tempdir().unwrap();
    benign(real.path());
    let d = tempfile::tempdir().unwrap();
    let link = d.path().join("root");
    std::os::unix::fs::symlink(real.path(), &link).unwrap();
    let mut seen = Vec::new();
    e.scan_tree(&link, |v| seen.push(v));
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(seen[0].error.as_deref().is_some_and(|m| m.contains("symlink")));
}
