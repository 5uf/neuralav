use std::process::Command;

// Two halves, so this source file is not itself an EICAR file.
fn eicar() -> Vec<u8> {
    let a = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-";
    let b = "ANTIVIRUS-TEST-FILE!$H+H*";
    format!("{a}{b}").into_bytes()
}

fn run(path: &std::path::Path, json: bool) -> (Option<i32>, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_neuralav-service"));
    cmd.arg("scan").arg(path.join("f"));
    if json {
        cmd.arg("--json");
    }
    let out = cmd.output().unwrap();
    (out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn eicar_exits_1() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("f"), eicar()).unwrap();
    let (code, out) = run(d.path(), true);
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("\"Malicious\"") && out.contains("EICAR_Test_File"), "{out}");
}

#[test]
fn benign_exits_0() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("f"), b"hello world, nothing to see\n").unwrap();
    let (code, out) = run(d.path(), false);
    assert_eq!(code, Some(0), "{out}");
}

#[test]
fn missing_path_exits_2() {
    let d = tempfile::tempdir().unwrap();
    let (code, _) = run(d.path(), false); // d/f does not exist
    assert_eq!(code, Some(2));
}

#[test]
fn directory_with_detection_and_error_exits_1() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("bad.com"), eicar()).unwrap();
    // A file the scanner cannot read is an error, never Clean.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let p = d.path().join("locked");
        std::fs::write(&p, b"x").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::File::open(&p).is_ok() {
            return; // running as root: cannot make a file unreadable
        }
    }
    let out = Command::new(env!("CARGO_BIN_EXE_neuralav-service")).arg("scan").arg(d.path()).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{text}");
    assert!(text.contains("EICAR_Test_File") && text.lines().count() == 2, "{text}");
}

#[test]
fn error_only_directory_exits_2() {
    let d = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        let real = tempfile::tempdir().unwrap();
        let link = d.path().join("root");
        std::os::unix::fs::symlink(real.path(), &link).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_neuralav-service")).arg("scan").arg(&link).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stdout));
    }
    let _ = d;
}

#[test]
fn json_flag_works_before_or_after_path() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("f");
    std::fs::write(&f, eicar()).unwrap();
    for args in [["scan", "--json", f.to_str().unwrap()], ["scan", f.to_str().unwrap(), "--json"]] {
        let out = Command::new(env!("CARGO_BIN_EXE_neuralav-service")).args(args).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(1), "{args:?} {text}");
        assert!(text.starts_with("{\"path\""), "{args:?} {text}");
    }
}
