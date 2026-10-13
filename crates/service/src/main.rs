use neuralav_engine::{Engine, EngineConfig};
use neuralav_proto::{Status, Verdict};
use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "usage: neuralav-service scan <path> [--json] | version";

fn print_verdict(v: &Verdict, json: bool) {
    if json {
        match serde_json::to_string(v) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("json: {e}"),
        }
    } else {
        let why: Vec<&str> = v.reasons.iter().map(|r| r.detail.as_str()).collect();
        println!("{:?}\t{}\t{}\t{}", v.status, v.path, why.join("; "), v.error.as_deref().unwrap_or(""));
    }
}

fn scan(path: &Path, json: bool) -> ExitCode {
    let engine = match Engine::load(EngineConfig::discover()) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("engine: {e}");
            return ExitCode::from(2);
        }
    };
    let (mut detected, mut errors) = (false, false);
    let mut report = |v: Verdict| {
        detected |= v.status != Status::Clean;
        errors |= v.error.is_some();
        print_verdict(&v, json);
    };
    if path.is_dir() {
        engine.scan_tree(path, &mut report);
    } else {
        report(engine.scan_file(path));
    }
    // A detection outranks a per-file error.
    ExitCode::from(if detected { 1 } else if errors { 2 } else { 0 })
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [c] if c == "version" => {
            println!("neuralav-service {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        [c, path] if c == "scan" => scan(Path::new(path), false),
        [c, path, f] | [c, f, path] if c == "scan" && f == "--json" => scan(Path::new(path), true),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
