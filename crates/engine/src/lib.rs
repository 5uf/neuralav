//! Neural-AV scan engine: allowlist/known-bad hashes, then YARA. No IPC, no UI.
use neuralav_proto::{Layer, Reason, Status, Verdict};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub rules_dir: PathBuf,
    pub max_file_size: u64,
}

impl EngineConfig {
    pub fn new(rules_dir: impl Into<PathBuf>) -> Self {
        EngineConfig { rules_dir: rules_dir.into(), max_file_size: 256 * 1024 * 1024 }
    }

    /// `NEURALAV_RULES`, else `<exe dir>/rules`, else (debug builds only) the repo path `crates/engine/rules`.
    pub fn discover() -> Self {
        let exe_rules = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("rules")));
        let rules = std::env::var_os("NEURALAV_RULES")
            .map(PathBuf::from)
            .or_else(|| exe_rules.clone().filter(|d| d.is_dir()));
        #[cfg(debug_assertions)]
        let rules = rules.unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("rules"));
        // Release builds bake in no build-machine path; a missing dir makes Engine::load fail.
        #[cfg(not(debug_assertions))]
        let rules = rules.or(exe_rules).unwrap_or_else(|| PathBuf::from("rules"));
        Self::new(rules)
    }
}

#[derive(Debug, Clone)]
pub struct EngineStatus {
    pub yara_rules: usize,
}

pub struct Engine {
    cfg: EngineConfig,
    allow: HashMap<String, String>,
    known_bad: HashMap<String, String>,
    rules: yara_x::Rules,
    yara_rules: usize,
}

fn load_hashes(path: &Path) -> Result<HashMap<String, String>> {
    // A missing list is an error (fail closed); an empty file is fine.
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut map = HashMap::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut parts = line.splitn(2, char::is_whitespace);
        if let Some(hash) = parts.next().filter(|h| !h.is_empty()) {
            if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!("{}:{}: not a 64-char hex sha256: {hash}", path.display(), i + 1));
            }
            map.insert(hash.to_ascii_lowercase(), parts.next().unwrap_or("").trim().to_string());
        }
    }
    Ok(map)
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// True for Windows reparse points (symlinks, junctions, mount points); always false elsewhere.
#[cfg(windows)]
pub fn is_reparse_point(entry: &walkdir::DirEntry) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    entry.metadata().map(|m| m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0).unwrap_or(true)
}
#[cfg(not(windows))]
pub fn is_reparse_point(_: &walkdir::DirEntry) -> bool {
    false
}

impl Engine {
    pub fn load(cfg: EngineConfig) -> Result<Engine> {
        let hashes = cfg.rules_dir.join("hashes");
        let allow = load_hashes(&hashes.join("allowlist.txt"))?;
        let known_bad = load_hashes(&hashes.join("known_bad.txt"))?;

        let mut compiler = yara_x::Compiler::new();
        let mut yara_rules = 0;
        for entry in walkdir::WalkDir::new(cfg.rules_dir.join("yara")).follow_links(false).sort_by_file_name() {
            let entry = entry.map_err(|e| format!("yara rules: {e}"))?;
            if entry.file_type().is_file() && entry.path().extension().is_some_and(|x| x == "yar") {
                let src = std::fs::read_to_string(entry.path()).map_err(|e| format!("{}: {e}", entry.path().display()))?;
                let origin = entry.path().to_string_lossy().into_owned();
                compiler
                    .add_source(yara_x::SourceCode::from(src.as_str()).with_origin(origin))
                    .map_err(|e| format!("{}: {e}", entry.path().display()))?;
                yara_rules += 1;
            }
        }
        if yara_rules == 0 {
            return Err(format!("no signature rules (*.yar) under {}", cfg.rules_dir.join("yara").display()));
        }
        let rules = compiler.build();

        Ok(Engine {
            cfg,
            allow,
            known_bad,
            rules,
            yara_rules,
        })
    }

    pub fn status(&self) -> EngineStatus {
        EngineStatus { yara_rules: self.yara_rules }
    }

    pub fn scan_file(&self, path: &Path) -> Verdict {
        let mut v = Verdict {
            path: path.to_string_lossy().into_owned(),
            sha256: String::new(),
            status: Status::Clean,
            reasons: Vec::new(),
            error: None,
        };
        if let Err(e) = self.scan_into(path, &mut v) {
            v.error = Some(e);
        }
        v
    }

    fn scan_into(&self, path: &Path, v: &mut Verdict) -> std::result::Result<(), String> {
        // symlink_metadata: a symlink or FIFO/device is not a regular file and is never opened.
        let meta = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !meta.is_file() {
            return Err("not fully scanned: not a regular file".to_string());
        }
        let size = meta.len();
        v.sha256 = sha256_file(path).map_err(|e| e.to_string())?;

        // Layer 1: hashes. Allowlist wins over everything.
        if let Some(name) = self.allow.get(&v.sha256) {
            v.reasons.push(Reason { layer: Layer::Hash, detail: format!("allowlisted {name}").trim_end().to_string() });
            return Ok(());
        }
        if let Some(name) = self.known_bad.get(&v.sha256) {
            v.status = Status::Malicious;
            v.reasons.push(Reason { layer: Layer::Hash, detail: format!("known bad {name}").trim_end().to_string() });
            return Ok(());
        }
        if size > self.cfg.max_file_size {
            return Err(format!("not fully scanned: over size limit ({size} bytes > max_file_size {})", self.cfg.max_file_size));
        }

        // Layer 2: YARA.
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let results = scanner.scan_file(path).map_err(|e| format!("yara: {e}"))?;
        for rule in results.matching_rules() {
            v.status = Status::Malicious;
            v.reasons.push(Reason { layer: Layer::Yara, detail: rule.identifier().to_string() });
        }
        Ok(())
    }

    /// Scans every regular file under `root`. Symlinks are not followed. Walk errors and non-regular entries come
    /// back as verdicts with `error` set.
    pub fn scan_tree(&self, root: &Path, mut on_verdict: impl FnMut(Verdict)) {
        let error = |path: &Path, e: String| Verdict {
            path: path.to_string_lossy().into_owned(),
            sha256: String::new(),
            status: Status::Clean,
            reasons: Vec::new(),
            error: Some(e),
        };
        if std::fs::symlink_metadata(root).is_ok_and(|m| m.file_type().is_symlink()) {
            return on_verdict(error(root, "not fully scanned: scan root is a symlink".to_string()));
        }
        let walk = walkdir::WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| e.depth() == 0 || !is_reparse_point(e));
        for entry in walk {
            match entry {
                Ok(e) if e.file_type().is_dir() || e.file_type().is_symlink() => {}
                // Regular files are scanned; FIFOs, devices etc. come back as errors from scan_file.
                Ok(e) => on_verdict(self.scan_file(e.path())),
                Err(e) => on_verdict(error(e.path().unwrap_or(root), e.to_string())),
            }
        }
    }
}
