//! Neural-AV scan engine: allowlist/known-bad hashes, then own literal signatures (aho-corasick). No IPC, no UI.
use neuralav_proto::{Layer, Reason, Status, Verdict};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use aho_corasick::AhoCorasick;
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
    pub rules: usize,
}

pub struct Engine {
    cfg: EngineConfig,
    allow: HashMap<String, String>,
    known_bad: HashMap<String, String>,
    sigs: Sigs,
}

/// Literal signatures: a rule matches when every one of its literals occurs in the file.
struct Sigs {
    ac: AhoCorasick,
    /// pattern id -> (rule index, bit in that rule's mask)
    owner: Vec<(usize, u32)>,
    /// (name, mask with one bit per literal)
    rules: Vec<(String, u64)>,
    max_len: usize,
}

fn parse_literals(s: &str) -> std::result::Result<Vec<Vec<u8>>, String> {
    let mut out = Vec::new();
    let mut rest = s.trim();
    loop {
        let lit = if let Some(q) = rest.strip_prefix('"') {
            let end = q.find('"').ok_or("unterminated quote")?;
            rest = q[end + 1..].trim_start();
            q[..end].as_bytes().to_vec()
        } else {
            let end = rest.find(';').unwrap_or(rest.len());
            let hex: String = rest[..end].split_whitespace().collect();
            rest = rest[end..].trim_start();
            if hex.len() % 2 != 0 || !hex.is_ascii() {
                return Err(format!("bad hex literal: {hex}"));
            }
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| format!("bad hex literal: {hex}")))
                .collect::<std::result::Result<_, _>>()?
        };
        if lit.is_empty() {
            return Err("empty literal".into());
        }
        out.push(lit);
        match rest.strip_prefix(';') {
            Some(r) => rest = r.trim_start(),
            None if rest.is_empty() => return Ok(out),
            None => return Err(format!("expected ';' before: {rest}")),
        }
    }
}

/// Bounds the scan buffer (`max_len - 1 + 64 KiB`).
const MAX_LITERAL: usize = 4096;

/// `*.txt` files under `dir`, lines `name<TAB>literal[;literal...]`; a literal is `"text"` or hex. `#` starts a comment line.
fn load_sigs(dir: &Path) -> Result<(Sigs, usize)> {
    let mut patterns: Vec<Vec<u8>> = Vec::new();
    let mut owner = Vec::new();
    let mut rules = Vec::new();
    let mut files = 0;
    for entry in walkdir::WalkDir::new(dir).follow_links(false).sort_by_file_name() {
        let entry = entry.map_err(|e| format!("signature rules: {e}"))?;
        if !entry.file_type().is_file() || entry.path().extension().is_none_or(|x| x != "txt") {
            continue;
        }
        files += 1;
        let path = entry.path();
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
        for (i, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let at = |m: String| format!("{}:{}: {m}", path.display(), i + 1);
            let (name, lits) = line.split_once('\t').ok_or_else(|| at("expected name<TAB>literals".into()))?;
            let name = name.trim();
            if name.is_empty() {
                return Err(at("empty rule name".into()));
            }
            let lits = parse_literals(lits).map_err(at)?;
            if lits.len() > 64 {
                return Err(at("more than 64 literals".into()));
            }
            if lits.iter().any(|l| l.len() > MAX_LITERAL) {
                return Err(at(format!("literal longer than {MAX_LITERAL} bytes")));
            }
            let mut mask = 0u64;
            for (bit, l) in lits.into_iter().enumerate() {
                mask |= 1 << bit;
                owner.push((rules.len(), bit as u32));
                patterns.push(l);
            }
            rules.push((name.to_string(), mask));
        }
    }
    if rules.is_empty() {
        return Err(format!("no signature rules (*.txt) under {}", dir.display()));
    }
    let max_len = patterns.iter().map(Vec::len).max().unwrap_or(1);
    let ac = AhoCorasick::new(&patterns).map_err(|e| format!("signature rules: {e}"))?;
    Ok((Sigs { ac, owner, rules, max_len }, files))
}

impl Sigs {
    /// Streams the file in 64 KiB chunks, keeping `max_len - 1` bytes of overlap so literals spanning chunks match.
    fn scan(&self, path: &Path) -> std::io::Result<Vec<&str>> {
        const CHUNK: usize = 64 * 1024;
        let keep = self.max_len - 1;
        let mut file = File::open(path)?;
        let mut buf = vec![0u8; keep + CHUNK];
        let mut have = 0; // carried bytes at the start of buf
        let mut seen = vec![0u64; self.rules.len()];
        loop {
            let n = file.read(&mut buf[have..])?;
            if n == 0 {
                break;
            }
            let end = have + n;
            for m in self.ac.find_overlapping_iter(&buf[..end]) {
                let (r, bit) = self.owner[m.pattern().as_usize()];
                seen[r] |= 1 << bit;
            }
            have = keep.min(end);
            buf.copy_within(end - have..end, 0);
        }
        Ok(self.rules.iter().zip(&seen).filter(|((_, mask), s)| mask == *s).map(|((n, _), _)| n.as_str()).collect())
    }
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

        let (sigs, _) = load_sigs(&cfg.rules_dir.join("sigs"))?;

        Ok(Engine {
            cfg,
            allow,
            known_bad,
            sigs,
        })
    }

    pub fn status(&self) -> EngineStatus {
        EngineStatus { rules: self.sigs.rules.len() }
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

        // Layer 2: literal signatures.
        for name in self.sigs.scan(path).map_err(|e| format!("signatures: {e}"))? {
            v.status = Status::Malicious;
            v.reasons.push(Reason { layer: Layer::Signature, detail: name.to_string() });
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
