//! Neural-AV scan engine: allowlist/known-bad hashes, own literal signatures (aho-corasick), then a PyInstaller
//! one-file unpacker (entries re-scanned by the layers above), then a static
//! gradient-boosted-tree model on PE files (Suspicious only). No IPC, no UI.
mod authenticode;
pub mod gbdt;
mod pe;
pub mod pe_features;
mod pyinstaller;

use neuralav_proto::{Layer, Reason, Status, Verdict};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Cursor, Read};
use aho_corasick::AhoCorasick;
use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub rules_dir: PathBuf,
    pub max_file_size: u64,
    /// Static model score at or above which a PE is reported Suspicious. See `DEFAULT_MODEL_THRESHOLD`.
    pub model_threshold: f64,
}

/// Static-model file under the rules dir. Absent = layer disabled; present but invalid = `Engine::load` fails.
pub const MODEL_FILE: &str = "models/ember2024_pe.navgbdt";

/// Static-model alert threshold (probability of malicious). Conservative on purpose: the EMBER2024 PE model's
/// scores are not calibrated for this feature port (see docs/ARCHITECTURE.md), and Suspicious is only a hint.
// ponytail: fixed constant; calibrate per file population (TPR at a fixed FPR on our own benign corpus) before lowering it.
pub const DEFAULT_MODEL_THRESHOLD: f64 = 0.95;

/// PEs larger than this skip the model: the feature extractor needs the whole file in memory.
// ponytail: 16 MiB cap keeps peak RSS small; an mmap-based extractor would lift it.
const MODEL_MAX_FILE: u64 = 16 * 1024 * 1024;

impl EngineConfig {
    pub fn new(rules_dir: impl Into<PathBuf>) -> Self {
        EngineConfig { rules_dir: rules_dir.into(), max_file_size: 256 * 1024 * 1024, model_threshold: DEFAULT_MODEL_THRESHOLD }
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
    /// Trees in the static model; `None` = model file absent, layer disabled.
    pub model_trees: Option<usize>,
    pub model_threshold: f64,
}

/// Static-model result for one file.
enum Outcome {
    /// Not a PE, no model, or too small.
    Skip,
    Score(f64),
    /// PE structure exhausted the parser's work budget (crafted to burn CPU).
    Anomalous,
}

pub struct Engine {
    cfg: EngineConfig,
    allow: HashMap<String, String>,
    known_bad: HashMap<String, String>,
    sigs: Sigs,
    model: Option<gbdt::Model>,
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
    fn scan(&self, path: &Path) -> std::io::Result<(Vec<&str>, Option<u64>)> {
        const CHUNK: usize = 64 * 1024;
        let keep = (self.max_len - 1).max(8); // also covers the PyInstaller cookie magic across chunks
        let mut file = File::open(path)?;
        let mut buf = vec![0u8; keep + CHUNK];
        let mut have = 0; // carried bytes at the start of buf
        let (mut base, mut magic) = (0u64, None); // file offset of buf[0], last PyInstaller magic seen
        let mut seen = vec![0u64; self.rules.len()];
        loop {
            let n = file.read(&mut buf[have..])?;
            if n == 0 {
                break;
            }
            let end = have + n;
            pyinstaller::last_magic(&buf[..end], base, &mut magic);
            for m in self.ac.find_overlapping_iter(&buf[..end]) {
                let (r, bit) = self.owner[m.pattern().as_usize()];
                seen[r] |= 1 << bit;
            }
            let carry = keep.min(end);
            base += (end - carry) as u64;
            have = carry;
            buf.copy_within(end - have..end, 0);
        }
        Ok((self.matched(&seen), magic))
    }

    /// Same result as `scan` for a file already in memory.
    fn scan_bytes(&self, b: &[u8]) -> Vec<&str> {
        let mut seen = vec![0u64; self.rules.len()];
        for m in self.ac.find_overlapping_iter(b) {
            if let Some(&(r, bit)) = self.owner.get(m.pattern().as_usize()) {
                if let Some(s) = seen.get_mut(r) {
                    *s |= 1 << bit;
                }
            }
        }
        self.matched(&seen)
    }

    fn matched(&self, seen: &[u64]) -> Vec<&str> {
        self.rules.iter().zip(seen).filter(|((_, mask), s)| mask == *s).map(|((n, _), _)| n.as_str()).collect()
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

fn starts_with_mz(path: &Path) -> bool {
    let mut magic = [0u8; 2];
    File::open(path).and_then(|mut f| f.read_exact(&mut magic)).is_ok() && &magic == b"MZ"
}

/// At most `size` bytes of the file.
fn read_file(path: &Path, size: u64) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(size as usize);
    File::open(path)?.take(size).read_to_end(&mut buf)?;
    Ok(buf)
}

fn sha256_hex(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|b| format!("{b:02x}")).collect()
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

        // Fail closed on a present-but-broken model; a missing file only disables layer 3.
        let model_path = cfg.rules_dir.join(MODEL_FILE);
        let model = match std::fs::read(&model_path) {
            Ok(bytes) => {
                let m = gbdt::Model::load(&bytes).map_err(|e| format!("{}: {e}", model_path.display()))?;
                if m.n_features() != pe_features::DIM {
                    return Err(format!("{}: expects {} features, extractor produces {}", model_path.display(), m.n_features(), pe_features::DIM));
                }
                Some(m)
            }
            // A release build must not silently run without layer 3; only debug builds (tests) may.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && cfg!(debug_assertions) => None,
            Err(e) => return Err(format!("{}: {e}", model_path.display())),
        };

        Ok(Engine {
            cfg,
            allow,
            known_bad,
            sigs,
            model,
        })
    }

    pub fn status(&self) -> EngineStatus {
        EngineStatus {
            rules: self.sigs.rules.len(),
            model_trees: self.model.as_ref().map(gbdt::Model::n_trees),
            model_threshold: self.cfg.model_threshold,
        }
    }

    /// Static-model score of a PE file, `None` for anything that is not a parseable PE (or too large).
    pub fn model_score(&self, path: &Path, size: u64) -> std::io::Result<Option<f64>> {
        if self.model.is_none() || !(64..=MODEL_MAX_FILE).contains(&size) {
            return Ok(None);
        }
        Ok(match self.model_outcome(&read_file(path, size)?) {
            Outcome::Score(s) => Some(s),
            _ => None,
        })
    }

    fn model_outcome(&self, buf: &[u8]) -> Outcome {
        let Some(model) = self.model.as_ref() else { return Outcome::Skip };
        if buf.len() < 64 || !buf.starts_with(b"MZ") {
            return Outcome::Skip;
        }
        match pe_features::extract_checked(buf) {
            Ok(x) => Outcome::Score(model.predict(&x)),
            Err(pe_features::ParseError::NotPe) => Outcome::Skip,
            Err(pe_features::ParseError::Exhausted) => Outcome::Anomalous,
        }
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
        // Only MZ files the model can read are loaded (once, shared by the hash, signature and model layers);
        // everything else is streamed.
        let buf = if size <= MODEL_MAX_FILE && starts_with_mz(path) { Some(read_file(path, size).map_err(|e| e.to_string())?) } else { None };
        v.sha256 = match &buf {
            Some(b) => sha256_hex(b),
            None => sha256_file(path).map_err(|e| e.to_string())?,
        };

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
        let mut magic = None;
        let hits = match &buf {
            Some(b) => {
                pyinstaller::last_magic(b, 0, &mut magic);
                self.sigs.scan_bytes(b)
            }
            None => {
                let (h, m) = self.sigs.scan(path).map_err(|e| format!("signatures: {e}"))?;
                magic = m;
                h
            }
        };
        for name in hits {
            v.status = Status::Malicious;
            v.reasons.push(Reason { layer: Layer::Signature, detail: name.to_string() });
        }

        // Layer 2b: PyInstaller one-file bundle (any host format): hash + signature layers over each entry.
        if v.status == Status::Clean {
            let mut visit = |name: &str, bytes: &[u8], raw: bool| {
                let h = sha256_hex(bytes);
                if self.allow.contains_key(&h) {
                    return false;
                }
                if let Some(bad) = self.known_bad.get(&h) {
                    v.status = Status::Malicious;
                    v.reasons.push(Reason { layer: Layer::Hash, detail: format!("inside PyInstaller: {name}: known bad {bad}").trim_end().to_string() });
                    return true;
                }
                // Stored entries are bytes of the file itself, already covered by the whole-file signature scan.
                let hits = if raw { Vec::new() } else { self.sigs.scan_bytes(bytes) };
                for rule in &hits {
                    v.status = Status::Malicious;
                    v.reasons.push(Reason { layer: Layer::Signature, detail: format!("inside PyInstaller: {name}: {rule}") });
                }
                !hits.is_empty()
            };
            let walked = match &buf {
                Some(b) => pyinstaller::walk(&mut Cursor::new(b.as_slice()), size, magic, &mut visit),
                None => File::open(path).map_or(pyinstaller::Walk::Done, |mut f| pyinstaller::walk(&mut f, size, magic, &mut visit)),
            };
            // Caps hit with nothing found: the unread part could hold the payload, so never Clean.
            if walked == pyinstaller::Walk::Truncated && v.status == Status::Clean {
                return Err("not fully scanned: PyInstaller archive over limits".to_string());
            }
        }

        // Layer 3: static model. Only files the layers above left Clean; it can say Suspicious, never Malicious.
        if v.status == Status::Clean {
            match buf.as_deref().map_or(Outcome::Skip, |b| self.model_outcome(b)) {
                Outcome::Score(s) if s >= self.cfg.model_threshold => {
                    v.status = Status::Suspicious;
                    v.reasons.push(Reason { layer: Layer::Model, detail: format!("Static model {s:.2}") });
                }
                // Not Clean: a structure built to exhaust the parser must not pass silently. Never Malicious.
                Outcome::Anomalous => {
                    v.status = Status::Suspicious;
                    v.reasons.push(Reason { layer: Layer::Model, detail: "Static model: anomalous PE structure".to_string() });
                }
                _ => {}
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The streaming scan (files over the in-memory cap, and non-MZ files) must agree with the in-memory scan,
    /// including a literal that straddles a read boundary.
    #[test]
    fn streaming_scan_matches_in_memory_scan_across_chunk_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sigs")).unwrap();
        std::fs::write(dir.path().join("sigs/t.txt"), "straddle\t\"NEEDLE-A1\"\ntwo\t\"NEEDLE-B2\";\"NEEDLE-C3\"\nabsent\t\"NEEDLE-ZZ\"\n").unwrap();
        let (sigs, _) = load_sigs(&dir.path().join("sigs")).unwrap();
        let keep = sigs.max_len - 1;
        let first_read = keep + 64 * 1024; // size of the first read; later reads are 64 KiB
        let cases: [(&str, &[(usize, &str)], &[&str]); 3] = [
            ("none", &[], &[]),
            ("straddle first read", &[(first_read - 4, "NEEDLE-A1")], &["straddle"]),
            // B2 ends exactly at a later boundary, C3 straddles the next one: needs the carried overlap
            ("two literals over later boundaries", &[(first_read + 64 * 1024 - 9, "NEEDLE-B2"), (first_read + 2 * 64 * 1024 - 3, "NEEDLE-C3")], &["two"]),
        ];
        for (name, plants, want) in cases {
            let mut data = vec![b'.'; first_read + 3 * 64 * 1024];
            for &(at, lit) in plants {
                data[at..at + lit.len()].copy_from_slice(lit.as_bytes());
            }
            let p = dir.path().join("f.bin");
            std::fs::write(&p, &data).unwrap();
            let (streamed, memory) = (sigs.scan(&p).unwrap().0, sigs.scan_bytes(&data));
            assert_eq!(streamed, memory, "{name}");
            assert_eq!(streamed, want, "{name}");
        }
    }
}
