//! Rust port of the EMBER2024 `PEFeatureExtractor` (thrember, Apache-2.0): a 2568-dim f32 vector for Windows PE files.
//!
//! Parity with thrember (see `scripts/ember_parity.py`, measured on harmless generated PEs and benign PEs on disk):
//!
//! | group (dims) | status |
//! |---|---|
//! | general (7), histogram (256), byteentropy (256), strings (177) | exact port (f32/f64 arithmetic, numpy pairwise sums, hand-written regex matchers) |
//! | header (74), datadirectories (34), richheader (33) | exact port of pefile's values (incl. thrember's skipped-last-directory bug) |
//! | section (224) | exact port; entry section and overlay follow pefile's `contains_rva` / `get_overlay` |
//! | imports (1282), exports (129) | port of pefile's table walkers with its caps and abort rules; approximation: ordinal imports of ws2_32/wsock32/oleaut32 stay `dll:ordinalN` (pefile's `ordlookup` would name them) |
//! | authenticode (8) | DER walker over the certificate table (`authenticode.rs`); approximation: DER errors map to `parse_error`, issuer==subject compares raw DER |
//! | pefilewarnings (88) | reproduced: byte share, header/section/alignment/entry-point warnings, section flags (dim 2547), import/export/relocation table errors, Rich header. Zero (not ported): resource, debug, TLS, load-config, delay-import, bound-import and exception directory warnings; `has_dynamic_relocs` (dim 2437) is always 0 |
//!
//! Hashing-trick groups use sklearn `FeatureHasher` semantics (MurmurHash3 x86_32, seed 0, signed index rule).
#![deny(clippy::indexing_slicing)] // file bytes drive every offset here and the release build aborts on panic

use crate::pe::{Pe, Section};
pub use crate::pe::ParseError;
use aho_corasick::{AhoCorasick, MatchKind};
use std::collections::HashSet;
use std::sync::OnceLock;

pub const DIM: usize = 2568;

/// Checked writes into a group's output slice (a short slice drops the write instead of panicking).
fn put(out: &mut [f32], i: usize, v: f32) {
    if let Some(o) = out.get_mut(i) {
        *o = v;
    }
}
fn win(out: &mut [f32], a: usize, b: usize) -> &mut [f32] {
    out.get_mut(a..b).unwrap_or_default()
}
fn tail(out: &mut [f32], a: usize) -> &mut [f32] {
    out.get_mut(a..).unwrap_or_default()
}
/// The slice of the feature vector that holds group `g` of `GROUPS`.
fn group(v: &mut [f32], g: usize) -> &mut [f32] {
    let start: usize = GROUPS.iter().take(g).map(|x| x.1).sum();
    win(v, start, start + GROUPS.get(g).map_or(0, |x| x.1))
}
/// (name, dims) in vector order.
pub const GROUPS: [(&str, usize); 12] = [
    ("general", 7),
    ("histogram", 256),
    ("byteentropy", 256),
    ("strings", 177),
    ("header", 74),
    ("section", 224),
    ("imports", 1282),
    ("exports", 129),
    ("datadirectories", 34),
    ("richheader", 33),
    ("authenticode", 8),
    ("pefilewarnings", 88),
];

/// numpy pairwise summation (the order matters for f32 bit parity).
fn psum<T: Copy + std::ops::Add<Output = T> + Default>(a: &[T]) -> T {
    let n = a.len();
    if n < 8 {
        return a.iter().fold(T::default(), |r, &x| r + x);
    }
    if n <= 128 {
        let Some((first, mut rest)) = a.split_first_chunk::<8>() else { return a.iter().fold(T::default(), |r, &x| r + x) };
        let mut r = *first;
        while let Some((c, more)) = rest.split_first_chunk::<8>() {
            for (x, y) in r.iter_mut().zip(c) {
                *x = *x + *y;
            }
            rest = more;
        }
        let mut res = ((r[0] + r[1]) + (r[2] + r[3])) + ((r[4] + r[5]) + (r[6] + r[7]));
        for &x in rest {
            res = res + x;
        }
        return res;
    }
    let mut n2 = n / 2;
    n2 -= n2 % 8;
    let (l, r) = a.split_at(n2);
    psum(l) + psum(r)
}

/// Python `-sum(p * math.log(p, 2))` over bytes in first-appearance order (dict order of `Counter`).
fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    let mut order = Vec::with_capacity(256);
    for &b in data {
        let Some(c) = counts.get_mut(b as usize) else { continue };
        if *c == 0 {
            order.push(b);
        }
        *c += 1;
    }
    let mut e = 0f64;
    for b in order {
        let p = counts.get(b as usize).map_or(0, |&c| c) as f64 / data.len() as f64;
        e -= p * (p.ln() / 2f64.ln());
    }
    e
}

// ---- sklearn FeatureHasher -------------------------------------------------------------------------------------

fn murmur3(key: &[u8]) -> i32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let mut h = 0u32;
    let mut chunks = key.chunks_exact(4);
    for c in &mut chunks {
        let k = u32::from_le_bytes(c.try_into().unwrap()).wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h = (h ^ k).rotate_left(13).wrapping_mul(5).wrapping_add(0xe654_6b64);
    }
    let tail = chunks.remainder();
    if !tail.is_empty() {
        let mut k = 0u32;
        for (i, &b) in tail.iter().enumerate() {
            k |= (b as u32) << (8 * i);
        }
        h ^= k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
    }
    h ^= key.len() as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h as i32
}

/// `FeatureHasher(n, ...)` accumulating in f64 and writing f32 into `out[..n]`.
struct Hasher {
    acc: Vec<f64>,
    signed: bool,
}

impl Hasher {
    fn new(n: usize, signed: bool) -> Self {
        Hasher { acc: vec![0.0; n], signed }
    }
    fn add(&mut self, key: &[u8], value: f64) {
        if value == 0.0 {
            return;
        }
        let (n, h) = (self.acc.len(), murmur3(key));
        let idx = if h == i32::MIN { (2147483647 - (n - 1)) % n } else { h.unsigned_abs() as usize % n };
        if let Some(a) = self.acc.get_mut(idx) {
            *a += if self.signed && h < 0 { -value } else { value };
        }
    }
    fn write(&self, out: &mut [f32]) {
        for (o, &a) in out.iter_mut().zip(&self.acc) {
            *o = a as f32;
        }
    }
}

// ---- group 4: strings -------------------------------------------------------------------------------------------

/// Case-insensitive literals as (sorted-key index, literal).
const CI: [(usize, &str); 55] = [
    (9, "<script"), (13, "base64"), (16, "cache"), (17, "certificate"), (18, "clipboard"), (19, "command"), (20, "connect"),
    (21, "cookie"), (22, "create"), (24, "debug"), (25, "decode"), (26, "delete"), (27, "desktop"), (28, "directory"),
    (29, "disk"), (31, "download"), (33, "encode"), (34, "enum"), (35, "environment"), (36, "exit"), (37, "file"), (39, "ftp:"),
    (40, "GET /"), (41, "hidden"), (42, "hostname"), (43, "html"), (44, "HTTP/"), (45, "http://"), (46, "https://"),
    (47, "install"), (48, "internet"), (51, "javascript"), (52, "keyboard"), (54, "memory"), (55, "module"), (56, "mutex"),
    (57, "onclick"), (58, "password"), (59, "POST /"), (60, "powershell"), (61, "privilege"), (62, "process"), (64, "remote"),
    (65, "resource"), (66, "security"), (67, "service"), (68, "shell"), (69, "snapshot"), (70, "system"), (71, "thread"),
    (72, "token"), (74, "User-Agent"), (75, "wallet"), (76, "window"),
    (0, "click"), // key ".click(" = regex `.click`: needs one char before "click"
];
/// Case-sensitive literals.
const CS: [(usize, &str); 14] = [
    (1, "/EmbeddedFile"), (2, "/FlateDecode"), (3, "/URI"), (4, "/bin/"), (5, "/dev/"), (6, "/proc/"), (7, "/tmp/"), (8, "/usr/"),
    (10, "Invoke-Command"), (11, "Invoke-Expression"), (12, "Start-process"),
    (14, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678"), (23, "crypt"), (30, "!This program "),
];
const CLICK: usize = 0;
const B64: usize = 14;
const BTC: usize = 15;
const EMAIL: usize = 32;
const FILE_PATH: usize = 38;
const IPV4: usize = 49;
const IPV6: usize = 50;
const MAC: usize = 53;
const REGISTRY: usize = 63;
const URL: usize = 73;

fn automata() -> &'static (AhoCorasick, AhoCorasick) {
    static AC: OnceLock<(AhoCorasick, AhoCorasick)> = OnceLock::new();
    AC.get_or_init(|| {
        let b = |ci: bool, p: Vec<&str>| AhoCorasick::builder().match_kind(MatchKind::Standard).ascii_case_insensitive(ci).build(p).unwrap();
        (b(true, CI.iter().map(|x| x.1).collect()), b(false, CS.iter().map(|x| x.1).collect()))
    })
}

fn is_word(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}
/// Regex `\b` before `s[i]`.
fn boundary(s: &[u8], i: usize) -> bool {
    let w = |j: Option<usize>| j.and_then(|j| s.get(j)).is_some_and(|&c| is_word(c));
    w(i.checked_sub(1)) != w(Some(i))
}
fn byte(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}
fn hex_run(s: &[u8], p: usize) -> usize {
    s.iter().skip(p).take(4).take_while(|c| c.is_ascii_hexdigit()).count()
}

fn url(s: &[u8]) -> bool {
    (0..s.len()).any(|i| {
        boundary(s, i)
            && [&b"http"[..], b"https", b"ftp"].iter().any(|p| {
                s.get(i..).is_some_and(|r| r.starts_with(p))
                    && s.get(i + p.len()..).is_some_and(|r| r.starts_with(b"://"))
                    && s.get(i + p.len() + 3).is_some_and(|c| c.is_ascii_alphanumeric() || b"-._~:?#[]@!$&'()*+,;=".contains(c))
            })
    })
}

fn octet_lens(s: &[u8], p: usize) -> u8 {
    let c = |k: usize| s.get(p + k).copied();
    let dig = |k: usize| c(k).is_some_and(|x| x.is_ascii_digit());
    let mut m = 0u8;
    if (c(0) == Some(b'2') && c(1) == Some(b'5') && matches!(c(2), Some(b'0'..=b'5'))) || (c(0) == Some(b'2') && matches!(c(1), Some(b'0'..=b'4')) && dig(2)) {
        m |= 1 << 3;
    }
    if dig(0) {
        m |= 1 << 1 | (dig(1) as u8) << 2;
    }
    if matches!(c(0), Some(b'0' | b'1')) && dig(1) {
        m |= 1 << 2 | (dig(2) as u8) << 3;
    }
    m
}
fn ipv4_at(s: &[u8], p: usize, n: usize) -> bool {
    let lens = octet_lens(s, p);
    (1..=3).any(|l| {
        lens >> l & 1 == 1 && {
            let q = p + l;
            if n == 3 { boundary(s, q) } else { s.get(q) == Some(&b'.') && ipv4_at(s, q + 1, n + 1) }
        }
    })
}
fn ipv4(s: &[u8]) -> bool {
    (0..s.len()).any(|i| byte(s, i).is_ascii_digit() && boundary(s, i) && ipv4_at(s, i, 0))
}

fn ipv6_a(s: &[u8], p: usize, g: usize) -> bool {
    (1..=hex_run(s, p)).any(|l| {
        let q = p + l;
        if g < 7 { s.get(q) == Some(&b':') && ipv6_a(s, q + 1, g + 1) } else { boundary(s, q) }
    })
}
fn ipv6_b(s: &[u8], p: usize, g: usize) -> bool {
    (1..=hex_run(s, p)).any(|l| {
        let q = p + l;
        s.get(q) == Some(&b':') && {
            let r = q + 1;
            (s.get(r) == Some(&b':') && boundary(s, r + 1)) || (g + 1 < 7 && ipv6_b(s, r, g + 1))
        }
    })
}
fn ipv6_c(s: &[u8], p: usize, reps: usize) -> bool {
    (1..=hex_run(s, p)).any(|l| {
        let q = p + l;
        (reps >= 1 && boundary(s, q)) || (reps < 6 && s.get(q) == Some(&b':') && ipv6_c(s, q + 1, reps + 1))
    })
}
fn ipv6(s: &[u8]) -> bool {
    (0..s.len()).any(|i| {
        (byte(s, i).is_ascii_hexdigit() && boundary(s, i) && (ipv6_a(s, i, 0) || ipv6_b(s, i, 0)))
            || (byte(s, i) == b':' && i > 0 && is_word(byte(s, i - 1)) && ipv6_c(s, i + 1, 0))
    })
}
fn mac(s: &[u8]) -> bool {
    (0..s.len().saturating_sub(16)).any(|i| {
        boundary(s, i)
            && (0..6).all(|k| byte(s, i + 3 * k).is_ascii_hexdigit() && byte(s, i + 3 * k + 1).is_ascii_hexdigit())
            && (0..5).all(|k| byte(s, i + 3 * k + 2) == b':' || byte(s, i + 3 * k + 2) == b'-')
            && boundary(s, i + 17)
    })
}
fn btc(s: &[u8]) -> bool {
    let b58 = |c: u8| matches!(c, b'1'..=b'9' | b'a'..=b'k' | b'm'..=b'z' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z');
    // `take(25)`: a long run of '1' must not cost O(n) per start position
    (0..s.len()).any(|i| matches!(byte(s, i), b'1' | b'3') && s.get(i + 1..).unwrap_or(&[]).iter().take_while(|&&c| b58(c)).take(25).count() >= 25)
}

/// Bit k set = the string matches pattern k (sorted-key order) of thrember's `StringExtractor`.
fn string_hits(s: &[u8]) -> u128 {
    let (ci, cs) = automata();
    let mut hits = 0u128;
    for m in ci.find_overlapping_iter(s) {
        let Some(&(k, _)) = CI.get(m.pattern().as_usize()) else { continue };
        if k != CLICK || m.start() >= 1 {
            hits |= 1 << k;
        }
    }
    for m in cs.find_overlapping_iter(s) {
        let Some(&(k, _)) = CS.get(m.pattern().as_usize()) else { continue };
        // Key 14 is regex `...012345678` + `9+/` (thrember forgot to escape the "+"): one or more 9, then "/".
        if k != B64 || s.get(m.end()..).unwrap_or(&[]).iter().skip_while(|&&c| c == b'9').next() == Some(&b'/') && s.get(m.end()) == Some(&b'9') {
            hits |= 1 << k;
        }
    }
    let at = |lit: &[u8]| (0..s.len()).any(|i| s.get(i..).is_some_and(|r| r.starts_with(lit)) && boundary(s, i));
    for (k, hit) in [
        (URL, url(s)),
        (IPV4, ipv4(s)),
        (IPV6, ipv6(s)),
        (MAC, mac(s)),
        (EMAIL, mac(s)), // thrember bug: the email regex is a copy of the MAC regex
        (BTC, btc(s)),
        (FILE_PATH, at(b"C:/")),
        (REGISTRY, at(b"KHEY_") || at(b"KHLM") || at(b"HKCU")),
    ] {
        hits |= (hit as u128) << k;
    }
    hits
}

fn strings(d: &[u8], out: &mut [f32]) {
    let (mut n, mut total) = (0u64, 0u64);
    let mut hist = [0u64; 96];
    let mut pat = [0u32; 77];
    // maximal runs of printable bytes (0x20..=0x7f)
    for s in d.split(|c| !(0x20..=0x7f).contains(c)) {
        if s.len() < 5 {
            continue;
        }
        n += 1;
        total += s.len() as u64;
        for &b in s {
            if let Some(h) = hist.get_mut((b - 0x20) as usize) {
                *h += 1;
            }
        }
        let hits = string_hits(s);
        for (k, p) in pat.iter_mut().enumerate() {
            *p += (hits >> k & 1) as u32;
        }
    }
    put(out, 0, n as f32);
    put(out, 1, if n > 0 { (total as f64 / n as f64) as f32 } else { 0.0 });
    put(out, 2, total as f32);
    let div = if total > 0 { total as f64 } else { 1.0 };
    for (o, &c) in win(out, 3, 99).iter_mut().zip(&hist) {
        *o = (c as f64 / div) as f32;
    }
    if total > 0 {
        // numpy 2: float32 array / int64 scalar promotes to float64
        let terms: Vec<f64> = hist.iter().filter(|&&c| c > 0).map(|&c| {
            let p = (c as f32 as f64) / total as f64;
            -p * p.log2()
        }).collect();
        put(out, 99, psum(&terms) as f32);
    }
    for (o, &c) in tail(out, 100).iter_mut().zip(&pat) {
        *o = c as f32;
    }
}

// ---- group 3: byte/entropy histogram ----------------------------------------------------------------------------

fn byte_entropy(d: &[u8], out: &mut [f32]) {
    let mut grid = [[0u32; 16]; 16];
    let mut block = |b: &[u8]| {
        let mut c = [0u32; 16];
        for &x in b {
            if let Some(v) = c.get_mut((x >> 4) as usize) {
                *v += 1;
            }
        }
        let terms: Vec<f32> = c.iter().filter(|&&x| x > 0).map(|&x| {
            let p = x as f32 / 2048.0;
            -p * p.log2()
        }).collect();
        let h = psum(&terms) * 2.0;
        let bin = ((h * 2.0) as usize).min(15);
        for (g, x) in grid.get_mut(bin).into_iter().flatten().zip(c) {
            *g += x;
        }
    };
    if d.len() < 2048 {
        block(d);
    } else {
        let mut s = 0;
        while let Some(b) = d.get(s..s + 2048) {
            block(b);
            s += 1024;
        }
    }
    let flat: Vec<f32> = grid.iter().flatten().map(|&x| x as f32).collect();
    let total = psum(&flat);
    for (o, x) in out.iter_mut().zip(flat) {
        *o = x / total;
    }
}

// ---- group 5: header --------------------------------------------------------------------------------------------

const MACHINES: [(u16, u8); 35] = [
    (0x014c, 1), (0x0162, 2), (0x0166, 3), (0x0168, 4), (0x0169, 5), (0x0184, 6), (0x01a2, 7), (0x01a3, 8), (0x01a4, 9),
    (0x01a6, 10), (0x01a8, 11), (0x01c0, 12), (0x01c2, 13), (0x01c4, 14), (0x01d3, 15), (0x01f0, 16), (0x01f1, 17),
    (0x0200, 18), (0x0266, 19), (0x0284, 21), (0x0366, 22), (0x0466, 23), (0x0520, 24), (0x0cef, 25), (0x0ebc, 26),
    (0x5032, 27), (0x5064, 28), (0x5128, 29), (0x6232, 30), (0x6264, 31), (0x8664, 32), (0x9041, 33), (0xaa64, 34),
    (0xc0ee, 35), (0, 0),
];

fn header(pe: &Pe, d: &[u8], out: &mut [f32]) {
    let subsystem = match pe.subsystem {
        s @ 0..=3 => s as u8,
        5 => 4,
        7 => 5,
        8..=14 => pe.subsystem as u8 - 2,
        16 => 13,
        _ => 0,
    };
    let machine = MACHINES.iter().find(|m| m.0 == pe.machine).map_or(0, |m| m.1);
    let v = [
        pe.timestamp as f32, pe.n_sections_hdr as f32, pe.n_symbols as f32, pe.size_opt as f32, pe.ptr_symtab as f32,
        machine as f32, subsystem as f32,
        pe.image.0 as f32, pe.image.1 as f32, pe.linker.0 as f32, pe.linker.1 as f32, pe.os.0 as f32, pe.os.1 as f32,
        pe.subsys_ver.0 as f32, pe.subsys_ver.1 as f32, pe.size_code as f32, pe.size_headers as f32, pe.size_image as f32,
        pe.size_init as f32, pe.size_uninit as f32, pe.stack.0 as f32, pe.stack.1 as f32, pe.heap.0 as f32, pe.heap.1 as f32,
        pe.aep as f32, pe.base_of_code as f32, pe.image_base as f32, pe.section_align as f32, pe.checksum as f32, pe.n_rva as f32,
    ];
    for (o, x) in out.iter_mut().zip(v) {
        *o = x;
    }
    for k in 0..16 {
        put(out, 30 + k, (pe.characteristics >> k & 1) as f32);
    }
    for k in 0..11 {
        put(out, 46 + k, ((pe.dll_chars >> (5 + k)) & 1) as f32);
    }
    // DOS header: e_magic .. e_ovno (14 words), e_oemid, e_oeminfo, e_lfanew
    let w = |o: usize| d.get(o..o + 2).and_then(|b| b.try_into().ok()).map_or(0, u16::from_le_bytes) as f32;
    for k in 0..14 {
        put(out, 57 + k, w(2 * k));
    }
    put(out, 71, w(36));
    put(out, 72, w(38));
    put(out, 73, d.get(60..64).and_then(|b| b.try_into().ok()).map_or(0, u32::from_le_bytes) as f32);
}

// ---- group 6: sections ------------------------------------------------------------------------------------------

const PROPS: &[(&str, u32)] = &[
    ("TYPE_DSECT", 0x1), ("TYPE_NOLOAD", 0x2), ("TYPE_GROUP", 0x4), ("TYPE_NO_PAD", 0x8), ("TYPE_COPY", 0x10), ("CNT_CODE", 0x20),
    ("CNT_INITIALIZED_DATA", 0x40), ("CNT_UNINITIALIZED_DATA", 0x80), ("LNK_OTHER", 0x100), ("LNK_INFO", 0x200),
    ("LNK_OVER", 0x400), ("LNK_REMOVE", 0x800), ("LNK_COMDAT", 0x1000), ("MEM_PROTECTED", 0x4000), ("NO_DEFER_SPEC_EXC", 0x4000),
    ("GPREL", 0x8000), ("MEM_FARDATA", 0x8000), ("MEM_SYSHEAP", 0x10000), ("MEM_PURGEABLE", 0x20000), ("MEM_16BIT", 0x20000),
    ("MEM_LOCKED", 0x40000), ("MEM_PRELOAD", 0x80000), ("ALIGN_1BYTES", 0x100000), ("ALIGN_2BYTES", 0x200000),
    ("ALIGN_4BYTES", 0x300000), ("ALIGN_8BYTES", 0x400000), ("ALIGN_16BYTES", 0x500000), ("ALIGN_32BYTES", 0x600000),
    ("ALIGN_64BYTES", 0x700000), ("ALIGN_128BYTES", 0x800000), ("ALIGN_256BYTES", 0x900000), ("ALIGN_512BYTES", 0xa00000),
    ("ALIGN_1024BYTES", 0xb00000), ("ALIGN_2048BYTES", 0xc00000), ("ALIGN_4096BYTES", 0xd00000), ("ALIGN_8192BYTES", 0xe00000),
    ("ALIGN_MASK", 0xf00000), ("LNK_NRELOC_OVFL", 0x1000000), ("MEM_DISCARDABLE", 0x2000000), ("MEM_NOT_CACHED", 0x4000000),
    ("MEM_NOT_PAGED", 0x8000000), ("MEM_SHARED", 0x10000000), ("MEM_EXECUTE", 0x20000000), ("MEM_READ", 0x40000000),
    ("MEM_WRITE", 0x80000000)
];

/// `Name.strip(b"\0").decode(errors="ignore").lower()`
fn section_name(raw: &[u8; 8]) -> String {
    let start = raw.iter().position(|&c| c != 0).unwrap_or(8);
    let end = raw.iter().rposition(|&c| c != 0).map_or(start, |p| p + 1);
    let mut s = String::new();
    for chunk in raw.get(start..end).unwrap_or(&[]).utf8_chunks() {
        s.push_str(chunk.valid());
    }
    s.to_lowercase()
}

fn sections(pe: &Pe, d: &[u8], out: &mut [f32]) {
    let secs: &[Section] = &pe.sections;
    let names: Vec<String> = secs.iter().map(|s| section_name(&s.name)).collect();
    let ents: Vec<f64> = secs.iter().map(|s| shannon(pe.section_data(s))).collect();
    // entry section: last section containing the entry point, else the first executable one
    let mut entry = String::new();
    for (s, n) in secs.iter().zip(&names) {
        if pe.contains_rva(s, pe.aep as i128) {
            entry = n.clone();
        }
    }
    for (s, n) in secs.iter().zip(&names) {
        if !entry.is_empty() {
            break;
        }
        if s.chars & 0x2000_0000 != 0 {
            entry = n.clone();
        }
    }
    let (mut ov_size, mut ov_ratio, mut ov_ent) = (0f64, 0f64, 0f64);
    if let Some(start) = pe.overlay_start() {
        let ov = d.get(start..).unwrap_or(&[]);
        (ov_size, ov_ratio, ov_ent) = (ov.len() as f64, ov.len() as f64 / d.len() as f64, shannon(ov));
    }
    let size_ratio: Vec<f64> = secs.iter().map(|s| s.raw_size as f64 / d.len() as f64).collect();
    let vsize_ratio: Vec<f64> = secs.iter().map(|s| s.raw_size as f64 / s.vsize.max(1) as f64).collect();
    let mx = |v: &[f64]| v.iter().cloned().fold(f64::MIN, f64::max);
    let mn = |v: &[f64]| v.iter().cloned().fold(f64::MAX, f64::min);
    let with = |v: &[f64], extra: &[f64]| [v, extra].concat();
    let (e, sr, vr) = (with(&ents, &[ov_ent, 0.0]), with(&size_ratio, &[ov_ratio, 0.0]), with(&vsize_ratio, &[0.0]));
    let has = |s: &Section, name: &str| PROPS.iter().any(|&(n, m)| n == name && m & s.chars != 0);
    let general = [
        secs.len() as f64,
        secs.iter().filter(|s| s.raw_size == 0).count() as f64,
        names.iter().filter(|n| n.is_empty()).count() as f64,
        secs.iter().filter(|s| has(s, "MEM_READ") && has(s, "MEM_EXECUTE")).count() as f64,
        secs.iter().filter(|s| has(s, "MEM_WRITE")).count() as f64,
        mx(&e), mn(&e), mx(&sr), mn(&sr), mx(&vr), mn(&vr),
    ];
    for (o, g) in out.iter_mut().zip(general) {
        *o = g as f32;
    }
    let mut h = [Hasher::new(50, true), Hasher::new(50, true), Hasher::new(50, true), Hasher::new(50, true), Hasher::new(10, true)];
    for ((s, name), &ent) in secs.iter().zip(&names).zip(&ents) {
        let n = name.as_bytes();
        h[0].add(n, s.raw_size as f64);
        h[1].add(n, s.vsize as f64);
        h[2].add(n, ent);
        for &(p, m) in PROPS {
            if m & s.chars != 0 {
                h[3].add(format!("{name}:{p}").as_bytes(), 1.0);
            }
        }
    }
    h[4].add(entry.as_bytes(), 1.0);
    for (k, (hh, off)) in h.iter().zip([11, 61, 111, 161, 211]).enumerate() {
        hh.write(win(out, off, off + if k == 4 { 10 } else { 50 }));
    }
    put(out, 221, ov_size as f32);
    put(out, 222, ov_ratio as f32);
    put(out, 223, ov_ent as f32);
}

// ---- groups 7-10 ------------------------------------------------------------------------------------------------

fn imports(pe: &Pe, out: &mut [f32]) {
    if pe.imports.is_empty() {
        return;
    }
    let mut libs = Hasher::new(256, false);
    let mut funcs = Hasher::new(1024, false);
    let mut seen = HashSet::new();
    let mut n_funcs = 0;
    for (dll, syms) in &pe.imports {
        let lower = dll.to_ascii_lowercase();
        if seen.insert(lower.clone()) {
            libs.add(&lower, 1.0);
        }
        for s in syms {
            let name = match (&s.name, s.ordinal) {
                (Some(n), _) if !n.is_empty() => n.clone(),
                (_, Some(o)) => format!("{}:ordinal{o}", String::from_utf8_lossy(dll)).into_bytes(),
                _ => continue,
            };
            let key = [&lower[..], b":", &name].concat();
            funcs.add(&key, 1.0);
            n_funcs += 1;
        }
    }
    put(out, 0, n_funcs as f32);
    put(out, 1, seen.len() as f32);
    libs.write(win(out, 2, 258));
    funcs.write(tail(out, 258));
}

fn exports(pe: &Pe, out: &mut [f32]) {
    if pe.exports.is_empty() {
        return;
    }
    let mut h = Hasher::new(128, true);
    for n in &pe.exports {
        h.add(n, 1.0);
    }
    put(out, 0, 128.0); // thrember: len() of the 128-wide hashed array
    h.write(tail(out, 1));
}

fn data_directories(pe: &Pe, out: &mut [f32]) {
    // thrember loops `range(1, len(raw) - 1)`, so the last directory present is never written.
    for (k, &(va, size)) in pe.dirs.iter().take(pe.dirs.len().saturating_sub(1)).enumerate() {
        put(out, 2 * k, size as f32);
        put(out, 2 * k + 1, va as f32);
    }
    put(out, 32, pe.has_relocs as u8 as f32);
}

fn rich(pe: &Pe, out: &mut [f32]) {
    let Some(v) = pe.rich.as_ref().filter(|v| !v.is_empty()) else { return };
    let mut h = Hasher::new(32, true);
    for p in v.chunks_exact(2) {
        if let &[a, b] = p {
            h.add(a.to_string().as_bytes(), b as f64);
        }
    }
    put(out, 0, (v.len() / 2) as f32);
    h.write(tail(out, 1));
}

fn warnings(pe: &Pe, out: &mut [f32]) {
    let w = pe.warnings();
    for id in 0..87 {
        put(out, id, (w >> id & 1) as f32);
    }
    put(out, 87, w.count_ones() as f32);
}

/// Feature vector for `d`, or `None` when `d` is not a PE that pefile would parse (thrember then zeroes dims 696+;
/// this layer simply does not run on such files).
pub fn extract(d: &[u8]) -> Option<Vec<f32>> {
    extract_checked(d).ok()
}

/// Like `extract`, but tells a non-PE apart from a PE whose structure exhausted the parser's work budget.
pub fn extract_checked(d: &[u8]) -> Result<Vec<f32>, ParseError> {
    let mut counts = [0u32; 256];
    for &b in d {
        if let Some(c) = counts.get_mut(b as usize) {
            *c += 1;
        }
    }
    let pe = Pe::parse(d, &counts)?;
    let mut v = vec![0f32; DIM];
    // general
    put(&mut v, 0, d.len() as f32);
    put(&mut v, 1, shannon(d) as f32);
    put(&mut v, 2, 1.0);
    for k in 0..4 {
        put(&mut v, 3 + k, d.get(k).copied().unwrap_or(0) as f32);
    }
    // histogram
    let hist: Vec<f32> = counts.iter().map(|&c| c as f32).collect();
    let total = psum(&hist);
    for (o, c) in group(&mut v, 1).iter_mut().zip(hist) {
        *o = c / total;
    }
    byte_entropy(d, group(&mut v, 2));
    strings(d, group(&mut v, 3));
    header(&pe, d, group(&mut v, 4));
    sections(&pe, d, group(&mut v, 5));
    imports(&pe, group(&mut v, 6));
    exports(&pe, group(&mut v, 7));
    data_directories(&pe, group(&mut v, 8));
    rich(&pe, group(&mut v, 9));
    for (o, x) in group(&mut v, 10).iter_mut().zip(crate::authenticode::features(&pe, d)) {
        *o = x as f32;
    }
    warnings(&pe, group(&mut v, 11));
    Ok(v)
}
