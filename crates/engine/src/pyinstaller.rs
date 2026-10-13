//! Reader for PyInstaller one-file bundles (CArchive appended to a PE/ELF/Mach-O host), written from the format
//! description: a cookie near the end of the file (`MEI\x0c\x0b\x0a\x0b\x0e`, then big-endian package length, TOC
//! offset, TOC length, Python version and, in PyInstaller 2.1+, a 64-byte library name) points at a TOC of
//! `entry_len, data_offset, compressed_len, uncompressed_len (u32 BE), compress flag, type code, NUL-padded name`.
//! Entries are raw or zlib. Used as a container unpacker: each entry is handed to the caller, which runs the
//! signature and hash layers over it. Entries (including `z` PYZ archives) are never unmarshalled or executed.
//!
//! Limits (all fixed): 4096 entries, 64 MiB total of compressed bytes read plus every byte inflated (including the
//! output of streams that fail their checksum), entries sharing one (offset, length) are processed once, script
//! (`s`) entries first so padding cannot push them past the caps. Hitting a cap returns `Walk::Truncated`: the
//! caller must not call the file Clean. `uncompressed_len` is never trusted. Like the real bootloader, only the
//! LAST cookie magic in the whole file counts (the caller finds it during its streamed scan, see `last_magic`) and
//! entries are bounds-checked against the file size, not `pkg_len`. A TOC over 2 MiB is `Truncated`. Corrupt cookie
//! or entry: ignored, the file is scanned as usual.
#![deny(clippy::indexing_slicing)] // parser of untrusted bytes under panic=abort: every access is checked

use miniz_oxide::inflate::{decompress_to_vec_zlib_with_limit, TINFLStatus};
use std::collections::HashSet;
use memchr::memmem;
use std::io::{Read, Seek, SeekFrom};

const MAGIC: &[u8; 8] = b"MEI\x0c\x0b\x0a\x0b\x0e";
const COOKIE_NEW: usize = 88; // !8sIIII64s
const COOKIE_OLD: usize = 24; // !8sIIII
const MAX_ENTRIES: usize = 4096;
const MAX_TOC: usize = 2 * 1024 * 1024;
const MAX_BUDGET: usize = 64 * 1024 * 1024;

#[derive(Debug, PartialEq)]
pub enum Walk {
    /// Every entry was visited (or the archive was absent or unreadable).
    Done,
    /// An entry, byte or entry-count cap was hit: some content was not inspected.
    Truncated,
}

struct Cookie {
    pkg_start: u64,
    toc_off: u64,
    toc_len: usize,
}

fn be32(b: &[u8], at: usize) -> Option<usize> {
    let w: [u8; 4] = b.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_be_bytes(w) as usize)
}

/// Records the offset of the last cookie magic in `chunk` (file offset `base`) into `last`.
pub fn last_magic(chunk: &[u8], base: u64, last: &mut Option<u64>) {
    if let Some(p) = memmem::rfind(chunk, MAGIC) {
        *last = Some(base + p as u64);
    }
}

/// Validates the cookie whose magic is at file offset `at` and starts `c` (bytes from there to the end of the file, at most 88).
fn parse_cookie(c: &[u8], at: u64, size: u64) -> Option<Cookie> {
    for len in [COOKIE_NEW, COOKIE_OLD] {
        if c.len() < len {
            continue;
        }
        let (Some(pkg_len), Some(toc_off), Some(toc_len)) = (be32(c, 8), be32(c, 12), be32(c, 16)) else { continue };
        let end = at + len as u64;
        if pkg_len as u64 <= end && toc_len >= 18 && (end - pkg_len as u64) + toc_off as u64 + toc_len as u64 <= size {
            return Some(Cookie { pkg_start: end - pkg_len as u64, toc_off: toc_off as u64, toc_len });
        }
    }
    None
}

/// Printable ASCII only, no commas, at most 128 chars: safe to embed in a `label,text` reason.
pub fn sanitize(name: &[u8]) -> String {
    name.iter().filter(|b| (0x20..0x7f).contains(*b) && **b != b',').take(128).map(|&b| b as char).collect()
}

struct Entry<'a> {
    off: usize,
    clen: usize,
    compressed: bool,
    script: bool,
    name: &'a [u8],
}

/// TOC records in order. A malformed record (shorter than the 18-byte header, or reaching past the TOC) yields
/// `None` and ends the walk: the bootloader would read it differently, so the rest of the TOC is unknown. Entries
/// reaching past the end of the file cannot be read, so they are skipped (`avail` = bytes from the package start
/// to the end of the file).
fn records(toc: &[u8], avail: u64) -> impl Iterator<Item = Option<Entry<'_>>> {
    let mut at = 0usize;
    std::iter::from_fn(move || loop {
        if at == toc.len() {
            return None;
        }
        let rec = be32(toc, at).filter(|&l| l >= 18).and_then(|l| toc.get(at..at.checked_add(l)?));
        let Some(rec) = rec else {
            at = toc.len();
            return Some(None);
        };
        at += rec.len();
        let (Some(off), Some(clen), Some(&flag), Some(&ty), Some(name)) =
            (be32(rec, 4), be32(rec, 8), rec.get(16), rec.get(17), rec.get(18..))
        else {
            return Some(None); // unreachable: rec.len() >= 18
        };
        if off.checked_add(clen).is_none_or(|e| e as u64 > avail) {
            continue;
        }
        let name = name.split(|&b| b == 0).next().unwrap_or(&[]);
        // The bootloader inflates only flag 1; any other value is stored.
        return Some(Some(Entry { off, clen, compressed: flag == 1, script: ty == b's', name }));
    })
}

/// Calls `visit(entry name, entry bytes, raw)` for each readable entry of the CArchive in `r` (`size` bytes) whose
/// cookie magic is at `magic_at` (see `last_magic`); `raw` is true for stored (not zlib) entries, whose bytes are
/// part of the file itself. `visit` returns true to stop.
pub fn walk<R: Read + Seek>(r: &mut R, size: u64, magic_at: Option<u64>, mut visit: impl FnMut(&str, &[u8], bool) -> bool) -> Walk {
    let Some(at) = magic_at else { return Walk::Done };
    let mut cookie = vec![0u8; (size.saturating_sub(at)).min(COOKIE_NEW as u64) as usize];
    if r.seek(SeekFrom::Start(at)).is_err() || r.read_exact(&mut cookie).is_err() {
        return Walk::Done;
    }
    let Some(c) = parse_cookie(&cookie, at, size) else { return Walk::Done };
    if c.toc_len > MAX_TOC {
        return Walk::Truncated;
    }
    let mut toc = vec![0u8; c.toc_len];
    if r.seek(SeekFrom::Start(c.pkg_start + c.toc_off)).is_err() || r.read_exact(&mut toc).is_err() {
        return Walk::Done;
    }
    let mut truncated = false;
    let (mut seen, mut entries) = (HashSet::new(), Vec::new());
    // Scripts first, so padding entries cannot push them past the entry cap.
    for scripts in [true, false] {
        for e in records(&toc, size - c.pkg_start) {
            let Some(e) = e else {
                truncated = true;
                break;
            };
            if e.script != scripts || !seen.insert((e.off, e.clen, e.compressed)) {
                continue; // identical (offset, length, compression): read once
            }
            if entries.len() == MAX_ENTRIES {
                truncated = true;
                break;
            }
            entries.push(e);
        }
    }
    let mut budget = MAX_BUDGET;
    for e in entries {
        if e.clen > budget {
            truncated = true;
            continue;
        }
        budget -= e.clen;
        let mut data = vec![0u8; e.clen];
        if r.seek(SeekFrom::Start(c.pkg_start + e.off as u64)).is_err() || r.read_exact(&mut data).is_err() {
            continue;
        }
        if e.compressed {
            // Every produced byte is charged, also when the stream turns out corrupt.
            match decompress_to_vec_zlib_with_limit(&data, budget) {
                Ok(v) => data = v,
                Err(err) => {
                    budget -= err.output.len().min(budget);
                    if err.status == TINFLStatus::HasMoreOutput {
                        truncated = true;
                    }
                    continue;
                }
            }
            budget -= data.len();
        }
        if visit(&sanitize(e.name), &data, !e.compressed) {
            break;
        }
    }
    if truncated { Walk::Truncated } else { Walk::Done }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn zlib(b: &[u8]) -> Vec<u8> {
        miniz_oxide::deflate::compress_to_vec_zlib(b, 6)
    }

    /// Entries are (name, flag, stored bytes). Returns host junk + data + TOC + cookie.
    fn build(entries: &[(&str, u8, Vec<u8>)], new_cookie: bool) -> Vec<u8> {
        let mut file = b"MZhost-bytes".to_vec();
        let pkg_start = file.len();
        let mut toc = Vec::new();
        for (name, flag, stored) in entries {
            let off = (file.len() - pkg_start) as u32;
            file.extend_from_slice(stored);
            let mut n = name.as_bytes().to_vec();
            n.push(0);
            let elen = 18 + n.len() as u32;
            for v in [elen, off, stored.len() as u32, stored.len() as u32] {
                toc.extend(v.to_be_bytes());
            }
            toc.extend([*flag, if name.starts_with('#') { b'x' } else { b's' }]);
            toc.extend(n);
        }
        let toc_off = (file.len() - pkg_start) as u32;
        file.extend_from_slice(&toc);
        let clen = if new_cookie { COOKIE_NEW } else { COOKIE_OLD };
        let pkg_len = (file.len() - pkg_start + clen) as u32;
        file.extend(MAGIC);
        for v in [pkg_len, toc_off, toc.len() as u32, 311] {
            file.extend(v.to_be_bytes());
        }
        if new_cookie {
            file.extend([0u8; 64]);
        }
        file
    }

    fn collect(f: &[u8]) -> (Vec<(String, Vec<u8>)>, Walk) {
        let mut seen = Vec::new();
        let mut at = None;
        last_magic(f, 0, &mut at);
        let w = walk(&mut Cursor::new(f), f.len() as u64, at, |n, b, _| {
            seen.push((n.to_string(), b.to_vec()));
            false
        });
        (seen, w)
    }

    #[test]
    fn reads_raw_and_zlib_entries_both_cookie_layouts() {
        for new in [true, false] {
            let f = build(&[("a.py", 0, b"raw".to_vec()), ("b,\nx.py", 1, zlib(b"inflated"))], new);
            let (seen, w) = collect(&f);
            assert_eq!(w, Walk::Done);
            assert_eq!(seen, [("a.py".to_string(), b"raw".to_vec()), ("bx.py".to_string(), b"inflated".to_vec())]);
        }
    }

    #[test]
    fn highly_compressible_entry_within_budget_is_just_read() {
        let f = build(&[("zeros", 1, zlib(&vec![0u8; 40 * 1024 * 1024]))], true);
        let (seen, w) = collect(&f);
        assert_eq!(w, Walk::Done);
        assert_eq!(seen.first().map(|e| e.1.len()), Some(40 * 1024 * 1024));
    }

    #[test]
    fn over_budget_entry_is_truncated_not_done() {
        let f = build(&[("big", 1, zlib(&vec![0u8; 70 * 1024 * 1024]))], true);
        let (seen, w) = collect(&f);
        assert!(seen.is_empty());
        assert_eq!(w, Walk::Truncated);
    }

    /// One corrupt-checksum blob referenced by 4096 TOC entries with distinct lengths (so dedupe cannot help):
    /// every inflated byte is charged, so total work stays bounded by the budget.
    #[test]
    fn corrupt_adler_entries_sharing_a_blob_are_bounded() {
        let mut blob = zlib(&vec![0u8; 20 * 1024 * 1024]);
        let n = blob.len();
        blob[n - 1] ^= 0xff;
        let mut f = b"MZ".to_vec();
        f.extend_from_slice(&blob);
        let start = 2;
        let mut toc = Vec::new();
        for i in 0..MAX_ENTRIES {
            let name = format!("e{i}\0");
            for v in [18 + name.len() as u32, 0, (blob.len() - (i % 4)) as u32, 0] {
                toc.extend(v.to_be_bytes());
            }
            toc.extend([1u8, b's']);
            toc.extend(name.as_bytes());
        }
        let toc_off = (f.len() - start) as u32;
        f.extend_from_slice(&toc);
        let pkg_len = (f.len() - start + COOKIE_OLD) as u32;
        f.extend(MAGIC);
        for v in [pkg_len, toc_off, toc.len() as u32, 311] {
            f.extend(v.to_be_bytes());
        }
        let t = std::time::Instant::now();
        let (seen, _) = collect(&f);
        assert!(seen.is_empty());
        assert!(t.elapsed().as_secs() < 10, "{:?}", t.elapsed());
    }

    #[test]
    fn entry_cap_is_truncated_and_scripts_come_first() {
        let mut entries: Vec<(String, u8, Vec<u8>)> = (0..MAX_ENTRIES).map(|i| (format!("#pad{i}"), 0u8, vec![i as u8; 1])).collect();
        entries.push(("script".to_string(), 0, b"payload".to_vec()));
        let refs: Vec<(&str, u8, Vec<u8>)> = entries.iter().map(|(n, f, d)| (n.as_str(), *f, d.clone())).collect();
        let (seen, w) = collect(&build(&refs, true));
        assert_eq!(w, Walk::Truncated);
        assert_eq!(seen.first().map(|e| e.0.as_str()), Some("script"));
    }

    #[test]
    fn cookie_found_before_large_trailer() {
        let mut f = build(&[("a", 0, b"x".to_vec())], true);
        f.extend(vec![0u8; 3 * 1024 * 1024]);
        assert_eq!(collect(&f).0.len(), 1);
    }

    #[test]
    fn corrupt_inputs_do_not_panic_or_yield() {
        let good = build(&[("a", 1, zlib(b"hello"))], true);
        for cut in 0..good.len() {
            collect(&good[..cut]);
        }
        let mut f = good.clone();
        let n = f.len();
        // out-of-range entry offset (bytes 4..8 of the first TOC record) and a huge compressed_len
        let toc = n - COOKIE_NEW - 20;
        f[toc + 4..toc + 8].copy_from_slice(&0xffff_fff0u32.to_be_bytes());
        assert!(collect(&f).0.is_empty());
        let mut f = good;
        f[toc + 8..toc + 12].copy_from_slice(&0xffff_fff0u32.to_be_bytes());
        assert!(collect(&f).0.is_empty());
    }

    #[test]
    fn cookie_at_file_edges() {
        let f = build(&[], true);
        assert!(collect(&f[f.len() - COOKIE_NEW..]).0.is_empty()); // cookie is the whole file
        assert!(collect(&[]).0.is_empty());
    }
}
