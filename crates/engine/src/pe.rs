//! Minimal PE reader that mirrors `pefile` 2024.8.26 only where the EMBER2024 (thrember) features depend on it:
//! headers, sections (sorted by VirtualAddress, alignment adjusted, RVA lookup), the import and export tables, the
//! relocation directory (existence only), the Rich header and the subset of pefile warnings that is cheap to reproduce.
//!
//! Not ported (documented approximations, see `pe_features.rs`): resource, debug, TLS, load-config, delay-import,
//! bound-import and exception directories (their warnings stay 0), `pefile.ordlookup` names for ordinal imports.
#![deny(clippy::indexing_slicing)] // parser of untrusted bytes under panic=abort: every access is checked

use std::cell::Cell;
use std::collections::{HashMap, HashSet};

// Warning ids = line index in thrember's `pefile_warnings.txt` (dims 2480 + id of the feature vector).
pub const W_AEP_OUTSIDE_SECTIONS: u8 = 0;
pub const W_BAD_RELOC_RVA: u8 = 1;
pub const W_BYTE_SHARE: u8 = 2;
pub const W_CORRUPT_HEADER: u8 = 3;
pub const W_IMPORT_TABLE_DAMAGED: u8 = 4;
pub const W_EXPORT_DIR_ERROR: u8 = 8;
pub const W_IMPORT_DIR_AT_RVA: u8 = 13;
pub const W_IMPORT_INVALID_DATA: u8 = 14;
pub const W_IMPORT_BEYOND_BOUNDS: u8 = 15;
pub const W_IMPORT_OVERLAP: u8 = 16;
pub const W_IMPORT_TABLE_INVALID_DATA: u8 = 17;
pub const W_EXCESSIVE_IMPORTS: u8 = 31;
pub const W_SECTION_ALIGNMENT: u8 = 38;
pub const W_FILE_ALIGNMENT: u8 = 39;
pub const W_PACKED_IMPORTS: u8 = 40;
pub const W_RELOC_CANT_READ: u8 = 48;
pub const W_RELOC_SIZE: u8 = 49;
pub const W_RELOC_VA: u8 = 50;
pub const W_INVALID_MAGIC: u8 = 54;
pub const W_RELOC_OVERLAP: u8 = 57;
pub const W_AEP_OUTSIDE_FILE: u8 = 58;
pub const W_RICH_MALFORMED: u8 = 61;
pub const W_RICH_NOT_MS: u8 = 62;
pub const W_EXPORT_FUNCS_INVALID: u8 = 63;
pub const W_EXPORT_NAMES_INVALID: u8 = 64;
pub const W_HEADERS_BELOW_AEP: u8 = 66;
pub const W_SECTION_FLAGS: u8 = 67;
pub const W_NUM_RVAS: u8 = 68;
pub const W_SECTION_VALUE: u8 = 69;
pub const W_SECTION_ABORT: u8 = 71;
pub const W_IMPORT_ERRORS: u8 = 73;
pub const W_TOO_MANY_SECTIONS: u8 = 74;
pub const W_SECTION_NULL: u8 = 77;
pub const W_SECTION_NO_DATA: u8 = 78;
pub const W_SECTION_PTR_BEYOND: u8 = 79;
pub const W_SECTION_PTR_ALIGN: u8 = 80;
pub const W_SECTION_SIZE: u8 = 81;
pub const W_ASSUMING_CORRUPT: u8 = 86;

const MAX_IMPORT_SYMBOLS: u32 = 0x2000;
const MAX_EXPORTS: usize = 0x2000;
const MAX_REPEATED_ORDINALS: u32 = 120;
/// Hard work budget (about one unit per section compared or entry visited). A crafted PE that exceeds it
/// (many sections x many unmapped RVAs, huge relocation/export tables) makes `parse` return `None`: no model score.
const MAX_WORK: u64 = 4_000_000;
const MAX_RELOC_BLOCKS: u32 = 0x10000;
const MAX_EXPORT_ITERS: usize = 0x10000;

#[derive(Clone)]
pub struct Section {
    pub name: [u8; 8],
    pub vsize: u32,
    pub va: u32,
    pub raw_size: u32,
    pub raw_ptr: u32,
    pub chars: u32,
    va_adj: i128,
    ptr_adj: i128,
    min_addr: i128,
    max_addr: i128,
}

impl Section {
    fn contains_rva(&self, rva: i128) -> bool {
        self.min_addr <= rva && rva < self.max_addr
    }
}

/// Why `Pe::parse` produced nothing.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    /// pefile would raise `PEFormatError`.
    NotPe,
    /// The work budget ran out: a crafted structure, not a plain non-PE file.
    Exhausted,
}

pub struct Sym {
    pub name: Option<Vec<u8>>,
    pub ordinal: Option<u32>,
}

pub struct Pe<'a> {
    d: &'a [u8],
    pub opt_off: usize,
    pub plus: bool,
    pub machine: u16,
    pub timestamp: u32,
    pub n_sections_hdr: u16,
    pub n_symbols: u32,
    pub size_opt: u16,
    pub ptr_symtab: u32,
    pub characteristics: u16,
    pub magic: u16,
    pub linker: (u8, u8),
    pub os: (u16, u16),
    pub image: (u16, u16),
    pub subsys_ver: (u16, u16),
    pub size_code: u32,
    pub size_headers: u32,
    pub size_image: u32,
    pub size_init: u32,
    pub size_uninit: u32,
    pub stack: (u64, u64),
    pub heap: (u64, u64),
    pub aep: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_align: u32,
    pub file_align: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_chars: u16,
    pub n_rva: u32,
    pub dirs: Vec<(u32, u32)>, // (VirtualAddress, Size) as pefile's DATA_DIRECTORY
    pub sections: Vec<Section>,
    header_len: usize,
    last_used: Cell<Option<usize>>,
    total_imports: Cell<u32>,
    warn: Cell<u128>,
    work: Cell<u64>,
    pub imports: Vec<(Vec<u8>, Vec<Sym>)>,
    pub exports: Vec<Vec<u8>>, // names, `ordinalN` for unnamed
    pub has_relocs: bool,
    pub rich: Option<Vec<u32>>,
}

/// `N` bytes at `o`; zeros when out of range (callers range-check first, this only keeps a bad offset from panicking).
fn bytes<const N: usize>(b: &[u8], o: usize) -> [u8; N] {
    o.checked_add(N).and_then(|e| b.get(o..e)).and_then(|x| x.try_into().ok()).unwrap_or([0; N])
}
fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(bytes(b, o))
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(bytes(b, o))
}
fn u64le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(bytes(b, o))
}

/// Python-style `b[a:e]` for non-negative `a`.
fn slice(b: &[u8], a: i128, e: i128) -> &[u8] {
    let n = b.len() as i128;
    let (a, e) = (a.clamp(0, n), e.clamp(0, n));
    if e <= a {
        &[]
    } else {
        b.get(a as usize..e as usize).unwrap_or(&[])
    }
}

fn is_valid_name(s: &[u8], extra: &[u8]) -> bool {
    s.iter().all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
}

impl<'a> Pe<'a> {
    pub fn warnings(&self) -> u128 {
        self.warn.get()
    }

    fn warn(&self, id: u8) {
        self.warn.set(self.warn.get() | 1u128 << id);
    }

    /// pefile `adjust_PointerToRawData` (also reports a non power of two FileAlignment once).
    fn adj_ptr(&self, v: u32) -> i128 {
        if self.file_align >= 0x200 && !self.file_align.is_power_of_two() {
            self.warn(W_FILE_ALIGNMENT);
        }
        (v & !0x1ff) as i128
    }

    /// pefile `adjust_SectionAlignment`.
    fn adj_va(&self, v: u32) -> i128 {
        let mut sa = self.section_align;
        if sa < 0x1000 {
            if self.file_align != sa {
                self.warn(W_SECTION_ALIGNMENT);
            }
            sa = self.file_align;
        }
        if sa != 0 && v % sa != 0 {
            (sa * (v / sa)) as i128
        } else {
            v as i128
        }
    }

    /// Charges `n` work units; false once the budget is spent.
    fn spend(&self, n: u64) -> bool {
        let w = self.work.get().saturating_add(n);
        self.work.set(w);
        w <= MAX_WORK
    }

    fn exhaust(&self) {
        self.work.set(MAX_WORK + 1);
    }

    fn section_by_rva(&self, rva: i128) -> Option<usize> {
        if let Some(i) = self.last_used.get() {
            if self.sections.get(i).is_some_and(|s| s.contains_rva(rva)) {
                return self.spend(1).then_some(i);
            }
        }
        if !self.spend(self.sections.len() as u64 + 1) {
            return None;
        }
        let i = self.sections.iter().position(|s| s.contains_rva(rva))?;
        self.last_used.set(Some(i));
        Some(i)
    }

    /// pefile `get_data(rva, length)`; Err = PEFormatError.
    fn get_data(&self, rva: i128, len: i128) -> Result<&'a [u8], ()> {
        if let Some(s) = self.section_by_rva(rva).and_then(|i| self.sections.get(i)) {
            let off = rva - s.va_adj + s.ptr_adj;
            let end = (off + len).min(s.raw_ptr as i128 + s.raw_size as i128);
            return Ok(slice(self.d, off, end));
        }
        let hdr = self.d.get(..self.header_len.min(self.d.len())).unwrap_or(&[]);
        if rva < hdr.len() as i128 {
            return Ok(slice(hdr, rva, rva + len));
        }
        if rva < self.d.len() as i128 {
            return Ok(slice(self.d, rva, rva + len));
        }
        Err(())
    }

    fn offset_from_rva(&self, rva: i128) -> Result<i128, ()> {
        match self.section_by_rva(rva).and_then(|i| self.sections.get(i)) {
            Some(s) => Ok(rva - s.va_adj + s.ptr_adj),
            None if rva < self.d.len() as i128 => Ok(rva),
            None => Err(()),
        }
    }

    /// pefile `get_string_at_rva`: bytes up to the first NUL.
    fn string_at(&self, rva: i128, max: i128) -> &'a [u8] {
        let s = match self.section_by_rva(rva).and_then(|i| self.sections.get(i)) {
            Some(s) => {
                let off = rva - s.va_adj + s.ptr_adj;
                slice(self.d, off, (off + max).min(s.raw_ptr as i128 + s.raw_size as i128))
            }
            None => slice(self.d, rva, rva + max),
        };
        s.split(|&c| c == 0).next().unwrap_or(&[])
    }

    /// Section data as pefile's `SectionStructure.get_data()`.
    pub fn section_data(&self, s: &Section) -> &'a [u8] {
        let end = (s.ptr_adj + s.raw_size as i128).min(s.raw_ptr as i128 + s.raw_size as i128);
        slice(self.d, s.ptr_adj, end)
    }

    pub fn contains_rva(&self, s: &Section, rva: i128) -> bool {
        s.contains_rva(rva)
    }

    /// pefile `get_overlay()` (start offset only; `None` when there is no overlay).
    pub fn overlay_start(&self) -> Option<usize> {
        let size = self.d.len() as i128;
        let mut best = (0i128, 0i128);
        let mut offer = |c: (i128, i128)| {
            if best.0 + best.1 < c.0 + c.1 && c.0 + c.1 <= size {
                best = c;
            }
        };
        offer((self.opt_off as i128, self.size_opt as i128));
        for s in &self.sections {
            offer((s.raw_ptr as i128, s.raw_size as i128));
        }
        for (i, &(va, sz)) in self.dirs.iter().enumerate() {
            if i == 4 {
                continue; // IMAGE_DIRECTORY_ENTRY_SECURITY
            }
            if let Ok(off) = self.offset_from_rva(va as i128) {
                offer((off, sz as i128));
            }
        }
        let end = best.0 + best.1;
        (size > end).then_some(end as usize)
    }

    /// Parses `d`; `None` when pefile would raise `PEFormatError` (the caller treats the file as non-PE).
    /// `counts` is the byte histogram of the whole file.
    pub fn parse(d: &'a [u8], counts: &[u32; 256]) -> Result<Pe<'a>, ParseError> {
        Self::parse_inner(d, counts).ok_or(ParseError::NotPe).and_then(|pe| if pe.work.get() > MAX_WORK { Err(ParseError::Exhausted) } else { Ok(pe) })
    }

    fn parse_inner(d: &'a [u8], counts: &[u32; 256]) -> Option<Pe<'a>> {
        if d.len() < 64 || !d.starts_with(b"MZ") {
            return None;
        }
        let nt = u32le(d, 60) as usize;
        if nt > d.len() || d.len() < nt + 4 + 20 || d.get(nt..nt + 4) != Some(b"PE\0\0") {
            return None;
        }
        let fh = nt + 4;
        let opt_off = fh + 20;
        let size_opt = u16le(d, fh + 16);
        let sections_off = opt_off + size_opt as usize;
        let raw = d.get(opt_off.min(d.len())..(opt_off + 0x200).min(d.len()))?;
        if raw.len() < 69 {
            return None;
        }
        let magic = u16le(raw, 0);
        let plus = magic == 0x20b;
        if plus && raw.len() < 73 {
            return None;
        }
        let mut b = raw.to_vec();
        b.resize(0x200 + 128, 0);
        let mut pe = Pe {
            d,
            opt_off,
            plus,
            machine: u16le(d, fh),
            timestamp: u32le(d, fh + 4),
            n_sections_hdr: u16le(d, fh + 2),
            n_symbols: u32le(d, fh + 12),
            size_opt,
            ptr_symtab: u32le(d, fh + 8),
            characteristics: u16le(d, fh + 18),
            magic,
            linker: (b.get(2).copied().unwrap_or(0), b.get(3).copied().unwrap_or(0)),
            os: (u16le(&b, 40), u16le(&b, 42)),
            image: (u16le(&b, 44), u16le(&b, 46)),
            subsys_ver: (u16le(&b, 48), u16le(&b, 50)),
            size_code: u32le(&b, 4),
            size_headers: u32le(&b, 60),
            size_image: u32le(&b, 56),
            size_init: u32le(&b, 8),
            size_uninit: u32le(&b, 12),
            stack: if plus { (u64le(&b, 72), u64le(&b, 80)) } else { (u32le(&b, 72) as u64, u32le(&b, 76) as u64) },
            heap: if plus { (u64le(&b, 88), u64le(&b, 96)) } else { (u32le(&b, 80) as u64, u32le(&b, 84) as u64) },
            aep: u32le(&b, 16),
            base_of_code: u32le(&b, 20),
            image_base: if plus { u64le(&b, 24) } else { u32le(&b, 28) as u64 },
            section_align: u32le(&b, 32),
            file_align: u32le(&b, 36),
            checksum: u32le(&b, 64),
            subsystem: u16le(&b, 68),
            dll_chars: u16le(&b, 70),
            n_rva: u32le(&b, if plus { 108 } else { 92 }),
            dirs: Vec::new(),
            sections: Vec::new(),
            header_len: 0,
            last_used: Cell::new(None),
            total_imports: Cell::new(0),
            warn: Cell::new(0),
            work: Cell::new(0),
            imports: Vec::new(),
            exports: Vec::new(),
            has_relocs: false,
            rich: None,
        };
        // Byte share warning (pefile: zero > 50%, any other byte > 15%).
        for (byte, &c) in counts.iter().enumerate() {
            let share = c as f64 / d.len() as f64;
            if (byte == 0 && share > 0.5) || (byte != 0 && share > 0.15) {
                pe.warn(W_BYTE_SHARE);
            }
        }
        if raw.len() < 96 || (plus && raw.len() < 112) {
            pe.warn(W_CORRUPT_HEADER); // pefile's first full-size unpack failed before it retried with padding
        }
        if magic != 0x10b && magic != 0x20b {
            pe.warn(W_INVALID_MAGIC);
        }
        if pe.aep < pe.size_headers {
            pe.warn(W_HEADERS_BELOW_AEP);
        }
        if pe.n_rva > 0x10 {
            pe.warn(W_NUM_RVAS);
        }
        let opt_size = if plus { 112 } else { 96 };
        let mut off = opt_off + opt_size;
        for i in 0..(pe.n_rva & 0x7fff_ffff) {
            if d.len() == off {
                break;
            }
            let mut e = [0u8; 8];
            let tail = d.get(off.min(d.len())..).unwrap_or(&[]);
            for (x, y) in e.iter_mut().zip(tail) {
                *x = *y;
            }
            if i >= 16 {
                break; // pefile DIRECTORY_ENTRY has 16 names
            }
            pe.dirs.push((u32le(&e, 0), u32le(&e, 4)));
            off += 8;
            if off >= opt_off + opt_size + 8 * 16 {
                break;
            }
        }
        let end_table = pe.parse_sections(sections_off)?;
        let lowest = pe.sections.iter().filter(|s| s.raw_ptr > 0).map(|s| pe.adj_ptr(s.raw_ptr)).min();
        pe.header_len = match lowest {
            Some(l) if l != 0 && l as usize >= end_table => l as usize,
            _ => end_table,
        };
        pe.finish_sections();
        match pe.section_by_rva(pe.aep as i128).and_then(|i| pe.sections.get(i)) {
            Some(s) => {
                if pe.aep as i128 - s.va_adj + s.ptr_adj > d.len() as i128 {
                    pe.warn(W_AEP_OUTSIDE_FILE);
                }
            }
            None => pe.warn(W_AEP_OUTSIDE_SECTIONS),
        }
        pe.parse_directories();
        pe.rich = pe.parse_rich();
        Some(pe)
    }

    /// Returns the end of the section table (pefile's `offset` result) or `None` for a truncated header.
    fn parse_sections(&mut self, sections_off: usize) -> Option<usize> {
        let d = self.d;
        for i in 0..self.n_sections_hdr as usize {
            if i >= 0x800 {
                self.warn(W_TOO_MANY_SECTIONS);
                break;
            }
            let o = sections_off + 40 * i;
            let sd = d.get(o.min(d.len())..(o + 40).min(d.len())).unwrap_or(&[]);
            if sd.len() == 40 && sd.iter().all(|&b| b == 0) {
                self.warn(W_SECTION_NULL);
                break;
            }
            if sd.is_empty() {
                self.warn(W_SECTION_NO_DATA);
                break;
            }
            if sd.len() < 40 {
                return None; // pefile raises PEFormatError: not a PE
            }
            let s = Section {
                name: bytes(sd, 0),
                vsize: u32le(sd, 8),
                va: u32le(sd, 12),
                raw_size: u32le(sd, 16),
                raw_ptr: u32le(sd, 20),
                chars: u32le(sd, 36),
                va_adj: 0,
                ptr_adj: 0,
                min_addr: 0,
                max_addr: 0,
            };
            let mut errors = 0;
            if s.raw_size as u64 + s.raw_ptr as u64 > d.len() as u64 {
                errors += 1;
                self.warn(W_SECTION_SIZE);
            }
            if self.adj_ptr(s.raw_ptr) > d.len() as i128 {
                errors += 1;
                self.warn(W_SECTION_PTR_BEYOND);
            }
            if s.vsize > 0x1000_0000 {
                errors += 1;
                self.warn(W_SECTION_VALUE);
            }
            if self.adj_va(s.va) > 0x1000_0000 {
                errors += 1;
                self.warn(W_SECTION_VALUE);
            }
            if self.file_align != 0 && s.raw_ptr % self.file_align != 0 {
                errors += 1;
                self.warn(W_SECTION_PTR_ALIGN);
            }
            if errors >= 3 {
                self.warn(W_SECTION_ABORT);
                break;
            }
            if s.chars & 0x8000_0000 != 0 && s.chars & 0x2000_0000 != 0 {
                let name_page = s.name.iter().rposition(|&c| c != 0).and_then(|p| s.name.get(..=p)) == Some(b"PAGE");
                if !(name_page && self.is_driver_lite()) {
                    self.warn(W_SECTION_FLAGS);
                }
            }
            self.sections.push(s);
        }
        self.sections.sort_by_key(|s| s.va);
        Some(if self.sections.is_empty() { sections_off } else { sections_off + 40 * self.n_sections_hdr as usize })
    }

    /// pefile `is_driver` without the import-table test (imports are parsed later): PAGE/PAGED section + native subsystem.
    fn is_driver_lite(&self) -> bool {
        let named = self.sections.iter().any(|s| {
            let end = s.name.iter().rposition(|&c| c != 0).map_or(0, |p| p + 1);
            let n = s.name.get(..end).unwrap_or(&[]).to_ascii_lowercase();
            n == b"page" || n == b"paged"
        });
        named && (self.subsystem == 1 || self.subsystem == 8)
    }

    /// Fills the adjusted addresses and the `contains_rva` ranges (pefile caches them on first use).
    fn finish_sections(&mut self) {
        let n = self.sections.len();
        let next: Vec<Option<u32>> = (0..n).map(|i| self.sections.get(i + 1).map(|s| s.va)).collect();
        for i in 0..n {
            let Some(s) = self.sections.get(i).cloned() else { break };
            let va_adj = self.adj_va(s.va);
            let mut ptr_adj = self.adj_ptr(s.raw_ptr);
            if self.section_align < 0x1000 && s.raw_ptr == s.va {
                ptr_adj = s.va as i128;
            }
            let mut size = if (self.d.len() as i128) - ptr_adj < s.raw_size as i128 { s.vsize } else { s.raw_size.max(s.vsize) } as i128;
            if let Some(nv) = next.get(i).copied().flatten() {
                if nv > s.va && va_adj + size > nv as i128 {
                    size = nv as i128 - va_adj;
                }
            }
            let Some(t) = self.sections.get_mut(i) else { break };
            (t.va_adj, t.ptr_adj, t.min_addr, t.max_addr) = (va_adj, ptr_adj, va_adj, va_adj + size);
        }
    }

    fn parse_directories(&mut self) {
        // pefile order: IMPORT, EXPORT, RESOURCE, DEBUG, BASERELOC, ... ; the first missing index ends the loop.
        for idx in [1usize, 0, 2, 6, 5] {
            let Some(&(va, size)) = self.dirs.get(idx) else { break };
            if va == 0 {
                continue;
            }
            match idx {
                1 => self.parse_import_directory(va as i128),
                0 => self.parse_export_directory(va as i128, size as i128),
                5 => self.has_relocs = self.parse_relocations(va as i128, size as i128),
                _ => {} // resource / debug: not ported
            }
        }
    }

    fn parse_import_directory(&mut self, mut rva: i128) {
        let mut error_count = 0;
        let mut found: Vec<(Vec<u8>, Vec<Sym>)> = Vec::new();
        loop {
            let Ok(data) = self.get_data(rva, 20) else {
                self.warn(W_IMPORT_DIR_AT_RVA);
                break;
            };
            if data.len() < 20 {
                self.warn(W_CORRUPT_HEADER);
                break;
            }
            if data.iter().all(|&b| b == 0) {
                break;
            }
            let file_offset = self.offset_from_rva(rva).unwrap_or(0);
            rva += 20;
            let (oft, ft, name) = (u32le(data, 0) as i128, u32le(data, 16) as i128, u32le(data, 12) as i128);
            let mut max_len = self.d.len() as i128 - file_offset;
            if rva > oft || rva > ft {
                max_len = (rva - oft).max(rva - ft);
            }
            let syms = match self.parse_imports(oft, ft, max_len) {
                Ok(v) => v,
                Err(()) => {
                    self.warn(W_IMPORT_INVALID_DATA);
                    Vec::new()
                }
            };
            if error_count > 5 {
                self.warn(W_IMPORT_ERRORS);
                break;
            }
            if syms.is_empty() {
                error_count += 1;
                continue;
            }
            let mut dll = self.string_at(name, 0x200);
            if !is_valid_name(dll, b"!#$%&'()-@^_`{}~+,.;=[]:\\/") {
                dll = b"*invalid*";
            }
            if !dll.is_empty() {
                found.push((dll.to_vec(), syms));
            }
        }
        let (mut suspicious, mut total) = (0, 0);
        for (_, syms) in &found {
            for s in syms {
                if let Some(n) = s.name.as_ref().filter(|n| !n.is_empty()) {
                    if n.starts_with(b"LoadLibrary") || n.starts_with(b"GetProcAddress") {
                        suspicious += 1;
                    }
                }
                total += 1;
            }
        }
        if suspicious == 2 && total < 20 {
            self.warn(W_PACKED_IMPORTS);
        }
        // thrember keys a dict by DLL name: a repeated DLL replaces the earlier entry.
        let mut index: HashMap<Vec<u8>, usize> = HashMap::new();
        for (dll, syms) in found {
            match index.get(&dll).and_then(|&p| self.imports.get_mut(p)) {
                Some(e) => e.1 = syms,
                None => {
                    index.insert(dll.clone(), self.imports.len());
                    self.imports.push((dll, syms));
                }
            }
        }
    }

    fn parse_imports(&self, oft: i128, ft: i128, max_len: i128) -> Result<Vec<Sym>, ()> {
        let ilt = self.import_table(oft, max_len);
        let iat = self.import_table(ft, max_len);
        let (ilt, iat) = (ilt.unwrap_or_default(), iat.unwrap_or_default());
        if ilt.is_empty() && iat.is_empty() {
            self.warn(W_IMPORT_TABLE_DAMAGED);
            return Ok(Vec::new());
        }
        let table = if ilt.is_empty() { &iat } else { &ilt };
        let ord_flag: u64 = if self.plus { 1 << 63 } else { 1 << 31 };
        let mut out = Vec::new();
        let mut num_invalid = 0usize;
        for (idx, &entry) in table.iter().enumerate() {
            let (mut ord, mut name): (Option<u32>, Option<Vec<u8>>) = (None, None);
            if entry != 0 {
                if entry & ord_flag != 0 {
                    ord = Some((entry & 0xffff) as u32);
                } else if self.get_data((entry & (ord_flag - 1)) as i128, 2).is_ok() {
                    let n = self.string_at(entry as i128 + 2, 0x200);
                    name = Some(if is_valid_name(n, b"._?@$()<>") { n.to_vec() } else { b"*invalid*".to_vec() });
                }
            }
            if ord.is_none() && name.is_none() {
                return Err(());
            }
            if name.as_deref() == Some(b"*invalid*") {
                if num_invalid > 1000 && num_invalid == idx {
                    return Err(());
                }
                num_invalid += 1;
                continue;
            }
            if ord.is_some_and(|o| o != 0) || name.as_ref().is_some_and(|n| !n.is_empty()) {
                out.push(Sym { name, ordinal: ord });
            }
        }
        Ok(out)
    }

    /// pefile `get_import_table`; `None` = parse error (pefile returns None), `Some(empty)` = bogus table.
    fn import_table(&self, start: i128, max_len: i128) -> Option<Vec<u64>> {
        let size: i128 = if self.plus { 8 } else { 4 };
        let ord_flag: u64 = if self.plus { 1 << 63 } else { 1 << 31 };
        let mut table = Vec::new();
        let (mut s32, mut s64): (HashSet<u64>, HashSet<u64>) = (HashSet::new(), HashSet::new());
        let (mut r32, mut r64) = ((u64::MAX, 0u64), (u64::MAX, 0u64)); // (min, max)
        let mut repeated = 0;
        let mut rva = start;
        while rva != 0 {
            if rva >= start + max_len {
                self.warn(W_IMPORT_BEYOND_BOUNDS);
                break;
            }
            if self.total_imports.get() > MAX_IMPORT_SYMBOLS {
                self.warn(W_EXCESSIVE_IMPORTS);
                break;
            }
            self.total_imports.set(self.total_imports.get() + 1);
            if repeated >= 15 {
                return Some(Vec::new());
            }
            let spread = |r: (u64, u64)| if r.0 == u64::MAX { 0 } else { r.1 - r.0 };
            if spread(r32) > 128 << 20 || spread(r64) > 128 << 20 {
                return Some(Vec::new());
            }
            let data = match self.get_data(rva, size) {
                Ok(d) if d.len() as i128 == size => d,
                _ => {
                    self.warn(W_IMPORT_TABLE_INVALID_DATA);
                    return None;
                }
            };
            let thunk = if self.plus { u64le(data, 0) } else { u32le(data, 0) as u64 };
            if thunk as i128 >= start && thunk as i128 <= rva {
                self.warn(W_IMPORT_OVERLAP);
                break;
            }
            if thunk != 0 {
                if thunk & ord_flag != 0 {
                    if thunk & 0x7fff_ffff > 0xffff {
                        return Some(Vec::new());
                    }
                } else {
                    let (set, r) = if thunk >= 1 << 32 { (&mut s64, &mut r64) } else { (&mut s32, &mut r32) };
                    if !set.insert(thunk) {
                        repeated += 1;
                    }
                    *r = (r.0.min(thunk), r.1.max(thunk));
                }
            }
            if thunk == 0 {
                break;
            }
            rva += size;
            table.push(thunk);
        }
        Some(table)
    }

    fn parse_export_directory(&mut self, rva: i128, size: i128) {
        let Ok(dir) = self.get_data(rva, 40) else {
            self.warn(W_EXPORT_DIR_ERROR);
            return;
        };
        if dir.len() < 40 {
            self.warn(W_CORRUPT_HEADER);
            return;
        }
        let (base, n_funcs, n_names) = (u32le(dir, 16) as i128, u32le(dir, 20) as i128, u32le(dir, 24) as i128);
        let (a_funcs, a_names, a_ords) = (u32le(dir, 28) as i128, u32le(dir, 32) as i128, u32le(dir, 36) as i128);
        let until_eof = |rva: i128| self.offset_from_rva(rva).map(|o| self.d.len() as i128 - o);
        let fetch = |rva: i128, count: i128| -> Result<&'a [u8], ()> { self.get_data(rva, until_eof(rva)?.min(count * 4)) };
        let (Ok(names), Ok(ords), Ok(funcs)) = (fetch(a_names, n_names), fetch(a_ords, n_names), fetch(a_funcs, n_funcs)) else {
            self.warn(W_EXPORT_DIR_ERROR);
            return;
        };
        let word = |b: &[u8], i: usize| (i * 2 + 2 <= b.len()).then(|| u16le(b, i * 2));
        let dword = |b: &[u8], i: usize| (i * 4 + 4 <= b.len()).then(|| u32le(b, i * 4));
        let safety = |rva: i128| match self.section_by_rva(rva).and_then(|i| self.sections.get(i)) {
            Some(s) => {
                s.va as i128 + self.section_data(s).len() as i128 - rva
            }
            None => self.d.len() as i128,
        };
        let mut syms: Vec<(Vec<u8>, i128)> = Vec::new(); // (name, ordinal)
        let mut budget = 10;
        let mut normal = true;
        let mut counts: std::collections::HashMap<(Vec<u8>, u32), u32> = Default::default();
        let n_loop = n_names.min(safety(a_names) / 4).max(0) as usize;
        if n_loop > MAX_EXPORT_ITERS {
            self.exhaust();
            return;
        }
        for i in 0..n_loop {
            if !self.spend(1) {
                return;
            }
            let Some(ordinal) = word(ords, i).filter(|&o| (o as usize) * 4 < funcs.len()) else { return };
            let addr = dword(funcs, ordinal as usize).unwrap_or(0);
            if addr == 0 {
                continue;
            }
            let (a, r) = (addr as i128, rva);
            if a >= r && a < r + size && self.offset_from_rva(a).is_err() {
                continue;
            }
            let Some(name_addr) = dword(names, i) else {
                normal = false; // pefile: get_string_at_rva(None) is invalid
                break;
            };
            let name = self.string_at(name_addr as i128, 0x200);
            if !is_valid_name(name, b"!\"#$%&'()*+,-./:<>?[\\]^_`{|}~@") {
                normal = false;
                break;
            }
            if self.offset_from_rva(name_addr as i128).is_err() {
                budget -= 2; // pefile retries once and loses one point per failed attempt
                if budget <= 0 {
                    normal = false;
                    break;
                }
                continue;
            }
            let c = counts.entry((name.to_vec(), addr)).or_insert(0);
            *c += 1;
            if *c > 10 {
                self.warn(W_ASSUMING_CORRUPT);
                break;
            }
            if counts.len() > MAX_EXPORTS || syms.len() >= MAX_EXPORTS {
                self.warn(W_ASSUMING_CORRUPT);
                break;
            }
            syms.push((name.to_vec(), base + ordinal as i128));
        }
        if !normal {
            self.warn(W_EXPORT_NAMES_INVALID);
        }
        let named: HashSet<i128> = syms.iter().map(|s| s.1).collect();
        let (mut budget, mut normal) = (10, true);
        let mut counts: std::collections::HashMap<Option<u32>, u32> = Default::default();
        let n_loop = n_funcs.min(safety(a_funcs) / 4).max(0) as usize;
        if n_loop > MAX_EXPORT_ITERS {
            self.exhaust();
            return;
        }
        for idx in 0..n_loop {
            if !self.spend(1) {
                return;
            }
            if named.contains(&(idx as i128 + base)) {
                continue;
            }
            let addr = dword(funcs, idx);
            if addr.is_none() {
                budget -= 1;
                if budget <= 0 {
                    normal = false;
                    break;
                }
            }
            if addr == Some(0) {
                continue;
            }
            let c = counts.entry(addr).or_insert(0);
            *c += 1;
            if *c > MAX_REPEATED_ORDINALS || counts.len() > MAX_EXPORTS || syms.len() >= MAX_EXPORTS {
                self.warn(W_ASSUMING_CORRUPT);
                break;
            }
            syms.push((Vec::new(), base + idx as i128));
        }
        if !normal {
            self.warn(W_EXPORT_FUNCS_INVALID);
            return;
        }
        // thrember: the exported name, or `ordinalN` when the name is empty.
        self.exports = syms
            .into_iter()
            .map(|(n, o)| if n.is_empty() { format!("ordinal{o}").into_bytes() } else { n })
            .collect();
    }

    /// True when pefile would set `DIRECTORY_ENTRY_BASERELOC` (at least one accepted relocation block).
    fn parse_relocations(&self, mut rva: i128, size: i128) -> bool {
        let end = rva + size;
        let mut blocks = 0;
        while rva < end {
            if blocks >= MAX_RELOC_BLOCKS {
                self.exhaust();
                break;
            }
            let Ok(data) = self.get_data(rva, 8) else {
                self.warn(W_RELOC_CANT_READ);
                break;
            };
            if data.len() < 8 {
                self.warn(W_CORRUPT_HEADER);
                break;
            }
            let (va, sz) = (u32le(data, 0), u32le(data, 4));
            if va > self.size_image {
                self.warn(W_RELOC_VA);
                break;
            }
            if sz > self.size_image {
                self.warn(W_RELOC_SIZE);
                break;
            }
            // Entry words: only the duplicate check can warn; the entries themselves are not needed.
            match self.get_data(rva + 8, sz as i128 - 8).and_then(|e| self.offset_from_rva(rva + 8).map(|_| e)) {
                Ok(e) => {
                    let mut seen = HashSet::new();
                    if !self.spend(e.len() as u64 / 2 * 4) {
                        break;
                    }
                    for w in e.chunks_exact(2) {
                        let w = u16le(w, 0);
                        if !seen.insert((w & 0x0fff, w >> 12)) {
                            self.warn(W_RELOC_OVERLAP);
                            break;
                        }
                    }
                }
                Err(()) => self.warn(W_BAD_RELOC_RVA),
            }
            blocks += 1;
            if sz == 0 {
                break;
            }
            rva += sz as i128;
        }
        blocks > 0
    }

    fn parse_rich(&self) -> Option<Vec<u32>> {
        const DANS: u32 = 0x536e_6144;
        const RICH: u32 = 0x6863_6952;
        let d = self.d;
        let hay = d.get(0x80..self.opt_off.min(d.len()))?;
        let at = hay.windows(4).position(|w| w == b"Rich")? + 0x80;
        let rich_data = d.get(0x80..(at + 8).min(d.len()))?;
        let rich_data = rich_data.get(..rich_data.len() / 4 * 4)?;
        let data: Vec<u32> = rich_data.chunks_exact(4).map(|c| u32le(c, 0)).collect();
        let key = *data.get(data.iter().position(|&x| x == RICH)? + 1)?;
        if data.len() < 4 {
            return None;
        }
        let [d0, d1, d2, d3, tail @ ..] = data.as_slice() else { return None };
        if d0 ^ key != DANS || *d1 != key || *d2 != key || *d3 != key {
            self.warn(W_RICH_NOT_MS);
        }
        let mut values = Vec::new();
        for p in tail.chunks_exact(2) {
            let &[a, b] = p else { break };
            if a == RICH {
                if b != key {
                    self.warn(W_RICH_MALFORMED);
                }
                break;
            }
            values.extend([a ^ key, b ^ key]);
        }
        Some(values)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)] // test fixtures index buffers they just built
mod tests {
    use super::*;

    fn put32(d: &mut [u8], o: usize, v: u32) {
        d[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// Single-section PE32 (raw 0x400 <-> rva 0x1000) whose export directory lists `n_names` names that all share one
    /// string and map onto `n_funcs` distinct addresses, 10 names per address (the most `*c > 10` lets through).
    fn export_pe(n_funcs: usize, n_names: usize) -> Vec<u8> {
        let mut d = vec![0u8; 0x400 + 0x80000];
        let rva = |off: usize| (off - 0x400 + 0x1000) as u32;
        d[0..2].copy_from_slice(b"MZ");
        put32(&mut d, 60, 0x40);
        d[0x40..0x44].copy_from_slice(b"PE\0\0");
        d[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());
        d[0x54..0x56].copy_from_slice(&224u16.to_le_bytes());
        let o = 0x58;
        d[o..o + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        put32(&mut d, o + 16, 0x1000);
        put32(&mut d, o + 32, 0x1000);
        put32(&mut d, o + 36, 0x200);
        put32(&mut d, o + 56, 0x100000);
        put32(&mut d, o + 92, 16);
        put32(&mut d, o + 96, 0x1000); // export directory rva
        put32(&mut d, o + 100, 40);
        let s = o + 224;
        d[s..s + 6].copy_from_slice(b".rdata");
        for (off, v) in [(8, 0x80000u32), (12, 0x1000), (16, 0x80000), (20, 0x400)] {
            put32(&mut d, s + off, v);
        }
        let (dir, funcs, names, ords, strs) = (0x400, 0x500, 0x500 + 4 * n_funcs, 0x500 + 4 * n_funcs + 4 * n_names, 0x500 + 4 * n_funcs + 6 * n_names);
        put32(&mut d, dir + 16, 1);
        put32(&mut d, dir + 20, n_funcs as u32);
        put32(&mut d, dir + 24, n_names as u32);
        put32(&mut d, dir + 28, rva(funcs));
        put32(&mut d, dir + 32, rva(names));
        put32(&mut d, dir + 36, rva(ords));
        for i in 0..n_funcs {
            put32(&mut d, funcs + 4 * i, 0x2000 + i as u32);
        }
        for i in 0..n_names {
            put32(&mut d, names + 4 * i, rva(strs));
            d[ords + 2 * i..ords + 2 * i + 2].copy_from_slice(&((i / 10) as u16).to_le_bytes());
        }
        d[strs..strs + 2].copy_from_slice(b"f\0");
        d
    }

    #[test]
    fn repeated_export_addresses_are_capped_at_max_exports() {
        // 6000 addresses x 10 names = 60000 exports, under every other limit (0x10000 iterations, 0x2000 distinct keys)
        let d = export_pe(6000, 60000);
        let pe = Pe::parse(&d, &[0; 256]).expect("parses");
        assert!(!pe.exports.is_empty());
        assert!(pe.exports.len() <= MAX_EXPORTS, "{} exports", pe.exports.len());
        assert_ne!(pe.warnings() >> W_ASSUMING_CORRUPT & 1, 0);
    }
}
