//! Crafted PEs that used to panic (release builds abort on panic) or burn CPU. Built in-test from the shipped
//! `pe_high.bin` fixture; every case must return quickly and never panic.
use neuralav_engine::pe_features::{extract, extract_checked, ParseError, DIM};
use neuralav_engine::{Engine, EngineConfig};
use neuralav_proto::{Layer, Status};
use std::time::{Duration, Instant};

const PARSE_ERROR: usize = 2476; // authenticode group (starts at 2472), dim 4
const ASSUMING_CORRUPT: usize = DIM - 88 + 86; // pefilewarnings group, warning id 86

fn base() -> Vec<u8> {
    std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/pe_high.bin")).unwrap()
}

fn der(tag: u8, c: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let n = c.len();
    if n < 0x80 {
        v.push(n as u8)
    } else {
        v.extend([0x82, (n >> 8) as u8, n as u8])
    }
    v.extend_from_slice(c);
    v
}

const OID_SD: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
const OID_IND: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04];
const OID_TS: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03, 0x03, 0x01];

fn content_info(sd_items: &[u8]) -> Vec<u8> {
    der(0x30, &[der(6, OID_SD), der(0xa0, &der(0x30, sd_items))].concat())
}

/// `base` plus a WIN_CERTIFICATE holding `ci`, registered in the certificate data directory.
fn with_cert(ci: &[u8]) -> Vec<u8> {
    let mut d = base();
    while d.len() % 8 != 0 {
        d.push(0)
    }
    let addr = d.len() as u32;
    d.extend(((ci.len() + 8) as u32).to_le_bytes());
    d.extend(0x200u16.to_le_bytes());
    d.extend(2u16.to_le_bytes());
    d.extend_from_slice(ci);
    while d.len() % 8 != 0 {
        d.push(0)
    }
    let opt = u32::from_le_bytes(d[60..64].try_into().unwrap()) as usize + 24;
    let (nrva, cert) = if u16::from_le_bytes([d[opt], d[opt + 1]]) == 0x20b { (opt + 108, opt + 144) } else { (opt + 92, opt + 128) };
    d[nrva..nrva + 4].copy_from_slice(&16u32.to_le_bytes());
    d[cert..cert + 4].copy_from_slice(&addr.to_le_bytes());
    let sz = d.len() as u32 - addr;
    d[cert + 4..cert + 8].copy_from_slice(&sz.to_le_bytes());
    d
}

#[test]
fn authenticode_signeddata_with_two_empty_certificates_does_not_panic() {
    // certificates [0] = { SEQUENCE {}, SEQUENCE {} }: the issuer/subject check read `seq(cert)[0]` of an empty cert
    let sd = [
        der(2, &[1]),
        der(0x31, &der(0x30, &[])),
        der(0x30, &der(6, OID_IND)),
        der(0xa0, &[der(0x30, &[]), der(0x30, &[])].concat()),
        der(0x31, &der(0x30, &[der(2, &[1]), der(0x30, &[]), der(0x30, &[]), der(4, &[])].concat())),
    ]
    .concat();
    let v = extract(&with_cert(&content_info(&sd))).expect("still a PE");
    assert_eq!(v[PARSE_ERROR], 1.0);
}

#[test]
fn authenticode_timestamp_token_with_empty_signeddata_does_not_panic() {
    // timestamp-token attribute whose inner SignedData has no items: the walker read `items[2]`
    let unauth = der(0xa1, &der(0x30, &[der(6, OID_TS), der(0x31, &content_info(&[]))].concat()));
    let si = der(0x30, &[der(2, &[1]), der(0x30, &[]), der(0x30, &[]), der(0x30, &[]), der(4, &[]), unauth].concat());
    let sd = [der(2, &[1]), der(0x31, &der(0x30, &[])), der(0x30, &der(6, OID_IND)), der(0x31, &si)].concat();
    let v = extract(&with_cert(&content_info(&sd))).expect("still a PE");
    assert_eq!(v[PARSE_ERROR], 1.0);
}

fn put32(d: &mut [u8], o: usize, v: u32) {
    d[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

/// Minimal PE32 with `nsec` sections (RVAs far from anything the directories point at) and `total` bytes.
fn skeleton(nsec: usize, total: usize) -> Vec<u8> {
    let mut d = vec![0u8; total];
    d[0..2].copy_from_slice(b"MZ");
    put32(&mut d, 60, 0x40);
    d[0x40..0x44].copy_from_slice(b"PE\0\0");
    let fh = 0x44;
    d[fh..fh + 2].copy_from_slice(&0x14cu16.to_le_bytes());
    d[fh + 2..fh + 4].copy_from_slice(&(nsec as u16).to_le_bytes());
    d[fh + 16..fh + 18].copy_from_slice(&224u16.to_le_bytes());
    let o = fh + 20;
    d[o..o + 2].copy_from_slice(&0x10bu16.to_le_bytes());
    put32(&mut d, o + 16, 0x0100_0000); // entry point
    put32(&mut d, o + 32, 0x1000); // section alignment
    put32(&mut d, o + 36, 0x200); // file alignment
    put32(&mut d, o + 56, 0xffff_ffff); // SizeOfImage
    put32(&mut d, o + 92, 16);
    for i in 0..nsec {
        let s = o + 224 + 40 * i;
        d[s..s + 8].copy_from_slice(b".x\0\0\0\0\0\0");
        put32(&mut d, s + 8, 0x1000);
        put32(&mut d, s + 12, 0x0100_0000 + 0x1000 * i as u32);
        put32(&mut d, s + 36, 0x6000_0020);
    }
    d
}

fn set_dir(d: &mut [u8], idx: usize, rva: u32, size: u32) {
    let r = 0x44 + 20 + 96 + 8 * idx;
    put32(d, r, rva);
    put32(d, r + 4, size);
}

fn assert_fast(d: &[u8], what: &str) -> Option<Vec<f32>> {
    let t = Instant::now();
    let r = extract(d);
    assert!(t.elapsed() < Duration::from_millis(1500), "{what}: {:?}", t.elapsed());
    r
}

fn relocation_bomb() -> Vec<u8> {
    let total = 4 << 20;
    let mut d = skeleton(2048, total);
    let start = 0x20000usize;
    set_dir(&mut d, 5, start as u32, (total - start) as u32);
    for p in (start..total - 8).step_by(8) {
        put32(&mut d, p, 0x1000);
        put32(&mut d, p + 4, 8);
    }
    d
}

#[test]
fn many_sections_and_many_relocation_blocks_stay_under_work_budget() {
    let d = relocation_bomb();
    let t = Instant::now();
    assert_eq!(extract_checked(&d).err(), Some(ParseError::Exhausted));
    assert!(t.elapsed() < Duration::from_millis(1500), "{:?}", t.elapsed());
    assert!(extract(&d).is_none());
}

#[test]
fn work_budget_exhaustion_is_suspicious_never_clean_or_malicious() {
    let e = Engine::load(EngineConfig::new(concat!(env!("CARGO_MANIFEST_DIR"), "/rules"))).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("bomb.bin");
    std::fs::write(&p, relocation_bomb()).unwrap();
    let t = Instant::now();
    let v = e.scan_file(&p);
    assert!(t.elapsed() < Duration::from_millis(500), "{:?}", t.elapsed());
    assert_eq!(v.status, Status::Suspicious, "{v:?}");
    assert!(v.reasons.iter().any(|r| r.layer == Layer::Model && r.detail == "Static model: anomalous PE structure"), "{v:?}");
}

#[test]
fn huge_export_tables_are_capped() {
    // 0x4000 named exports at distinct addresses inside one section: capped at 0x2000 symbols with a warning
    let n = 0x4000usize;
    let mut d = skeleton(1, 0x400 + 0x30000);
    let sec = 0x44 + 20 + 224;
    put32(&mut d, sec + 8, 0x30000); // vsize
    put32(&mut d, sec + 12, 0x1000); // va
    put32(&mut d, sec + 16, 0x30000); // raw size
    put32(&mut d, sec + 20, 0x400); // raw ptr
    put32(&mut d, 0x44 + 20 + 16, 0x1000); // entry point inside the section
    let (dir, funcs, names, ords, strs) = (0x400usize, 0x500usize, 0x500 + 4 * n, 0x500 + 8 * n, 0x500 + 10 * n);
    put32(&mut d, dir + 16, 1);
    put32(&mut d, dir + 20, n as u32);
    put32(&mut d, dir + 24, n as u32);
    put32(&mut d, dir + 28, (funcs - 0x400 + 0x1000) as u32);
    put32(&mut d, dir + 32, (names - 0x400 + 0x1000) as u32);
    put32(&mut d, dir + 36, (ords - 0x400 + 0x1000) as u32);
    set_dir(&mut d, 0, 0x1000, 40);
    for i in 0..n {
        put32(&mut d, funcs + 4 * i, 0x2000 + i as u32);
        put32(&mut d, names + 4 * i, (strs - 0x400 + 0x1000) as u32);
        d[ords + 2 * i..ords + 2 * i + 2].copy_from_slice(&(i as u16).to_le_bytes());
    }
    d[strs..strs + 2].copy_from_slice(b"f\0");
    let v = assert_fast(&d, "export bomb").expect("capped, not rejected");
    assert_eq!(v[ASSUMING_CORRUPT], 1.0);
}

#[test]
fn long_run_of_base58_chars_is_not_quadratic() {
    // the bitcoin-address matcher counted the whole run from every '1'
    let mut d = base();
    d.extend(std::iter::repeat(b'1').take(200_000));
    assert!(assert_fast(&d, "btc run").is_some());
}
