//! Cheap port of the 8 EMBER2024 `authenticode` features (thrember uses `signify`): a tiny DER walker over the
//! WIN_CERTIFICATE table. It reads the structure, never verifies anything.
//!
//! Approximations versus signify/asn1crypto: DER errors map to `parse_error` (signify has more error kinds),
//! certificate issuer/subject are compared as raw DER bytes (asn1crypto compares normalized names), single-byte tags only.

#![deny(clippy::indexing_slicing)] // untrusted DER under panic=abort: every access is checked

use crate::pe::Pe;

const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
const OID_SPC_INDIRECT: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04];
const OID_SPC_OPUS: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0c];
const OID_NESTED: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x04, 0x01];
const OID_COUNTER_SIG: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x06];
const OID_SIGNING_TIME: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05];
const OID_TIMESTAMP_TOKEN: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03, 0x03, 0x01];
const MAX_DEPTH: usize = 8;

#[derive(Clone, Copy)]
struct T<'a> {
    tag: u8,
    content: &'a [u8],
    raw: &'a [u8],
}

/// First TLV in `b` and the bytes after it.
fn tlv(b: &[u8]) -> Option<(T<'_>, &[u8])> {
    let tag = *b.first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let l = *b.get(1)? as usize;
    let (len, hdr) = if l < 0x80 {
        (l, 2)
    } else {
        let n = l & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut v = 0usize;
        for i in 0..n {
            v = v << 8 | *b.get(2 + i)? as usize;
        }
        (v, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    Some((T { tag, content: b.get(hdr..end)?, raw: b.get(..end)? }, b.get(end..)?))
}

fn kids(c: &[u8]) -> Option<Vec<T<'_>>> {
    let mut out = Vec::new();
    let mut rest = c;
    while !rest.is_empty() {
        let (t, r) = tlv(rest)?;
        out.push(t);
        rest = r;
    }
    Some(out)
}

fn seq<'a>(t: &T<'a>) -> Option<Vec<T<'a>>> {
    (t.tag == 0x30).then(|| kids(t.content)).flatten()
}

/// `(oid, values)` for each Attribute in a SET OF Attribute.
fn attrs<'a>(set: &T<'a>) -> Option<Vec<(&'a [u8], Vec<T<'a>>)>> {
    kids(set.content)?
        .iter()
        .map(|a| {
            let k = seq(a)?;
            let oid = k.first().filter(|o| o.tag == 6)?.content;
            Some((oid, kids(k.get(1).filter(|v| v.tag == 0x31)?.content)?))
        })
        .collect()
}

/// UTCTime / GeneralizedTime to Unix seconds.
fn time(t: &T) -> Option<f64> {
    let s = std::str::from_utf8(t.content).ok()?.strip_suffix('Z')?;
    let (digits, frac) = s.split_once('.').map_or((s, ""), |(a, b)| (a, b));
    let n = |a: usize, l: usize| digits.get(a..a + l)?.parse::<i64>().ok();
    let (y, rest) = match t.tag {
        0x17 => (n(0, 2)? + if n(0, 2)? >= 50 { 1900 } else { 2000 }, 2),
        0x18 => (n(0, 4)?, 4),
        _ => return None,
    };
    let (mo, d, h, mi) = (n(rest, 2)?, n(rest + 2, 2)?, n(rest + 4, 2)?, n(rest + 6, 2)?);
    let sec = if digits.len() >= rest + 10 { n(rest + 8, 2)? } else { 0 };
    // days from civil (Howard Hinnant)
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let days = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    let fraction = if frac.is_empty() { 0.0 } else { format!("0.{frac}").parse::<f64>().ok()? };
    Some((days * 86400 + h * 3600 + mi * 60 + sec) as f64 + fraction)
}

struct Sd {
    has_program_name: bool,
    countersign: Option<f64>,
    n_certs: usize,
    self_signed: bool,
}

/// ContentInfo{signedData} -> SignedData SEQUENCE items.
fn signed_data<'a>(ci: &T<'a>) -> Option<Vec<T<'a>>> {
    let k = seq(ci)?;
    if k.first()?.content != OID_SIGNED_DATA {
        return None;
    }
    let (inner, _) = tlv(k.get(1).filter(|t| t.tag == 0xa0)?.content)?;
    seq(&inner)
}

/// Walks one ContentInfo and its nested signatures in signify's iteration order (parent first).
fn walk(ci: &[u8], depth: usize, out: &mut Vec<Sd>) -> Option<()> {
    if depth > MAX_DEPTH {
        return None;
    }
    let (ci, _) = tlv(ci)?;
    let sd = signed_data(&ci)?;
    // version, digestAlgorithms, encapContentInfo, [certificates], [crls], signerInfos
    if sd.len() < 4 || sd.get(1)?.tag != 0x31 || kids(sd.get(1)?.content)?.len() != 1 {
        return None;
    }
    if seq(sd.get(2)?)?.first()?.content != OID_SPC_INDIRECT {
        return None;
    }
    let mut i = 3;
    let mut certs = Vec::new();
    if sd.get(i)?.tag == 0xa0 {
        certs = kids(sd.get(i)?.content)?.into_iter().filter(|c| c.tag == 0x30).collect();
        i += 1;
    }
    if sd.get(i).is_some_and(|t| t.tag == 0xa1) {
        i += 1;
    }
    let signers = sd.get(i).filter(|t| t.tag == 0x31)?;
    let signers = kids(signers.content)?;
    let [signer] = signers.as_slice() else { return None };
    let si = seq(signer)?;
    let mut j = 3;
    let mut auth = Vec::new();
    if si.get(j)?.tag == 0xa0 {
        auth = attrs(si.get(j)?)?;
        j += 2; // skip digestEncryptionAlgorithm
    } else {
        j += 1;
    }
    j += 1; // signature
    let unauth = match si.get(j) {
        Some(t) if t.tag == 0xa1 => attrs(t)?,
        _ => Vec::new(),
    };

    let mut has_program_name = false;
    for (oid, vals) in &auth {
        if *oid == OID_SPC_OPUS {
            let [v] = vals.as_slice() else { return None };
            has_program_name = seq(v)?.iter().any(|t| t.tag == 0xa0);
        }
    }
    let mut nested: Vec<&[u8]> = Vec::new();
    let (mut countersign, mut has_counter, mut has_token) = (None, false, false);
    for (oid, vals) in &unauth {
        if *oid == OID_NESTED {
            nested.extend(vals.iter().map(|v| v.raw));
        } else if *oid == OID_COUNTER_SIG {
            has_counter = true;
            let cs = seq(vals.first()?)?;
            let cs_auth = attrs(cs.iter().find(|t| t.tag == 0xa0)?)?;
            let (_, v) = cs_auth.iter().find(|(o, _)| *o == OID_SIGNING_TIME)?;
            countersign = Some(time(v.first()?)?);
        } else if *oid == OID_TIMESTAMP_TOKEN {
            has_token = true;
            let [v] = vals.as_slice() else { return None };
            let ts = signed_data(v)?;
            let encap = seq(ts.get(2)?)?;
            let (octets, _) = tlv(encap.get(1).filter(|t| t.tag == 0xa0)?.content)?;
            let (tst, _) = tlv(octets.content)?;
            countersign = Some(time(seq(&tst)?.get(4)?)?);
        }
    }
    if has_counter && has_token {
        return None;
    }

    let issuer_subject = |c: &T| -> Option<bool> {
        let tbs = seq(seq(c)?.first()?)?;
        let k = if tbs.first()?.tag == 0xa0 { 1 } else { 0 };
        Some(tbs.get(k + 2)?.raw == tbs.get(k + 4)?.raw)
    };
    let mut self_signed = false;
    for c in certs.iter().take(certs.len().saturating_sub(1)) {
        self_signed |= issuer_subject(c)?;
    }
    out.push(Sd { has_program_name, countersign, n_certs: certs.len(), self_signed });
    for n in nested {
        walk(n, depth + 1, out)?;
    }
    Some(())
}

/// Features in thrember order: num_certs, self_signed, empty_program_name, no_countersigner, parse_error,
/// chain_max_depth, latest_signing_time, signing_time_diff.
pub fn features(pe: &Pe, d: &[u8]) -> [f64; 8] {
    let mut f = [0f64; 8];
    let len = d.len() as u64;
    // signify `get_authenticode_omit_sections`: where is the certificate table?
    let (opt, size_opt) = (pe.opt_off as u64, pe.size_opt as u64);
    if size_opt + opt > len || size_opt < 68 || !(pe.magic == 0x10b || pe.magic == 0x20b) {
        return f;
    }
    let (rva_base, cert_base) = if pe.magic == 0x10b { (opt + 92, opt + 128) } else { (opt + 108, opt + 144) };
    let rd = |o: u64| d.get(o as usize..(o as usize).saturating_add(4)).and_then(|b| b.try_into().ok()).map_or(0, |b| u32::from_le_bytes(b) as u64);
    if opt + size_opt < rva_base + 4 || rd(rva_base) < 5 || opt + size_opt < cert_base + 8 {
        return f;
    }
    let (address, size) = (rd(cert_base), rd(cert_base + 4));
    if size == 0 || address < size_opt + opt || address + size > len {
        return f;
    }
    let (mut pos, end) = (address, address + size);
    while pos < end {
        if pos + 8 > len {
            break;
        }
        let hdr: [u8; 4] = d.get(pos as usize + 4..pos as usize + 8).and_then(|b| b.try_into().ok()).unwrap_or_default();
        let (length, revision, kind) = (rd(pos), u16::from_le_bytes([hdr[0], hdr[1]]), u16::from_le_bytes([hdr[2], hdr[3]]));
        if length <= 8 || pos + length > end || revision != 0x200 {
            break;
        }
        if kind == 2 {
            let mut sds = Vec::new();
            let Some(cert) = d.get(pos as usize + 8..(pos + length) as usize) else { break };
            if walk(cert, 0, &mut sds).is_none() {
                f[4] = 1.0;
                break;
            }
            for sd in &sds {
                f[0] += 1.0;
                f[2] = f[2].max(!sd.has_program_name as u8 as f64);
                match sd.countersign {
                    Some(t) => {
                        if t >= f[6] {
                            f[6] = t;
                        }
                        f[7] = t - pe.timestamp as f64;
                    }
                    None => f[3] = 1.0,
                }
                f[5] = f[5].max(sd.n_certs as f64);
                f[1] = f[1].max(sd.self_signed as u8 as f64);
            }
        }
        pos += length + (8 - length % 8) % 8;
    }
    f
}
