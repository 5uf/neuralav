//! Evaluator for `NAVGBDT1` gradient-boosted tree models (LightGBM binary objective, converted offline). std only.
//!
//! Layout, little endian:
//! - header: `"NAVGBDT1"`, n_features u32, n_trees u32, sigmoid f32, n_pool u32
//! - pool: `n_pool` x u32 categorical bitsets, each stored as `[nwords, w0, w1, ...]`
//! - tree: n_int u16, n_int x node, (n_int + 1) x leaf f32
//! - node (10 bytes): feat u16 (bit 15 = categorical), thr f32, left i16, right i16
//!   (child >= 0 is an internal node index, child < 0 is leaf `-child - 1`; categorical: `thr` bits = pool offset)
//!
//! Semantics match LightGBM's predictor: numeric nodes go left when `x <= thr` with NaN and `|x| <= 1e-35` read as 0;
//! categorical nodes go left when `int(x)` is in the bitset (NaN and negatives go right).

#![deny(clippy::indexing_slicing)] // `load` validates every index; `raw` still never indexes unchecked

#[derive(Clone, Copy)]
struct Node {
    feat: u16,
    thr: f32,
    left: i16,
    right: i16,
}

pub struct Model {
    n_features: usize,
    sigmoid: f32,
    pool: Vec<u32>,
    trees: Vec<(Vec<Node>, Vec<f32>)>, // (internal nodes, leaves)
}

struct Rd<'a>(&'a [u8], usize);

impl Rd<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let end = self.1.checked_add(N).ok_or("truncated model")?;
        let b = self.0.get(self.1..end).ok_or("truncated model")?;
        self.1 = end;
        Ok(b.try_into().unwrap())
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take()?))
    }
    fn i16(&mut self) -> Result<i16, String> {
        Ok(i16::from_le_bytes(self.take()?))
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take()?))
    }
    fn f32(&mut self) -> Result<f32, String> {
        Ok(f32::from_le_bytes(self.take()?))
    }
}

impl Model {
    /// Parses and validates a model. Every index is bounds-checked and every child must point forward, so a
    /// corrupt file is rejected here and `raw` can neither panic nor loop.
    pub fn load(b: &[u8]) -> Result<Model, String> {
        let mut r = Rd(b, 0);
        if &r.take::<8>()? != b"NAVGBDT1" {
            return Err("bad magic".into());
        }
        let (n_features, n_trees) = (r.u32()? as usize, r.u32()? as usize);
        let sigmoid = r.f32()?;
        if n_features == 0 || n_features > 0x7fff || n_trees == 0 || !sigmoid.is_finite() {
            return Err("bad header".into());
        }
        let n_pool = r.u32()? as usize;
        // Counts come from the file: never reserve more than the remaining bytes can hold.
        if n_pool > b.len() / 4 || n_trees > b.len() / 2 {
            return Err("truncated model".into());
        }
        let pool = (0..n_pool).map(|_| r.u32()).collect::<Result<Vec<_>, _>>()?;
        let mut trees = Vec::with_capacity(n_trees);
        for _ in 0..n_trees {
            let ni = r.u16()? as usize;
            let mut nodes = Vec::with_capacity(ni);
            for i in 0..ni {
                let feat = r.u16()?;
                let thr = r.f32()?;
                let (left, right) = (r.i16()?, r.i16()?);
                // Internal children must come later in the array (LightGBM numbering), which rules out cycles.
                let bad_child = |c: i16| if c >= 0 { (c as usize) <= i || c as usize >= ni } else { (-(c as i32) - 1) as usize > ni };
                let bad_cat = feat & 0x8000 != 0 && {
                    let off = thr.to_bits() as usize;
                    let len = pool.get(off).map(|&n| n as usize);
                    len.is_none_or(|n| off.checked_add(1).and_then(|o| o.checked_add(n)).is_none_or(|e| e > pool.len()))
                };
                if (feat & 0x7fff) as usize >= n_features || bad_child(left) || bad_child(right) || bad_cat {
                    return Err("corrupt node".into());
                }
                nodes.push(Node { feat, thr, left, right });
            }
            let leaves = (0..=ni).map(|_| r.f32()).collect::<Result<Vec<_>, _>>()?;
            trees.push((nodes, leaves));
        }
        if r.1 != b.len() {
            return Err("trailing bytes after model".into());
        }
        Ok(Model { n_features, sigmoid, pool, trees })
    }

    pub fn n_features(&self) -> usize {
        self.n_features
    }

    pub fn n_trees(&self) -> usize {
        self.trees.len()
    }

    /// Raw margin (sum of leaves, accumulated in f64). `x` must hold at least `n_features` values.
    /// `load` validated every index, so the `NAN` exits below are unreachable; they only replace a panic.
    pub fn raw(&self, x: &[f32]) -> f64 {
        assert!(x.len() >= self.n_features, "feature vector too short");
        let mut sum = 0f64;
        for (nodes, leaves) in &self.trees {
            let mut i = 0i32;
            if !nodes.is_empty() {
                loop {
                    let Some(n) = usize::try_from(i).ok().and_then(|i| nodes.get(i)) else { return f64::NAN };
                    let Some(&v) = x.get((n.feat & 0x7fff) as usize) else { return f64::NAN };
                    let left = if n.feat & 0x8000 != 0 {
                        let off = n.thr.to_bits() as usize;
                        let (bits, Some(&len)) = (v as i32, self.pool.get(off)) else { return f64::NAN };
                        let w = (bits >> 5) as usize;
                        !v.is_nan() && bits >= 0 && w < len as usize && self.pool.get(off + 1 + w).is_some_and(|p| p >> (bits & 31) & 1 == 1)
                    } else {
                        (if v.is_nan() || v.abs() <= 1e-35 { 0.0 } else { v }) <= n.thr
                    };
                    i = (if left { n.left } else { n.right }) as i32;
                    if i < 0 {
                        i = -i - 1;
                        break;
                    }
                }
            }
            let Some(&leaf) = usize::try_from(i).ok().and_then(|i| leaves.get(i)) else { return f64::NAN };
            sum += leaf as f64;
        }
        sum
    }

    /// Probability of "malicious" in [0, 1].
    pub fn predict(&self, x: &[f32]) -> f64 {
        1.0 / (1.0 + (-(self.sigmoid as f64) * self.raw(x)).exp())
    }
}
