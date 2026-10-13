"""Parity of the Rust EMBER2024 feature port against thrember (needs `pip install thrember lightgbm numpy`).

usage: ember_parity.py <EMBER2024_PE.model> <model.navgbdt> <dump_features binary> <file>... [--ref prefix]
  --ref prefix  reuse/store thrember vectors in prefix.f32 + prefix.txt (extraction is slow)

Run only on harmless PEs (generated or benign files from outside the repo). Run python with -I.
Prints per-group max abs diff, #dims that differ, and the score diff (Rust vector -> Rust model vs thrember vector -> LightGBM).
"""
import os, subprocess, sys, tempfile, warnings
import numpy as np

warnings.filterwarnings("ignore")
GROUPS = [("general", 7), ("histogram", 256), ("byteentropy", 256), ("strings", 177), ("header", 74), ("section", 224),
          ("imports", 1282), ("exports", 129), ("datadirectories", 34), ("richheader", 33), ("authenticode", 8), ("pefilewarnings", 88)]
DIM = sum(n for _, n in GROUPS)

args = sys.argv[1:]
ref = args[args.index("--ref") + 1] if "--ref" in args else None
if ref:
    del args[args.index("--ref"):args.index("--ref") + 2]
lgb_model, navmodel, harness, files = args[0], args[1], args[2], args[3:]

if ref and os.path.exists(ref + ".f32"):
    py = np.fromfile(ref + ".f32", dtype="<f4").reshape(-1, DIM)
    names = open(ref + ".txt").read().split("\n")
else:
    import thrember
    ex = thrember.PEFeatureExtractor()
    rows, names = [], []
    for p in files:
        try:
            b = open(p, "rb").read()
            rows.append(ex.feature_vector(b)); names.append(p)
        except Exception as e:
            print("skip", p, repr(e)[:80], file=sys.stderr)
    py = np.vstack(rows).astype("<f4")
    if ref:
        py.tofile(ref + ".f32"); open(ref + ".txt", "w").write("\n".join(names))

out = tempfile.mktemp(suffix=".f32")
lines = subprocess.run([harness, navmodel, out] + names, capture_output=True, text=True, check=True).stdout.strip().split("\n")
got = [l.split("\t")[0] for l in lines]
assert got == names, f"Rust skipped files: {set(names) - set(got)}"
rs = np.fromfile(out, dtype="<f4").reshape(-1, DIM)
rscore = np.array([float(l.split("\t")[1]) for l in lines])
os.unlink(out)

d = np.abs(py.astype(np.float64) - rs.astype(np.float64))
print(f"{len(names)} files")
print(f"{'group':16}{'dims':>6}{'max abs diff':>16}{'files differing':>17}{'dims differing':>16}")
off = 0
for g, n in GROUPS:
    blk = d[:, off:off + n]
    print(f"{g:16}{n:>6}{blk.max():>16.6g}{int((blk.max(axis=1) > 1e-6).sum()):>17}{int((blk.max(axis=0) > 1e-6).sum()):>16}")
    off += n
import lightgbm as lgb
bst = lgb.Booster(model_file=lgb_model)
ps = bst.predict(py)
print(f"score: python(thrember vec) vs rust(rust vec): max abs diff {np.abs(ps - rscore).max():.4g}, mean {np.abs(ps - rscore).mean():.4g}")
print(f"       python range [{ps.min():.4f}, {ps.max():.4f}], rust range [{rscore.min():.4f}, {rscore.max():.4f}]")
for t in (0.5, 0.9, 0.95):
    print(f"       >= {t}: python {int((ps >= t).sum())}, rust {int((rscore >= t).sum())}, disagree {int(((ps >= t) != (rscore >= t)).sum())}")
bad = np.argsort(-d.max(axis=1))[:5]
for i in bad:
    if d[i].max() > 1e-6:
        dims = np.where(d[i] > 1e-6)[0]
        print("worst:", os.path.basename(names[i]), "max", d[i].max(), "dims", dims[:12].tolist())
