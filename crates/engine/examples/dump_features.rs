//! Parity harness: `cargo run --release -p neuralav-engine --example dump_features -- <model.navgbdt> <out.f32> <file>...`
//! Writes one 2568-dim little-endian f32 row per PE file and prints `path<TAB>score` (rows and lines stay aligned;
//! non-PE files are skipped). Compare against thrember with `scripts/ember_parity.py`.
use neuralav_engine::{gbdt::Model, pe_features};
use std::io::Write;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let model = Model::load(&std::fs::read(&a[1]).expect("model")).expect("model load");
    let mut out = std::io::BufWriter::new(std::fs::File::create(&a[2]).expect("out"));
    for p in &a[3..] {
        let Ok(d) = std::fs::read(p) else { continue };
        let Some(v) = pe_features::extract(&d) else { continue };
        for x in &v {
            out.write_all(&x.to_le_bytes()).unwrap();
        }
        println!("{p}\t{:.17}", model.predict(&v));
    }
}
