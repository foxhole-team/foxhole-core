//! Write `fuzz/corpus/<target>/` from the seeds in `seeds.rs`.
//!
//! Regenerating rather than committing bytes by hand keeps the corpus tied to
//! the unit tests it came from: a fixture that changes shape is one edit away
//! from a corpus that still matches it. Existing files are overwritten by name
//! and nothing is deleted, so a corpus grown by an actual fuzz run survives.

use std::path::PathBuf;
use std::{env, fs, io, process};

use foxcore_fuzz_harness::seeds;

fn main() {
    let root = match env::args().nth(1) {
        Some(path) => PathBuf::from(path),
        // Default to `fuzz/corpus` relative to this crate, so the command works
        // from anywhere without an argument.
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("the harness lives inside fuzz/")
            .join("corpus"),
    };

    if let Err(error) = write_all(&root) {
        eprintln!("seed-corpus: {error}");
        process::exit(1);
    }
}

fn write_all(root: &std::path::Path) -> io::Result<()> {
    let mut total = 0;
    for target in seeds::TARGETS {
        let directory = root.join(target);
        fs::create_dir_all(&directory)?;
        for seed in seeds::seeds_for(target) {
            fs::write(directory.join(seed.name), &seed.bytes)?;
            total += 1;
        }
    }
    println!("wrote {total} seeds under {}", root.display());
    Ok(())
}
