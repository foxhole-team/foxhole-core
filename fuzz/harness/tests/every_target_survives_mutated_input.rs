//! What stands in for a fuzz run on a stable toolchain.
//!
//! `cargo fuzz` needs nightly and a linked libFuzzer, and this repository is
//! pinned to 1.97.1. Without this file the target bodies would be code nobody
//! ever compiles, let alone runs, until someone installs a second toolchain —
//! which is exactly how fuzz harnesses rot. Here every body is fed its own
//! seeds plus a deterministic set of mutations of them, so the harness code and
//! its invariant assertions are exercised by the ordinary gate.
//!
//! This is not a substitute for fuzzing. It runs a few thousand inputs, not a
//! few hundred million, and it mutates rather than explores. It catches a
//! harness that stopped compiling or an assertion that was always wrong.

use foxcore_fuzz_harness::seeds;

/// Dispatch by name so the test and the corpus cannot disagree about which
/// targets exist.
fn run(target: &str, input: &[u8]) {
    match target {
        "flow_key_from_packet" => foxcore_fuzz_harness::flow_key_from_packet(input),
        "dns_message" => foxcore_fuzz_harness::dns_message(input),
        "wireguard_message" => foxcore_fuzz_harness::wireguard_message(input),
        "socks_codec" => foxcore_fuzz_harness::socks_codec(input),
        "http_codec" => foxcore_fuzz_harness::http_codec(input),
        "reality_records" => foxcore_fuzz_harness::reality_records(input),
        "share_link" => foxcore_fuzz_harness::share_link(input),
        "shadowtls_server_stream" => foxcore_fuzz_harness::shadowtls_server_stream(input),
        other => panic!("no body wired up for target {other}"),
    }
}

/// A tiny xorshift, so a failure is reproducible from the seed name alone. A
/// real RNG dependency would make the same input unreachable on a rerun.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            usize::try_from(self.next() % bound as u64).expect("bounded by `bound`")
        }
    }
}

/// The four mutations libFuzzer spends most of its time on.
fn mutate(input: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut output = input.to_vec();
    match rng.next() % 4 {
        0 if !output.is_empty() => {
            let index = rng.below(output.len());
            output[index] ^= 1 << (rng.next() % 8);
        }
        1 if !output.is_empty() => {
            let index = rng.below(output.len());
            output[index] = u8::try_from(rng.next() % 256).expect("modulo 256 fits a byte");
        }
        2 if !output.is_empty() => {
            output.truncate(rng.below(output.len()));
        }
        _ => {
            output.push(u8::try_from(rng.next() % 256).expect("modulo 256 fits a byte"));
        }
    }
    output
}

#[test]
fn every_target_accepts_its_own_seed_corpus_without_panicking() {
    for target in seeds::TARGETS {
        let seeds = seeds::seeds_for(target);
        assert!(
            !seeds.is_empty(),
            "target {target} has no seeds, so it would start from noise"
        );
        for seed in seeds {
            run(target, &seed.bytes);
        }
    }
}

#[test]
fn every_target_survives_mutations_of_its_seeds() {
    // Enough that the gate stays quick, not enough to be called fuzzing. The
    // point is that the harness code runs, not that the space is covered.
    const ROUNDS: usize = 2_048;

    for target in seeds::TARGETS {
        for seed in seeds::seeds_for(target) {
            let mut rng = Rng(0x243F_6A88_85A3_08D3);
            let mut input = seed.bytes.clone();
            for _ in 0..ROUNDS {
                input = mutate(&input, &mut rng);
                run(target, &input);
                // Restart from the seed regularly, or the input degenerates to
                // empty and the rest of the rounds test nothing.
                if input.len() < seed.bytes.len() / 2 {
                    input = seed.bytes.clone();
                }
            }
        }
    }
}

#[test]
fn every_target_survives_degenerate_input() {
    let degenerate: [Vec<u8>; 8] = [
        Vec::new(),
        vec![0],
        vec![0xff],
        vec![0; 4],
        vec![0xff; 4],
        vec![0; 64],
        vec![0xff; 64],
        (0..=255_u8).collect(),
    ];

    for target in seeds::TARGETS {
        for input in &degenerate {
            run(target, input);
        }
    }
}

#[test]
fn a_diagnostic_phrase_elsewhere_in_a_subscription_is_not_a_leak() {
    // Regression for a real campaign finding. The old harness compared each
    // generic rejection reason with the entire subscription body. LibFuzzer
    // could therefore put the same harmless words in another line and make
    // the harness report a credential leak that never happened.
    let body = b"unsupported share-link scheme notice\n\
vless://d0cf0001-0000-4000-8000-000000000000@example.com:443?security=tls&type=tcp\n\
notice://example\n";
    foxcore_fuzz_harness::share_link(body);
}

#[test]
fn the_seed_names_are_unique_within_a_target_so_none_overwrites_another() {
    for target in seeds::TARGETS {
        let seeds = seeds::seeds_for(target);
        let mut names: Vec<&str> = seeds.iter().map(|seed| seed.name).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "duplicate seed name in target {target}");
    }
}
