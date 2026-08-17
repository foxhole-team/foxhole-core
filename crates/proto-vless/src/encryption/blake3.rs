//! BLAKE3 in `derive_key` mode, with a **byte-string** context.
//!
//! VLESS Encryption derives every symmetric key with BLAKE3's `derive_key`
//! mode, and it passes raw binary as the context: a 16-byte IV, a 1216-byte
//! ML-KEM encapsulation key, a whole TLS-shaped record. Upstream writes
//! `blake3.DeriveKey(k, string(ctx), key)`, and Go's `string(bytes)` is a
//! reinterpretation, not a validation.
//!
//! The `blake3` crate cannot express that. Both of its derive-key entry points
//! (`derive_key` and `Hasher::new_derive_key`) take `&str`, and the only way to
//! hand them non-UTF-8 bytes is `str::from_utf8_unchecked` — `unsafe`, which
//! this crate forbids. `hazmat::Mode` has no `DeriveKeyContext` variant either,
//! so the context hash cannot be assembled from the exposed tree primitives.
//!
//! So the compression function and tree hashing live here, transcribed from the
//! BLAKE3 reference implementation (§2 of the specification). It is
//! flag-parameterised rather than derive-key-only on purpose: that makes the
//! *plain* and *keyed* modes reachable from tests, and those are exactly the two
//! the `blake3` crate can be asked for. `tests/blake3_vector.rs` runs all three
//! modes against that crate across every input length where the tree shape
//! changes, so this file is pinned to the reference implementation rather than
//! to its own output.

const OUT_LEN: usize = 32;
const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
#[cfg(test)]
const KEYED_HASH: u32 = 1 << 4;
const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// A chunk stack never needs more than one entry per bit of the chunk counter.
const MAX_DEPTH: usize = 54;

#[allow(clippy::too_many_arguments)]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    // Columns.
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    // Diagonals.
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

fn permute(m: &mut [u32; 16]) {
    let original = *m;
    for i in 0..16 {
        m[i] = original[MSG_PERMUTATION[i]];
    }
}

fn compress(
    chaining_value: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut state: [u32; 16] = [
        chaining_value[0],
        chaining_value[1],
        chaining_value[2],
        chaining_value[3],
        chaining_value[4],
        chaining_value[5],
        chaining_value[6],
        chaining_value[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    let mut block = *block_words;
    for r in 0..7 {
        round(&mut state, &block);
        if r < 6 {
            permute(&mut block);
        }
    }
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= chaining_value[i];
    }
    state
}

fn first_8_words(compression_output: [u32; 16]) -> [u32; 8] {
    let mut out = [0_u32; 8];
    out.copy_from_slice(&compression_output[..8]);
    out
}

fn words_from_le_bytes(bytes: &[u8; BLOCK_LEN]) -> [u32; 16] {
    let mut words = [0_u32; 16];
    for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(4)) {
        *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    words
}

fn key_words_from_le_bytes(key: &[u8; OUT_LEN]) -> [u32; 8] {
    let mut words = [0_u32; 8];
    for (word, chunk) in words.iter_mut().zip(key.chunks_exact(4)) {
        *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    words
}

fn root_output_bytes(
    input_chaining_value: &[u32; 8],
    block_words: &[u32; 16],
    block_len: u32,
    flags: u32,
) -> [u8; OUT_LEN] {
    // Only the first 32 output bytes are ever needed here, so this is the
    // `counter = 0` block of the root XOF and nothing more.
    let words = compress(
        input_chaining_value,
        block_words,
        0,
        block_len,
        flags | ROOT,
    );
    let mut out = [0_u8; OUT_LEN];
    for (chunk, word) in out.chunks_exact_mut(4).zip(words.iter().take(8)) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    out
}

struct ChunkState {
    chaining_value: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: u8,
    blocks_compressed: u8,
    flags: u32,
}

impl ChunkState {
    fn new(key_words: [u32; 8], chunk_counter: u64, flags: u32) -> Self {
        Self {
            chaining_value: key_words,
            chunk_counter,
            block: [0; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * self.blocks_compressed as usize + self.block_len as usize
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.block_len as usize == BLOCK_LEN {
                let block_words = words_from_le_bytes(&self.block);
                self.chaining_value = first_8_words(compress(
                    &self.chaining_value,
                    &block_words,
                    self.chunk_counter,
                    BLOCK_LEN as u32,
                    self.flags | self.start_flag(),
                ));
                self.blocks_compressed += 1;
                self.block = [0; BLOCK_LEN];
                self.block_len = 0;
            }
            let want = BLOCK_LEN - self.block_len as usize;
            let take = want.min(input.len());
            self.block[self.block_len as usize..self.block_len as usize + take]
                .copy_from_slice(&input[..take]);
            self.block_len += take as u8;
            input = &input[take..];
        }
    }

    /// The chunk's output, as the pieces a root finalisation would need.
    fn output(&self) -> Output {
        Output {
            input_chaining_value: self.chaining_value,
            block_words: words_from_le_bytes(&self.block),
            counter: self.chunk_counter,
            block_len: self.block_len as u32,
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
}

struct Output {
    input_chaining_value: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        first_8_words(compress(
            &self.input_chaining_value,
            &self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        ))
    }

    fn root_output_bytes(&self) -> [u8; OUT_LEN] {
        root_output_bytes(
            &self.input_chaining_value,
            &self.block_words,
            self.block_len,
            self.flags,
        )
    }
}

fn parent_output(
    left_child_cv: [u32; 8],
    right_child_cv: [u32; 8],
    key_words: [u32; 8],
    flags: u32,
) -> Output {
    let mut block_words = [0_u32; 16];
    block_words[..8].copy_from_slice(&left_child_cv);
    block_words[8..].copy_from_slice(&right_child_cv);
    Output {
        input_chaining_value: key_words,
        block_words,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: PARENT | flags,
    }
}

/// One pass of BLAKE3 over `input`, keyed by `key_words` and tagged with
/// `flags`, producing the 32-byte root hash.
fn hash_all(key_words: [u32; 8], flags: u32, input: &[u8]) -> [u8; OUT_LEN] {
    let mut chunk_state = ChunkState::new(key_words, 0, flags);
    let mut cv_stack = [[0_u32; 8]; MAX_DEPTH];
    let mut cv_stack_len: usize = 0;

    let mut input = input;
    while !input.is_empty() {
        if chunk_state.len() == CHUNK_LEN {
            // The finished chunk's CV is merged into the stack. The number of
            // trailing 1-bits of the *new* chunk count says how many parent
            // nodes are complete, which is what keeps the tree left-balanced.
            let chunk_cv = chunk_state.output().chaining_value();
            let total_chunks = chunk_state.chunk_counter + 1;
            let mut new_cv = chunk_cv;
            let mut remaining = total_chunks;
            while remaining & 1 == 0 {
                cv_stack_len -= 1;
                new_cv = parent_output(cv_stack[cv_stack_len], new_cv, key_words, flags)
                    .chaining_value();
                remaining >>= 1;
            }
            cv_stack[cv_stack_len] = new_cv;
            cv_stack_len += 1;
            chunk_state = ChunkState::new(key_words, total_chunks, flags);
        }
        let want = CHUNK_LEN - chunk_state.len();
        let take = want.min(input.len());
        chunk_state.update(&input[..take]);
        input = &input[take..];
    }

    // Finalise: the current chunk is the rightmost subtree, folded into
    // everything on the stack from the right.
    let mut output = chunk_state.output();
    let mut parent_nodes_remaining = cv_stack_len;
    while parent_nodes_remaining > 0 {
        parent_nodes_remaining -= 1;
        output = parent_output(
            cv_stack[parent_nodes_remaining],
            output.chaining_value(),
            key_words,
            flags,
        );
    }
    output.root_output_bytes()
}

/// BLAKE3, plain hash mode. Used to bind each relay hop to the next, and the
/// shape the differential test can compare against the reference crate.
pub(crate) fn hash(input: &[u8]) -> [u8; OUT_LEN] {
    hash_all(IV, 0, input)
}

/// BLAKE3, keyed hash mode. Test-only for the same reason as [`hash`].
#[cfg(test)]
pub(crate) fn keyed_hash(key: &[u8; OUT_LEN], input: &[u8]) -> [u8; OUT_LEN] {
    hash_all(key_words_from_le_bytes(key), KEYED_HASH, input)
}

/// BLAKE3 `derive_key` mode with an arbitrary byte-string context.
///
/// Equivalent to `blake3::derive_key(context, key_material)` whenever `context`
/// happens to be valid UTF-8, and defined for every other byte string as well —
/// which is what this protocol needs.
pub(crate) fn derive_key(context: &[u8], key_material: &[u8]) -> [u8; OUT_LEN] {
    let context_key = hash_all(IV, DERIVE_KEY_CONTEXT, context);
    hash_all(
        key_words_from_le_bytes(&context_key),
        DERIVE_KEY_MATERIAL,
        key_material,
    )
}

#[cfg(test)]
mod tests {
    //! Holds this implementation to the reference `blake3` crate.
    //!
    //! It exists only because that crate cannot hash a non-UTF-8 `derive_key`
    //! context. Everything else about it — the compression function, the chunk
    //! chaining, the tree merge — is meant to be the reference algorithm
    //! exactly, so the reference crate is the oracle.
    //!
    //! The lengths sweep the points where the tree shape changes: block
    //! boundaries, chunk boundaries, and the powers of two where a new parent
    //! node is merged. A bug in the stack-merge logic hides at exactly those
    //! sizes and nowhere else.
    fn interesting_lengths() -> Vec<usize> {
        let mut lengths = vec![0, 1, 2, 31, 32, 33, 63, 64, 65, 127, 128, 129];
        for chunks in 1..=9 {
            let base = chunks * 1024;
            lengths.extend([base - 1, base, base + 1]);
        }
        lengths.extend([2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192, 8193, 16385]);
        lengths.sort_unstable();
        lengths.dedup();
        lengths
    }

    fn pattern(len: usize) -> Vec<u8> {
        // Not all-zero and not repeating with any power-of-two period, so a chunk
        // that is fed into the tree at the wrong offset cannot coincidentally agree.
        (0..len)
            .map(|i| (i as u32).wrapping_mul(2654435761) as u8)
            .collect()
    }

    #[test]
    fn hash_matches_reference() {
        for len in interesting_lengths() {
            let input = pattern(len);
            assert_eq!(
                super::hash(&input),
                *blake3::hash(&input).as_bytes(),
                "plain hash disagrees at {len} bytes"
            );
        }
    }

    #[test]
    fn keyed_hash_matches_reference() {
        let key = pattern(32);
        let key: [u8; 32] = key.try_into().unwrap();
        for len in interesting_lengths() {
            let input = pattern(len);
            assert_eq!(
                super::keyed_hash(&key, &input),
                *blake3::keyed_hash(&key, &input).as_bytes(),
                "keyed hash disagrees at {len} bytes"
            );
        }
    }

    /// The mode the protocol actually uses. The reference crate can only be asked
    /// for UTF-8 contexts, so this sweeps context *and* material lengths over
    /// contexts that happen to be representable, which exercises the same code path
    /// the binary contexts take.
    #[test]
    fn derive_key_matches_reference() {
        for context_len in [0, 1, 5, 63, 64, 65, 1023, 1024, 1025, 1216, 4096] {
            let context: String = std::iter::repeat_n('a', context_len).collect();
            for material_len in [0, 1, 32, 64, 1024, 1025, 8213] {
                let material = pattern(material_len);
                assert_eq!(
                    super::derive_key(context.as_bytes(), &material),
                    blake3::derive_key(&context, &material),
                    "derive_key disagrees at context {context_len} / material {material_len}"
                );
            }
        }
    }

    /// Multi-byte UTF-8 keeps the context bytes non-ASCII while still being
    /// expressible to the reference crate.
    #[test]
    fn derive_key_matches_reference_for_non_ascii_context() {
        for repeats in [1, 100, 500, 1000] {
            let context: String = std::iter::repeat_n('\u{10348}', repeats).collect();
            let material = pattern(777);
            assert_eq!(
                super::derive_key(context.as_bytes(), &material),
                blake3::derive_key(&context, &material),
                "derive_key disagrees for a {repeats}-codepoint non-ASCII context"
            );
        }
    }

    /// Negative control for the three tests above.
    ///
    /// Each assertion is that two independent implementations agree. If the subject
    /// silently ignored its input — or ignored the context, or the mode flags —
    /// those assertions would still have to fail, and this test is what proves the
    /// comparisons are load-bearing rather than vacuous.
    #[test]
    fn reference_disagrees_when_the_input_is_wrong() {
        let material = pattern(2000);

        // A context that differs by one byte must produce a different key. If the
        // context were being dropped, `derive_key` would be a plain keyed hash and
        // this would pass trivially.
        let a = super::derive_key(b"context-a", &material);
        let b = super::derive_key(b"context-b", &material);
        assert_ne!(a, b, "derive_key ignores its context");

        // The three modes must be distinct on identical input: the flag bytes are
        // what separates them, and dropping them is a real and silent failure.
        let key = [0_u8; 32];
        assert_ne!(
            super::hash(&material),
            super::keyed_hash(&key, &material),
            "plain and keyed hash are not separated"
        );
        assert_ne!(
            super::keyed_hash(&key, &material),
            super::derive_key(&[], &material),
            "keyed hash and derive_key are not separated"
        );

        // And a truncated input must not agree, which is what catches a tree that
        // stops merging early.
        assert_ne!(
            super::hash(&material),
            super::hash(&material[..material.len() - 1]),
            "hash ignores its last byte"
        );
    }

    /// The one derivation this whole layer is pinned to, taken from the reference
    /// Go implementation rather than from either Rust crate:
    /// `blake3.DeriveKey(k, "VLESS", []byte("material"))`.
    #[test]
    fn matches_recorded_go_output() {
        let expected =
            hex_literal("2bf7b4c8872dbfd2fedfb970ab8e0e4a1c00a187328b31174d0bba412131a74a");
        assert_eq!(super::derive_key(b"VLESS", b"material"), expected[..]);

        // A binary context, which is the case neither Rust crate can express and
        // the one the protocol actually relies on.
        let expected =
            hex_literal("2ba3b56c7d1770b4e0d60ecdb42fd8652fd5f69ef4e4a81b7c8c554484bfe542");
        assert_eq!(
            super::derive_key(&[0x00, 0xff, 0x80], &[1, 2, 3]),
            expected[..]
        );
    }

    fn hex_literal(text: &str) -> Vec<u8> {
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }
}
