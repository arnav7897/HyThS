# Phase 2 implementation checklist

Phase 2 is in progress through feature branches. The audit v5 PDF and `suite-draft.md` define the scheme and research suite. An unchecked item is not complete. Record the commit, commands, results, and any limitations alongside the item when it is finished. Tests are evidence of behavior, not a security proof.

## Current evidence

- [x] RFC 9380 SHA-256 `expand_message_xmd`: published short- and long-DST vectors, multi-block output, and length boundaries. Pushed in `2e38ba4`.
- [x] Public secp256k1 hash-to-field: RFC 9380 J.8.1 intermediate field-element vectors for empty and `abc` messages, length boundaries, and domain separation. This is not full hash-to-curve.
- [x] Public secp256k1 hash-to-curve: RFC 9380 J.8.1 compressed-point vectors for empty, `abc`, and `abcdef0123456789`. Uses variable-time OpenSSL `BIGNUM` operations; tests are not an independent vector set or security proof.
- [x] E1 prototype: public secp256k1 generator/variable multiplication, MSM (1/8/32/128), hash-to-scalar, and hash-to-curve. Nine raw samples at 300 iterations per sample and host metadata saved in `docs/benchmarks/`; harness commit `f3e06fb`. BLS pairing, NTT, protocol-level operations, and publication-quality repetitions remain open.
- [ ] Suite scalar-challenge hashing: implementation and one example are in `2da0ee2`; force and check rejection, nonzero, and counter-exhaustion paths before completion.
- [ ] Review and pin all cryptographic dependencies. The research mcl revision and source hash are pinned; OpenSSL is selected by version range, and backend platform and timing evidence remain incomplete.
- [ ] Research public-input secp256k1 adapter: mcl revision and source hash are pinned in CMake. Known G and 2G, identity, malformed inputs, scalar boundaries, and public MSM are tested. Cross-platform and broader independent checks remain; secret inputs and concurrent mixed mcl curves are unsupported.
- [x] Secret scalar sampling prototype: OpenSSL `RAND_priv_bytes`, rejection of zero/out-of-range candidates, move-only wrapper, and best-effort `OPENSSL_cleanse` on destruction and moves. NIST CTR_DRBG KAT, forced rejection/RNG failure tests, and secret arithmetic remain open.

## Build in dependency order

- [ ] **Scalar and point representations:** Implement canonical 32-byte big-endian scalars and SEC 1 compressed points, including the single-byte identity where allowed. Test boundaries, malformed lengths, noncanonical scalars, invalid or off-curve points, identity policy, and encode/decode round trips. Do not use mcl's native byte format as the suite format.
- [ ] **Group and field arithmetic:** Provide the planned backend interface, scalar and point arithmetic, fixed-base multiplication and MSM. Test identity, inverse, edge scalars, valid/invalid inputs and independent cross-checks. Label secret-dependent variable-time paths; do not claim constant-time behavior without evidence.
- [ ] **Generator derivation:** Implement typed, context-bound generator derivation and the protocol's identity retry. Add independently generated vectors for DST, generator context, and indices. Hash-to-curve alone does not finish generator derivation.
- [ ] **Randomness and secrets:** Finish RNG failure and forced rejection tests; add planned deterministic CTR_DRBG vectors. Current sampler uses rejection sampling over 32-byte RNG output. Nonce persistence and one-use session lifecycle belong to the later signer implementation.
- [ ] **BLS12-381 and pairing primitives:** Implement and test the planned backend support, subgroup validation, identity handling, and multi-pairing needed for comparison work. Do not imply the first secp256k1 suite needs pairings.
- [ ] **Operation counters:** Instrument the selected backend and test representative counts with instrumentation enabled and disabled.
- [ ] **E1 microbenchmarks:** Implement and save reproducible raw measurements for the roadmap's fixed/variable multiplication, MSM sizes, pairing, hash-to-curve, hash-to-scalar, and NTT. Record commit, dependencies, hardware, compiler, timing method, repetitions, and constant-time or variable-time caveats. Follow the roadmap's specification and correctness gates before publishing results.

## Exit check

- [ ] Published RFC 9380 vectors pass for every implemented curve suite. Current secp256k1 XMD/SWU_RO empty, `abc`, and `abcdef0123456789` vectors pass.
- [ ] Serialization round trips and malformed-input tests pass for all supported primitives.
- [ ] E1 results are saved with reproducibility metadata and caveats.
- [ ] Review outstanding Phase 0 specification evidence, Phase 1 container reproducibility, and any unresolved backend or side-channel limitations. Do not mark external review or security proof complete without evidence.
- [ ] Record the final Phase 2 commit and results; stop and report before starting Phase 3.
