# Phase 2 implementation checklist

Phase 2 secp256k1 prototype coding is implemented on `main`. Independent evidence, platform review, and optional comparison work remain open. The audit v5 PDF and `suite-draft.md` define the scheme and research suite. Tests show behavior; they are not security proofs.

## Current evidence

- [x] RFC 9380 SHA-256 `expand_message_xmd`: published short- and long-DST vectors, multi-block output, and length boundaries. Pushed in `2e38ba4`.
- [x] Public secp256k1 hash-to-field: RFC 9380 J.8.1 intermediate field-element vectors for empty and `abc` messages, length boundaries, and domain separation. This is not full hash-to-curve.
- [x] Public secp256k1 hash-to-curve: RFC 9380 J.8.1 compressed-point vectors for empty, `abc`, and `abcdef0123456789`. Uses variable-time OpenSSL `BIGNUM` operations; tests are not an independent vector set or security proof.
- [x] E1 prototype: public secp256k1 generator/variable multiplication, MSM (1/8/32/128), hash-to-scalar, and hash-to-curve. Nine raw samples at 300 iterations per sample and host metadata saved in `docs/benchmarks/`; harness commit `f3e06fb`. BLS pairing, NTT, protocol-level operations, and publication-quality repetitions remain open.
- [x] Suite scalar-challenge hashing: implementation in `2da0ee2`; example plus forced out-of-range retry, zero rejection, and counter-exhaustion tests pass. Independent vectors remain open.
- [x] Protocol generator derivation: typed `GEN` transcript, pinned `HTA-v1-secp256k1-Hgen` DST, context/N/index binding, identity retry transcript, and parameter bounds are implemented. Forced identity retry and overflow tests pass; independent generator vectors remain open.
- [ ] Review and pin all cryptographic dependencies. The research mcl revision and source hash are pinned; OpenSSL is selected by version range, and backend platform and timing evidence remain incomplete.
- [x] Public-input secp256k1 adapter: mcl revision and source hash are pinned in CMake. Known G and 2G, identity, malformed inputs, scalar boundaries, and public MSM are tested. Cross-platform and independent backend checks remain; secret inputs and concurrent mixed mcl curves are unsupported.
- [x] Secret scalar sampling prototype: OpenSSL `RAND_priv_bytes`, unbiased rejection sampling with nonzero and full-field modes, move-only wrapper, and best-effort `OPENSSL_cleanse` on destruction and moves. Forced zero/range rejection, zero acceptance, RNG error, and rejection-limit tests pass. Deterministic CTR_DRBG KAT remains optional research evidence.
- [x] Secret secp256k1 arithmetic prototype: scalar add/multiply, generator/variable multiplication, and MSM cross-check against public mcl operations, including zero output and empty MSM. mcl secret paths are variable-time and must not face timing/cache observers; internal Fr temporaries lack verified wiping.
- [x] Optional high-level operation counters: count successful scalar add/multiply, point add/multiply, generator-multiply, and MSM calls/bases. Enabled and disabled tests check counts; they do not track internal field operations.

## Build in dependency order

- [x] **Scalar and point representations:** Canonical 32-byte big-endian scalars and SEC 1 compressed points, including the single-byte identity where allowed. Tests cover boundaries, malformed lengths, noncanonical scalars, invalid/off-curve points, identity policy, and canonical values.
- [x] **Group and field arithmetic prototype:** Public identity, inverse, invalid-input, and MSM behavior are tested. Secret scalar operations cross-check against the public adapter; mcl is variable-time, and independent backend and constant-time evidence remain open.
- [x] **Generator derivation implementation:** RFC 9380 suite, DST, context/N/index binding, and identity retries are implemented. Independent vectors remain open; caller authenticates and pins context externally.
- [x] **Randomness and secrets prototype:** OpenSSL rejection sampling supports nonzero keys/nonces and full-field proof blinders. The optional deterministic CTR_DRBG KAT is not implemented; runtime uses OpenSSL `RAND_priv_bytes`. Nonce state is process-local; crash-safe persistence remains open.
- [ ] **BLS12-381 and pairing comparison:** Not needed by the selected secp256k1 protocol implementation. Defer subgroup and multi-pairing work unless the comparison track is resumed.
- [x] **Operation counters:** Instrument selected secp256k1 adapter API calls; `opcounts` preset tests enabled counters; default preset confirms disabled counters report zero. Internal backend work is not counted.
- [x] **E1 secp256k1 prototype benchmarks:** Primitive raw data and metadata are in `docs/benchmarks/e1-prototype.jsonl` and `e1-prototype-metadata.txt`. Pairing and NTT measurements are deferred with the BLS comparison track; results remain prototype and variable-time.

## Exit check

- [x] Published RFC 9380 secp256k1 XMD/SWU_RO vectors pass for empty, `abc`, and `abcdef0123456789`; separate independent vectors remain open.
- [x] Primitive and protocol serialization round trips and malformed-input tests pass for the selected secp256k1 suite.
- [x] E1 secp256k1 results are saved with reproducibility metadata and caveats. Protocol-level prototype results are in `docs/benchmarks/phase-3-prototype.jsonl`.
- [ ] Review outstanding Phase 0 specification evidence, Phase 1 container reproducibility, and any unresolved backend or side-channel limitations. Do not mark external review or security proof complete without evidence.
- [x] Selected-suite Phase 2 coding and primitive benchmark commits are merged to `main`. External review, independent vectors, cross-platform evidence, and optional BLS comparison remain open; do not describe the whole research phase as externally validated.
