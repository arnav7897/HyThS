# Phase 5: optimization

Research prototype only. Variable-time secret arithmetic, external generator-context authentication, and lack of expert cryptographic review remain.

## Implemented

- [x] Signer replay IDs have a hard process-local cap of 65,536. Constructor may set a lower cap for a deployment or test.
- [x] When full, signer rejects new session IDs. Existing IDs remain reserved through completion and abort; no eviction enables replay.
- [x] Test covers fail-closed behavior after a session completes at capacity.
- [x] One-entry, exact-key generator cache for repeated context and dimension.
- [x] Randomized cross-signature verifier combines C1, C2, C4, and Schnorr equations in one MSM; checks C3 exactly; and rejects malformed or oversized batches (64 signatures / 32,768 MSM terms maximum).
- [x] Spec-literal verifier remains available and is the fallback when batching is disabled.
- [x] Public MSM exposes a diagnostic bucket sweep; protocol calls retain mcl's default because measured winners varied between runs.
- [x] Ablation switches: `HTA_GENERATOR_CACHE` and `HTA_BATCH_VERIFY`. `bench-reference` disables both.
- [x] Optimized and reference builds produce byte-identical Phase 3 KAT responses.
- [x] Raw benchmark samples and metadata recorded in `docs/benchmarks/phase5-*.jsonl` and `docs/benchmarks/phase5-benchmark-report.md`.

## Remaining

- [ ] Fixed-base precomputation tables for `G`, `H0`, `G_i`, `H_i`, and roster-dependent `PK_pad`.
- [ ] Differential backend comparison with libsecp256k1. `blst` belongs with the Phase 6 BLS baseline, not this secp256k1 implementation.
- [ ] Repeat bucket and protocol benchmarks across more `n,t` settings and independent process runs before selecting any non-default profile.
- [ ] Durable replay storage only if restart-safe replay protection becomes a requirement; current bounded design fails closed at capacity.

The bounded replay set does not persist across restarts. A full set rejects new sessions until restart. Batched verification has probabilistic soundness and remains research code, not a security proof.

Core exit evidence exists: KAT bytes match; local speedups have raw samples and caveats; implemented optimizations have ablation switches. Phase 5 remains open because fixed-base tables, backend comparison, and broader benchmark evidence remain incomplete.
