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
- [x] Correct full-width surplus weights for audit v5 equations (12) and (14); regression exercises `n=257`, surplus 256.
- [x] Explicit signer cancellation and dropout/restart regression for 4-of-8, including replay and cancellation race.
- [x] Apply the same 32,768-term batch limit in both verifier configurations.
- [x] Optional signer timeout automatically erases expired live nonce state and retains spent IDs; caller configures the timeout. Automatic dropout detection and restart need a transport/orchestration layer.
- [x] Bound aggregate active signer-session memory to 64 MiB, accounting for stored message/context copies and per-session overhead; cancellation, Round 2, and timeout expiry release the budget. Regression confirms capacity is recovered after cancellation.
- [x] Switchable public-generator fixed-base table; secret-scalar operations remain on the existing variable-time path.
- [x] Compare mcl and libsecp256k1 public generator and variable-point multiplication; see `docs/benchmarks/phase5-backend-public.md`. Full backend/MSM comparison remains open.
- [x] Debug CTest 19/19 and Python tests 6/6 pass; the phase 5 regression and KAT also pass in the `bench-reference` build. Batch regression tests 40 valid, 40 with one invalid, and 41 signatures at `n=257`.
- [x] Focused ASan/UBSan signer, phase 5 regression, and phase 3 KAT checks pass (3/3).
- [x] Current debug and ASan/UBSan CTest suites pass 20/20 each, and Python tests pass 6/6. Differential tests cover eight parameter sets and modified signature/proof fields.
- [ ] ThreadSanitizer for the timeout worker: the target builds, but execution fails on this host with `ThreadSanitizer: unexpected memory mapping`; rerun on a compatible machine.
- [x] Preliminary protocol matrices through `n=512` use five process launches and 150 sessions per configuration, except `n=512,t=256,k=256` with 25; see `benchmark.md` for means, raw data and limits.

## Remaining

- [ ] Evaluate fixed-base precomputation for `H0`, `G_i`, `H_i`, and roster-dependent `PK_pad`; public `G` is implemented. Do not apply variable-time public tables to secrets.
- [ ] Full differential protocol/backend comparison with libsecp256k1 remains open; the existing public-operation comparison covers only two primitives. `blst` belongs with the Phase 6 BLS baseline.
- [ ] Repeat bucket and protocol benchmarks across more `n,t` settings and independent process runs before selecting any non-default profile.
- [ ] Extend reference/optimized differential testing beyond the exercised batch and surplus-weight cases.
- [ ] Durable replay storage only if restart-safe replay protection becomes a requirement; current bounded design fails closed at capacity.

The bounded replay set does not persist across restarts. A full set rejects new sessions until restart. Batched verification has probabilistic soundness and remains research code, not a security proof.

Core exit evidence exists: KAT bytes match; local measurements have raw samples and caveats; implemented optimizations have ablation switches. Phase 5 remains open because proof-generator tables, full backend comparison, and broader benchmark evidence remain incomplete.
