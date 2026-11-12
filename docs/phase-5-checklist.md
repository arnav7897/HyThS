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
- [x] Compare mcl and libsecp256k1 public generator, variable-point multiplication, and component MSM at 1/4/16/64 terms; see `docs/benchmarks/phase5-backend-public.md`. Full protocol backend remains open.
- [x] Debug CTest 19/19 and Python tests 6/6 pass; the phase 5 regression and KAT also pass in the `bench-reference` build. Batch regression tests 40 valid, 40 with one invalid, and 41 signatures at `n=257`.
- [x] Focused ASan/UBSan signer, phase 5 regression, and phase 3 KAT checks pass (3/3).
- [x] Current debug and ASan/UBSan CTest suites pass 20/20 each, and Python tests pass 6/6. Differential tests cover eight parameter sets and modified signature/proof fields.
- [x] ThreadSanitizer timeout-worker coverage passed locally with ASLR disabled (`setarch ... -R`): signer and phase5_regression 2/2. Standard TSan startup still fails on this host without that workaround.
- [x] Preliminary protocol matrices through `n=512` use five process launches and 150 sessions per configuration, except `n=512,t=256,k=256` with 25; see `benchmark.md` for means, raw data and limits.

## Remaining

- [x] Evaluate 4-bit public tables for `H0`, `G_i`, `H_i`, and roster keys at n=8/64/256; setup is 98 ms/580 ms/2.12 s and memory 4.9/29.4/110.9 MiB. Keep disabled pending integrated amortization/cache measurements. Never apply these variable-time tables to secrets.
- [ ] Full protocol/backend comparison with libsecp256k1 remains open. The public component MSM comparison is recorded; `blst` belongs with the Phase 6 BLS baseline.
- [ ] Repeat bucket and protocol benchmarks across more `n,t` settings and independent process runs before selecting any non-default profile.
- [x] Broaden reference/optimized differential tests across malformed encodings and batch sizes/positions; see `benchmark.md` §8. Continue fuzzing and boundary expansion as separate robustness work.
- [ ] Durable replay storage only if restart-safe replay protection becomes a requirement; current bounded design fails closed at capacity.

The bounded replay set does not persist across restarts. A full set rejects new sessions until restart. Batched verification has probabilistic soundness and remains research code, not a security proof.

Core exit evidence exists: KAT bytes match; local measurements have raw samples and caveats; implemented optimizations have ablation switches. Phase 5 remains open because full protocol/backend comparison, broader controlled benchmark evidence, held fuzz soak, and expert review remain incomplete. Proof-generator tables were evaluated and deliberately left disabled pending integrated amortization evidence.
