# Phase 5: optimization

Research prototype only. Variable-time secret arithmetic, external generator-context authentication, and lack of expert cryptographic review remain.

## Implemented

- [x] Signer replay IDs have a hard process-local cap of 65,536. Constructor may set a lower cap for a deployment or test.
- [x] When full, signer rejects new session IDs. Existing IDs remain reserved through completion and abort; no eviction enables replay.
- [x] Test covers fail-closed behavior after a session completes at capacity.

## Remaining

- [ ] Fixed-base precomputation for `G`, `H0`, `G_i`, `H_i`, and roster-dependent `PK_pad`.
- [ ] Tune Pippenger window by MSM size `k` and benchmark.
- [ ] Durable replay storage if deployments must preserve replay protection across restart.
- [ ] Randomized batch verification with a spec-literal verifier retained for comparison.
- [ ] Cross-signature batch verification and differential KAT/negative tests.
- [ ] Add ablation switches and report reproducible speedups.

The current bounded replay set does not persist across process restarts. Services needing restart-safe replay protection still need durable state. A full capacity rejects all further new sessions until restart.

Phase 5 exit requires byte-identical KATs and documented speedups with caveats and ablation controls. No exit claim until those results exist.
