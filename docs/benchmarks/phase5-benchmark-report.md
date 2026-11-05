# Phase 5 benchmark report

Research prototype measurements only. They establish neither security nor general performance.

## Environment and commands

- Captured: 2026-11-05 UTC.
- Host: Ubuntu 24.04 x86_64, Intel Core i5-1240P.
- Compiler: GCC 13.3.0; CMake 3.28.3; OpenSSL 3.0.13; mcl revision pinned in `CMakeLists.txt`.
- Protocol runs: `protocol_bench 30 8 5 5`; 30 sessions per sample, five samples; `n=8`, `t=5`, five signers.
- MSM sweep: `primitive_bench 300`; nine samples per operation, 300 operations per sample, forced buckets 2–12. Bases were distinct multiples of secp256k1 G.
- Optimized build enables `HTA_GENERATOR_CACHE` and `HTA_BATCH_VERIFY`; reference build disables both. Both use mcl's default bucket heuristic in protocol runs.
- Raw outputs: `phase5-optimized-n8.jsonl`, `phase5-reference-n8.jsonl`, `phase5-msm-buckets.jsonl`, `phase5-msm-buckets-reference.jsonl`.

## Observed results

| Operation | Optimized median | Reference median | Change |
|---|---:|---:|---:|
| Authorization prove | 2.322 ms | 8.971 ms | 74.1% lower |
| Full verify | 1.503 ms | 8.111 ms | 81.5% lower |
| Four-signature batch, per signature | 1.218 ms | 8.115 ms | 85.0% lower |
| Batch vs four cached individual verifies, per signature | 1.218 ms | 1.475 ms | 17.4% lower |

The reference preset disables generator caching and randomized batching. Each value is a median from five samples in one process and one `(n,t)` setting. Treat these as smoke measurements, not a broad performance claim.

The bucket sweep did not produce stable winners. Across optimized/reference builds, the fastest bucket at 32 terms varied from 4 to 8; at 128 terms, it varied from 3 to 10. CPU frequency and run order moved medians enough that no non-default profile is justified. Protocol calls keep mcl's size-based default. The raw sweep files are diagnostic evidence, not a tuning claim.

Optimized and reference `phase3_kat_generator` outputs compared byte-for-byte with `cmp`. Both presets passed focused KAT, signer, and secp256k1 tests. Debug passed all 18 C++ tests and all six Python tests.

## Limits and reproduction

Run `cmake --preset bench && cmake --build --preset bench --target protocol_bench primitive_bench -j2`, then run the commands above. Use `bench-reference` for ablation comparison.

The protocol benchmark uses a small roster, one host, and no external baseline library. Fixed-base precomputation and a libsecp256k1 comparison remain open. Results do not establish constant-time behavior or protocol security.
