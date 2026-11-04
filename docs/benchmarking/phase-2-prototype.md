# Phase 2 primitive benchmark prototype

Run `bench/run_e1.sh [iterations]` on a Linux host. It builds the Release `bench` preset and saves nine raw timing samples per operation plus host metadata under `docs/benchmarks/`.

Current measurements cover public-input secp256k1 generator multiplication, variable-base multiplication, MSM at 1/8/32/128 bases, suite hash-to-scalar, and RFC 9380 hash-to-curve. They do not cover BLS pairings, NTT, full protocol signing, constant-time operations, or cross-backend comparison. The mcl and OpenSSL paths are research prototype code. Treat timings as machine-specific smoke evidence, not publication-ready results.

The benchmark uses steady-clock wall time, a short warmup, and nine samples. `median_ns_per_op` is the median sample duration divided by the per-sample operation count. Save a fresh raw file for each environment; do not compare results without matching hardware, compiler, dependency, and build metadata.
