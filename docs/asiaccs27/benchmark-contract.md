# Benchmark contract

## Matrix and reproducibility

Use secp256k1, the pinned mcl backend, and identical build flags for same-library comparisons. n={64,256,1024,2048,4096}, t=(2*n+2)//3, exactly t active signers; r={0,kappa-3,kappa}. Both signing modes get separate results; Table A/B use certificate-only mode and label it. Run 10 untimed warmups and 100 measured sessions per cell. Retain every failure and retry record; a failed cell is incomplete, not a smaller successful sample set.

Report median, p25, p75 and p95 using linear interpolation at (count-1)*p. Preserve per-sample nanoseconds and bytes. Record source commit and dirty status, PDF hashes, CPU model/core count, OS/kernel, compiler/version, flags, dependency commits, curve, worker count, affinity, cache policy, RNG mode, message size, and command. Use a fixed 32-byte message for the primary matrix, unique session IDs, and fresh production-random secrets/nonces. Seed only workload selection for reproducibility; deterministic crypto RNG belongs solely to tests.

Microbenchmarks use one pinned CPU and one worker, with counters disabled. Timed samples exclude setup and validation harness overhead; each result is verified outside its measured section. Explicitly include protocol-mandated validation in actor timings. Setup costs and cold/warm measurements are separate. Measure process peak RSS in isolated child runs, report baseline RSS and total peak; do not present process RSS as exact per-object memory. Memory runs are separate from timing runs.

## Stages

| Actor | Required stages |
| --- | --- |
| Coordinator | A/Scom/Qs/T1/T2 commitment phase; folding total and per-round times; other proof work; total proof; nonce aggregation; response aggregation; individual share checks separately; total coordinator CPU; peak RSS |
| Signer | V1/V2 certificate verification; optional mask-linkage check; nonce generation; Round-2 response including validation and nonce combination; total per-session CPU |
| Verifier | V1; folding scalar computation; V2 MSM; other preparation; Schnorr equation; total full verification |
| Registration | PoP generation and verification per key; roster validation/setup separately |
| Wire | Actual request, responses, certificate, signature, roster and generator bytes; raw cryptographic payload and framing separately |

Round 2 is not assumed to cost only hash/field arithmetic: the implementation also validates and combines aggregate nonce points. Report that work. Ensure total timers are measured directly, not synthesized from rounded substage medians. Folding vectors shrink each round; report measured operations without assuming N work at every depth. Cached roster mode reuses Kchi/padded keys; uncached mode includes their construction. Generator derivation remains setup, with its own cost.

## Baselines

Implement plain Schnorr and RFC 9591 FROST(secp256k1,SHA-256) over the same mcl/OpenSSL primitives. Keep each baseline's specified encodings, domains, binding factors, share identifiers and interpolation rules; do not substitute HTA transcripts. Inspect the pinned reference and official specification before implementing; validate deterministic cases against independent reference outputs and negative tests. Trusted-dealer Shamir setup is outside timed signing and reported explicitly; do not claim DKG measurements. Match active signer count, worker budget and network conditions. FROST's fixed configured threshold and shared group key differ from HTA's independent-key roster and authorization certificate.

Reuse existing Zcash FROST harness as a separately labeled cross-library reference, not the same-library result. No MuSig2 or BLS rerun is required. Do not reuse withdrawn FROST ratios. No overhead ratio is published until correctness and timing boundaries match. Missing analogous stages are N/A, not zero.

## End-to-end and concurrency

Measure (a) request dispatch through final signature assembly, with proof generation excluded because it precedes dispatch, and (b) proof start through final signature assembly. Also report final-verification time separately. All selected signers verify certificates independently. Setup is excluded.

Run k={1,10,100} concurrent sessions at every matrix cell, both modes, with 0/10/50 ms simulated one-way delay per transmitted protocol message. Use a deterministic event scheduler with bounded CPU workers; delays do not occupy CPU workers. Primary worker budget is one, exposing interleaving independently of multicore scaling. A secondary run uses min(physical_cores,8) workers, labeled separately. Do not create a worker per signer. Keep session state and nonces isolated. Shared immutable roster/generators may be cached. Document that fixed delay models propagation only, not bandwidth, congestion, loss or a real distributed deployment.

Collect at least 100 completed sessions per cell under the stated concurrency; report wall-time throughput and session-latency distribution, failure rate and peak RSS. Start measurement before dispatch and end after final completion; include drain time in throughput denominator. Record achieved concurrency and queue time. Operational concurrency results do not prove the paper's security claim.

## Outputs

Table A: n rows, full folding, prove/signer certificate verification/full verification/signature payload and wire bytes. Table B: r=0,kappa-3,kappa at n=2048, same columns. Generate separate mode tables, raw JSONL, environment manifest, size CSV and concurrency/latency figures from saved records. No manually copied timings. Show median and IQR in tables; p95 in supporting data. Do not measure security bounds.
