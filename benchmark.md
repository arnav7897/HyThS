# ASIACCS27 and FROST Benchmark Comparison

**Status:** research measurements only. This report compares the current isolated ASIACCS27 variant with an RFC 9591 FROST reference driver. It does not claim production readiness, NIST approval, or a completed security audit.

## Summary

Both schemes were measured over secp256k1 at matching `n` and `t=ceil(2n/3)`, with 100 measured samples per configuration. Runs used the same mcl arithmetic adapter, compiler, host, and pinned CPU. ASIACCS27 includes a roster-bound authorization certificate; FROST produces a conventional threshold Schnorr signature.

FROST signature size is 65 bytes at every tested size. ASIACCS27 full-folding signatures range from 1,186 bytes at n=64 to 1,642 bytes at n=4,096. ASIACCS27 public point storage grows with the roster and generator set; FROST public group information grows with the verification-share list. Peak RSS was not measured, so space comparison below gives complexity and serialized public-state size, not process memory.

Timings are not direct speed ratios. FROST's reported session total includes all share checks and final Schnorr verification. ASIACCS27 proof generation, signer certificate checks, and full signature-plus-certificate verification are reported as separate stages. These checks establish different statements.

## Time and space complexity at a glance

Here, `n` is the number of registered signers, `t` is the threshold and active signer count, `N` is the proof's power-of-two vector size, and `r` is the number of proof-folding rounds. **TC** means time complexity: how computation grows as these values grow. **SC** means space complexity: how stored keys and temporary session data grow. `O(n)` means roughly proportional to n; `O(1)` means the amount does not grow with n. Big O describes growth, not elapsed time or a memory measurement.

| Measure | ASIACCS27 | FROST | Plain meaning |
|---|---|---|---|
| TC: prove/sign | Authorization proof and verification require roster-sized work, O(N+n). Signer certificate verification is also O(N+n). | Each signer does O(1) nonce/response arithmetic; binding-factor work reads an O(t) commitment transcript. Coordinator aggregates O(t) shares. | ASIACCS27 does more work as the roster grows; FROST keeps final signing arithmetic small per signer. |
| TC: final verify | O(N+n), including the authorization certificate. | O(1) Schnorr equation once the group key is known. | FROST verifier work does not grow with the number of participants. |
| SC: signature | O(r + N/2^r) proof points/scalars; full folding gives a compact, slowly growing signature. | O(1): 65 bytes in this encoding. | FROST sends a fixed-size final signature; ASIACCS27 carries an authorization proof. |
| SC: public state | O(n+N): roster keys plus `2N+3` generators. | O(n): group public key plus participant verification shares. | Both keep public participant data; ASIACCS27 also keeps a roster-sized generator set. |
| SC: one live session | O(N+n) proof/verifier working state; O(1) signer secret/nonces. | O(t) coordinator commitment/share records; O(1) signer secret/nonces. | The coordinator holds one record per active signer in either protocol. |

The later tables give encoded byte counts and measured medians. Peak RSS was not measured, so SC values are analytic storage bounds, not observed process memory.

## Aggregation, setup, and verification only

Times are median milliseconds with p25–p75. `Aggregation` sums nonce/group commitment work and response aggregation; FROST also includes binding-factor calculation. `Verification` sums certificate verification, all share checks, and final verification. `Total` adds setup, aggregation, and verification per sample. It excludes proof generation and other stages, so it is not the whole-protocol runtime.

| n | Scheme | Aggregation | Setup | Verification | Total |
|---:|---|---:|---:|---:|---:|
| 64 | ASIACCS27 | 2.709 [2.674–2.766] | 0.122 per key | 31.363 [30.918–32.012] | 34.334 [33.775–34.926] |
| 64 | FROST | 7.389 [7.159–7.945] | 20.402 per group† | 12.545 [12.234–13.621] | 40.339 [39.825–42.002] |
| 256 | ASIACCS27 | 10.152 [10.058–10.440] | 0.122 per key | 101.319 [100.811–102.067] | 111.678 [111.243–112.440] |
| 256 | FROST | 28.445 [24.440–32.001] | 118.453 per group† | 49.342 [40.244–54.879] | 196.426 [183.632–205.379] |
| 1,024 | ASIACCS27 | 40.191 [39.801–40.553] | 0.122 per key | 382.669 [381.168–383.753] | 422.878 [421.548–424.031] |
| 1,024 | FROST | 115.727 [105.897–127.150] | 870.021 per group† | 194.325 [176.881–212.814] | 1,182.526 [1,153.006–1,206.308] |
| 2,048 | ASIACCS27 | 59.996 [58.244–62.075] | 0.122 per key | 559.578 [544.044–577.341] | 619.271 [602.704–640.506] |
| 2,048 | FROST | 204.510 [150.052–235.297] | 5,262.240 per group† | 333.195 [263.984–392.188] | 5,802.117 [5,691.959–5,889.830] |
| 4,096 | ASIACCS27 | 221.444 [182.644–261.038] | 0.122 per key | 2,019.641 [1,750.831–2,292.427] | 2,243.961 [1,962.630–2,536.181] |
| 4,096 | FROST | 454.406 [427.454–494.117] | 16,577.928 per group† | 768.885 [723.184–837.545] | 17,810.438 [17,745.524–17,910.163] |

**Setup scope:** ASIACCS27 setup is PoP creation plus verification for one key, measured over 100 keys. †FROST setup is one trusted-dealer Shamir setup for all n participants; the driver records one setup observation per n. The total column adds each setup figure as reported, so setup-inclusive totals do not compare equal scopes. ASIACCS27 full-roster setup was not measured. Compare aggregation and verification for per-session work. The [raw-derived stage summary](docs/benchmarks/asiaccs27-20261116/aggregation-setup-verification.csv) records these definitions and sample counts.

## Benchmark method

| Item | ASIACCS27 | FROST |
|---|---|---|
| Protocol | Submission variant `HTA-secp256k1-asiaccs27-v1`; both certificate-only and mask-disclosure signer modes | RFC 9591 FROST(secp256k1, SHA-256), implemented in the repository benchmark driver |
| Baseline validation | Every certificate and final signature verified | RFC 9591 Appendix E.5 vector self-test; every share and final signature verified |
| Backend | mcl secp256k1; OpenSSL 3 for hashing and randomness | Same mcl secp256k1 arithmetic adapter and OpenSSL hashing/randomness |
| Threshold | `t=ceil(2n/3)`; exactly t active signers | Same n and t, with trusted-dealer Shamir setup |
| Samples | 10 warmups, then 100 measured sessions per cell | 10 warmups, then 100 measured sessions per n |
| Host | Ubuntu 24.04, Intel Core i5-1240P, GCC 13.3.0, Release `-O3 -DNDEBUG`, one process/thread pinned to CPU 2 | Same host, build, and CPU affinity |
| Timed setup | Roster, PoP registration, and generator setup excluded; registration reported separately | Dealer setup and Lagrange coefficient preparation excluded |

FROST's central harness hashes the common commitment list once. Distributed signers would each process their commitment transcript. Thus these are controlled single-process measurements, not distributed latency. Raw data and environment details are linked below.

## Table A: full folding

Times are median milliseconds with p25–p75. Signature and request sizes are actual encoded bytes. `HTA signer verify` is the certificate check in certificate-only mode.

| n | t | r | HTA prove | HTA signer verify | HTA full verify | HTA signature | HTA Round-1 request | FROST sign, all share checks + final verify | FROST final verify | FROST signature |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 64 | 43 | 7 | 79.62 [79.22, 80.50] | 11.58 [11.33, 11.85] | 11.60 [11.39, 11.97] | 1,186 B | 1,863 B | 30.17 [29.39, 33.00] | 0.157 [0.152, 0.168] | 65 B |
| 256 | 171 | 9 | 291.06 [289.97, 292.45] | 34.74 [34.43, 35.09] | 34.86 [34.41, 35.18] | 1,338 B | 3,679 B | 116.59 [100.65, 131.30] | 0.154 [0.128, 0.171] | 65 B |
| 1,024 | 683 | 11 | 1,101.06 [1,099.03, 1,104.15] | 127.78 [127.32, 128.39] | 127.57 [127.06, 128.35] | 1,490 B | 10,487 B | 475.78 [441.58, 527.36] | 0.156 [0.145, 0.169] | 65 B |
| 2,048 | 1,366 | 12 | 1,615.33 [1,571.18, 1,656.55] | 184.52 [179.05, 189.61] | 184.13 [179.37, 189.49] | 1,566 B | 19,442 B | 833.14 [684.49, 928.18] | 0.130 [0.098, 0.156] | 65 B |
| 4,096 | 2,731 | 13 | 5,892.27 [5,222.22, 6,413.10] | 660.80 [579.58, 745.20] | 654.79 [553.22, 763.18] | 1,642 B | 37,263 B | 1,896.12 [1,793.67, 2,017.73] | 0.155 [0.135, 0.167] | 65 B |

FROST session totals are summed per sample before calculating quantiles. They include Round 1, binding-factor derivation, group commitment, Round 2, every share check, response aggregation, and final verification. The final-verification column is also shown separately.

### Total sequential protocol time

Each total is assembled per sample, then summarized with median and p25–p75. ASIACCS27 total is `serial_end_to_end_ns + full_verify_ns`: proof creation, one certificate check, simulated nonce/share work for t signers, response aggregation, and final signature-plus-certificate verification. FROST total includes Round 1, binding factors, group commitment, Round 2, all share checks, response aggregation, and final signature verification. Both exclude setup and network delay. They are whole-path measurements, not exact like-for-like latency: the protocols verify different statements and the harness runs all actors sequentially in one process.

| n | t | ASIACCS27 total | FROST total |
|---:|---:|---:|---:|
| 64 | 43 | 119.92 ms [119.28, 120.87] | 30.17 ms [29.39, 33.00] |
| 256 | 171 | 425.88 ms [424.56, 427.49] | 116.59 ms [100.65, 131.30] |
| 1,024 | 683 | 1,615.17 ms [1,611.95, 1,619.94] | 475.78 ms [441.58, 527.36] |
| 2,048 | 1,366 | 2,364.22 ms [2,312.17, 2,443.96] | 833.14 ms [684.49, 928.18] |
| 4,096 | 2,731 | 8,754.43 ms [7,752.51, 9,410.29] | 1,896.12 ms [1,793.67, 2,017.73] |

## Table B: folding sweep at n=2,048

All timings are median milliseconds with p25–p75. FROST uses the same n/t at every row; it has no folding parameter.

| Scheme | n | t | r | Prove | Certificate verify | Full verify | Certificate raw/encoded | Signature raw/encoded | Round-1 request |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ASIACCS27 | 2,048 | 1,366 | 0 | 770.94 [749.53, 825.35] | 165.75 [160.49, 177.46] | 164.92 [161.79, 172.53] | 262,437/303,516 B | 262,535/303,684 B | 321,560 B |
| ASIACCS27 | 2,048 | 1,366 | 9 | 1,601.10 [1,556.39, 1,645.26] | 175.89 [171.97, 182.80] | 175.04 [171.34, 180.80] | 1,399/1,688 B | 1,497/1,856 B | 19,732 B |
| ASIACCS27 | 2,048 | 1,366 | 12 | 1,615.33 [1,571.18, 1,656.55] | 184.52 [179.05, 189.61] | 184.13 [179.37, 189.49] | 1,149/1,398 B | 1,247/1,566 B | 19,442 B |
| FROST | 2,048 | 1,366 | N/A | Included in session total | N/A | 0.130 [0.098, 0.156] | N/A | 65 B | RFC commitment list |

At n=2,048, full folding reduces the encoded ASIACCS27 signature from 303,684 B at r=0 to 1,566 B at r=12. Median proving time increases from 770.94 ms to 1,615.33 ms. The implemented Round-1 request encodes each selected signer index as a framed integer. Therefore the original estimate of about 1.2 KB at n=2,048 does not describe this encoding.

## Signer stages

Median milliseconds with p25–p75. `Round 1` includes certificate verification and nonce generation. Mask-disclosure mode adds the mask-linkage check.

| n | r | Mode | Certificate verify | Mask linkage | Round 1 total | Round 2 | Request bytes |
|---:|---:|---|---:|---:|---:|---:|---:|
| 64 | 7 | Certificate-only | 11.58 [11.33, 11.85] | N/A | 12.45 [12.19, 12.76] | 0.13 [0.12, 0.13] | 1,863 |
| 64 | 7 | Mask-disclosure | 11.54 [11.33, 11.96] | 0.89 [0.88, 0.91] | 13.31 [13.10, 13.73] | 0.12 [0.12, 0.12] | 1,900 |
| 256 | 9 | Certificate-only | 34.74 [34.43, 35.09] | N/A | 37.45 [37.06, 37.82] | 0.13 [0.13, 0.14] | 3,679 |
| 256 | 9 | Mask-disclosure | 34.88 [34.45, 35.36] | 3.44 [3.41, 3.52] | 41.10 [40.56, 41.62] | 0.12 [0.12, 0.12] | 3,716 |
| 1,024 | 11 | Certificate-only | 127.78 [127.32, 128.39] | N/A | 137.63 [137.17, 138.23] | 0.15 [0.15, 0.16] | 10,487 |
| 1,024 | 11 | Mask-disclosure | 127.80 [127.32, 128.50] | 13.77 [13.63, 14.03] | 151.55 [151.04, 152.20] | 0.13 [0.13, 0.13] | 10,524 |
| 2,048 | 12 | Certificate-only | 184.52 [179.05, 189.61] | N/A | 199.09 [193.22, 204.64] | 0.13 [0.13, 0.14] | 19,442 |
| 2,048 | 12 | Mask-disclosure | 184.90 [179.37, 189.85] | 20.59 [20.11, 21.29] | 220.16 [213.42, 226.21] | 0.11 [0.11, 0.12] | 19,479 |
| 4,096 | 13 | Certificate-only | 660.80 [579.58, 745.20] | N/A | 710.99 [621.55, 806.54] | 0.25 [0.20, 0.32] | 37,263 |
| 4,096 | 13 | Mask-disclosure | 645.65 [562.19, 756.80] | 73.25 [62.01, 89.17] | 769.24 [674.90, 895.70] | 0.22 [0.18, 0.27] | 37,300 |

FROST per-session medians by stage (ms):

| n | Round 1 | Binding factors | Group commitment | Round 2 | All share checks | Response aggregation | Final verify |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 64 | 10.17 | 0.284 | 7.07 | 0.146 | 12.38 | 0.023 | 0.157 |
| 256 | 39.62 | 1.108 | 27.29 | 0.577 | 49.19 | 0.086 | 0.154 |
| 1,024 | 162.20 | 4.755 | 110.24 | 2.231 | 194.16 | 0.341 | 0.156 |
| 2,048 | 274.43 | 7.810 | 196.75 | 4.124 | 333.08 | 0.600 | 0.130 |
| 4,096 | 629.21 | 17.220 | 435.75 | 8.888 | 768.73 | 1.332 | 0.155 |

## Size and space complexity

Let `n` be roster size, `t` active signers, `N` the power-of-two folding dimension, and `r` the number of folding rounds. Point counts below use 33-byte compressed secp256k1 points. They exclude container overhead, identifiers, caches, secret shares, and runtime allocator costs.

| Property | ASIACCS27 | FROST |
|---|---|---|
| Signature size | O(r + N/2^r) points/scalars. With full folding, r=kappa and encoded size grows slowly with n; with r=0 it is O(N). | O(1): 33-byte R plus 32-byte response, 65 bytes total. |
| Public state | O(n+N): n roster keys and d=2N+3 derived generators. | O(n): n public verification shares plus one group public key. |
| Prover/coordinator state | O(n+N) for authorization vectors, proof, roster, and generator access. | O(t) commitments and shares for a signing session. |
| Per-signer secret state | O(1) key and live nonce state. | O(1) secret share and live nonce state. |
| Proof/signing work | Proving and full verification use roster-sized MSMs and O(N) field/group work; folding vectors shrink geometrically. Certificate verification is O(N+n). | O(1) nonce/response arithmetic per signer; coordinator processes O(t) commitments/responses. Each signer derives a binding factor from an O(t) commitment transcript. |
| Final verification | O(N+n) group/MSM and field work, plus O(r) folding challenges. | O(1) Schnorr verification given the group public key. |

Analytic public-point storage at full folding:

| n | ASIACCS27 roster + generators | FROST group key + verification shares |
|---:|---:|---:|
| 64 | 10,659 B | 2,145 B |
| 256 | 42,339 B | 8,481 B |
| 1,024 | 169,059 B | 33,825 B |
| 2,048 | 338,019 B | 67,617 B |
| 4,096 | 675,939 B | 135,201 B |

These sizes are analytic serialized point bytes, not measured peak memory. At n=2,048 the original approximate public-state estimate of 270 KB is low for the implemented N=4,096 dimension; the point encoding totals 338,019 B.

## Registration and remaining measurements

The ASIACCS27 registration driver measured 100 keys after 10 warmups. Median PoP creation is **65.29 μs/key** [64.89, 66.13]; median PoP verification is **56.22 μs/key** [55.89, 57.19]. Encoded registration size is **175 B**. FROST dealer setup and share conversion are excluded from signing timings and are not directly equivalent to independent-key PoP registration.

Not measured: peak RSS, constrained-device memory, simulated network delay, concurrent throughput, or distributed end-to-end latency. The session measurements are sequential one-process work. Security bounds are analytic and are not benchmark measurements. Variable-time secret operations remain a research-code limitation.

## Reproduction and raw data

The benchmark drivers and generated outputs are on branch `asiaccs27/bench`. The benchmark environment, source revision, PDF hash, and collection notes are in [`docs/benchmarks/asiaccs27-20261116/metadata.md`](docs/benchmarks/asiaccs27-20261116/metadata.md). Raw JSONL, CSV summaries, and generated detailed tables are in [`docs/benchmarks/asiaccs27-20261116/`](docs/benchmarks/asiaccs27-20261116/). The FROST summary includes per-stage medians and quantiles. The driver is a repository RFC 9591 implementation, not the Zcash Foundation measurements from the older report.

Example commands for a fresh run:

```sh
taskset -c 2 ./build-asiaccs-release/asiaccs27_bench 4096 13 100 > docs/benchmarks/asiaccs27-20261116/release-n4096-r13.jsonl
taskset -c 2 ./build-asiaccs-release/asiaccs27_frost_baseline 4096 100 > docs/benchmarks/asiaccs27-20261116/release-frost-n4096.jsonl
python3 tools/summarize_asiaccs27.py
```

The summarizer regenerates `summary.csv`, `tables.md`, `registration-summary.csv`, `baseline-summary.csv`, `frost-summary.csv`, and `aggregation-setup-verification.csv`. Complete collected matrix: Table A has n={64,256,1024,2048,4096} at r=kappa; Table B has n=2048 at r={0,9,12}. Matching FROST runs have 100 samples at each n.

## Appendix A: User-supplied benchmark specification

The original requested text is preserved below. Its estimates are planning inputs; actual measured encodings above take precedence.

```text
1. Sizes (analytic, so you can fill these in now)

Signature size: (7+2r) group elements + (5 + 2N/2^r) scalars.
Certificate size: the signature minus Q_e, R and s_e, i.e. 98 bytes less.
Round-1 request: what the coordinator sends to each signer: ctx, S, Q_e and π_Auth, about 1.2 KB at n = 2048.
Signer messages: two points in Round 1 (66 B) and one scalar in Round 2 (32 B).
Public parameters: the roster of n keys and d = 2N+3 generators (≈ 270 KB at n = 2048). These are one-time setup costs, not per-signature.

2. Coordinator (prover)

Time to produce π_Auth. This is the heaviest cost: about O(N) group operations per folding round.
Breakdown of that time: computing the commitments (A, S_com, Q_s, T₁, T₂) versus the folding rounds.
Time to aggregate: combining R₁, R₂ and the responses into s_e.
Peak memory.

3. Signer, per session. This is what matters for HSMs and phones.

Certificate verification time. This is the dominant signer cost: one multi-scalar multiplication of size about 2N + n.
Nonce generation (Round 1): two scalar multiplications.
Response time (Round 2): a hash plus field arithmetic.
Total signer CPU per session, plus memory if you test on constrained hardware.

4. Verifier

Full verification time, for (V1), (V2) and the Schnorr equation together.
Breakdown: the (V2) multi-scalar multiplication, computing the folding scalars, and the cheap (V1) check.
Optional: cached versus uncached roster precomputation (K_χ, the padded keys).

5. End-to-end

Latency: from the coordinator’s request to the final signature, with and without simulated network delay.
Throughput under concurrency: signatures per second with k parallel sessions (for example k = 1, 10, 100). This supports the paper’s central concurrency claim operationally.

6. Registration (one-time)

PoP generation and verification time, per key.

Parameter sweep

n ∈ {64, 256, 1024, 2048, 4096}, with t = ⌈2n/3⌉ or n/2 (pick one and state it).
r ∈ {0, κ−3, κ}, to show the size versus speed trade-off: smaller r means larger signatures but fewer rounds.
Report the median and the spread over at least 100 runs, plus the platform (CPU, single thread, library, curve).

Baselines

Same-library baselines: a plain Schnorr signature and MuSig2 or FROST signing, so readers can see the overhead.
Optional: BLS-based numbers from the hinTS paper, cited rather than re-run, for context only.

What not to bother measuring: security bounds. Those are analytic and already in Appendix E.

Suggested tables for the paper:

Table A: Prove, signer verify, full verify and signature size, by n (at r = κ).
Table B: the same columns for r = 0, κ−3 and κ at n = 2048.
Optional: one concurrency/latency figure.
```
