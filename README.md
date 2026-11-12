# HTA Schnorr research prototype

Prototype implementation of the two-nonce, roster-based Schnorr protocol with hidden threshold authorization described in `Threshold_Schnorr_Integrated_Proof_Audit_v5.pdf`. It covers registration and roster checks, two-round signing, proof generation, verification, and typed message encoding. There is no interactive CLI or app.

This is research code. It is not production-ready, independently audited, or constant-time. Passing tests do not prove security. Phase 5 remains open; see the [phase checklist](docs/phase-5-checklist.md). Expert cryptographic review remains a separate gate.

## HTA vs. FROST

HTA uses independent signer keys and adds a roster-based proof of threshold authorization. FROST uses shares of a group signing key and produces a compact Schnorr signature. Their verification workloads differ. HTA follows [audit v5](Threshold_Schnorr_Integrated_Proof_Audit_v5.pdf), Algorithms 1–2 and checks C1–C4. The baseline uses [Zcash Foundation FROST](https://github.com/ZcashFoundation/frost/tree/0966bd1529aa062ad3b621af99e277f976b1c0f0).

### Time and space complexity

Let `n` be roster size, `t` the threshold, and `k` the number of participating signers. `MSM(n)` denotes a multiscalar multiplication with O(n) terms; its runtime depends on the backend. Space describes stored elements, not measured RAM.

| Operation or state | HTA | FROST |
|---|---|---|
| Setup | Independent keys and PoPs; O(n) roster validation and O(n) generator derivations. | The measured trusted dealer evaluates a degree-(t−1) polynomial for n shares: approximately O(nt) field work. DKG is not measured. |
| Signing | O(1) core arithmetic per signer per round, excluding roster and context processing; O(k) core arithmetic across signers. | Round 1: O(1) per signer. In the measured API, each Round 2 signer processes the k-commitment list, giving O(k²) total work. |
| Authorization proof | O(n) field work and several MSMs with O(n) terms. | No separate HTA-style authorization proof. |
| Final verification | O(n) field work and MSM terms, plus the Schnorr check. | O(1) in n for the final Schnorr signature. |
| Signature size | O(n). | O(1); 65 bytes in the measured encoding. |
| Public verification state | O(n) roster and generators, or information to derive them. | O(1) group verification key for final verification. |
| Coordinator / setup state | O(n) proof working state, plus signer messages. | O(n) public shares for the measured setup and O(k) session commitments and shares. |

These structural bounds do not specify exact elapsed time or peak memory. HTA's implementation performs roster and context processing beyond the core signer arithmetic.

### Benchmarks

Measurements use secp256k1 on one unpinned Intel i5-1240P host. Signer work is sequential in one process; values are milliseconds. HTA entries are medians of five single-session samples from one launch; FROST entries are one session per size without warmup. HTA uses C++/mcl and FROST uses Rust. For `n ≥ 4`, `t = k = n/2`; for `n = 2`, `t = k = 2`.

| n | t = k | HTA Round 1 | FROST Round 1 | HTA Round 2 | FROST Round 2 | HTA proof |
|---:|---:|---:|---:|---:|---:|---:|
| 2 | 2 | 0.45 | 0.40 | 0.27 | 0.83 | 1.63 |
| 4 | 2 | 0.49 | 0.23 | 0.26 | 0.31 | 2.12 |
| 8 | 4 | 1.44 | 0.48 | 0.49 | 0.85 | 3.20 |
| 32 | 16 | 7.50 | 1.32 | 1.75 | 6.11 | 8.40 |
| 64 | 32 | 24.65 | 2.15 | 3.47 | 17.42 | 14.65 |
| 128 | 64 | 51.90 | 4.48 | 4.23 | 68.04 | 15.12 |
| 256 | 128 | 205.15 | 8.44 | 8.77 | 273.56 | 29.37 |
| 512 | 256 | 978.25 | 17.20 | 24.64 | 1,082.82 | 71.20 |
| 1,024 | 512 | 3,500.92 | 42.73 | 39.36 | 5,377.28 | 111.33 |
| 2,048 | 1,024 | 11,488.26 | 86.78 | 73.99 | 32,534.25 | 188.46 |

| n | HTA full verify (ms) | FROST verify (ms) | HTA signature (bytes) | FROST signature (bytes) |
|---:|---:|---:|---:|---:|
| 2 | 1.25 | 0.52 | 875 | 65 |
| 4 | 1.42 | 0.18 | 1,097 | 65 |
| 8 | 2.03 | 0.17 | 1,467 | 65 |
| 32 | 4.64 | 0.13 | 3,391 | 65 |
| 64 | 7.78 | 0.13 | 5,833 | 65 |
| 128 | 7.94 | 0.11 | 10,643 | 65 |
| 256 | 15.10 | 0.11 | 20,189 | 65 |
| 512 | 34.42 | 0.10 | 39,207 | 65 |
| 1,024 | 53.08 | 0.12 | 77,169 | 65 |
| 2,048 | 89.64 | 0.23 | 153,019 | 65 |

HTA full verification checks the Schnorr signature and authorization proof; FROST verifies its Schnorr signature. FROST's measured aggregation verifies the combined signature and checks individual shares only if it fails. HTA's separately measured individual share checks are excluded from these tables. HTA registers independent keys; this FROST run uses a trusted dealer and validates its shares. Neither measures DKG.

### Results and theory

| Theoretical expectation | Observation in these runs |
|---|---|
| HTA proof and verification process a roster-sized statement. | From n=64 to n=2,048, proof time rises from 14.65 to 188.46 ms and full verification from 7.78 to 89.64 ms. |
| HTA signatures grow with n; FROST signatures stay constant-size. | HTA grows from 5,833 to 153,019 bytes across those sizes; FROST remains 65 bytes. |
| FROST final verification is independent of n. | Samples range from 0.10 to 0.52 ms. One sample per size cannot establish a scaling law. |
| FROST Round 2 processes the commitment list for each selected signer in this implementation. | With k increasing from 32 to 1,024, total sequential Round 2 rises from 17.42 to 32,534.25 ms. This is an implementation measurement, not a protocol lower bound. |
| HTA core signer arithmetic is constant per signer, excluding context processing. | Total Round 1 rises from 24.65 ms at k=32 to 11,488.26 ms at k=1,024. The measured path includes roster and context handling. |

These exploratory results do not establish security or general performance superiority. The large HTA binary's exact source provenance was not independently established, and a short overlapping run affected the start of the n=2,048 HTA process. Network latency, parallel signing and peak memory were not measured. See the [detailed benchmark report](benchmark.md#7-zcash-frost-comparison) for setup, aggregation, raw samples and reproduction details.

## Protocol in brief

Each signer has an individual key registered in an ordered public roster; there is no DKG in this protocol. A coordinator selects at least `t` signers. Signers exchange two rounds: first, each sends two one-use nonce commitments; second, each returns a response. The coordinator combines responses into a Schnorr signature and creates an authorization proof. That proof is designed to show the threshold condition without revealing the selected subset to the verifier. The verifier checks the signature and proof against the message, threshold, roster, and configured generator context.

## Implemented suite

| Part | Current choice |
|---|---|
| Group | secp256k1 prime-order group |
| Point encoding | Strict SEC 1 compressed points (33 bytes); `00` identity only where allowed |
| Scalar encoding | Canonical 32-byte big-endian integer below the group order; no reduction of input bytes |
| Transcript | `HTA-secp256k1-v1`, typed and length-prefixed |
| Hash | SHA-256 for transcripts and challenges |
| Generator derivation | RFC 9380 `secp256k1_XMD:SHA-256_SSWU_RO_`, DST `HTA-v1-secp256k1-Hgen` |
| Scalar challenges | Domain-separated SHA-256 with rejection sampling; `Y`, `Z`, `X` are nonzero; `POP`, `NON`, and `SIG` may be zero |
| Curve backend | mcl `9f49ba06593e2d426ab6fb9b0e17bc125a6f720c`; variable-time secret operations remain a limitation |
| Randomness and nonces | OpenSSL 3 CSPRNG (`RAND_priv_bytes`) with rejection sampling; two independent, one-use signing nonces |
| Generator context | Caller must authenticate and pin suite, context, and dimensions; the library does not authenticate application configuration |
| Proof of possession | Schnorr-style heuristic; it does not instantiate the paper's ideal extractable registration assumption |

See the [suite draft](docs/suite-draft.md) for framing and validation rules, the [audit traceability](docs/traceability.md) for paper-to-code mapping, and the [Phase 3 checklist](docs/phase-3-checklist.md) for protocol implementation evidence.

## Build, test, and benchmark

Requires CMake 3.21+, a C++17 compiler, OpenSSL 3 development files, and Python 3. The first build downloads the hash-pinned mcl source.

```sh
cmake --preset debug
cmake --build --preset debug -j2
ctest --preset debug --output-on-failure
python3 -m unittest discover -s tests -v
```

The C++ tests cover primitives, protocol behavior, malformed frames, simulator equations, and deterministic KATs. Python tests cover reference vectors and protocol algebra.

Run the default protocol matrix (`n=2,4,8`) and primitive benchmarks:

```sh
cmake --preset bench
cmake --build --preset bench --target protocol_bench primitive_bench -j2
./build/bench/protocol_bench 30
./build/bench/primitive_bench 300
```

Use `cmake --preset bench-reference` for the reference build. See [benchmark plan and detailed HTA/FROST/hinTS comparison](benchmark.md) and [benchmark artifact index](docs/benchmarks/README.md). Presets also include ASan/UBSan, TSan, coverage, and fuzz builds; fuzz requires Clang.

CI covers the preset matrix, GCC/Clang versions, Linux/macOS platforms, and static analysis. `docker build -t hta-scaffold .` builds and tests the container. Its clean-build comparison is currently disabled because the pinned Ubuntu snapshot endpoint returns HTTP 502; image reproducibility is not established.

## Limits and project info

The signer replay-ID set is process-local, capped at 65,536, and rejects new sessions at capacity; it is not durable across restart. A nonzero signer timeout enables automatic expiry of live sessions, with one worker thread per signer; zero disables automatic expiry. Cleanup may wait for an in-flight operation, while late Round 2 requests reject. The application must detect dropouts and coordinate a fresh session. Public generator multiplication has optional fixed-base precomputation; proof-generator and roster-key tables have been measured but remain disabled due to setup and memory costs. The libsecp256k1 comparison covers public primitives and component MSM only; no full protocol backend comparison exists. Tests and benchmark results do not establish security. NIST-inspired testing does not imply NIST approval or FIPS validation.

Authors: Arnav Sharda, Rineet Pandey, Kumar Bhaskar, and Dr R Kabaleeshwaran. Repository code is licensed under [Apache-2.0](LICENSE). Rights to redistribute the included audit PDF have not been established.
