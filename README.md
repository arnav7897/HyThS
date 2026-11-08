# HTA Schnorr research prototype

Prototype implementation of the two-nonce, roster-based Schnorr protocol with hidden threshold authorization described in `Threshold_Schnorr_Integrated_Proof_Audit_v5.pdf`. It covers registration and roster checks, two-round signing, proof generation, verification, and typed message encoding. There is no interactive CLI or app.

This is research code. It is not production-ready, independently audited, or constant-time. Passing tests do not prove security. Phase 5 remains open; see the [phase checklist](docs/phase-5-checklist.md). Expert cryptographic review remains a separate gate.

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

## Latest prototype benchmark

Release run on 2026-11-08, using the optimized build on one Intel i5-1240P host. Each `(n,t,k)` configuration used five independent process launches, each with five groups of six signing sessions, except the final large-threshold row which used one session per group. Values are mean milliseconds per session across the 25 grouped samples; Round 1 and Round 2 sum work across the `k` selected signers in one process.

| n | t | k | Round 1 | Round 2 | Prove | Verify | Signature bytes |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 8 | 4 | 4 | 1.839 | 0.830 | 5.453 | 3.462 | 1467 |
| 8 | 4 | 5 | 2.146 | 0.981 | 5.057 | 3.245 | 1467 |
| 16 | 8 | 8 | 5.019 | 1.753 | 9.208 | 5.483 | 2133 |
| 32 | 1 | 32 | 26.867 | 6.276 | 14.019 | 8.041 | 3391 |
| 32 | 16 | 16 | 13.541 | 3.237 | 14.851 | 8.437 | 3391 |
| 32 | 32 | 32 | 26.173 | 6.025 | 13.814 | 7.915 | 3391 |
| 64 | 32 | 32 | 45.439 | 6.749 | 25.997 | 14.345 | 5833 |
| 128 | 64 | 64 | 159.574 | 13.027 | 46.367 | 23.919 | 10643 |
| 256 | 128 | 128 | 590.178 | 26.255 | 84.752 | 44.274 | 20189 |
| 512 | 1 | 1 | 8.811 | 0.210 | 164.166 | 79.666 | 39207 |
| 512 | 256 | 256 | 622.769 | 14.531 | 44.008 | 21.831 | 39207 |

These unpinned, single-host prototype results do not represent network latency or a comparison against other protocols. The two `n=512` runs show substantial variation despite using the same binary; they were collected separately with different group sizes and should not be interpreted as a threshold effect. The measured source had uncommitted changes. Raw samples, metadata, source snapshot and reproduction details are in the [benchmark plan](benchmark.md) and [benchmark results](docs/benchmarks/README.md).

The [benchmark plan](benchmark.md) covers correctness fixes, dropout recovery, optimizations, larger roster and threshold matrices, upstream comparisons, measurement methodology, and per-step complexity. Preliminary results and the full paper study have separate milestones.

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

Use `cmake --preset bench-reference` for the reference build. See [benchmark docs](docs/benchmarks/README.md) for options and saved results. Presets also include ASan/UBSan, TSan, coverage, and fuzz builds; fuzz requires Clang.

CI covers the preset matrix, GCC/Clang versions, Linux/macOS platforms, and static analysis. `docker build -t hta-scaffold .` builds and tests the container. Its clean-build comparison is currently disabled because the pinned Ubuntu snapshot endpoint returns HTTP 502; image reproducibility is not established.

## Limits and project info

The signer replay-ID set is process-local, capped at 65,536, and rejects new sessions at capacity; it is not durable across restart. A nonzero signer timeout enables automatic expiry of live sessions, with one worker thread per signer; zero disables automatic expiry. Cleanup may wait for an in-flight operation, while late Round 2 requests reject. The application must detect dropouts and coordinate a fresh session. Public generator multiplication has optional fixed-base precomputation; proof-generator and roster-key tables remain open. The libsecp256k1 comparison covers public primitives only. Tests and benchmark results do not establish security. NIST-inspired testing does not imply NIST approval or FIPS validation.

Authors: Arnav Sharda, Rineet Pandey, Kumar Bhaskar, and Dr R Kabaleeshwaran. Repository code is licensed under [Apache-2.0](LICENSE). Rights to redistribute the included audit PDF have not been established.
