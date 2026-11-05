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

Fresh Release run on 2026-11-05. Each configuration used five timing samples of 30 sessions in one process. The reference build disables generator caching and batch verification. The optimized build enables both. Times are milliseconds per operation; batch time is per signature in a four-signature batch.

| n | t | Signers | Signature bytes | Auth.Prove optimized / reference | Verify optimized / reference | Batch verify optimized / reference |
|---:|---:|---:|---:|---:|---:|---:|
| 2 | 1 | 1 | 875 | 0.688 / 2.424 | 0.550 / 2.253 | 0.456 / 2.220 |
| 4 | 2 | 2 | 1,097 | 0.963 / 3.562 | 0.697 / 3.268 | 0.540 / 3.232 |
| 8 | 4 | 4 | 1,467 | 1.429 / 5.555 | 0.936 / 5.067 | 0.782 / 5.019 |

These are single-host prototype measurements, not publication-grade results or comparisons against other protocols. Raw samples, environment, and reproduction steps are in [benchmark results](docs/benchmarks/README.md). The bucket sweep showed unstable winners, so protocol MSMs retain mcl's default.

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

The signer replay-ID set is process-local, capped at 65,536, and rejects new sessions at capacity; it is not durable across restart. Fixed-base precomputation and a libsecp256k1 comparison are still open. Tests and benchmark results do not establish security. NIST-inspired testing does not imply NIST approval or FIPS validation.

Authors: Arnav Sharda, Rineet Pandey, Kumar Bhaskar, and Dr R Kabaleeshwaran. Repository code is licensed under [Apache-2.0](LICENSE). Rights to redistribute the included audit PDF have not been established.
