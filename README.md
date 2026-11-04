# Threshold Schnorr research repository

This repository contains a C++ research prototype of the selected protocol from `Threshold_Schnorr_Integrated_Proof_Audit_v5.pdf`: registration and roster checks, two-round signing, authorization proofs, verification, and typed message encoding. It has tests and prototype benchmarks, but no interactive CLI or app.

Project authors: Arnav Sharda, Rineet Pandey, Kumar Bhaskar, and Dr R Kabaleeshwaran.

The proof audit states that its proofs require independent verification and do not guarantee implementation security. Do not use this work for production security decisions.

NIST-inspired testing and documentation do not imply NIST approval, algorithm validation, or FIPS module validation. See the [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program).

Repository code is licensed under [Apache-2.0](LICENSE). The included audit PDF is provided as a source document; its authorship and redistribution rights have not yet been established.

For the specification and current implementation evidence, see the [suite draft](docs/suite-draft.md), [audit traceability](docs/traceability.md), [Phase 3 checklist](docs/phase-3-checklist.md), and [Phase 0 review record](docs/phase-0-review.md). Independent expert review remains a separate open item.

The existing checks require CMake, a C++17 compiler, OpenSSL 3 development headers, Python 3, and network access to download the hash-pinned mcl source on the first build:

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
python3 -m unittest discover -s tests -v
```

The C++ suite includes primitive, protocol, malformed-frame, simulator-equation, and deterministic KAT checks. Python tests cover reference vectors and algebra. Tests are evidence about sampled behavior; they do not prove security.

The experimental secp256k1 adapter handles public inputs only. It does not support signing keys or nonces, and it must not share a process with code that reinitializes mcl for another curve. No constant-time claim is made.

The CMake presets include `debug`, `release`, `asan-ubsan`, `tsan`, `coverage`, `fuzz`, and `bench`. Presets require CMake 3.21 or newer; `fuzz` requires Clang. Run the normal tests with `cmake --preset debug`, `cmake --build --preset debug`, and `ctest --preset debug --output-on-failure`. The `bench` preset builds prototype measurements. The extended Phase 3 completeness runner performs 10,000 randomized runs for each documented `(n,t)` set and takes several minutes; see the checklist for its command.

`docker build -t hta-scaffold .` builds and tests the scaffold in an Ubuntu container. The base image is pinned by digest and the toolchain uses the Ubuntu archive snapshot dated 2026-10-01. The certificate bootstrap uses a version-pinned package and its dependencies from the live archive. Repeatability depends on archive availability and has not yet been verified by independent clean builds.

The CI workflow checks GCC 12/13, Clang 16/17, clang-format, clang-tidy, and cppcheck. Its container repeatability job is temporarily commented out while the pinned Ubuntu snapshot endpoint returns HTTP 502; re-enable it when the endpoint recovers. When active, it builds twice without cache and compares installed package versions and C++ test executable hashes. This does not prove bit-for-bit reproducibility of every image artifact.
