# Threshold Schnorr research repository

This workspace is an early research scaffold for the protocol in `Threshold_Schnorr_Integrated_Proof_Audit_v5.pdf`. It contains no implementation or benchmark results yet.

Project authors: Arnav Sharda, Rineet Pandey, Kumar Bhaskar, and Dr R Kabaleeshwaran.

The proof audit states that its proofs require independent verification and do not guarantee implementation security. Do not use this work for production security decisions.

NIST-inspired testing and documentation do not imply NIST approval, algorithm validation, or FIPS module validation. See the [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program).

Repository code is licensed under [Apache-2.0](LICENSE). The included audit PDF is provided as a source document; its authorship and redistribution rights have not yet been established.

For the Phase 0 review, start with the [suite draft](docs/suite-draft.md), [audit traceability](docs/traceability.md), and [review questions](docs/phase-0-review.md). The examples are self-generated and need independent validation.

The existing checks require CMake, a C++17 compiler, and Python 3:

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
python3 -m unittest discover -s tests -v
```

These checks cover framing, parameters, and toy-group algebra. They do not implement or verify a complete cryptographic protocol.
