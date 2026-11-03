# Phase 0 review checklist

This is a working review packet, not an independent review or an approval to freeze the suite. Source: `Threshold_Schnorr_Integrated_Proof_Audit_v5.pdf`. The suite draft contains local design choices that the PDF does not standardize.

| Plan item | Draft disposition | Review still needed |
| --- | --- | --- |
| S1–S3 | Typed framing, scalar rejection sampling and RFC 9380 generator proposal are specified. | Independently verify byte encodings, tags, generator retry, exact vectors, and backend support. |
| S4 | Use N from audit equation (1), with cache keyed by suite, context and N. Generator context is authenticated configuration, not embedded in CPK or the signature. | Check context selection and substitution, fixed-tuple d-DLR assumptions, cache isolation, and roster-change behavior. |
| S5–S6 | PoP context and ordered roster are proposed; individual PoP checks. | Authors must review registration context and the limits of heuristic PoP; do not assert ideal extraction. |
| S7–S9 | Partial-share verification is an optional extension; abort, subset, and signing message encodings are proposed. | Review extension, transport authentication assumptions, error handling, message limits, and interoperability vectors. |
| S10 | Durable sid reservation and fail-closed crash behavior are proposed. | Review storage rollback, concurrency, lifecycle, and actual implementation evidence. |
| S11–S13 | n ≤ 65535, thresholds, dimensions, verifier inputs, and edge cases are specified. | Confirm resource limits and exercise complete protocol edge cases. |
| S14 | Secret-bearing variable-time operations are explicitly labeled. | Select and examine backend operations; do not claim constant-time behavior without evidence. |

Before freezing, obtain an independent cryptographic review and author decisions. Apache-2.0 was selected for repository code; the four project authors are listed in the README. Audit PDF redistribution rights and the public hosting destination remain unset. Test vectors, proof/point validation and interoperability evidence remain incomplete. The benchmark hypotheses and traceability matrix are committed; they are not performance results or security proofs.

## Questions for an independent reviewer

Review the PDF, the draft suite, and traceability matrix at a recorded commit. Report findings with references, severity, impact, and proposed resolution. Distinguish mathematical proof review from implementation and operational review; neither a review request nor a passing test implies approval.

1. Does each draft transcript preserve the fields and ordering in audit equations (4)–(8), (17), and Algorithm 2? Check typed framing, domain separation, canonical identity encoding, hash-to-scalar rejection, and cross-protocol replay.
2. Does deterministic generator derivation match Definition 2.1's interface? Assess retry handling, configuration substitution, and the scope of the fixed-tuple d-DLR assumption. Do not assume the ideal-generator reduction applies to the deterministic tuple.
3. Does the registration proposal accurately state the gap between Schnorr PoP and Assumption 3.1? Assess rogue-key risks, registry context, roster ordering, and application authentication.
4. Assess Algorithm 1 implementation requirements under concurrency, abort, crash, uncertain persistence, rollback, nonce erasure, and malicious coordinators. Identify operational guarantees that exceed or fall outside the PDF's model.
5. Independently regenerate positive and malformed-input vectors for transcripts, point/scalar encodings, generator derivation, and proof/signature serialization. Verify every rejection and size boundary without relying solely on the existing tests.
6. Review proof extraction and unforgeability under the precise annotated model and stated corruption assumptions. Specifically assess the simulator's programmable-oracle and prior-query conditions; do not treat it as an ordinary verifier test.

Record the reviewer identity, review date, exact commit and PDF digest, scope, findings, and resolutions. Any unreviewed claim or untested property remains explicitly open. A separate side-channel review is needed for actual backend code when it exists.

## Coding review — 2026-11-03

Reviewer: delegated AI code-review agent; reviewed commit `1ebdfba3b50bf54cefa8a3fc1045c41a5622251e`. Audit PDF SHA-256: `271ee56591f8f960f92bd317bf77a1045e254d5b1488cf47f91f2e0b960d8cb8`. This is an independent pass over the repository code and tests, not an independent expert cryptographic or mathematical review.

What this change does: the repository implements draft typed framing, public scalar canonicality checks, and roster dimension calculations. Python tests illustrate signing and authorization algebra in an insecure toy group; the protocol itself is not implemented.

### Must fix before the Phase 0 gate

1. **The suite is not frozen** (`docs/suite-draft.md:3`, `plan.md` Phase 0). The normative byte-level specification remains a proposal with explicitly incomplete encodings, independent vectors, and review. A reader cannot yet rely on a final interoperable wire format. Resolve the open suite items and obtain the planned author and independent expert review before declaring the gate complete. Status: open.

2. **Independent vector and protocol review remain outstanding** (`docs/suite-draft.md:99`, `docs/traceability.md:3`). Existing transcript examples are self-generated, while generator derivation, point validation, full serialization, and implementations of Algorithm 1 and Algorithm 2 have not been independently checked. Passing these tests cannot establish conformance to audit equations (4)–(8), (17), or authorization checks (C1)–(C4). Independently regenerate vectors and review the suite and scheme before freezing; implement and test protocol behavior only in its planned phase. Status: open.

### Evidence and limits

- Fresh Debug CMake build with GCC 13.3.0 succeeded; `ctest --test-dir /tmp/hyths-phase0-review --output-on-failure` passed 2/2 tests.
- `python3 -m unittest discover -s tests -p 'test_*.py' -v` passed 5/5 tests, including toy signing and authorization algebra and transcript examples.
- `docs/benchmarking/hypotheses.md` and `docs/traceability.md` are tracked; the normative frozen specification remains outstanding. The tested dimensions follow audit equations (1)–(2); framing is a local draft choice, not a byte encoding supplied by the PDF.
- No concrete defect was confirmed in the inspected framing or dimension code within this limited review. Tests are not security proofs. No backend, nonce persistence, full protocol, adversarial implementation, interoperability, or side-channel behavior was verified. This review does not replace the requested independent expert review.

Verdict: Phase 0 is not complete; resolve findings 1 and 2 before the suite freeze.

**2026-11-03 status update:** The user selected the suite as a frozen research implementation baseline and authorized implementation. This decision does not resolve the independent vector and expert review findings above or establish agreement by the other authors. The full Phase 0 review gate remains open; review findings may require a new suite version.

**Expert review reported by user:** The user reports that an expert reviewed the work and approved proceeding with implementation. The reviewer identity, exact reviewed commit or suite version, review scope, written findings, and resolutions were not supplied; the review cannot yet be checked against this baseline.

**Separate hash check:** OpenSSL SHA-256 of the hexadecimal nested `SCALAR(SUBSET([1,2]), 0)` input in `tests/test_framing_vector.py` returned `5080236740f6e6e3c1a21df66e2692563a091966343e86c8c09a2a23b42858dc`, matching the existing vector. The input was copied from the existing example: this independently checks the hash calculation only, not construction of the transcript, the full suite, or cryptographic correctness. Independently constructed vectors remain open.
