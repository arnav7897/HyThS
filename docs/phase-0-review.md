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
