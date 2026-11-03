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
