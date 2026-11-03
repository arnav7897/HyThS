# Audit v5 implementation traceability

Status: specification work; no protocol implementation or independently validated vectors exist. Section, equation, and algorithm references are to `Threshold_Schnorr_Integrated_Proof_Audit_v5.pdf` (SHA-256 `271ee56591f8f960f92bd317bf77a1045e254d5b1488cf47f91f2e0b960d8cb8`).

| Audit reference | Required behavior | Implementation and test status |
| --- | --- | --- |
| §2.1, (1)–(2) | Prime-order group; canonical typed encodings; dimensions and parameter bounds. Intermediate proof commitments may be identity. | Draft suite dimensions tested exhaustively for allowed n; framing and scalar checks exist. Group validation, independent vectors and full parser tests pending. |
| Definition 2.1, (3) | Derive exactly 2N+1 nonidentity generators in the specified order from suite, context, N, and index. | Draft RFC 9380 suite proposed; implementation and independent vectors pending. |
| Assumption 3.1, (4) | Ordered distinct nonidentity roster; ideal extractable registration in proofs. PoP is a heuristic practical proposal. | Registration design and tests pending. |
| (5)–(7) | Bind ordered roster, threshold, message, subset and masked key into the specified contexts. Resample identity masked keys. | Encoding and tests pending. |
| Algorithm 1, (8)–(10) | Reject reused session IDs and invalid inputs; maintain immutable context and erase one-use nonces on completion or abort; verify Schnorr equation. | Toy additive-group test exercises the signing equation; state persistence and real implementation tests pending. |
| (11)–(17), Algorithm 2 | Construct exact integer threshold witness and linked masked key; generate authorization proof. | Implementation and vectors pending. |
| (18)–(20), checks C1–C4 | Verify all four authorization equations and Schnorr equation with canonical group checks. | Toy additive-group test exercises authorization algebra across thresholds; real verifier, transcripts and negative tests pending. |
| Proposition 5.1, (21)–(22) | Honest completeness, including masked signing equation and constant polynomial term. | Toy algebra checks only; real-group completeness tests pending. |
| Lemma 7.3, (31)–(35) | Simulator operates with programmable random oracles, conditioned on no prior-query conflict. | Test-only oracle interface, simulator and conflict tests pending. |
| Algorithm 3; Definitions 2.2, 6.1, 7.1, 8.1, 8.3; §§6–8 | Security experiments and reductions, not deployed protocol operations. | Independent mathematical review pending; do not infer proof validity from tests. |
| §9 | Preserve proof model and scope limitations in all security claims. | Independent review pending. |

Tests provide evidence of conformance, not a proof of security. A suite-specific specification must settle choices not fixed by the PDF before vectors or interoperability claims are meaningful.
