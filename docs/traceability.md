# Audit v5 implementation traceability

Status: specification work; no protocol implementation or independently validated vectors exist. Section, equation, and algorithm references are to `Threshold_Schnorr_Integrated_Proof_Audit_v5.pdf` (SHA-256 `271ee56591f8f960f92bd317bf77a1045e254d5b1488cf47f91f2e0b960d8cb8`).

| Audit reference | Required behavior | Implementation and test status |
| --- | --- | --- |
| §2.1, (1)–(2) | Prime-order group; canonical typed encodings; dimensions and parameter bounds. Intermediate proof commitments may be identity. | secp256k1 suite and framing drafted; one self-generated framing example tested, independent vectors and parser tests pending. |
| Assumption 3.1, (4) | Ordered distinct nonidentity roster; ideal extractable registration in proofs. PoP is a heuristic practical proposal. | Registration design and tests pending. |
| (5)–(7) | Bind ordered roster, threshold, message, subset and masked key into the specified contexts. Resample identity masked keys. | Encoding and tests pending. |
| Algorithm 1, (8)–(10) | Reject reused session IDs and invalid inputs; maintain immutable context and erase one-use nonces on completion or abort; verify Schnorr equation. | State persistence, implementation and tests pending. |
| (11)–(17), Algorithm 2 | Construct exact integer threshold witness and linked masked key; generate authorization proof. | Implementation and vectors pending. |
| (18)–(20), checks C1–C4 | Verify all four authorization equations and Schnorr equation with canonical group checks. | Implementation and negative tests pending. |
| Lemma 7.3 | Simulator operates with programmable random oracles, conditioned on no prior-query conflict. | Test-only oracle interface and conflict tests pending. |
| §9 | Preserve proof model and scope limitations in all security claims. | Independent review pending. |

Tests provide evidence of conformance, not a proof of security. A suite-specific specification must settle choices not fixed by the PDF before vectors or interoperability claims are meaningful.
