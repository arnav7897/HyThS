# Phase 4 negative-test matrix

Run with `ctest --preset debug --output-on-failure -R 'signer|protocol_encoding|registration'`.
Cases below are assertions in those test executables. This is implementation test evidence only.

| Case | Assertion location | Covered input |
|---|---|---|
| N1 | `tests/signer_test.cpp` | Authorization prover rejects fewer selected keys than threshold. |
| N2 | `tests/signer_test.cpp` | Prover rejects a selector value outside {0,1}. |
| N3 | `tests/signer_test.cpp` | Prover rejects surplus bits inconsistent with selected count minus threshold. |
| N4 | `tests/signer_test.cpp` | Verifier rejects a proof against a different valid masked key. |
| N5 | `tests/signer_test.cpp` | Verifier rejects a different message, threshold, and roster size. |
| N6 | `tests/signer_test.cpp` | Verifier rejects changed `vL`, `vR`, `mu`, `tau_x`, and `t_hat`. |
| N7 | `tests/signer_test.cpp` | Verifier rejects changed `A`, `S`, `Qs`, `T1`, and `T2`. |
| N8 | `tests/signer_test.cpp` | Verifier rejects a changed Schnorr response or valid but unrelated nonce point. |
| N9 | `tests/signer_test.cpp` | Verifier rejects identity masked key and identity nonce. |
| N10 | `tests/signer_test.cpp` | Identity proof points round-trip through encoding; verifier handles each without throwing. |
| N11 | `tests/protocol_encoding_test.cpp` | Malformed corpus checks invalid point/scalar payloads, framing, lengths, and trailing data. |
| N12 | `tests/protocol_encoding_test.cpp` | Decoder rejects a non-canonical scalar (`ff` bytes). |
| N13 | `tests/registration_test.cpp` | Roster rejects duplicate and identity keys; verifier rejects a tampered proof of possession. |
| N14 | `tests/signer_test.cpp` | Signer rejects replay, Round 2 without a live Round 1 session, and a changed session ID; malformed Round 2 input also burns the session. |
| N15 | `tests/signer_test.cpp` | Signer rejects an index outside the subset and a subset below threshold. |
| N16 | `tests/signer_test.cpp` | Verifier rejects a signature replayed with a different message. |
| N17 | `tests/signer_test.cpp` | Verifier rejects the same signature under a different roster of equal size. |

The paper's N1–N17 wording includes internal proof witnesses (`b`, `ds`) that are not exposed by the public protocol API. N2 and N3 therefore test rejection at the prover input boundary. Tests do not prove the corresponding protocol lemmas.
