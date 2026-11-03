# Draft concrete suite: secp256k1

This is a design proposal, not a frozen wire format or a security claim. The accompanying audit v5 PDF is authoritative. Independent review, complete encodings, and known-answer vectors are required before the specification gate in `plan.md` is met.

## Parameters and public data

- Use the secp256k1 prime-order group and its standard base point G. The order is `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141` in hexadecimal.
- Scalars have canonical 32-byte big-endian encodings strictly below q. Never reduce untrusted scalar encodings.
- Use SEC 1 compressed points for nonidentity elements and the single byte `00` for identity. Validate curve membership and canonical form before use. Audit §2.1 permits identity for intermediate proof commitments; reject identity only where the algorithm requires it.
- Restrict 1 ≤ n ≤ 65535 and 1 ≤ t ≤ n. Compute l = bit_length(n), N = n + l + 1, and check audit equation (2) before allocation.
- The roster is an explicitly ordered list of distinct nonidentity points. Indices start at one. Subsets are strictly increasing lists of distinct roster indices.

## Generator proposal

Derive the 2N+1 generators in the exact order of audit equation (3), using RFC 9380 `secp256k1_XMD:SHA-256_SSWU_RO_` with DST ASCII `HTA-v1-secp256k1-Hgen`. Its input is the `GEN` transcript defined below. If the output is identity, retry with input `T("GEN-RETRY", B(original GEN transcript), U(counter))`, starting at counter 1. Fail if the 64-bit counter overflows. Retries are internal to Hgen, not additional exposed generator addresses. This produces the audit's deterministic generator model, whose d-DLR assumption is separate from the ideal generator model. RFC 9380: https://www.rfc-editor.org/rfc/rfc9380.html

## Transcript encoding proposal

All lengths and integers below are unsigned big-endian. `F(tag,payload)` is one byte tag, four bytes payload length, and payload; reject a payload longer than 2^32−1. Define `B(x)=F(02,x)`, `U(x)=F(03, eight-byte x)`, `P(x)=F(04, canonical point x)`, `Q(x)=F(05, canonical scalar x)`, and `V(x1,...,xk)=F(06,x1 || ... || xk)`. Values in V are already framed. `T(label,x1,...,xk)=F(01,B("HTA-secp256k1-v1") || B(label) || x1 || ... || xk)`, where quoted strings are ASCII bytes without a terminating zero. All nested transcripts are passed as framed bytes using B, preserving their boundaries. Reject malformed lengths, unexpected types, noncanonical values, and trailing bytes; impose resource limits before allocation. These choices are draft and require independent review and vectors.

Let `suite` be ASCII `HTA-secp256k1-v1`, `sigma_gen` a published byte string, `registry_id` a nonempty published byte string fixed before registration, and `sid` and `m` byte strings. All points and scalars below are their canonical values. `CPK` is the 32-byte SHA-256 digest of the roster transcript. The complete transcript definitions are:

| Purpose | Encoding |
| --- | --- |
| Generator address | `T("GEN", B(suite), B(sigma_gen), U(N), U(k))`, 1 ≤ k ≤ 2N+1 |
| Registration context | `T("POPCTX", B(registry_id))` |
| PoP challenge | `T("POP", B(POPCTX), U(i), P(PK_i), P(B_i))` |
| Roster | `T("ROSTER", U(n), V(P(PK_1),...,P(PK_n)))` |
| Subset | `T("SUBSET", V(U(i_1),...,U(i_s)))` |
| Session context | `T("CTX", B(sid), B(CPK), U(t), B(m), P(Qe), B(SUBSET))` |
| Nonce challenge | `T("NON", B(CTX), P(R1), P(R2))` |
| Signature challenge | `T("SIG", B(CPK), P(Qe), U(t), P(R), B(m))` |
| Authorization statement | `T("ST", B(CPK), U(n), U(t), B(m), P(Qe))` |
| Authorization prefix | `T("T0", B(ST), P(A), P(Scom), P(Qs))` |
| Authorization y | `T("Y", B(T0))` |
| Authorization z | `T("Z", B(T0), Q(y))` |
| Authorization x | `T("X", B(T0), Q(y), Q(z), P(T1), P(T2))` |

Uppercase transcript names in the table represent the full encoded bytes from their corresponding rows. This preserves the field order in audit equations (4), (5), (7), (8), (17), and Algorithm 2. `POPCTX` is independent of the eventual roster digest; application policy must assign unique registry identifiers. PoP is a heuristic implementation choice and does not realize the audit's ideal extraction by assertion.

For POP, NON, SIG, Y, Z, and X, calculate SHA-256 over `T("SCALAR", B(transcript), U(counter))`, with counter initially zero. Interpret the 32-byte digest as an integer; accept if less than q, additionally requiring nonzero for Y, Z and X. Otherwise increment counter and retry; fail on 64-bit overflow. Under a random-oracle idealization this is uniform in the respective range. Secrets use an independently supplied cryptographic random source and unbiased sampling, not this public hash procedure.

## Registration and signing message proposal

The following are draft transport encodings, distinct from the transcript inputs above. The application supplies an authenticated roster, registry identifier, suite, and generator context to the parties; these encodings do not provide transport authentication or establish participant authorization. Every received message is one complete T value: reject unexpected labels, extra fields, trailing bytes, noncanonical encodings and oversized inputs before allocating or operating on points.

| Message | Encoding |
| --- | --- |
| Registration for index i | `T("REGISTER", U(i), P(PK_i), P(B_i), Q(z_i))` |
| Round 1 request to signer i | `T("ROUND1-REQUEST", U(i), B(sid), B(CPK), U(t), B(m), P(Qe), B(SUBSET))` |
| Round 1 response | `T("ROUND1-RESPONSE", U(i), B(sid), P(U_i1), P(U_i2))` |
| Round 2 request to signer i | `T("ROUND2-REQUEST", U(i), B(sid), P(R1), P(R2))` |
| Round 2 response | `T("ROUND2-RESPONSE", U(i), B(sid), Q(s_i))` |

The registry checks the assigned index, distinct nonidentity PK, canonical group membership, and the PoP equation (4) with the published registry context before accepting the ordered roster. No extraction from this PoP is claimed. Round 1 validates the received CPK against the locally authenticated roster, verifies the recipient index and subset, and constructs CTX from the received sid, CPK, t, m, Qe, and SUBSET. Each signer binds the resulting context to sid. Round 2 uses the stored context; it does not accept a replacement context from the coordinator. Responses must match the expected participant and session. The coordinator validates canonical nonidentity nonce commitments before aggregation; signers reject invalid or identity R1, R2, and R as in Algorithm 1.

The message m is at most 16 MiB, sid is 1–256 bytes, and SUBSET contains at most n strictly increasing valid indices. Limit a complete round-1 request to 17 MiB, and each other transport message to 4096 bytes. Implementations must validate each nested length and field count before use. These limits are suite choices and need interoperability review. A request arriving after an abort or reply must not reactivate a session.

## Proof and signature encoding proposal

Given n and therefore N from the authenticated verification context, encode audit Algorithm 2's output and equation (20) as:

```
proof = T("PROOF", P(A), P(Scom), P(Qs), P(T1), P(T2),
          V(Q(vL_1),...,Q(vL_N)), V(Q(vR_1),...,Q(vR_N)),
          Q(t_hat), Q(mu), Q(tau_x))
signature = T("SIGNATURE", P(Qe), P(R), Q(s_e), B(proof))
```

The verifier obtains the suite, n, t, ordered roster, generator context, and message independently; none is inferred from the signature. It recomputes CPK and the generators from that context. Each vector must contain exactly N scalars. Reject a wrong suite or label, wrong field count or type, malformed or noncanonical point or scalar, wrong vector length, overlong or truncated length, and any trailing bytes at every nested level. Reject identity Qe and R; accept identity in A, Scom, Qs, T1, and T2 when all verification equations hold. Parsing success alone never implies signature validity: verify the Schnorr equation and all four authorization checks.

At the maximum n, the signature is below 5 MiB with these encodings. Limit encoded signatures to 5 MiB and messages to 16 MiB before allocation; reject larger inputs. These suite limits are implementation choices, not bounds claimed by the audit. Actual serialized lengths, including framing and identity-point encodings, must be measured in benchmarks rather than inferred from the audit's abstract size formula.

## Signer state and crash behavior proposal

Each signing key has one persistent used-session-ID set shared by every process and roster using that key. A session ID is a nonempty byte string of at most 256 bytes; equality means exact byte equality. The store must support an atomic, durable insert-if-absent and serialize competing requests. Reuse remains forbidden across restarts and roster changes. The application must provide rollback-resistant storage or retire the key after any restore or suspected rollback; an ordinary database backup alone cannot guarantee uniqueness.

Round 1 first validates the signer index, threshold, roster, subset, message length and nonidentity Qe. It then atomically reserves sid and waits for durable confirmation before sampling nonzero nonces, recording immutable ctx and returning commitments. A failed or uncertain reservation fails closed; never return commitments until reservation is known durable. If sampling or any subsequent operation fails, sid remains spent. The implementation retains live nonce scalars only in protected process memory, not in the durable replay store.

Round 2 must atomically claim the live session before checking its immutable context and aggregate points, so at most one request can use the nonce pair. After validation, it follows Algorithm 1 exactly, erases the nonce pair before returning a response, and permanently closes the session. Any malformed request, changed context, invalid point, identity aggregate, computation error, timeout, cancellation, or shutdown closes the session and erases live nonce state. An unknown or already claimed session fails without a response scalar. Concurrent round-2 calls cannot both succeed.

On process restart all sessions formerly live are aborted and their IDs remain spent; never reconstruct or resume their nonce state. Memory wiping is best effort in ordinary software and requires backend and compiler review; this design does not promise physical erasure. If durable reservation, concurrency control, or rollback resistance is unavailable, fail closed rather than claiming crash-safe signing. These operational rules instantiate Algorithm 1's permanent sid and one-use requirements; they do not add a same-session agreement guarantee.

## Operational choices for review

- Cache generators only by the complete tuple `(suite, sigma_gen, N)`. Use audit equation (1) exactly; do not bucket roster sizes or reuse a different N's tuple.
- The application supplies authenticated roster, threshold, suite, and generator context to every verifier. A valid signature alone does not establish that the caller selected an appropriate roster or threshold.
- On invalid roster, subset, canonical encoding, input length, group point, or signer state, return an error and no signature share. The coordinator resamples xi when Qe is identity and aborts the session when R1, R2, or R is identity, as specified in audit §4.1–4.2. Retry a failed session only with a fresh sid and fresh nonces.
- Optional partial-share verification is an implementation extension: check `s_i G = U_i1 + beta U_i2 + c PK_i` using the recorded commitments and the session's challenges. The audit does not specify this as a separate protocol algorithm, and accepting individual shares does not replace final verification.
- Use individual PoP checks for the reference; no batch-verification rule is specified. Check all edge cases including n = 1, t = 1, t = n and signer count exactly t.
- Signer secret keys and nonces and prover witness and blinders are secret. A variable-time operation on these values can leak information. Any research-only variable-time implementation and results must be labeled, and no constant-time claim is made without independent evidence.

## Remaining specification gates

1. Independently review the transcript proposal against the PDF and generate deterministic vectors for every encoding and oracle, including rejection cases.
2. Review proof and signature layouts and test all parser rejection behavior against independent vectors.
3. Independently review the signer-state design and test crashes, uncertain writes, concurrent calls, and storage rollback handling.
4. Validate the selected backend, hash-to-curve vectors, side-channel properties, and toolchain before freezing the suite. Practical PoP remains a heuristic, not proof of ideal extractable registration.

The signer does not establish that the coordinator's masked key is linked to the chosen subset; audit §4.1 explicitly leaves that check to final verification. The audit does not establish same-session agreement, adaptive-corruption security, or full interactive-transcript signer privacy.
