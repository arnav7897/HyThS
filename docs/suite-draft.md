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

## Remaining specification gates

1. Independently review the transcript proposal against the PDF and generate deterministic vectors for every encoding and oracle, including rejection cases.
2. Define serialized proof and signature layouts, limits, and complete parser rejection behavior.
3. Specify permanent session-ID replay prevention and nonce erasure across crashes. Fail closed if durable state cannot be guaranteed.
4. Validate the selected backend, hash-to-curve vectors, side-channel properties, and toolchain before freezing the suite. Practical PoP remains a heuristic, not proof of ideal extractable registration.

The signer does not establish that the coordinator's masked key is linked to the chosen subset; audit §4.1 explicitly leaves that check to final verification. The audit does not establish same-session agreement, adaptive-corruption security, or full interactive-transcript signer privacy.
