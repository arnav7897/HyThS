# Draft concrete suite: secp256k1

This is a design proposal, not a frozen wire format or a security claim. The accompanying audit v5 PDF is authoritative. Independent review, complete encodings, and known-answer vectors are required before the specification gate in `plan.md` is met.

## Parameters and public data

- Use the secp256k1 prime-order group and its standard base point G. The order is `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141` in hexadecimal.
- Scalars have canonical 32-byte big-endian encodings strictly below q. Never reduce untrusted scalar encodings.
- Use SEC 1 compressed points for nonidentity elements and the single byte `00` for identity. Validate curve membership and canonical form before use. Audit §2.1 permits identity for intermediate proof commitments; reject identity only where the algorithm requires it.
- Restrict 1 ≤ n ≤ 65535 and 1 ≤ t ≤ n. Compute l = bit_length(n), N = n + l + 1, and check audit equation (2) before allocation.
- The roster is an explicitly ordered list of distinct nonidentity points. Indices start at one. Subsets are strictly increasing lists of distinct roster indices.

## Generator proposal

Derive the 2N+1 generators in the exact order of audit equation (3), using RFC 9380 `secp256k1_XMD:SHA-256_SSWU_RO_` and a protocol-specific domain separation tag. Each input must include the suite identifier, published generator context, N, and the 1-based generator index. Specify identity retries and byte-level inputs before implementation. This produces the audit's deterministic generator model, whose d-DLR assumption is separate from the ideal generator model. RFC 9380: https://www.rfc-editor.org/rfc/rfc9380.html

## Remaining specification gates

1. Define injective, prefix-free typed framing for every nested transcript, including identity point representation and subset encoding. Fix exact domain tags and byte strings for all random oracles and generator derivation.
2. Define unbiased hash-to-scalar procedures for Fq and Fq* with explicit retry behavior. Define registration context without circular dependency on the roster digest.
3. Define serialized proof and signature layouts, limits, parser rejection behavior, and deterministic vectors for every transcript.
4. Specify permanent session-ID replay prevention and nonce erasure across crashes. Fail closed if durable state cannot be guaranteed.
5. Validate the selected backend, hash-to-curve vectors, side-channel properties, and toolchain before freezing the suite. Practical PoP remains a heuristic, not proof of ideal extractable registration.

The signer does not establish that the coordinator's masked key is linked to the chosen subset; audit §4.1 explicitly leaves that check to final verification. The audit does not establish same-session agreement, adaptive-corruption security, or full interactive-transcript signer privacy.
