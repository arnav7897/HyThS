# ASIACCS27 secp256k1 research suite

Status: frozen implementation target for the next core phase; not independently reviewed or a security certification. No cryptographic implementation changes belong to this specification phase.

## Sources and precedence

Baseline commit: `3f2561b6af6a844b065c92906947cc5634733db6`.

- New scheme: `asiaccs27_submission_final.pdf`, SHA-256 `989c5b8217e6da18b93d4b79efc4f83ab817d8c58c808e40e028faa8e4b3d1d1`.
- Historical scheme: `Threshold_Schnorr_Integrated_Proof_Audit_v5.pdf`, SHA-256 `271ee56591f8f960f92bd317bf77a1045e254d5b1488cf47f91f2e0b960d8cb8`.

The submission governs this variant; audit v5 remains the source for historical implementation reviews. This document supplies byte-level choices left abstract by the paper. Any contradiction with the submission blocks the affected implementation until recorded and resolved; do not silently change equations. The local submission PDF remains untracked; redistribution is outside this phase.

## Parameters and primitives

Suite ASCII identifier: `HTA-secp256k1-asiaccs27-v1`. Use the existing secp256k1 group, canonical 32-byte big-endian scalars, SHA-256, and RFC 9380 secp256k1 hash-to-curve primitive. Existing mcl/OpenSSL pins remain unchanged. Secret operations remain variable-time research operations.

Require `1 <= t <= n <= 65535`. Compute `ell=bit_length(n)`, `kappa=bit_length(n+ell-1)`, `N=1<<kappa`, `d=2*N+3`, and require `0<=r<=kappa`. Check equation (3.2): `q > max(N+1,n+2^ell-1,3)`. Maximum N is 131072. Use checked integer arithmetic before allocation. Do not retain the v5 maximum-N limit.

Nonidentity points use canonical 33-byte SEC 1 compressed encoding. Identity is exactly one byte `00`. Reuse the v5 strict curve decoder: no coordinate reduction, alternate encodings, or trailing bytes. Identity is allowed in PoP commitments, A, Scom, Qs, T1, T2, and folding L/R; reject identity roster keys, Qe, signer nonce commitments, aggregate R1/R2, and R. Scalars must be below q; never reduce received scalar bytes.

Roster keys are ordered, distinct, nonidentity. Indices are one-based; subsets are strictly increasing, distinct, in-range indices. Surplus bits are least-significant first. Construct `aL=(selectors || surplus || zero padding)`, `aR=aL-1_N`; xi is not a vector coordinate. Enforce witness equations (5.7) and (5.8) in the prover. Use all-one chi, weights and padded keys from (5.6), including padding coordinates in the Boolean relation. Cache Kchi and padded keys by authenticated roster digest.

Derive generators in order `(H0,G1..GN,H1..HN,Gxi,Gip)` using DST ASCII `HTA-asiaccs27-v1-secp256k1-Hgen`. Address `T("GEN",B(suite),B(sigma_gen),U(N),U(k))`, k=1..d. Retry identity using `T("GEN-RETRY",B(original_address),U(counter))`, counter starting at 1; fail on uint64 overflow. Cache by `(suite,sigma_gen,N)`, never r alone. Application authenticates and pins the roster and generator context before signing.

## Canonical framing and transcripts

Retain the framing grammar, not the old suite identifier: `F(tag,payload)=tag:u8 || length:u32be || payload`; `B=F(02,bytes)`, `U=F(03,u64be)`, `P=F(04,point)`, `Q=F(05,scalar)`, `V=F(06,concatenated framed values)`. `T(label,fields)=F(01,B(suite)||B(ASCII label)||fields)`. No string terminators. Reject incorrect labels, field counts, types, lengths, noncanonical values, and trailing bytes at every level.

Define the configuration transcript `CFG=T("CONFIG",B(sigma_gen),U(N),U(r))`. Its inclusion in ST binds folding depth and generator context as suite-level public parameters; it is an explicit instantiation extension to the paper's abstract statement. A verifier supplies expected CFG independently and rejects mismatches. Full certificate bytes are used in CTX and SIG; no certificate-digest optimization in this version.

| Name | Exact transcript |
| --- | --- |
| POPCTX | `T("POPCTX",B(registry_id))` |
| POP | `T("POP",B(POPCTX),U(i),P(PK_i),P(B_i))` |
| ROSTER | `T("ROSTER",U(n),V(P(PK_1),...,P(PK_n)))` |
| SUBSET | `T("SUBSET",V(U(i_1),...,U(i_s)))` |
| ST | `T("ST",B(CFG),B(CPK),U(n),U(t),B(m),P(Qe))` |
| T0 | `T("T0",B(ST),P(A),P(Scom),P(Qs))` |
| Y | `T("Y",B(T0))` |
| Z | `T("Z",B(T0),Q(y))` |
| X | `T("X",B(T0),Q(y),Q(z),P(T1),P(T2))` |
| TPSI | `T("TPSI",B(T0),Q(y),Q(z),P(T1),P(T2),Q(x),Q(t_hat),Q(mu),Q(mu_xi),Q(tau_x))` |
| PSI | `T("PSI",B(TPSI),U(0))` |
| OMEGA | `T("PSI",B(TPSI),U(1))` |
| TAU0 | `T("FOLDCTX",B(TPSI),Q(psi),Q(omega))` |
| UPSILON j | `T("UPSILON",U(j),B(TAU0),V(Q(u_1),...,Q(u_{j-1})),V(P(L_1),P(R_1),...,P(L_j),P(R_j)))` |
| CTX | `T("CTX",B(sid),B(CPK),U(t),B(m),P(Qe),B(SUBSET),B(proof))` |
| NON | `T("NON",B(CTX),P(R1),P(R2))` |
| SIG | `T("SIG",B(CPK),P(Qe),U(t),P(R),B(m),B(proof))` |

CPK is SHA-256(ROSTER). Registry ID is nonempty and fixed before registration. All uppercase nested names denote complete transcript bytes. Empty V is encoded normally. For every scalar challenge hash `SHA256(T("SCALAR",B(challenge_transcript),U(counter)))`; start counter at zero, accept the digest integer only if below q, otherwise retry. Y/Z/X/PSI/OMEGA/UPSILON additionally reject zero. POP/NON/SIG allow zero. Independent component labels instantiate the pair oracle. Fail on counter overflow. Sample secret keys/nonces uniformly in Fq*, and xi/proof blinders uniformly in Fq, using the existing CSPRNG rejection sampler. Resample xi if Qe is identity.

## Proof and transport

Implement authorization Algorithm 2 exactly, including separate mu_xi, generator Gxi, and adjusted generators `Gi+psi*PKpad_i`. Implement Algorithm 3's low/high split, cross inner products, inverses, and whole-prefix challenges. Emit exactly r folding pairs and terminal vectors of length N/2^r. Verification reconstructs equation (5.11), folding weights in Section 5.4, and both V1/V2. Final verification also checks (5.5) with the certificate-bound SIG challenge. Do not substitute v5 C1-C4 or its batch equation.

```
proof = T("PROOF",U(r),P(A),P(Scom),P(Qs),P(T1),P(T2),
          Q(t_hat),Q(mu),Q(mu_xi),Q(tau_x),
          V(P(L_1),P(R_1),...,P(L_r),P(R_r)),
          V(Q(a_1),...,Q(a_h)),V(Q(b_1),...,Q(b_h)))
signature = T("SIGNATURE",P(Qe),P(R),Q(s_e),B(proof))
```

Here h=N/2^r. Encoded r must equal the independently configured r. The proof does not carry a replaceable generator context.

Retain v5 REGISTER and Round-1/2 response and Round-2 request field layouts with the new suite. Replace Round-1 request with:

```
T("ROUND1-REQUEST",U(i),B(sid),B(CPK),U(t),B(m),P(Qe),
  B(SUBSET),B(proof),U(mode),V(optional Q(xi)))
```

Mode 0 is certificate-only and requires an empty V. Mode 1 is mask-disclosure and requires exactly one scalar. Signer policy permits an explicit set of modes; default requires mode 1, with mode 0 enabled explicitly for its experiments. Never fall back between modes. Mode 1 checks `Qe=sum(PK_j for j in S)+xi*G` before reserving a nonce session. Mode is immutable local session metadata; the paper's CTX and final signature remain common to both modes. Disclosed xi is not included in the final signature. Certificate-only acceptance does not prove linkage to the named S.

Limits: message 16 MiB; sid 1..256 bytes; registry ID and sigma_gen each 1 MiB maximum (registry ID nonempty); subset at most n; encoded proof/signature 10 MiB; Round-1 request 28 MiB; other transport messages 4096 bytes. Check limits and exact vector lengths before allocations. Identity encodings make actual payload sizes variable; always report actual wire length separately from fixed-width analytic counts.

## Session lifecycle and interfaces

Round 1 validates configuration, canonical inputs, subset, threshold, Qe, V1/V2 and selected mode before sampling nonces. Atomically recheck/reserve sid under signer synchronization after proof verification; racing requests cannot both reserve it. Store immutable certificate bytes, CTX, mode, roster association and live nonces. Failure after reservation leaves sid spent.

Round 2 atomically consumes live state; validate nonidentity R1/R2/R, derive beta and c from stored bytes, return one response, and erase nonces before return. Invalid inputs, cancellation, timeout, shutdown and computation errors erase live state without removing the spent sid. Keep existing 65536 replay-ID cap and 64 MiB estimated active-session cap; include certificate storage in accounting. No eviction. Replay state remains process-local: restart safety is unsupported. A signing key must not resume after restart with lost replay history. Durable storage is outside this phase and must not be claimed implemented.

- Extend Dimensions with kappa; derive N/d as above.
- Replace AuthorizationProof's vL/vR with terminal a/b, add mu_xi and ordered folding pairs. Keep r in the encoded proof and require expected r in prove/verify/codec interfaces.
- RoundOneRequest carries certificate, mode and optional mask. Signer round1 accepts authenticated generator context and expected r as configuration, not untrusted overrides.
- Coordinator receives the finalized certificate before nonce collection; retains exact bytes for challenge construction and final assembly. Validate individual shares using the same certificate-bound challenge.
- Disable the old randomized batch verifier in this variant until a separately tested V1/V2 batch design exists. Use individual full verification in benchmarks.
- Reuse primitives and framing helpers; replace suite-bound callers, KATs, fuzz inputs and examples together. v5 bytes must reject rather than auto-detect.

No new network service, persistence subsystem, backend, or production-security claim is introduced. Independent cryptographic review and independent vectors remain outstanding.
