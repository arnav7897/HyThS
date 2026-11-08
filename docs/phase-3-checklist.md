# Phase 3 protocol implementation checklist

Phase 3 implements the audit v5 protocol using the research suite. Code and tests do not prove security, constant-time behavior, crash safety, or ideal registration extraction.

## Progress

- [x] Registration proof of possession and ordered duplicate-free roster: audit §3 equation (4), §4.1 equation (5). Tests cover valid proofs, context mismatch, tampering, duplicate keys, ordering, and empty roster.
- [x] Round 1 and Round 2 signer state machine: audit §4.2 Algorithm 1. Enforces immutable `CTX`, process-lifetime sid reservation, two independently sampled nonces, one-use consumption, explicit cancellation, optional automatic expiry, and atomic sid reservation. Timeout is disabled by default; callers configure it or cancel abandoned sessions. Replay state is not durable or rollback-resistant.
- [x] Coordinator: computes `Qe`, validates and aggregates nonce commitments, derives `beta` and `c`, consumes shares once, applies `c*xi`, and checks the final Schnorr equation. Maps to audit §4.1 equations (6)–(10). Tweak lifetime is one coordinator session; arithmetic remains variable-time.
- [x] Coordinator can individually verify each response share with `s_i G = U_i1 + beta U_i2 + c PK_i` before aggregation; valid and modified shares are tested.
- [x] Authorization prover and verifier: audit §4.3 Algorithm 2 and §4.4 checks C1–C4. Final verification also checks the Schnorr equation. Tests cover an end-to-end `n=2,t=2` signature, a modified proof, wrong message, and invalid witness.
- [x] Frozen typed encoders/parsers cover registration, both signing rounds, proof vectors, and final signatures. Enforce labels, tags, nested lengths, canonical values, identity policy, and suite size limits. End-to-end round trips and trailing-byte rejection pass.
- [x] Independent Python reference vectors cover registration, both signing rounds, authorization proof, and final signature; C++ encoders match all seven frozen byte strings. Malformed-frame corpus truncates each message at every byte, corrupts every nested tag and length, checks overflow/trailing data, and rejects noncanonical integer, point, and scalar payloads. This is independent implementation evidence, not external review.
- [x] Protocol-level prototype benchmark measures registration/roster, both signing rounds, proof generation, verification, and serialized size for n=2,4,8. Raw data and environment metadata are in `docs/benchmarks/phase-3-prototype.jsonl` and `phase-3-prototype-metadata.txt`; results are variable-time, single-host, and not publication-grade.
- [x] Test-only programmed-oracle simulator constructs a witness-free authorization proof using Audit v5 equations (32)–(35), verifies C1–C4, and rejects prior-query conflicts at `Hy`, `Hz`, and `Hx`. Fixed algebraic inputs do not validate simulator distribution or the lemma's proof.
- [x] Deterministic whole-protocol `.req/.rsp` KAT records registrations, signer commitments/responses, challenges, proof bytes, and final signature. It uses test-only SHA-256 counter expansion, not production randomness or an approved DRBG. Wire vectors remain separately independently generated.
- [x] Full protocol generated and verified 10,000 randomized signatures for each `(n,t)`: `(1,1)`, `(2,1)`, `(2,2)`, `(3,2)`. Subset sizes alternate between `t` and `n`; run evidence and environment are saved in `docs/benchmarks/phase3-completeness.txt`.

The simulator and KAT are CTest targets. Build the randomized runner with `cmake --preset release && cmake --build --preset release --target phase3_completeness`; run `./build/release/phase3_completeness 10000` to repeat the 40,000-run matrix.

The protocol benchmark accepts `./build/bench/protocol_bench iterations n threshold [signers]`. `iterations` is 1–100 per sample; `signers` defaults to `threshold` and may be set up to `n`. It emits JSON lines, including partial-share verification time. With no `n threshold`, it retains the default `(2,1)`, `(4,2)`, `(8,4)` benchmark matrix. A ten-iteration sample for the same matrix as the completeness runner is saved in `docs/benchmarks/phase3-parameter-matrix.jsonl` with metadata alongside it.

## Limits

The optional partial-share check is implemented in the coordinator. Simulator tests validate the equations and programmed-oracle conflict path only; they do not validate the lemma's distributional argument.

- Secret arithmetic uses variable-time mcl. Do not expose secrets to timing or cache observers.
- Signer replay state is process-local, not persistent or crash-safe. Phase 5 caps it at 65,536 IDs and rejects new sessions at capacity; IDs are never evicted during the process lifetime.
- PoP is a heuristic practical mechanism; it does not instantiate the audit's ideal extractable registration.
- No security review is requested in this work pass. Do not claim audit completion or production readiness.
