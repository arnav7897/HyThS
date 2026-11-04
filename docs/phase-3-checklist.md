# Phase 3 protocol implementation checklist

Phase 3 implements the audit v5 protocol using the research suite. Code and tests do not prove security, constant-time behavior, crash safety, or ideal registration extraction.

## Progress

- [x] Registration proof of possession and ordered duplicate-free roster: audit §3 equation (4), §4.1 equation (5). Tests cover valid proofs, context mismatch, tampering, duplicate keys, ordering, and empty roster.
- [x] Round 1 and Round 2 signer state machine: audit §4.2 Algorithm 1. Enforces immutable `CTX`, process-lifetime sid reservation, two independently sampled nonces, one-use consumption, abort behavior, and atomic sid reservation. Tests cover the protocol equation, replay, abort burn, and concurrent same/different sids. Replay state is not durable or rollback-resistant.
- [x] Coordinator: computes `Qe`, validates and aggregates nonce commitments, derives `beta` and `c`, consumes shares once, applies `c*xi`, and checks the final Schnorr equation. Maps to audit §4.1 equations (6)–(10). Tweak lifetime is one coordinator session; arithmetic remains variable-time.
- [x] Authorization prover and verifier: audit §4.3 Algorithm 2 and §4.4 checks C1–C4. Final verification also checks the Schnorr equation. Tests cover an end-to-end `n=2,t=2` signature, a modified proof, wrong message, and invalid witness.
- [x] Frozen typed encoders/parsers cover registration, both signing rounds, proof vectors, and final signatures. Enforce labels, tags, nested lengths, canonical values, identity policy, and suite size limits. End-to-end round trips and trailing-byte rejection pass.
- [ ] Broader independent suite byte vectors remain open. Tests now include a hand-specified round-two response wire vector, every truncated prefix of a round-one request, wrong suite/tag/roster size, overflowing frame length, and a noncanonical response scalar.
- [x] Protocol-level prototype benchmark measures registration/roster, both signing rounds, proof generation, verification, and serialized size for n=2,4,8. Raw data and environment metadata are in `docs/benchmarks/phase-3-prototype.jsonl` and `phase-3-prototype-metadata.txt`; results are variable-time, single-host, and not publication-grade.

## Limits

- Secret arithmetic uses variable-time mcl. Do not expose secrets to timing or cache observers.
- Signer replay state is not persistent or crash-safe until a durable store is designed and tested.
- PoP is a heuristic practical mechanism; it does not instantiate the audit's ideal extractable registration.
- No security review is requested in this work pass. Do not claim audit completion or production readiness.
