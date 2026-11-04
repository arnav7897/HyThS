# Phase 3 protocol implementation checklist

Phase 3 implements the audit v5 protocol using the research suite. Code and tests do not prove security, constant-time behavior, crash safety, or ideal registration extraction.

## Progress

- [x] Registration proof of possession and ordered duplicate-free roster: audit §3 equation (4), §4.1 equation (5). Tests cover valid proofs, context mismatch, tampering, duplicate keys, ordering, and empty roster.
- [ ] Round 1 and Round 2 signer state machine: audit Algorithm 1. Require immutable contexts, permanent session IDs, independent nonces, one-use erase, abort behavior, and concurrency tests. Current repository has no durable rollback-resistant session store.
- [ ] Coordinator: masked aggregate key, aggregate commitments, challenge binding, response aggregation, and final Schnorr equation. Map to audit §4.1 equations (6)–(10).
- [ ] Authorization proof and verifier: implement audit Algorithm 2 and checks C1–C4 exactly. No proof or final verifier exists yet.
- [ ] Protocol serialization and end-to-end valid/invalid tests: use frozen typed frames, strict limits, and byte vectors.
- [ ] Protocol-level benchmark: record setup, registration, both signing rounds, proof generation, verification, serialized sizes, and environment metadata.

## Limits

- Secret arithmetic uses variable-time mcl. Do not expose secrets to timing or cache observers.
- Signer replay state is not persistent or crash-safe until a durable store is designed and tested.
- PoP is a heuristic practical mechanism; it does not instantiate the audit's ideal extractable registration.
- No security review is requested in this work pass. Do not claim audit completion or production readiness.
