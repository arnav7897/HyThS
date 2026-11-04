# Phase 4: adversarial testing and fuzzing

Research validation only. Passing tests and fuzz runs are not security proofs or an expert review.

## Implemented

- [x] A Clang/libFuzzer target invokes every protocol deserializer and, when a signature parses, `verify_signature` (`fuzz/protocol_fuzz.cpp`).
- [x] Fuzzer target is built only with the `fuzz` instrumentation preset; ASan and UBSan instrumentation are included by that preset.
- [x] Existing deterministic negative tests cover tampered authorization fields, wrong message/threshold, replayed session IDs, changed signing context, malformed frames, altered partial shares, and invalid roster registrations. See `tests/signer_test.cpp`, `tests/protocol_encoding_test.cpp`, and `tests/registration_test.cpp`.

## Still required for Phase 4 exit

- [ ] Run each fuzzer continuously for 24 hours and archive corpus, command, compiler version, and result.
- [ ] Obtain clean TSan and Valgrind runs; record tool versions. ASan/UBSan result is recorded below.
- [ ] Measure line coverage and reach at least 90% across `src/` core code.
- [ ] Complete deterministic negative cases N1–N17 in `plan.md` §10.2; current test mapping is partial.
- [ ] Add a robustness-benchmark `FaultInjector` for invalid share, dropout, and malformed message, with deterministic schedules and metrics.

## Local evidence (2026-11-04)

- [x] Debug CTest: 17/17; Python reference tests: 6/6.
- [x] ASan/UBSan CTest: 17/17.
- [x] Coverage-instrumented CTest: 17/17; line percentage has not been measured.
- [ ] TSan execution: build succeeds, but this host's runtime fails with `ThreadSanitizer: unexpected memory mapping`; rerun on a compatible runner.
- [ ] libFuzzer execution: local Clang is unavailable; CI fuzz smoke is configured but has not run for this branch yet.
- [ ] Valgrind: unavailable in the local environment.

The fuzz harness caps roster size at 16 to bound work per input. `decode_signature` gates the verifier call, so verifier coverage depends on valid structured inputs in the corpus. This phase remains open until all exit criteria have evidence.
