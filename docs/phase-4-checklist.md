# Phase 4: adversarial testing and fuzzing

Research validation only. Passing tests and fuzz runs are not security proofs or an expert review.

## Implemented

- [x] A Clang/libFuzzer target invokes every protocol deserializer and, when a signature parses, `verify_signature` (`fuzz/protocol_fuzz.cpp`).
- [x] Fuzzer target is built only with the `fuzz` instrumentation preset; ASan and UBSan instrumentation are included by that preset.
- [x] Existing deterministic negative tests cover tampered authorization fields, wrong message/threshold, replayed session IDs, changed signing context, malformed frames, altered partial shares, and invalid roster registrations. See `tests/signer_test.cpp`, `tests/protocol_encoding_test.cpp`, and `tests/registration_test.cpp`.
- [x] `phase4_fault_injector` runs deterministic dropout, invalid partial-share, and malformed-wire scenarios and reports rejection counts and timing as JSON lines (`tools/phase4_fault_injector.cpp`).

## Still required for Phase 4 exit

- [ ] Run each fuzzer continuously for 24 hours and archive corpus, command, compiler version, and result.
- [ ] Obtain clean TSan and Valgrind runs; record tool versions. ASan/UBSan result is recorded below.
- [ ] Measure line coverage and reach at least 90% across `src/` core code.
- [x] Add deterministic assertions for N1–N17 and map each case in `docs/phase-4-negative-matrix.md`.
- [ ] Run the mapped negative-test command on the review machine and confirm every assertion passes.
- [x] Add a robustness-benchmark `FaultInjector` for invalid share, dropout, and malformed message, with deterministic schedules and metrics.

## Earlier local evidence (2026-11-04, before the current N1–N17 additions)

- [x] Debug CTest: 17/17; Python reference tests: 6/6.
- [x] ASan/UBSan CTest: 17/17.
- [x] Coverage-instrumented CTest: 17/17; line percentage has not been measured.
- [ ] TSan execution: build succeeds, but this host's runtime fails with `ThreadSanitizer: unexpected memory mapping`; rerun on a compatible runner.
- [ ] libFuzzer execution: local Clang is unavailable; CI fuzz smoke is configured but has not run for this branch yet.
- [ ] Valgrind: unavailable in the local environment.
- [x] Latest Phase 4 test and tool targets compile; the expanded negative tests and fault scenarios have not been run on this branch.

## Commands for another machine

Install tools on Ubuntu: `sudo apt-get update && sudo apt-get install -y clang libclang-rt-dev cmake g++ libssl-dev make python3 python3-pip valgrind gcovr`.

Run existing negative tests and the fault injector:

```sh
cmake --preset debug
cmake --build --preset debug -j2
ctest --preset debug --output-on-failure -R 'signer|protocol_encoding|registration'
./build/debug/phase4_fault_injector 1000
```

Run the fuzzer for 24 hours. Keep the resulting corpus and crash artifacts for review:

```sh
cmake --preset fuzz
cmake --build --preset fuzz --target protocol_fuzz -j2
mkdir -p build/fuzz/corpus/phase4 build/fuzz/artifacts/phase4
python3 tools/phase4_seed_corpus.py build/fuzz/corpus/phase4
set -o pipefail
./build/fuzz/protocol_fuzz -max_total_time=86400 -timeout=30 -print_final_stats=1 -artifact_prefix=build/fuzz/artifacts/phase4/ build/fuzz/corpus/phase4 2>&1 | tee build/fuzz/phase4-24h.log
```

Run sanitizers and coverage:

```sh
cmake --preset asan-ubsan && cmake --build --preset asan-ubsan -j2 && ctest --preset asan-ubsan --output-on-failure
cmake --preset tsan && cmake --build --preset tsan -j2 && ctest --preset tsan --output-on-failure
cmake --preset coverage && cmake --build --preset coverage -j2 && ctest --preset coverage --output-on-failure
gcovr --root . --filter 'src/' build/coverage --print-summary
ctest --test-dir build/debug -T memcheck --overwrite MemoryCheckCommand=valgrind --overwrite 'MemoryCheckCommandOptions=--leak-check=full --error-exitcode=1'
```

Save command output, tool versions, fuzzer corpus/artifacts, and coverage summary with the review evidence. The 24-hour run command writes libFuzzer's evolved corpus in place and stores crash artifacts separately.

Record the environment with `clang --version`, `cmake --version`, `g++ --version`, `valgrind --version`, and `gcovr --version`.

The fuzz harness caps roster size at 16 to bound work per input. `decode_signature` gates the verifier call, so verifier coverage depends on valid structured inputs in the corpus. This phase remains open until all exit criteria have evidence.
