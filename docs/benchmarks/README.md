# Benchmark results

This is the repository's single benchmark folder. `docs/benchmarking` was merged here; protocol-only examples now live in [`docs/protocol-examples`](../protocol-examples/). The folders had different content: `benchmarking` held hypotheses and notes, while `benchmarks` held measured data.

## Latest run — 2026-11-05

The latest Release run used `protocol_bench 30`, which measures the default matrix `(n,t)=(2,1),(4,2),(8,4)` with signer count equal to `t`. Each row has five samples of 30 sessions in one process. The optimized build enables generator caching and randomized batch verification; `bench-reference` disables both. Raw JSONL files:

- [`final-prototype-optimized.jsonl`](final-prototype-optimized.jsonl)
- [`final-prototype-reference.jsonl`](final-prototype-reference.jsonl)
- [`final-prototype-primitives.jsonl`](final-prototype-primitives.jsonl): 300 operations per sample, nine samples per primitive; includes bucket diagnostics.
- [Environment metadata](final-prototype-metadata.txt)

The summary table is in the [repository README](../../README.md). The run is a smoke benchmark from one host and one process per build. It does not meet the planned five-process-launch methodology and does not support general performance claims.

## Reproduce

```sh
cmake --preset bench
cmake --build --preset bench --target protocol_bench primitive_bench -j2
./build/bench/protocol_bench 30
./build/bench/primitive_bench 300

cmake --preset bench-reference
cmake --build --preset bench-reference --target protocol_bench -j2
./build/bench-reference/protocol_bench 30
```

`protocol_bench iterations n threshold [signers]` measures one configuration. The default command runs `(2,1)`, `(4,2)`, and `(8,4)`. `primitive_bench iterations` measures public secp256k1 operations and MSMs at several sizes. It also compares explicit mcl buckets; the observed winners varied, so protocol calls keep mcl's default.

## Files

- `final-prototype-*`: latest benchmark run and metadata.
- `e1-prototype*`: earlier primitive benchmark.
- `phase-3-*`, `phase3-*`: protocol prototype, parameter matrix, and completeness evidence from Phase 3.
- `phase5-*`: Phase 5 optimization comparison and bucket-sweep evidence.
- [`hypotheses.md`](hypotheses.md): predictions registered before protocol timing.
- [`primitive-prototype.md`](primitive-prototype.md): Phase 2 primitive benchmark notes.

All timings are variable-time prototype measurements. They are not security evidence. See the [Phase 5 checklist](../phase-5-checklist.md) for unfinished optimization work.
