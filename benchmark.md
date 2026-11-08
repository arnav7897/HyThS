# Protocol implementation and benchmarking plan

Status: planning, 2026-11-08. Research prototype; audit v5 is the scheme source.
The expert review and 24-hour fuzz run are on hold. Tests are not security proofs.
Follow the one-roadmap-phase-per-branch rule and report each phase before starting another.

## 1. Correctness before measurements

1. Surplus weights now encode `2^j` as a full field scalar, per audit v5 equations (12) and (14). A regression exercises `n=257,t=1,|S|=257` and surplus 256; extend boundary and verifier comparisons.
2. Explicit signer cancellation erases live nonce state while retaining the used session ID. A configured nonzero timeout automatically expires live sessions using one worker thread per signer; zero disables it. Cleanup may wait for an in-flight signer operation holding the lock; late Round 2 requests reject. Tests cover timeout, repeated cancellation, concurrency with Round 2 and replay.
3. A regression covers `n=8,t=4,|S|=5`: one selected signer drops, the original session is cleaned up, and a fresh four-signer session verifies. Attempts with fewer than four reject. Coordinator dropout detection and automatic restart still require a transport and orchestration layer.
4. Both batch configurations now apply the same combined-term limit. Expand valid/invalid differential testing around the boundary. Randomized batching has probabilistic soundness.
5. Run fresh builds, KATs, negative matrix, serialization tests and available sanitizers. Record results and tools. Measure coverage and run TSan/Valgrind where available; record failures or missing tools. The held 24-hour run and expert review remain open.

Replay IDs currently do not survive restart. Variable-time secret arithmetic and heuristic PoP remain explicit research limitations; do not claim ideal registration extraction or deployment safety.

## 2. Optimization candidates

- Already implemented: one-entry generator cache, randomized cross-signature batch verification, and a public-generator fixed-base table, each switchable. Measure cold and warm separately. The fixed-base table does not handle secret scalars.
- Profile first: time and memory of generator derivation, secret/public MSM, field operations, allocation, serialization and roster validation across increasing `n`.
- Evaluate fixed-base tables for proof generators and roster keys; report construction time, memory, reuse, cache invalidation and an off switch. The public G table has an ablation switch; its lookup is variable-time and is not used for secret scalars.
- Repeat MSM bucket experiments across process launches and sizes; retain backend defaults unless repeatable evidence supports a change.
- Evaluate proof generation alongside signing rounds only after measuring dependencies and actual parallel execution; report resource contention and sequential results too.
- A [public-operation mcl/libsecp256k1 comparison](docs/benchmarks/phase5-backend-public.md) covers two primitives and 100 cross-checks per launch; it is not a full backend or MSM comparison. Never silently change transcripts or encodings.
- Improve roster validation and allocation only after profiling; measure one signer and whole-system work separately. Do not evict replay IDs to improve performance.

## 3. Parameter matrix

Define `n` = registered roster size, `t` = threshold, `k = |S|` = selected signers, with `1 <= t <= k <= n`. Threshold is a per-message statement; the subset is fixed during each session.

- Core scaling: `n = 8,16,32,64,128,256,512,1024,2048,4096`; add 100 and 1000. Probe 8192 and 16384 if runtime and memory permit. The suite limit is 65535, not an assertion that these experiments are feasible.
- Boundaries: 1, 2, 3, 255, 256, 257, plus powers of two and adjacent sizes where dimensions change. Exercise surplus 255, 256 and higher.
- Thresholds at each size: `1`, `ceil(n/3)`, `floor(n/2)+1`, `ceil(2n/3)`, `n`; deduplicate. Select `k=t`, a middle value, and `k=n`, subject to runtime. At fixed `n,k`, vary `t`; at fixed `n,t`, vary `k`.
- Run a pilot first; capture timeouts, memory limits and uncompleted configurations instead of extrapolating. Do not use production runs before the weight fix and regression pass.

## 4. Measurements and comparisons

Use actual upstream FROST, MuSig2, hinTS, BIP340, and suitable BLS/threshold BLS implementations when buildable. Pin revisions, run applicable published/upstream vectors, record patches and licenses. Build small measurement drivers if necessary. Treat this as a cross-implementation comparison; languages, curves, backends, preprocessing, and security/functional properties differ. MuSig2 is multisignature, not a general t-of-n threshold scheme. Compare matching curves where available and label others separately. For FROST report dealer or actual DKG separately; do not assume one setup method. Record hinTS CRS and setup assumptions. Report unavailable fields as N/A.

| Experiment | Measurements |
|---|---|
| Setup | Per-party key and PoP, roster validation, generator derivation, setup interaction, messages, bytes and assumptions; distinguish cold from cached. |
| Signing | One-signer Round 1 and Round 2 distributions; aggregate CPU work over `k`; nonce and share aggregation; share checks; serialization. |
| Authorization | Prover time, allocations and peak memory; verifier Schnorr and C1–C4 where instrumentable. Distinguish proving from authentication of applications/users. |
| Verification | Single signature, cold and warm; batch throughput and per-signature cost at batch sizes 1, 2, 4, 8, 16, 32, 64 within limits. |
| End-to-end | Sequential measured wall time and actual parallel critical path if implemented; count two signing rounds. Separately label analytic LAN/WAN estimates and validate them against process/socket experiments where available. |
| Space and traffic | Actual serialized signature, roster and generator state; per-message and total bytes including framing, plus per-role peak RSS. |
| Faults | Dropout before/after each round, recovery from 5 to 4 of 8, below-threshold rejection, invalid shares, replay and malformed inputs; record detection and restart time. |
| Scaling | Sweep `n,t,k`; fit and plot trends with uncertainty. Record upper bounds reached, failure modes and crossover only if observed. |
| Ablation | Cache off/on, individual/batch verification, tables off/on if implemented, backend, bucket settings and parallel/sequential execution. |
| Reproducibility | Run upstream reference benchmarks or vectors and validate harness using known workloads; retain source, environment, raw results, analysis scripts and checksums. |

The current harness sums signer work in one process; it is not parallel signer wall time. It currently uses five samples per process and a batch of up to four; extend measurement before drawing paper-level conclusions.

## 5. Complexity model

Let `ell=ceil(log2(n+1))`, `N=n+ell+1`, `k=|S|`, and `MSM(m)` denote an m-base multiscalar multiplication. Counts below are algorithmic group/field operations from audit v5 §4, Algorithm 1, Algorithm 2 and checks C1–C4, assuming fixed-size group elements, already validated/cached public context, and a fixed-size message. MSM runtime depends on backend and scalar width; do not infer exact wall-time exponents from operation counts.

| Step | Cost and qualification |
|---|---|
| Key generation and PoP | O(1) group operations per participant; n parties O(n). Practical PoP is heuristic under the paper's ideal extractable-registration assumption. |
| Roster validation and digest | n PoP checks plus roster hashing: O(n) group/hash work; duplicate detection and implementation data structures can add O(n log n). |
| Generator derivation, cold | `2N+1` hash-to-curve calls: O(n) under fixed-size parameters; cache storage O(n). |
| Masked key | O(k) point additions plus one fixed-base scalar multiplication. |
| Round 1, one signer | Two fixed-base scalar multiplications, O(1) group work; processing the encoded subset and roster validation may add O(k) or O(n) or more depending on implementation. |
| Round 2, one signer | O(1) scalar/group operations and hashes on an already prepared context; hashing the full encoded context adds O(k + message length) byte work. |
| Coordinator aggregation | O(k) additions for commitments and responses; individual share verification adds O(k) group work. |
| Authorization proof | Two MSMs over approximately `2N+1` bases, one over `n+1` relevant bases, small MSMs and O(N) field work; O(n) proof working storage. Do not equate this to an exact backend wall-time bound. |
| Final verification | Schnorr check; C1 and C2 use MSMs of O(N) and O(n) bases; C3 O(N) field work; C4 constant-size group work. Generator setup and roster checks add cold costs. |
| Signature | `7` group elements and `2N+4` scalars abstractly: O(n) size; actual bytes include encoding/framing and identity representations. |
| Dropout recovery | Discard old selected-set session and repeat both rounds with fresh state. Cost includes detection, cleanup, new proof and work for new `k`; cannot reuse old nonces. |

Per-signer preprocessing and validation can change measured dependence on n and k. At fixed n, proof dimensions do not depend on t; witness construction and implementation costs can still vary with k. Measure rather than assume constant total signer time.

## 6. Execution order and evidence

- By 10 November target: phase 5 correctness fixes and regression gates, pilot matrix, usable upstream baseline builds, same-machine preliminary raw results and explicit limitations. Do not promise a full paper-ready study in two days. Report phase 5 status before starting a separate baseline phase.
- Paper study: complete phase gates, fuller matrix, multi-process repetitions, fault/network experiments, analysis and reproducibility artifact. Record deviations and failed hypotheses.
- Freeze exact source revisions for each result set; record dirty state, compiler, flags, CPU, OS, dependencies, clock, cache/preprocessing and timing mode. Warm up; randomize run order; target at least 30 timed samples across at least five independent process launches, reducing only with stated resource reasons. Summarize median, IQR and 95% confidence intervals using process launches appropriately; retain raw data and analysis code.
- No performance results establish proof validity, independent review, constant-time behavior or production readiness.

## 7. Preliminary measurements, 2026-11-08

The matrix in [README.md](README.md#latest-prototype-benchmark) reports means for eleven `(n,t,k)` configurations. Each uses five independent launches and five grouped timing samples per launch. Ten configurations use six sessions per group: 150 sessions but 25 grouped samples, not 150 independent measurements. The `n=512,t=256,k=256` case uses one session per group, or 25 sessions, to bound runtime. Setup is measured separately once per group. `signer_round1` and `signer_round2` sum all `k` signers in one process, not parallel or network latency. `n=512,t=1,k=1` exercises a large roster with one selected signer. The two `n=512` cases were collected separately with different group sizes and show substantial timing variation; do not infer a threshold effect from their means. The runs use variable-time secret operations; signer timeout is disabled.

Raw data and per-stage means/medians are in [the main matrix](docs/benchmarks/phase5-matrix-20261108/), [extended matrix](docs/benchmarks/phase5-matrix-extended-20261108/) and [large-threshold matrix](docs/benchmarks/phase5-matrix-large-threshold-20261108/). Metadata records the measured binary hash, compiler, build flags, CPU and OS. The extended run saved a source snapshot after the first run, with no intervening executable-code changes; the source tree was dirty and no frozen commit exists for these results. Runs were unpinned, on one host, and should be treated as exploratory. Reproduce with `python3 tools/run_phase5_matrix.py build/bench/protocol_bench OUTPUT_DIRECTORY`; use `--configs n,t,k ...` to choose cases. Generate the table with `python3 tools/summarize_phase5_matrix.py docs/benchmarks/phase5-matrix-20261108 docs/benchmarks/phase5-matrix-extended-20261108 docs/benchmarks/phase5-matrix-large-threshold-20261108`.

The public-generator fixed-base ablation used five process launches per mode and nine grouped samples per launch, five operations per sample. Its unpinned arithmetic means were 36.146 µs/op with the table and 120.367 µs/op without it. [Raw samples](docs/benchmarks/phase5-fixed-base-20261108.jsonl) and `tools/run_fixed_base_bench.py` retain the evidence. This compares public multiplication only; proof-generator tables and a constant-time secret path are not implemented.

The [mcl/libsecp256k1 public-operation comparison](docs/benchmarks/phase5-backend-public.md) reports five launches and 100 cross-checks per launch. It does not implement a full interchangeable protocol backend or general MSM comparison. The timeout-worker TSan target builds but this host fails at startup with `ThreadSanitizer: unexpected memory mapping`; race checking remains open. Neither these measurements nor the matrix are paper-grade results until the remaining controls, broader parameter sweep and external validation are complete.
