# ASIACCS27 vs FROST: Stage-by-Stage Comparison

> **Status:** research measurements only. Not a claim of production readiness, NIST approval, or a completed security audit.
>
> All times are **medians over 100 samples** (10 warm-ups, one pinned CPU core, secp256k1 with mcl). Numbers marked *derived* are simple arithmetic on the reported medians. Raw data and conditions: see [Fine print](#6-fine-print).

**Headline:** FROST has the smaller signature, the cheaper verification and the faster aggregation, because it does not build or check ASIACCS27's roster-bound authorization certificate. The one place the picture flips is the setup-inclusive final time at large `n`, where FROST's one-time dealer setup dominates.

**Jump to:** [1. Complexity](#1-time-and-space-complexity) · [2. Size](#2-size) · [3. Time by stage](#3-time-by-stage-measured) · [4. Inside the stages](#4-inside-the-stages-at-n--2048) · [5. Takeaways](#5-takeaways) · [6. Fine print](#6-fine-print)

---

## 0. What is being compared

- **FROST** (RFC 9591, secp256k1): `t` of `n` signers produce an ordinary 65-byte threshold Schnorr signature.
- **ASIACCS27**: the same kind of threshold signing, plus a **roster-bound authorization certificate**. The coordinator builds it, each signer checks it before signing, and the verifier checks it again with the signature.

**Symbols:** `n` roster size · `t = ⌈2n/3⌉` active signers · `N` proof vector size (`N = 2n` in these runs) · `r` folding rounds (full folding: `r = log₂N`, i.e. 7–13 here).

### The four stages used throughout

| Stage | ASIACCS27 | FROST |
|---|---|---|
| **Setup** | PoP (proof of possession) creation + verification for **one key** | One trusted-dealer Shamir setup for the **whole group** |
| **Aggregation** | Round 1 + Round 2 + coordinator forming = **authorization proof generation** | Round 1 + Round 2 + coordinator forming = binding factors, group commitment, response aggregation (no proof) |
| **Verification** | Certificate check + all share checks + final signature-and-certificate check | All share checks + final Schnorr check |
| **Final time** | Setup + Aggregation + Verification | Setup + Aggregation + Verification |

The certificate check at the start of an ASIACCS27 signer's Round 1 is counted under **Verification**, not Aggregation, so nothing is counted twice.

---

## 1. Time and space complexity

`O(n)` means "grows roughly in proportion to n"; `O(1)` means "does not grow with n". Big-O shows growth, not elapsed time or memory.

### 1.1 Time complexity, by stage

| Stage | ASIACCS27 | FROST | Plain meaning |
|---|---|---|---|
| **Setup** | **O(1) per key** (PoP create + verify); a full roster is `n` independent registrations | One dealer run for the whole group; measured to grow **faster than linearly** (≈ 812× when `n` grows 64×) | ASIACCS27 setup is per key and does not depend on roster size. FROST's dealer pays for the whole group at once. |
| **Aggregation** | Proof forming **O(N + n)**; signer Rounds 1–2 O(1) each; combining responses O(t) → overall **O(N + n)** | Signer Rounds 1–2 O(1) each; binding factors, group commitment and combining O(t) → overall **O(t)** | ASIACCS27 adds one roster-sized proof. FROST's work scales with the number of active signers. |
| **Verification** | Certificate check O(N + n) per signer; share checks O(t); final check **O(N + n)** + O(r) folding challenges | Share checks O(t); final check **O(1)** | FROST's final check never slows down as the roster grows. ASIACCS27's does. |
| **Final time** | **O(N + n)** | **O(t)** | With `t = ⌈2n/3⌉` and `N = 2n`, both whole sessions grow about linearly with `n` (measured: ≈ 73× vs ≈ 63× for a 64× bigger roster). ASIACCS27 has the larger constant. |

### 1.2 Space complexity

| Item | ASIACCS27 | FROST | Plain meaning |
|---|---|---|---|
| **Final signature** | O(r + N / 2^r); at full folding **O(log N)** | **O(1)**, 65 B | FROST is fixed-size. ASIACCS27 carries a compact, slowly growing proof. |
| **Public state** | **O(n + N)**: `n` roster keys + `2N+3` generators | **O(n)**: group key + `n` verification shares | Both grow with the roster. ASIACCS27 also stores a roster-sized generator set. |
| **Coordinator / prover live state** | O(N + n) | O(t) | Both hold per-session records. ASIACCS27 also holds proof working state. |
| **Signer secret state** | O(1) | O(1) | Same for both. |

These are analytic bounds. **Peak RSS was not measured.**

---

## 2. Size

### 2.1 Signature and public state (full folding for ASIACCS27)

| n | Signature: ASIACCS27 | Signature: FROST | Public state: ASIACCS27 | Public state: FROST |
|---:|---:|---:|---:|---:|
| 64 | 1,186 B | 65 B | 10,659 B | 2,145 B |
| 256 | 1,338 B | 65 B | 42,339 B | 8,481 B |
| 1,024 | 1,490 B | 65 B | 169,059 B | 33,825 B |
| 2,048 | 1,566 B | 65 B | 338,019 B | 67,617 B |
| 4,096 | 1,642 B | 65 B | 675,939 B | 135,201 B |

- **Signature:** ASIACCS27 is ≈ 18× (n=64) to ≈ 25× (n=4,096) larger (*derived*). FROST is flat.
- **Public state:** ASIACCS27 is ≈ 5× larger at every `n` (*derived*). Both are analytic serialized point bytes (33 B per compressed point), not process memory.

### 2.2 Messages and registration

| Item | n=64 | n=256 | n=1,024 | n=2,048 | n=4,096 |
|---|---:|---:|---:|---:|---:|
| ASIACCS27 Round-1 request (coordinator → each signer) | 1,863 B | 3,679 B | 10,487 B | 19,442 B | 37,263 B |

- ASIACCS27 registration record: **175 B per key** (independent of `n`).
- FROST uses the RFC 9591 commitment list; its byte size was not reported.
- The ASIACCS27 request grows with `n` because each selected signer index is encoded as a framed integer.

### 2.3 Folding trades signature size against proving time (ASIACCS27 only, n = 2,048)

| Folding rounds | Signature | Round-1 request | Prove | Full verify |
|---|---:|---:|---:|---:|
| r = 0 (none) | 303,684 B | 321,560 B | 771 ms | 165 ms |
| r = 9 | 1,856 B | 19,732 B | 1,601 ms | 175 ms |
| r = 12 (full) | 1,566 B | 19,442 B | 1,615 ms | 184 ms |
| *FROST (for reference)* | *65 B* | *RFC list* | *no proof step* | *0.13 ms* |

Full folding makes the signature ≈ 194× smaller than r = 0, for ≈ 2.1× the proving time and ≈ 1.1× the verification time (*derived*). Most of the benefit arrives by r = 9.

---

## 3. Time by stage (measured)

Milliseconds. **Final time = Setup + Aggregation + Verification.** *Aggregation is derived as the measured session total minus the measured Verification*, so Aggregation + Verification equals the measured session time exactly.

| n | Scheme | Setup (one-time) | Aggregation | Verification | **Final time** |
|---:|---|---:|---:|---:|---:|
| 64 | ASIACCS27 | 0.122 *(per key)* | 88.6 | 31.4 | **120.0** |
| 64 | FROST | 20.4 *(per group)* | 17.6 | 12.5 | **50.6** |
| 256 | ASIACCS27 | 0.122 *(per key)* | 324.6 | 101.3 | **426.0** |
| 256 | FROST | 118.5 *(per group)* | 67.2 | 49.3 | **235.0** |
| 1,024 | ASIACCS27 | 0.122 *(per key)* | 1,232.5 | 382.7 | **1,615.3** |
| 1,024 | FROST | 870.0 *(per group)* | 281.5 | 194.3 | **1,345.8** |
| 2,048 | ASIACCS27 | 0.122 *(per key)* | 1,804.6 | 559.6 | **2,364.3** |
| 2,048 | FROST | 5,262.2 *(per group)* | 499.9 | 333.2 | **6,095.4** |
| 4,096 | ASIACCS27 | 0.122 *(per key)* | 6,734.8 | 2,019.6 | **8,754.6** |
| 4,096 | FROST | 16,577.9 *(per group)* | 1,127.2 | 768.9 | **18,474.0** |

> **Setup scopes differ.** ASIACCS27's setup figure is **one key**; FROST's is **the whole group**. ASIACCS27 full-roster setup was not measured. As a rough, *derived* estimate (not a measurement), registering all `n` keys would cost about `n × 0.122 ms`, i.e. 7.8 ms at n=64 up to about 500 ms at n=4,096. Setup is paid **once**, while aggregation and verification are paid **per signature**.

### Gap at a glance (ASIACCS27 ÷ FROST, *derived*)

| n | Aggregation | Verification | Session (Agg + Ver) | Final incl. setup |
|---:|---:|---:|---:|---:|
| 64 | ≈ 5.0× | ≈ 2.5× | ≈ 4.0× | ≈ 2.4× |
| 256 | ≈ 4.8× | ≈ 2.1× | ≈ 3.7× | ≈ 1.8× |
| 1,024 | ≈ 4.4× | ≈ 2.0× | ≈ 3.4× | ≈ 1.2× |
| 2,048 | ≈ 3.6× | ≈ 1.7× | ≈ 2.8× | **≈ 0.39×** (ASIACCS27 faster) |
| 4,096 | ≈ 6.0× | ≈ 2.6× | ≈ 4.6× | **≈ 0.47×** (ASIACCS27 faster) |

Values above 1× mean ASIACCS27 takes longer; below 1× means it takes less time. The setup-inclusive final time crosses over between n = 1,024 and n = 2,048 because FROST's dealer setup grows much faster than its signing session. This holds even if ASIACCS27 is charged the `n × 0.122 ms` estimate above.

---

## 4. Inside the stages at n = 2,048

Where the Aggregation and Verification time actually goes (ms, medians).

| Stage | Piece | ASIACCS27 | FROST |
|---|---|---:|---:|
| **Aggregation** | Coordinator forming *(ASIACCS27: authorization proof; FROST: binding factors + group commitment + response aggregation)* | 1,615.3 | 204.5 |
| | Round 1 + Round 2 (+ combining, for ASIACCS27), all `t` signers | ≈ 189.3 *(derived)* | 278.6 |
| | **Aggregation total** | **1,804.6** | **499.9** |
| **Verification** | Certificate check | 184.5 | none |
| | Share checks, all `t` | ≈ 190.9 *(derived)* | 333.1 |
| | Final check | 184.1 | 0.13 |
| | **Verification total** | **559.6** | **333.2** |
| **Session total** | Aggregation + Verification | **2,364.2** | **833.1** |

- **ASIACCS27:** the authorization proof is ≈ 88–90 % of Aggregation at every tested `n` (*derived*). Verification is split almost evenly between the certificate check, the share checks and the final check.
- **FROST:** the cost sits in Round 1, the group commitment and the share checks. Its final check is negligible (0.13 ms).
- FROST's pieces are stage medians, so they sum to within about 3 % of the totals (medians do not add exactly).

---

## 5. Takeaways

1. **Complexity and size:** FROST's signature and final check are `O(1)` (65 B, ≈ 0.15 ms). ASIACCS27's grow with the roster (1.2–1.6 KB signature, 11.6–655 ms final check) because they carry and check the authorization certificate.
2. **Setup:** ASIACCS27 registers keys independently at 0.122 ms per key. FROST's dealer setup covers the whole group and grows from 20 ms to 16.6 s (n = 64 → 4,096). The two are not like-for-like.
3. **Aggregation:** ASIACCS27 is ≈ 3.6–6× slower, almost entirely because of proof generation.
4. **Verification:** ASIACCS27 is ≈ 1.7–2.6× slower once share checks are included.
5. **Final time:** per signing session ASIACCS27 is ≈ 2.8–4.6× slower. Including one-time setup, FROST is faster up to n = 1,024 and ASIACCS27 is faster from n = 2,048 upward.

---

## 6. Fine print

- **Different statements are verified.** FROST checks one Schnorr signature. ASIACCS27 checks signature + certificate. Gaps show the cost of the extra proof, not like-for-like speed.
- **Sequential, one process.** All signers run one after another on one core. These are not network latency, parallel speed-up or distributed end-to-end latency. The ASIACCS27 sequential total counts the certificate check **once**; in a real deployment each of the `t` signers performs it on its own hardware.
- **Not the earlier "Total" column.** The earlier report's Total (setup + aggregation + verification) left out proof generation and signer rounds. The Final time here is a whole-session figure, so the two should not be compared.
- **Noisier at the top end.** n = 4,096 has the widest spread (ASIACCS27 session total p25–p75: 7.75–9.41 s). Full spreads are in the raw tables.
- **Not measured:** peak RSS, constrained-device memory, network delay, concurrent throughput, distributed latency. Security bounds are analytic. Variable-time secret operations remain a research-code limitation.

| Condition | Value |
|---|---|
| Host | Ubuntu 24.04, Intel Core i5-1240P, GCC 13.3.0, Release `-O3 -DNDEBUG`, one process/thread pinned to CPU 2 |
| Backend | mcl secp256k1; OpenSSL 3 for hashing and randomness (both schemes) |
| ASIACCS27 | `HTA-secp256k1-asiaccs27-v1`; every certificate and final signature verified |
| FROST | RFC 9591 FROST(secp256k1, SHA-256), repository driver; RFC 9591 Appendix E.5 vector self-test; every share and final signature verified |
| Samples | 10 warm-ups, 100 measured sessions per `n`; `n ∈ {64, 256, 1,024, 2,048, 4,096}` |

Raw JSONL, CSV summaries, environment details and source revision: branch `asiaccs27/bench`, folder [`docs/benchmarks/asiaccs27-20261116/`](docs/benchmarks/asiaccs27-20261116/) (`metadata.md`, `tables.md`, `aggregation-setup-verification.csv`).

```sh
taskset -c 2 ./build-asiaccs-release/asiaccs27_bench 4096 13 100 > docs/benchmarks/asiaccs27-20261116/release-n4096-r13.jsonl
taskset -c 2 ./build-asiaccs-release/asiaccs27_frost_baseline 4096 100 > docs/benchmarks/asiaccs27-20261116/release-frost-n4096.jsonl
python3 tools/summarize_asiaccs27.py
```
