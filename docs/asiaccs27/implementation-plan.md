# ASIACCS27 phase gates and source mapping

## Baseline inspection

At baseline `3f2561b6af6a844b065c92906947cc5634733db6`, the C++ core has registration/PoP, two-nonce signer state, coordinator share checking/aggregation, explicit-vector authorization, final and randomized batch verification, codecs, and primitive adapters. Tests, deterministic vectors, fuzz drivers and benchmark artifacts exist. This specification phase does not rerun or certify that evidence. Historical flow.md entries describing no implementation are superseded by its latest status entry.

No `.ua/knowledge-graph.json` or legacy knowledge graph was available during inspection. No graph-derived review result is claimed.

| Area | Audit-v5 source and implementation | Submission replacement |
| --- | --- | --- |
| Dimensions | Equations (1)-(3); parameters/generator_derivation | (3.1)-(3.2), Definition 3.1: power-of-two N, Gxi/Gip |
| Witness and commitments | Algorithm 2; authorization | (5.6)-(5.10), Algorithm 2: separate xi commitment and mu_xi |
| Proof verification | C1-C4; authorization | (5.11), V1/V2; folded inner product |
| Compression | Explicit vL/vR in AuthorizationProof | Algorithm 3; r pairs, terminal a/b |
| Signer | Algorithm 1; signer | Algorithm 1 lines 1-6: verify certificate before nonce sampling; optional mask check |
| Challenges | Audit final verifier omits certificate from SIG | (5.3)-(5.5): certificate bound to CTX and SIG |
| Coordinator | Existing protocol benchmark proves after signing | Section 5.1: prove before collecting nonces |
| Encoding | protocol_encoding, suite-draft | New suite, proof fields and Round-1 certificate/mode |
| Registration | Audit equation (4); registration | Submission Section 4; retain heuristic PoP, new domains |

## Phase 1: specification

Branch `asiaccs27/spec` starts from the baseline above. Deliver specification.md, this source map, benchmark-contract.md and sizes.md. Update roadmap pointers and decision/current-flow records. Preserve the untracked submission PDF. Do not change cryptographic source, merge, or push main.

Exit checks: exact transcript and wire definitions; nonce and validation policy; both signing modes; analytic tables independently recalculated; resource-limit arithmetic checked; document links valid; git diff whitespace clean; AGENTS.md, decision.md and flow.md each below 100 lines. Report and stop. Specification freeze is an implementation target, not an independent security review.

## Phase 2: core

Create `asiaccs27/core` from accepted spec branch. Implement in dependency order:

1. Suite domains, dimensions, generator extension, proof/configuration types and strict codecs.
2. New explicit-vector authorization at r=0; readable algebra reference and vectors.
3. Algorithm 3 folding and V1/V2 for all r; differential verification against explicit folded-generator calculations.
4. Certificate-first coordinator flow and signer checks; both modes; transcript binding; lifecycle accounting.
5. Replace all suite-dependent tests, fixtures, tools and examples. Disable v5 batching; preserve primitive regression tests.

Tests must include n=1, threshold endpoints, power-of-two boundary transitions, exact and surplus signer sets, every supported r on small rosters, and smoke coverage of all benchmark n values. Reject wrong masks, malformed or oversized proofs, noncanonical scalars/points, identity forbidden points, changed messages/rosters/configurations, altered folding challenges and proof substitutions. Allow identity intermediate commitments when equations hold. Check mutation of each proof field, terminal vector and fold pair; malformed counts, zero challenge retry via test oracle, r=0 empty folds, and mismatched expected r.

Exercise duplicate Round 1 races, duplicate Round 2, cancellation, timeout, memory/replay caps, invalid certificate before nonce allocation, cross-session state isolation and both mode policies. Keep deterministic test RNG separate from production CSPRNG. Include full encode/decode vectors and byte reproducibility; independent algebra oracle plus external vectors where available. Self-generated vectors are not independent evidence.

Exit: debug and ASan/UBSan tests pass, protocol KATs reproducible, negative and differential checks pass, fuzz smoke passes, source mapping updated, limitations documented. Attempt TSan; explicitly report host limitations rather than claiming a pass. Review changes with available ponytail/review tools; use graph review only if a graph exists. Stop and report before benchmarks.

## Phase 3: comparison

Create `asiaccs27/bench` from accepted core branch. Follow benchmark-contract.md. Implement and validate same-library baselines before collecting the full matrix. Separate raw data from derived tables and preserve the exact source/environment manifest.

Exit: at least 100 valid measured samples per required configuration/stage, errors reported rather than silently discarded, reproducible Tables A/B and concurrency plots, actual versus analytic sizes reconciled, baseline vectors checked, full raw records and command manifest retained. Stop and report. Main is unchanged until separately authorized.
