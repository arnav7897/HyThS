# Benchmark hypotheses

Registered 2026-11-03, before protocol performance measurements. These are predictions, not results. The existing toy algebra and framing tests are correctness checks, not performance measurements. Amend this file with a dated explanation before inspecting relevant results; retain earlier revisions in version control.

## Comparisons and measurements

Compare within the same curve family, machine, compiler configuration, and backend where possible. Report upstream implementations separately, including language and implementation differences. Measure actual serialized bytes and raw timings. Separate cold setup from warm execution, signer cost from coordinator and verifier cost, and sequential elapsed time from measured parallel critical path. Record n, t, signer count, scheme, version, curve, backend, platform, build flags, cache state, and secret-scalar timing mode. Report setup and security assumptions alongside results; unavailable comparisons are N/A.

For each configuration, capture environment and immutable source revisions, warm up, then collect at least 30 timed samples across at least five process launches. Randomize configuration order, preserve raw results and configuration, and report distributions and confidence intervals. Treat the process launch as the independent unit where appropriate. Do not substitute toy-group timings for real cryptographic measurements.

## Predictions

| ID | Prediction | Measurement |
| --- | --- | --- |
| H1 | Per-signer two-round cost is within 1.2× of matched MuSig2 and FROST implementations. | Compare per-signer round times with preprocessing and protocol differences reported. |
| H2 | Authorization proof cost scales approximately linearly with roster size n and has no systematic dependence on threshold t at fixed n. | Measure proof time and allocation at several n and t; report fitted trends and uncertainty. |
| H3 | Warm verification cost increases with n and shows no systematic dependence on t at fixed n. | Measure end-to-end verification and C1–C4 separately, including serialization and roster context assumptions. |
| H4 | The measured signature is larger than hinTS for the tested n ≥ 2. | Compare bytes from actual serializers, with curve and feature differences labeled. |
| H5 | Per-party key generation and PoP setup require no interactive key generation and remain approximately constant as n grows. | Separate per-party work from O(n) roster validation and generator derivation; compare setup assumptions. |
| H6 | A crossover exists in the tested range where total cost changes relative to hinTS. | Measure comparable end-to-end costs for each network profile; report no crossover if none is observed. |
| H7 | A fixed-subset signer dropout causes a restart and greater recovery latency than a noninteractive hinTS collection under matched failure conditions. | Inject the same dropout and include detection and restart costs; state baseline-specific behavior. |
| H8 | Prover memory grows with n and is dominated by authorization vectors. | Measure per-role peak memory and report measurement method and allocator effects. |

Predictions can fail. Report all results and deviations, not only favorable comparisons. The audit's O(n) signature and verification structure is an analytical expectation, not a measured result. Numerical predictions such as 1.2× and a crossover are speculative and may depend strongly on implementation and hardware.
