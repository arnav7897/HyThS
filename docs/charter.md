# Project charter

Working name: `hta-schnorr`. The permanent repository name and hosting destination are not yet chosen. Project authors are Arnav Sharda, Rineet Pandey, Kumar Bhaskar, and Dr R Kabaleeshwaran.

The project aims to produce a readable reference implementation of the protocol in `Threshold_Schnorr_Integrated_Proof_Audit_v5.pdf`, independently review its cryptographic design and implementation, and publish reproducible comparative benchmarks. The PDF is the source of truth for the scheme; a concrete suite must separately document any implementation choices that it leaves open.

The initial audience is cryptographic researchers and artifact evaluators. The repository is research software, not a production signing service. NIST-inspired documentation and testing are not NIST approval, algorithm validation, or FIPS module validation. Passing tests or reproducing algebra does not prove security, side-channel resistance, or the audit's proofs.

Code is licensed under Apache-2.0. The audit PDF's authorship and redistribution rights must be confirmed before public release. The draft suite and current helpers are not a frozen protocol specification.

Use version numbers `MAJOR.MINOR.PATCH`, starting with a `0.x` research release only after a release is explicitly prepared. Before 1.0, incompatible changes may require a minor version increment; patch versions preserve documented interfaces and encodings. Any incompatible suite encoding or transcript change requires a new suite identifier and new vectors. A version number does not imply a security audit. No release tag exists yet.

The team works one roadmap phase per branch and stops at each phase's exit criteria for review. Phase 0 must not be marked complete while its specification, independent review, and author decisions remain unresolved.
