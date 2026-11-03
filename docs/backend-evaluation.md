# Backend evaluation

Status: preliminary source review, 2026-11-03. No dependency is selected or pinned; no performance or constant-time claims have been verified.

The draft's first suite needs secp256k1 group arithmetic including the identity, canonical point and scalar handling, and RFC 9380 `secp256k1_XMD:SHA-256_SSWU_RO_` with the specified DST. Prover secret scalars and signer secrets require separately assessed timing behavior. Pairing and BLS12-381 support are needed for later comparison, not to establish correctness of the first suite.

| Candidate | Evidence | Open work |
| --- | --- | --- |
| [mcl](https://github.com/herumi/mcl) | Upstream describes BLS12-381, `mulVec`, and a history entry for secp256k1. Its [API documentation](https://github.com/herumi/mcl/blob/master/api.md) describes selectable hash-to-curve modes and global DST settings. | The cited pairing API does not establish RFC 9380 secp256k1 support. Verify concrete secp256k1 initialization, identity, scalar decoding, RFC vectors, thread safety, and secret-scalar timing at a pinned revision. Global settings must not silently mix suites. |
| [libsecp256k1](https://github.com/bitcoin-core/secp256k1) | Upstream documents secp256k1 operations and notes that its public API emphasizes higher-level interfaces. | Determine whether its supported public API can implement every required operation and identity case without private internals. Do not assume RFC 9380 support or constant-time multi-scalar multiplication. |
| [blst](https://github.com/supranational/blst) | Upstream describes BLS12-381 and RFC 9380 support; its [public header](https://github.com/supranational/blst/blob/master/bindings/blst.h) exposes G1 multi-scalar routines. | Useful for later BLS12-381 comparisons, not the draft secp256k1 suite. Verify API, subgroup checks, identity handling, and timing at a pinned revision. |

Before adopting a backend, record its immutable revision, license, build flags, platform and API calls. Run upstream RFC 9380 vectors for the exact curve and DST handling, canonical-encoding and identity tests, and independent arithmetic cross-checks. Treat variable-time secret operations as research-only and label benchmark results. Pinning a dependency or passing vectors is not an independent security review.

At mcl revision `9f49ba06593e2d426ab6fb9b0e17bc125a6f720c`, `sample/ecdh.cpp` initializes secp256k1 and demonstrates point multiplication. Its `api.md` describes little-endian field serialization and an all-zero fixed-width identity representation, which do not match the suite's big-endian scalars and single-byte identity. Its FAQ warns `setStr` may mask or truncate oversized values. A suite adapter must validate canonical input before conversion and explicitly implement the specified encodings. This is source inspection, not a selected dependency or evidence of constant-time behavior.

On Linux x86-64 with GCC 13.3, this revision built with `MCL_USE_GMP=OFF`. A temporary probe initialized secp256k1, serialized and round-tripped the generator, and serialized scalar one. The generator used a 33-byte prefix-plus-little-endian-x encoding; scalar one used 32-byte little-endian encoding. This probe does not validate malformed inputs, side-channel behavior, or other platforms.
