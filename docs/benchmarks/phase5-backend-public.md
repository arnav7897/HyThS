# Public secp256k1 backend microbenchmark

Captured 2026-11-08 UTC on an Intel Core i5-1240P. The prototype mcl adapter was built with the `bench` CMake preset (`-O3 -DNDEBUG`), at mcl revision `9f49ba06593e2d426ab6fb9b0e17bc125a6f720c`. Comparison used Ubuntu Noble's `libsecp256k1` 0.2.0-2 binaries, extracted into `/tmp/hyths-secp`; neither package was installed. Package SHA-256: development `597adcb084fb41d073db42080477d6db190a88eea6b366c18593691b867882e5`, runtime `7e435140687357fd20b08da85e390902e5cb504588cf53c57aba0a06ee2d96a4`.

Source: `bench/secp256k1_backend_compare.cpp`. Five independent processes each cross-checked 100 full-width nonzero scalars for generator and variable-base multiplication, comparing compressed outputs, then collected five samples of 1,000 operations for each backend and operation. Raw sample totals are in `phase5-backend-public.jsonl`.

Arithmetic mean across all 25 samples, microseconds per operation:

| Operation | mcl adapter | libsecp256k1 public API |
|---|---:|---:|
| Generator multiplication | 33.94 | 64.72 |
| Variable-point multiplication | 108.28 | 105.56 |

These are exploratory measurements, not proof of equivalent side-channel behavior or a full protocol comparison. mcl's public operations are variable-time; libsecp256k1 public APIs have different internal guarantees and validation paths. Both include canonical compressed serialization, and variable multiplication includes point parsing. Operations use deterministic full-width input scalars; other CPU load, core frequency, thermal effects and compiler/library builds were not controlled. The public libsecp256k1 API does not supply this project's general MSM/identity interface. Measurements do not establish an interchangeable backend or indicate whole-protocol performance.

Reproduction after extracting the two recorded Ubuntu packages and building the existing `bench` preset:

```sh
g++ -std=c++17 -O3 -DNDEBUG -Iinclude -I/tmp/hyths-secp/usr/include bench/secp256k1_backend_compare.cpp build/bench/libhta_secp256k1_public.a build/bench/lib/libmcl.a build/bench/libhta_framing.a -L/tmp/hyths-secp/usr/lib/x86_64-linux-gnu -lsecp256k1 -lcrypto -o /tmp/hyths-backend-compare
LD_LIBRARY_PATH=/tmp/hyths-secp/usr/lib/x86_64-linux-gnu /tmp/hyths-backend-compare 1000
```

Repeat the executable five times for five independent process launches. The executable checks backend equality before producing each run's timing samples and exits nonzero on mismatch.
