#!/bin/sh
set -eu

iterations=${1:-1000}
cmake --preset bench -DHTA_BUILD_BENCH=ON
cmake --build --preset bench --target primitive_bench
mkdir -p docs/benchmarks
metadata=docs/benchmarks/e1-prototype-metadata.txt
results=docs/benchmarks/e1-prototype.jsonl
{
  printf 'commit='; git rev-parse HEAD
  printf 'date_utc='; date -u +%Y-%m-%dT%H:%M:%SZ
  printf 'system='; uname -a
  printf 'cpu='; awk -F: '/model name/ {gsub(/^ +/, "", $2); print $2; exit}' /proc/cpuinfo 2>/dev/null || true
  printf 'compiler='; c++ --version | head -n 1
  printf 'openssl='; openssl version
  printf 'cmake='; cmake --version | head -n 1
  printf 'iterations_per_sample=%s\n' "$iterations"
  printf 'mode=public-input research prototype; variable-time; not a security claim\n'
} > "$metadata"
./build/bench/primitive_bench "$iterations" > "$results"
