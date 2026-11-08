#!/usr/bin/env python3
"""Collect independent process samples from the phase 5 protocol benchmark."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import random
import statistics
import subprocess
import tarfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--launches", type=int, default=5)
    parser.add_argument("--iterations", type=int, default=6)
    parser.add_argument("--configs", nargs="+", default=["8,4,4", "8,4,5", "16,8,8",
                        "32,16,16", "64,32,32", "128,64,64", "256,128,128"])
    args = parser.parse_args()
    if args.launches < 1 or not 1 <= args.iterations <= 100:
        parser.error("invalid launch or iteration count")
    configs = [tuple(map(int, value.split(","))) for value in args.configs]
    if any(len(c) != 3 or not 1 <= c[1] <= c[2] <= c[0] <= 65535 for c in configs):
        parser.error("configs must be n,t,k with 1 <= t <= k <= n <= 65535")
    binary = args.binary.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=False)
    source_archive = args.output / "source-snapshot.tar.gz"
    tracked_and_untracked = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"]
    ).decode().split("\0")
    source_prefixes = ("src/", "include/", "bench/", "tests/", "tools/")
    with tarfile.open(source_archive, "w:gz") as archive:
        for name in sorted(set(tracked_and_untracked)):
            if name and (name.startswith(source_prefixes) or name in
                         {"CMakeLists.txt", "CMakePresets.json", "LICENSE"}) and Path(name).is_file():
                archive.add(name, recursive=False)
    meta = {"binary": str(binary), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "source_snapshot_sha256": hashlib.sha256(source_archive.read_bytes()).hexdigest(),
            "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
            "git_status": subprocess.check_output(["git", "status", "--porcelain"], text=True),
            "platform": platform.platform(), "cpu": platform.processor(),
            "launches": args.launches, "iterations_per_sample": args.iterations,
            "samples_per_launch": 5, "configs": configs, "order_seed": 20261108,
            "start_unix": time.time(), "note": "single-process sequential signer work; variable-time secrets"}
    cache = binary.parent / "CMakeCache.txt"
    if cache.exists():
        meta["cmake_cache_sha256"] = hashlib.sha256(cache.read_bytes()).hexdigest()
        meta["build_settings"] = [line for line in cache.read_text().splitlines()
                                  if line.startswith(("CMAKE_CXX_COMPILER:", "CMAKE_BUILD_TYPE:",
                                                      "CMAKE_CXX_FLAGS", "HTA_"))]
        compiler = next((line.split("=", 1)[1] for line in meta["build_settings"]
                         if line.startswith("CMAKE_CXX_COMPILER:")), None)
        if compiler:
            meta["compiler_version"] = subprocess.check_output([compiler, "--version"], text=True).splitlines()[0]
    diff = subprocess.check_output(["git", "diff", "--binary", "HEAD"])
    meta["tracked_diff_sha256"] = hashlib.sha256(diff).hexdigest()
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        meta["cpu_model"] = next((line.split(":", 1)[1].strip() for line in cpuinfo.read_text().splitlines()
                                  if line.startswith("model name")), "unknown")
    (args.output / "metadata.json").write_text(json.dumps(meta, indent=2) + "\n")
    rng = random.Random(meta["order_seed"])
    observations = {}
    with (args.output / "raw.jsonl").open("w") as raw:
        for launch in range(args.launches):
            order = configs[:]
            rng.shuffle(order)
            for n, t, k in order:
                command = [str(binary), str(args.iterations), str(n), str(t), str(k)]
                result = subprocess.run(command, text=True, capture_output=True, check=True)
                for line in result.stdout.splitlines():
                    row = json.loads(line)
                    row["launch"] = launch + 1
                    raw.write(json.dumps(row) + "\n")
                    if "samples_ns" in row:
                        key = (n, t, k, row["stage"])
                        unit = row["iterations_per_sample"]
                        observations.setdefault(key, []).extend(value / unit for value in row["samples_ns"])
                raw.flush()
                print(f"launch={launch + 1} n={n} t={t} k={k} complete", flush=True)
    with (args.output / "summary.jsonl").open("w") as summary:
        for (n, t, k, stage), values in sorted(observations.items()):
            summary.write(json.dumps({"n": n, "t": t, "k": k, "stage": stage,
                                      "samples": len(values), "mean_ns": statistics.mean(values),
                                      "median_ns": statistics.median(values),
                                      "min_ns": min(values), "max_ns": max(values)}) + "\n")


if __name__ == "__main__":
    main()
