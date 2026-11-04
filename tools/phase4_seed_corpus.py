#!/usr/bin/env python3
"""Write checked-in wire vectors and a valid signature as libFuzzer seeds."""

from pathlib import Path
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} CORPUS_DIR", file=sys.stderr)
        return 2
    corpus = Path(sys.argv[1])
    corpus.mkdir(parents=True, exist_ok=True)

    for line in Path("tests/vectors/phase3-wire-vectors.tsv").read_text().splitlines():
        name, encoded = line.split("\t", 1)
        (corpus / name).write_bytes(bytes.fromhex(encoded))

    for line in Path("tests/kats/phase3-basic.rsp").read_text().splitlines():
        if line.startswith("signature="):
            (corpus / "phase3-signature").write_bytes(bytes.fromhex(line.split("=", 1)[1]))
            return 0
    print("KAT signature seed not found", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
