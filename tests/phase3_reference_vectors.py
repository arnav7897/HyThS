"""Independent, dependency-free wire-format reference vectors for Phase 3."""

from pathlib import Path
import struct


G = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
ZERO = bytes(32)


def frame(tag, payload):
    return bytes((tag,)) + struct.pack(">I", len(payload)) + payload


def integer(value):
    return frame(3, value.to_bytes(8, "big"))


def transcript(label, *fields):
    payload = frame(2, b"HTA-secp256k1-v1") + frame(2, label.encode("ascii"))
    return frame(1, payload + b"".join(fields))


def vectors():
    point = frame(4, G)
    scalar = frame(5, ZERO)
    subset = transcript("SUBSET", frame(6, integer(1)))
    registration = transcript("REGISTER", integer(1), point, point, scalar)
    round_one_request = transcript(
        "ROUND1-REQUEST",
        integer(1),
        frame(2, b"s"),
        frame(2, ZERO),
        integer(1),
        frame(2, b"m"),
        point,
        frame(2, subset),
    )
    round_one_response = transcript("ROUND1-RESPONSE", integer(1), frame(2, b"s"), point, point)
    round_two_request = transcript("ROUND2-REQUEST", integer(1), frame(2, b"s"), point, point)
    round_two_response = transcript("ROUND2-RESPONSE", integer(1), frame(2, b"s"), scalar)

    scalar_vector = frame(6, scalar * 3)
    proof = transcript(
        "PROOF",
        *([point] * 5),
        scalar_vector,
        scalar_vector,
        scalar,
        scalar,
        scalar,
    )
    signature = transcript("SIGNATURE", point, point, scalar, frame(2, proof))
    return {
        "registration": registration,
        "round_one_request": round_one_request,
        "round_one_response": round_one_response,
        "round_two_request": round_two_request,
        "round_two_response": round_two_response,
        "authorization_proof": proof,
        "signature": signature,
    }


def write_vectors(path):
    path = Path(path)
    path.write_text("".join(f"{name}\t{data.hex()}\n" for name, data in vectors().items()))


if __name__ == "__main__":
    write_vectors(Path(__file__).parent / "vectors" / "phase3-wire-vectors.tsv")
