#!/usr/bin/env python3
"""Regenerate x25519_test_public_keys.json from x25519_test.json.

The Wycheproof XDH vectors carry each test's private key as a raw scalar,
but `lann:webcrypto`'s only secret-key import is the RFC 8037 OKP private
JWK, whose public coordinate `x` is mandatory. This script derives that
coordinate — X25519(clamp(private), 9), the RFC 7748 public key — for
every vector, so the conformance guest can build the JWK the interface
requires. The output maps tcId to the 32-byte u-coordinate in hex.

Self-checks against the RFC 7748 §6.1 key pairs before writing.
"""

import json
import os

P = 2**255 - 19


def clamp(scalar: bytes) -> int:
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def x25519(k: int, u: int) -> int:
    """RFC 7748 §5: the Montgomery ladder over GF(2^255 - 19)."""
    x1, x2, z2, x3, z3 = u, 1, 0, u, 1
    swap = 0
    for t in reversed(range(255)):
        k_t = (k >> t) & 1
        swap ^= k_t
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_t
        a = (x2 + z2) % P
        aa = (a * a) % P
        b = (x2 - z2) % P
        bb = (b * b) % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = (d * a) % P
        cb = (c * b) % P
        x3 = (da + cb) % P
        x3 = (x3 * x3) % P
        z3 = (da - cb) % P
        z3 = (z3 * z3) % P
        z3 = (z3 * x1) % P
        x2 = (aa * bb) % P
        z2 = (e * (aa + 121665 * e)) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, P - 2, P)) % P


def public_key(private_hex: str) -> str:
    k = clamp(bytes.fromhex(private_hex))
    return x25519(k, 9).to_bytes(32, "little").hex()


def self_check() -> None:
    # RFC 7748 §6.1: Alice's and Bob's published key pairs.
    pairs = [
        (
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        ),
        (
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        ),
    ]
    for private, expected in pairs:
        got = public_key(private)
        assert got == expected, f"self-check failed: {got} != {expected}"


def main() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    self_check()
    with open(os.path.join(here, "x25519_test.json")) as f:
        vectors = json.load(f)
    derived = {}
    for group in vectors["testGroups"]:
        for test in group["tests"]:
            derived[str(test["tcId"])] = public_key(test["private"])
    with open(os.path.join(here, "x25519_test_public_keys.json"), "w") as f:
        json.dump(derived, f, indent=0, sort_keys=False)
        f.write("\n")


if __name__ == "__main__":
    main()
