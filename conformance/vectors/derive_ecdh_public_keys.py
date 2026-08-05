#!/usr/bin/env python3
"""Regenerate the ecdh_*_public_keys.json companions from the ECDH vector
files.

The Wycheproof ECDH `asn`- and `ecpoint`-encoded vectors carry each test's
private key as a raw scalar, but `polymorph:webcrypto`'s ECDH secret-key imports
are the platform formats — an EC private JWK, whose public coordinates
`x`/`y` RFC 7518 makes mandatory, or PKCS#8. This script derives those
coordinates — the affine point `d * G` — for every vector, so the
conformance guest can build the JWK the interface requires. Each output
maps tcId to the field-size `x` and `y` coordinates in hex.

Self-checks against every valid vector before writing: the x-coordinate of
`d * public` must equal the vector's published shared secret.

The webcrypto-encoded vector files need no companion: their keys are
already JWKs.
"""

import json
import os

CURVES = {
    "secp256r1": dict(
        p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
        size=32,
    ),
    "secp384r1": dict(
        p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
        b=0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
        gx=0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
        gy=0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
        size=48,
    ),
}

FILES = [
    ("ecdh_secp256r1_test", "secp256r1"),
    ("ecdh_secp256r1_ecpoint_test", "secp256r1"),
    ("ecdh_secp384r1_test", "secp384r1"),
    ("ecdh_secp384r1_ecpoint_test", "secp384r1"),
]


def scalar_mult(k, P, p):
    """Jacobian-coordinate double-and-add over a short-Weierstrass curve
    with a = -3 (the NIST curves). One field inversion total, at the final
    conversion back to affine; the per-vector self-check against the
    published shared secrets guards the formulas."""

    def dbl(X1, Y1, Z1):
        # dbl-2001-b (Bernstein), a = -3.
        delta = Z1 * Z1 % p
        gamma = Y1 * Y1 % p
        beta = X1 * gamma % p
        alpha = 3 * (X1 - delta) * (X1 + delta) % p
        X3 = (alpha * alpha - 8 * beta) % p
        Z3 = ((Y1 + Z1) * (Y1 + Z1) - gamma - delta) % p
        Y3 = (alpha * (4 * beta - X3) - 8 * gamma * gamma) % p
        return X3, Y3, Z3

    def add_mixed(X1, Y1, Z1, x2, y2):
        # madd-2007-bl (Bernstein–Lange), Z2 = 1.
        Z1Z1 = Z1 * Z1 % p
        U2 = x2 * Z1Z1 % p
        S2 = y2 * Z1 * Z1Z1 % p
        H = (U2 - X1) % p
        r = (2 * (S2 - Y1)) % p
        if H == 0:
            if r == 0:
                return dbl(X1, Y1, Z1)
            return None  # P + (-P): the point at infinity
        HH = H * H % p
        I = 4 * HH % p
        J = H * I % p
        V = X1 * I % p
        X3 = (r * r - J - 2 * V) % p
        Y3 = (r * (V - X3) - 2 * Y1 * J) % p
        Z3 = ((Z1 + H) * (Z1 + H) - Z1Z1 - HH) % p
        return X3, Y3, Z3

    x2, y2 = P
    acc = None  # the point at infinity, as None
    for bit in bin(k)[2:]:
        if acc is not None:
            acc = dbl(*acc)
        if bit == "1":
            acc = (x2, y2, 1) if acc is None else add_mixed(*acc, x2, y2)
    if acc is None:
        return None
    X, Y, Z = acc
    zi = pow(Z, p - 2, p)
    zi2 = zi * zi % p
    return (X * zi2 % p, Y * zi2 * zi % p)


def decode_point(hexstr, size):
    raw = bytes.fromhex(hexstr)
    if len(raw) != 1 + 2 * size or raw[0] != 0x04:
        return None
    return (
        int.from_bytes(raw[1 : 1 + size], "big"),
        int.from_bytes(raw[1 + size :], "big"),
    )


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    for name, curve_name in FILES:
        curve = CURVES[curve_name]
        p, size = curve["p"], curve["size"]
        g = (curve["gx"], curve["gy"])
        with open(os.path.join(here, f"{name}.json")) as f:
            vectors = json.load(f)
        out = {}
        for group in vectors["testGroups"]:
            for test in group["tests"]:
                tc_id, d_hex = test["tcId"], test["private"]
                d = int(d_hex, 16)
                x, y = scalar_mult(d, g, p)
                out[str(tc_id)] = {
                    "x": x.to_bytes(size, "big").hex(),
                    "y": y.to_bytes(size, "big").hex(),
                }
                # Self-check every valid vector: the x-coordinate of
                # d * public is the published shared secret. (The asn file's
                # public keys are SPKI; check only the ecpoint encodings.)
                if test["result"] == "valid" and vectors["testGroups"][0].get(
                    "encoding"
                ) == "ecpoint":
                    peer = decode_point(test["public"], size)
                    if peer is not None:
                        sx, _ = scalar_mult(d, peer, p)
                        shared = sx.to_bytes(size, "big").hex()
                        assert shared == test["shared"], (
                            f"{name} tc{tc_id}: derived shared secret "
                            f"disagrees with the vector"
                        )
        out_path = os.path.join(here, f"{name}_public_keys.json")
        with open(out_path, "w") as f:
            json.dump(out, f, indent=1)
            f.write("\n")
        print(f"wrote {out_path} ({len(out)} entries)")


if __name__ == "__main__":
    main()
