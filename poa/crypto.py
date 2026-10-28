"""Pure-Python ECDSA over secp256k1 with deterministic nonces.

Kept dependency-free so the whole project runs on a stock Python install.
Not constant-time: fine for a simulation, not for production keys.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

# secp256k1 domain parameters
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

Point = tuple[int, int] | None  # None is the point at infinity


def _add(a: Point, b: Point) -> Point:
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def _mul(k: int, pt: Point) -> Point:
    result: Point = None
    while k:
        if k & 1:
            result = _add(result, pt)
        pt = _add(pt, pt)
        k >>= 1
    return result


def _on_curve(pt: Point) -> bool:
    return pt is not None and (pt[1] ** 2 - pt[0] ** 3 - 7) % P == 0


def sha3(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def canonical(obj) -> bytes:
    """Deterministic JSON encoding used for every hash in the system."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def hash_obj(obj) -> str:
    return sha3(canonical(obj)).hex()


def encode_pubkey(pt: Point) -> str:
    assert pt is not None
    return f"{pt[0]:064x}{pt[1]:064x}"


def decode_pubkey(hexstr: str) -> Point:
    if len(hexstr) != 128:
        raise ValueError("bad public key length")
    pt = (int(hexstr[:64], 16), int(hexstr[64:], 16))
    if not _on_curve(pt):
        raise ValueError("public key not on curve")
    return pt


def address_of(pubkey_hex: str) -> str:
    """Ethereum-style 20-byte address (sha3-256 stands in for keccak-256)."""
    return "0x" + sha3(bytes.fromhex(pubkey_hex))[-20:].hex()


@dataclass(frozen=True)
class Signature:
    r: int
    s: int
    pubkey: str  # carried explicitly since we don't implement key recovery

    def to_dict(self) -> dict:
        return {"r": f"{self.r:064x}", "s": f"{self.s:064x}", "pubkey": self.pubkey}

    @classmethod
    def from_dict(cls, d: dict) -> "Signature":
        return cls(int(d["r"], 16), int(d["s"], 16), d["pubkey"])

    @property
    def signer(self) -> str:
        return address_of(self.pubkey)


class PrivateKey:
    def __init__(self, secret: int):
        if not 1 <= secret < N:
            raise ValueError("private key out of range")
        self.secret = secret
        self.pubkey = encode_pubkey(_mul(secret, G))
        self.address = address_of(self.pubkey)

    @classmethod
    def from_seed(cls, seed: str) -> "PrivateKey":
        return cls(int.from_bytes(sha3(seed.encode()), "big") % (N - 1) + 1)

    def _nonce(self, z: int, attempt: int) -> int:
        # Simplified RFC 6979: k = HMAC(d, z || attempt), so signing never
        # depends on an RNG and the same message always yields the same k.
        key = self.secret.to_bytes(32, "big")
        msg = z.to_bytes(32, "big") + attempt.to_bytes(4, "big")
        return int.from_bytes(hmac.new(key, msg, hashlib.sha256).digest(), "big") % N

    def sign(self, digest_hex: str) -> Signature:
        z = int(digest_hex, 16) % N
        attempt = 0
        while True:
            k = self._nonce(z, attempt)
            attempt += 1
            if k == 0:
                continue
            r = _mul(k, G)[0] % N
            if r == 0:
                continue
            s = pow(k, -1, N) * (z + r * self.secret) % N
            if s == 0:
                continue
            if s > N // 2:  # low-s normalisation prevents signature malleability
                s = N - s
            return Signature(r, s, self.pubkey)


def verify(digest_hex: str, sig: Signature) -> bool:
    try:
        pub = decode_pubkey(sig.pubkey)
    except ValueError:
        return False
    if not (1 <= sig.r < N and 1 <= sig.s <= N // 2):
        return False
    z = int(digest_hex, 16) % N
    w = pow(sig.s, -1, N)
    pt = _add(_mul(z * w % N, G), _mul(sig.r * w % N, pub))
    return pt is not None and pt[0] % N == sig.r
