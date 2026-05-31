from __future__ import annotations

from app.crypto.sha256 import sha256

BLOCK_SIZE = 64


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    if len(key) > BLOCK_SIZE:
        key = sha256(key)
    key = key.ljust(BLOCK_SIZE, b"\x00")
    outer = bytes(byte ^ 0x5C for byte in key)
    inner = bytes(byte ^ 0x36 for byte in key)
    return sha256(outer + sha256(inner + message))


def constant_time_equal(left: bytes, right: bytes) -> bool:
    if len(left) != len(right):
        return False
    diff = 0
    for l_byte, r_byte in zip(left, right):
        diff |= l_byte ^ r_byte
    return diff == 0
