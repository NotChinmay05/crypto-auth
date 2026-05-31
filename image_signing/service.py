from __future__ import annotations

import io
import json
import os
import time
import uuid
from hashlib import sha256 as stdlib_sha256
from dataclasses import dataclass
from typing import Any

from PIL import Image, UnidentifiedImageError

from app.crypto.hmac import constant_time_equal, hmac_sha256

MAGIC = b"CIS1"
SIGNATURE_SIZE = 32
LENGTH_SIZE = 4
HEADER_SIZE = len(MAGIC) + LENGTH_SIZE
ALGORITHM = "LSB-RED-HMAC-SHA256"


class ImageSigningError(Exception):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


@dataclass(frozen=True)
class EmbeddedPayload:
    certificate: dict[str, Any]
    certificate_bytes: bytes
    signature: bytes
    payload_bytes: bytes
    carrier_pixels: int


class ImageSigningService:
    def __init__(self, signing_key: bytes | None = None) -> None:
        self.signing_key = signing_key or _load_key("IMAGE_SIGNING_KEY", 32)

    def sign(self, image_bytes: bytes, author: str | None = None) -> tuple[bytes, dict[str, Any]]:
        image = _load_rgb_image(image_bytes)
        pixel_bytes = bytearray(image.tobytes())
        if not pixel_bytes:
            raise ImageSigningError("image has no pixels")

        certificate = self._build_certificate(pixel_bytes, author)
        certificate_bytes = _json_bytes(certificate)
        signature = hmac_sha256(self.signing_key, certificate_bytes)
        payload = _pack_payload(certificate_bytes, signature)
        _ensure_capacity(pixel_bytes, len(payload))

        _embed_payload(pixel_bytes, payload)
        signed = Image.frombytes("RGB", image.size, bytes(pixel_bytes))

        out = io.BytesIO()
        signed.save(out, format="PNG", compress_level=1)
        return out.getvalue(), {
            "certificate": certificate,
            "payload_bytes": len(payload),
            "carrier_pixels": len(payload) * 8,
            "capacity_bytes": _pixel_count(pixel_bytes) // 8,
        }

    def verify(self, image_bytes: bytes) -> dict[str, Any]:
        image = _load_rgb_image(image_bytes)
        pixel_bytes = image.tobytes()
        try:
            embedded = self._extract(pixel_bytes)
        except ImageSigningError as exc:
            return {"status": "UNSIGNED", "reason": exc.message, "certificate": None}

        expected_signature = hmac_sha256(self.signing_key, embedded.certificate_bytes)
        hmac_valid = constant_time_equal(expected_signature, embedded.signature)
        hash_valid = False
        recomputed_hash = None
        if hmac_valid:
            recomputed_hash = _canonical_hash(pixel_bytes, embedded.carrier_pixels)
            hash_valid = recomputed_hash == embedded.certificate.get("hash")

        status = "AUTHENTIC" if hmac_valid and hash_valid else "TAMPERED"
        reasons = []
        if not hmac_valid:
            reasons.append("certificate signature does not match")
        if hmac_valid and not hash_valid:
            reasons.append("pixel hash does not match certificate")

        return {
            "status": status,
            "reason": "; ".join(reasons) if reasons else "image signature and pixel hash are valid",
            "certificate": embedded.certificate,
            "hmac_valid": hmac_valid,
            "pixel_hash_valid": hash_valid,
            "expected_hash": embedded.certificate.get("hash"),
            "actual_hash": recomputed_hash,
            "payload_bytes": len(embedded.payload_bytes),
            "carrier_pixels": embedded.carrier_pixels,
        }

    def inspect(self, image_bytes: bytes) -> dict[str, Any]:
        image = _load_rgb_image(image_bytes)
        pixel_bytes = image.tobytes()
        embedded = self._extract(pixel_bytes)
        return {
            "magic": MAGIC.decode("ascii"),
            "certificate": embedded.certificate,
            "certificate_json": embedded.certificate_bytes.decode("utf-8"),
            "signature_hex": embedded.signature.hex(),
            "payload_hex": embedded.payload_bytes.hex(),
            "payload_bytes": len(embedded.payload_bytes),
            "carrier_pixels": embedded.carrier_pixels,
            "capacity_bytes": _pixel_count(pixel_bytes) // 8,
            "warning": "Inspection extracts embedded data but does not verify authenticity.",
        }

    def _build_certificate(self, pixel_bytes: bytes, author: str | None) -> dict[str, Any]:
        timestamp = int(time.time())
        image_id = str(uuid.uuid4())
        base = {
            "algorithm": ALGORITHM,
            "author": (author or "anonymous").strip() or "anonymous",
            "hash": "0" * 64,
            "image_id": image_id,
            "timestamp": timestamp,
        }
        payload_len = len(_pack_payload(_json_bytes(base), b"\x00" * SIGNATURE_SIZE))
        _ensure_capacity(pixel_bytes, payload_len)
        base["hash"] = _canonical_hash(pixel_bytes, payload_len * 8)
        return base

    def _extract(self, pixel_bytes: bytes) -> EmbeddedPayload:
        if _pixel_count(pixel_bytes) < HEADER_SIZE * 8:
            raise ImageSigningError("image is too small to contain a signature")

        header = _extract_bytes(pixel_bytes, HEADER_SIZE)
        if header[: len(MAGIC)] != MAGIC:
            raise ImageSigningError("magic header not found")

        cert_len = int.from_bytes(header[len(MAGIC) : HEADER_SIZE], "big")
        if cert_len <= 0:
            raise ImageSigningError("invalid certificate length")

        payload_len = HEADER_SIZE + cert_len + SIGNATURE_SIZE
        _ensure_capacity(pixel_bytes, payload_len)
        payload = _extract_bytes(pixel_bytes, payload_len)
        certificate_bytes = payload[HEADER_SIZE : HEADER_SIZE + cert_len]
        signature = payload[HEADER_SIZE + cert_len :]

        try:
            certificate = json.loads(certificate_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ImageSigningError("embedded certificate is not valid JSON") from exc
        if not isinstance(certificate, dict):
            raise ImageSigningError("embedded certificate is not an object")

        return EmbeddedPayload(
            certificate=certificate,
            certificate_bytes=certificate_bytes,
            signature=signature,
            payload_bytes=payload,
            carrier_pixels=payload_len * 8,
        )


def _load_rgb_image(image_bytes: bytes) -> Image.Image:
    try:
        image = Image.open(io.BytesIO(image_bytes))
        return image.convert("RGB")
    except UnidentifiedImageError as exc:
        raise ImageSigningError("uploaded file is not a supported image") from exc


def _json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _pack_payload(certificate_bytes: bytes, signature: bytes) -> bytes:
    if len(signature) != SIGNATURE_SIZE:
        raise ImageSigningError("signature must be 32 bytes")
    if len(certificate_bytes) > 0xFFFFFFFF:
        raise ImageSigningError("certificate is too large")
    return MAGIC + len(certificate_bytes).to_bytes(LENGTH_SIZE, "big") + certificate_bytes + signature


def _ensure_capacity(pixel_bytes: bytes | bytearray, payload_bytes: int) -> None:
    required = payload_bytes * 8
    available = _pixel_count(pixel_bytes)
    if available < required:
        raise ImageSigningError(
            f"image is too small: requires {required} pixels but only has {available}",
            413,
        )


def _embed_payload(pixel_bytes: bytearray, payload: bytes) -> None:
    for index, bit in enumerate(_bits_from_bytes(payload)):
        red_offset = index * 3
        pixel_bytes[red_offset] = (pixel_bytes[red_offset] & 0xFE) | bit


def _extract_bytes(pixel_bytes: bytes, byte_count: int) -> bytes:
    bits = [pixel_bytes[index * 3] & 1 for index in range(byte_count * 8)]
    return _bytes_from_bits(bits)


def _bits_from_bytes(data: bytes) -> list[int]:
    return [(byte >> shift) & 1 for byte in data for shift in range(7, -1, -1)]


def _bytes_from_bits(bits: list[int]) -> bytes:
    if len(bits) % 8:
        raise ImageSigningError("bit stream length must be a multiple of 8")
    output = bytearray()
    for offset in range(0, len(bits), 8):
        value = 0
        for bit in bits[offset : offset + 8]:
            value = (value << 1) | bit
        output.append(value)
    return bytes(output)


def _canonical_hash(pixel_bytes: bytes, carrier_pixels: int) -> str:
    data = bytearray(pixel_bytes)
    for index in range(min(carrier_pixels, _pixel_count(data))):
        red_offset = index * 3
        data[red_offset] &= 0xFE
    return stdlib_sha256(data).hexdigest()


def _pixel_count(pixel_bytes: bytes | bytearray) -> int:
    return len(pixel_bytes) // 3


def _load_key(env_name: str, length: int) -> bytes:
    value = os.getenv(env_name)
    if not value:
        return os.urandom(length)
    try:
        key = bytes.fromhex(value)
    except ValueError:
        key = value.encode("utf-8")
    if len(key) != length:
        raise RuntimeError(f"{env_name} must be {length} bytes or {length * 2} hex characters")
    return key
