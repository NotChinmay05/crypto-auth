from __future__ import annotations

import json
import time
from dataclasses import dataclass
from io import BytesIO
from typing import Any

from PIL import Image, PngImagePlugin

from app.auth.service import AuthError, AuthService
from app.crypto.aes import BLOCK_SIZE, aes128_cbc_decrypt, aes128_cbc_encrypt
from app.crypto.encoding import b64url_decode, b64url_encode, json_b64url_encode
from app.crypto.hmac import constant_time_equal, hmac_sha256
from app.crypto.sha256 import sha256
from image_signing.service import (
    HEADER_SIZE,
    ImageSigningService,
    SIGNATURE_SIZE,
    _embed_payload,
    _json_bytes,
    _pack_payload,
    _pixel_count,
)

ANALYSIS_ENCRYPTION_KEY = b"A" * 16
ANALYSIS_SIGNING_KEY = b"B" * 32
COMMON_PASSWORDS = [
    "123456",
    "password",
    "qwerty",
    "letmein",
    "admin",
    "dragon",
    "correcthorsebatterystaple",
    "sunshine",
    "password123",
]


@dataclass(frozen=True)
class PasswordRecord:
    username: str
    password: str
    salt: bytes


class CryptanalysisService:
    def signature_forgery(self, random_key_attempts: int = 128) -> dict[str, Any]:
        service = AuthService(
            encryption_key=ANALYSIS_ENCRYPTION_KEY,
            signing_key=ANALYSIS_SIGNING_KEY,
            token_ttl_seconds=900,
        )
        service.register("eve", "password123", {"role": "user"})
        login = service.login("eve", "password123")
        token = login["token"]
        original_claims = service.verify(token)

        tampered_payload = {**original_claims, "role": "admin", "exp": original_claims["exp"] + 3600}
        tampered_token = _replace_encrypted_payload_without_resigning(service, token, tampered_payload)
        tampered_result = _verify_status(service, tampered_token)

        forged_result = _try_random_hmac_keys(tampered_token, service.signing_key, random_key_attempts)

        return {
            "analysis": "signature_forgery",
            "summary": "Changing encrypted CAT claims without the server signing key fails at HMAC verification before decryption.",
            "original_claims": original_claims,
            "tampered_claims_attempted": tampered_payload,
            "tampered_token_verification": tampered_result,
            "random_key_forgery": forged_result,
            "length_extension_note": {
                "naive_signature": "sha256(secret || message) is structurally length-extension prone.",
                "cat_signature": "CAT uses HMAC-SHA256, so the SHA-256 compression state cannot be reused to extend a valid signature.",
                "result": "not applicable to CAT",
            },
        }

    def password_attacks(self) -> dict[str, Any]:
        records = [
            PasswordRecord("alice", "password", bytes.fromhex("00112233445566778899aabbccddeeff")),
            PasswordRecord("bob", "dragon", bytes.fromhex("11112233445566778899aabbccddeeff")),
            PasswordRecord("carol", "password", bytes.fromhex("22222233445566778899aabbccddeeff")),
            PasswordRecord("dave", "correcthorsebatterystaple", bytes.fromhex("33333333445566778899aabbccddeeff")),
        ]

        plain_hashes = {record.username: sha256(record.password.encode("utf-8")).hex() for record in records}
        rainbow_table = {sha256(candidate.encode("utf-8")).hex(): candidate for candidate in COMMON_PASSWORDS}
        plain_cracks = {
            username: rainbow_table[digest]
            for username, digest in plain_hashes.items()
            if digest in rainbow_table
        }

        salted_hashes = {
            record.username: sha256(record.salt + record.password.encode("utf-8")).hex()
            for record in records
        }
        rainbow_against_salted = {
            username: rainbow_table[digest]
            for username, digest in salted_hashes.items()
            if digest in rainbow_table
        }

        salted_dictionary_cracks: dict[str, str] = {}
        salted_hash_computations = 0
        for record in records:
            for candidate in COMMON_PASSWORDS:
                salted_hash_computations += 1
                digest = sha256(record.salt + candidate.encode("utf-8")).hex()
                if constant_time_equal(bytes.fromhex(digest), bytes.fromhex(salted_hashes[record.username])):
                    salted_dictionary_cracks[record.username] = candidate
                    break

        return {
            "analysis": "password_bruteforce_and_rainbow_table",
            "summary": "Unsalted SHA-256 passwords are reusable rainbow-table targets; per-user salts force candidate recomputation per account.",
            "users": [record.username for record in records],
            "plain_sha256": {
                "stored_hashes": plain_hashes,
                "rainbow_table_entries": len(rainbow_table),
                "cracked": plain_cracks,
                "cracked_count": len(plain_cracks),
            },
            "salted_sha256": {
                "stored_hashes": salted_hashes,
                "rainbow_table_reuse_cracked": rainbow_against_salted,
                "dictionary_cracked": salted_dictionary_cracks,
                "hash_computations": salted_hash_computations,
                "cost_model": "candidate passwords x users, instead of one reusable precomputed table",
            },
        }

    def replay_attack(self) -> dict[str, Any]:
        service = AuthService(
            encryption_key=ANALYSIS_ENCRYPTION_KEY,
            signing_key=ANALYSIS_SIGNING_KEY,
            token_ttl_seconds=900,
        )
        service.register("mallory", "password123", {"role": "user"})
        token = service.login("mallory", "password123")["token"]

        first_access = _verify_status(service, token)
        signed_claims_before_revoke = service._verified_payload(token)
        revoke_result = service.revoke(token, "logout")
        replay_after_revoke = _verify_status(service, token)

        no_revocation_service = AuthService(
            encryption_key=ANALYSIS_ENCRYPTION_KEY,
            signing_key=ANALYSIS_SIGNING_KEY,
            token_ttl_seconds=900,
        )
        no_revocation_service.register("mallory", "password123", {"role": "user"})
        unrevoked_token = no_revocation_service.login("mallory", "password123")["token"]
        replay_without_revocation = _verify_status(no_revocation_service, unrevoked_token)

        return {
            "analysis": "token_replay",
            "summary": "A copied token remains cryptographically valid until expiry unless server-side revocation rejects its jti.",
            "initial_access": first_access,
            "cryptographic_claims_before_revoke": signed_claims_before_revoke,
            "revoke_result": revoke_result,
            "replay_after_revoke": replay_after_revoke,
            "replay_without_revocation": replay_without_revocation,
        }

    def run_all(self) -> dict[str, Any]:
        started = time.perf_counter()
        results = {
            "signature_forgery": self.signature_forgery(),
            "password_attacks": self.password_attacks(),
            "replay_attack": self.replay_attack(),
            "image_metadata_and_format": self.image_metadata_and_format(),
            "image_pixel_sensitivity": self.image_pixel_sensitivity(),
            "image_certificate_forgery": self.image_certificate_forgery(),
        }
        return {"duration_ms": round((time.perf_counter() - started) * 1000, 2), "results": results}

    def image_metadata_and_format(self) -> dict[str, Any]:
        image_service = ImageSigningService(signing_key=ANALYSIS_SIGNING_KEY)
        signed_png, signing = image_service.sign(_sample_png_with_metadata(), "Ada")

        stripped_png = _resave_png_without_metadata(signed_png)
        jpeg_round_trip_png = _jpeg_round_trip_png(signed_png)

        original = image_service.verify(signed_png)
        stripped = image_service.verify(stripped_png)
        jpeg = image_service.verify(jpeg_round_trip_png)

        return {
            "analysis": "image_metadata_stripping_and_format_conversion",
            "summary": "Pixel-embedded LSB signatures survive metadata stripping but do not survive lossy JPEG conversion.",
            "signed_image": {
                "author": signing["certificate"]["author"],
                "image_id": signing["certificate"]["image_id"],
                "payload_bytes": signing["payload_bytes"],
                "carrier_pixels": signing["carrier_pixels"],
            },
            "metadata_stripping": {
                "change": "re-save signed PNG from pixel data without text/EXIF metadata",
                "verification": original["status"],
                "after_strip_verification": stripped["status"],
                "survived": stripped["status"] == "AUTHENTIC",
            },
            "jpeg_conversion": {
                "change": "convert signed PNG to JPEG and back to PNG",
                "after_conversion_verification": jpeg["status"],
                "reason": jpeg["reason"],
                "survived": jpeg["status"] == "AUTHENTIC",
            },
        }

    def image_pixel_sensitivity(self) -> dict[str, Any]:
        image_service = ImageSigningService(signing_key=ANALYSIS_SIGNING_KEY)
        signed_png, signing = image_service.sign(_sample_png_with_metadata(), "Grace")
        baseline = image_service.verify(signed_png)
        expected_hash = baseline["expected_hash"]
        carrier_pixels = signing["carrier_pixels"]

        scenarios = [
            ("large_region", 256, carrier_pixels + 20),
            ("small_region", 16, carrier_pixels + 400),
            ("single_pixel_plus_one", 1, carrier_pixels + 900),
        ]
        results = []
        for name, count, start in scenarios:
            tampered = _mutate_pixels(signed_png, start, count)
            verification = image_service.verify(tampered)
            actual_hash = verification["actual_hash"]
            results.append(
                {
                    "scenario": name,
                    "modified_pixels": count,
                    "verification": verification["status"],
                    "pixel_hash_valid": verification["pixel_hash_valid"],
                    "hamming_distance_bits": _hex_hamming_distance(expected_hash, actual_hash),
                    "expected_hash_prefix": expected_hash[:16],
                    "actual_hash_prefix": actual_hash[:16] if actual_hash else None,
                }
            )

        return {
            "analysis": "image_pixel_modification_sensitivity",
            "summary": "Changing even one non-carrier pixel changes the canonical image hash and causes verification failure.",
            "baseline": {
                "verification": baseline["status"],
                "image_id": baseline["certificate"]["image_id"],
                "expected_hash": expected_hash,
            },
            "modifications": results,
            "avalanche_note": "SHA-256 hash outputs are 256 bits, so unrelated modified-image hashes tend to differ by about 128 bits.",
        }

    def image_certificate_forgery(self) -> dict[str, Any]:
        image_service = ImageSigningService(signing_key=ANALYSIS_SIGNING_KEY)
        signed_png, _ = image_service.sign(_sample_png_with_metadata(), "Alice")
        extracted = image_service.inspect(signed_png)
        embedded = image_service._extract(Image.open(BytesIO(signed_png)).convert("RGB").tobytes())

        forged_certificate = {**embedded.certificate, "author": "Mallory"}
        forged_certificate_bytes = _json_bytes(forged_certificate)
        forged_signature = hmac_sha256(b"wrong-secret-key".ljust(32, b"!"), forged_certificate_bytes)
        forged_payload = _pack_payload(forged_certificate_bytes, forged_signature)
        forged_png = _embed_payload_in_png(signed_png, forged_payload)
        verification = image_service.verify(forged_png)

        return {
            "analysis": "image_lsb_certificate_forgery",
            "summary": "LSB extraction reveals the hidden certificate, but editing it without the server HMAC key fails verification.",
            "extracted_certificate": extracted["certificate"],
            "forged_certificate_attempt": forged_certificate,
            "forgery": {
                "change": "author changed from Alice to Mallory",
                "signature_strategy": "recomputed HMAC with a wrong key",
                "payload_bytes": len(forged_payload),
            },
            "verification": verification,
            "takeaway": "Steganography hides bytes; HMAC authenticates them.",
        }

    def run_image_all(self) -> dict[str, Any]:
        started = time.perf_counter()
        results = {
            "metadata_and_format": self.image_metadata_and_format(),
            "pixel_sensitivity": self.image_pixel_sensitivity(),
            "certificate_forgery": self.image_certificate_forgery(),
        }
        return {"duration_ms": round((time.perf_counter() - started) * 1000, 2), "results": results}


def _replace_encrypted_payload_without_resigning(service: AuthService, token: str, payload: dict[str, Any]) -> str:
    encoded_header, _, encoded_signature = service._split(token)
    plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    iv = b"C" * BLOCK_SIZE
    ciphertext = aes128_cbc_encrypt(plaintext, service.encryption_key, iv)
    return f"{encoded_header}.{b64url_encode(iv + ciphertext)}.{encoded_signature}"


def _try_random_hmac_keys(token: str, actual_key: bytes, attempts: int) -> dict[str, Any]:
    encoded_header, encoded_payload, encoded_signature = token.split(".")
    target = b64url_decode(encoded_signature)
    message = f"{encoded_header}.{encoded_payload}".encode("ascii")
    successes = 0
    for index in range(max(0, attempts)):
        key_material = sha256(f"wrong-key-{index}".encode("utf-8"))
        candidate = hmac_sha256(key_material, message)
        if constant_time_equal(candidate, target):
            successes += 1
    actual_signature_matches = constant_time_equal(hmac_sha256(actual_key, message), target)
    return {
        "attempts": attempts,
        "successful_random_forges": successes,
        "actual_server_key_would_match": actual_signature_matches,
        "conclusion": "random guessing did not produce the required 256-bit HMAC",
    }


def _verify_status(service: AuthService, token: str) -> dict[str, Any]:
    try:
        return {"accepted": True, "claims": service.verify(token)}
    except AuthError as exc:
        return {"accepted": False, "error": exc.message}


def make_toy_plaintext_token(claims: dict[str, Any], key: bytes = ANALYSIS_SIGNING_KEY) -> str:
    header = {"typ": "TOY", "alg": "HMAC-SHA256"}
    encoded_header = json_b64url_encode(header)
    encoded_payload = json_b64url_encode(claims)
    signature = hmac_sha256(key, f"{encoded_header}.{encoded_payload}".encode("ascii"))
    return f"{encoded_header}.{encoded_payload}.{b64url_encode(signature)}"


def _sample_png_with_metadata(size: tuple[int, int] = (96, 96)) -> bytes:
    image = Image.new("RGB", size)
    pixels = []
    for y in range(size[1]):
        for x in range(size[0]):
            pixels.append(((x * 3 + y) % 256, (y * 5 + 40) % 256, (x * 7 + 90) % 256))
    image.putdata(pixels)
    info = PngImagePlugin.PngInfo()
    info.add_text("creator", "cryptanalysis-demo")
    out = BytesIO()
    image.save(out, format="PNG", pnginfo=info)
    return out.getvalue()


def _resave_png_without_metadata(png_bytes: bytes) -> bytes:
    image = Image.open(BytesIO(png_bytes)).convert("RGB")
    out = BytesIO()
    image.save(out, format="PNG", compress_level=1)
    return out.getvalue()


def _jpeg_round_trip_png(png_bytes: bytes) -> bytes:
    image = Image.open(BytesIO(png_bytes)).convert("RGB")
    jpeg = BytesIO()
    image.save(jpeg, format="JPEG", quality=75)
    jpeg.seek(0)
    converted = Image.open(jpeg).convert("RGB")
    out = BytesIO()
    converted.save(out, format="PNG", compress_level=1)
    return out.getvalue()


def _mutate_pixels(png_bytes: bytes, start_pixel: int, count: int) -> bytes:
    image = Image.open(BytesIO(png_bytes)).convert("RGB")
    pixels = bytearray(image.tobytes())
    total_pixels = _pixel_count(pixels)
    for pixel in range(start_pixel, min(start_pixel + count, total_pixels)):
        green_offset = pixel * 3 + 1
        pixels[green_offset] = (pixels[green_offset] + 1) % 256
    mutated = Image.frombytes("RGB", image.size, bytes(pixels))
    out = BytesIO()
    mutated.save(out, format="PNG", compress_level=1)
    return out.getvalue()


def _embed_payload_in_png(png_bytes: bytes, payload: bytes) -> bytes:
    image = Image.open(BytesIO(png_bytes)).convert("RGB")
    pixels = bytearray(image.tobytes())
    if _pixel_count(pixels) < len(payload) * 8:
        raise ValueError("sample image lacks payload capacity")
    _embed_payload(pixels, payload)
    forged = Image.frombytes("RGB", image.size, bytes(pixels))
    out = BytesIO()
    forged.save(out, format="PNG", compress_level=1)
    return out.getvalue()


def _hex_hamming_distance(left: str | None, right: str | None) -> int | None:
    if not left or not right:
        return None
    return sum(bin(a ^ b).count("1") for a, b in zip(bytes.fromhex(left), bytes.fromhex(right)))
