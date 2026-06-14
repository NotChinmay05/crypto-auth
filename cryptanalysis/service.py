from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from app.auth.service import AuthError, AuthService
from app.crypto.aes import BLOCK_SIZE, aes128_cbc_decrypt, aes128_cbc_encrypt
from app.crypto.encoding import b64url_decode, b64url_encode, json_b64url_encode
from app.crypto.hmac import constant_time_equal, hmac_sha256
from app.crypto.sha256 import sha256

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

    def token_walkthrough(self, token: str, modified_payload: dict[str, Any] | None = None) -> dict[str, Any]:
        token = (token or "").strip()
        if not token:
            raise AuthError("token is required", 400)

        try:
            encoded_header, encoded_payload, encoded_signature = token.split(".")
        except ValueError as exc:
            raise AuthError("token must have three dot-separated parts", 400) from exc

        header = json.loads(b64url_decode(encoded_header).decode("utf-8"))
        encrypted_payload = b64url_decode(encoded_payload)
        if len(encrypted_payload) < BLOCK_SIZE * 2:
            raise AuthError("token payload is too short", 400)

        iv = encrypted_payload[:BLOCK_SIZE]
        ciphertext = encrypted_payload[BLOCK_SIZE:]
        original_payload = json.loads(
            aes128_cbc_decrypt(ciphertext, ANALYSIS_ENCRYPTION_KEY, iv).decode("utf-8")
        )
        supplied_signature = b64url_decode(encoded_signature)
        expected_signature = hmac_sha256(
            ANALYSIS_SIGNING_KEY,
            f"{encoded_header}.{encoded_payload}".encode("ascii"),
        )

        walkthrough = {
            "analysis": "token_walkthrough",
            "summary": "Decode the CAT header, decrypt the payload, edit the payload, then compare signatures and verification results.",
            "header": header,
            "original_payload": original_payload,
            "supplied_signature_hex": supplied_signature.hex(),
            "computed_signature_hex": expected_signature.hex(),
            "signature_matches": constant_time_equal(supplied_signature, expected_signature),
            "modified_payload": None,
            "modified_signature_hex": None,
            "modified_signature_matches": None,
            "modified_token_verification": None,
            "steps": [
                "Split the token into header, payload, and signature.",
                "Decode the header and payload from base64url.",
                "Decrypt the payload with the analysis AES key.",
                "Compare the supplied signature with the computed HMAC.",
            ],
        }

        if modified_payload is None:
            return walkthrough
        if not isinstance(modified_payload, dict):
            raise AuthError("modified payload must be an object", 400)

        modified_plaintext = json.dumps(modified_payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        modified_ciphertext = aes128_cbc_encrypt(modified_plaintext, ANALYSIS_ENCRYPTION_KEY, iv)
        modified_encoded_payload = b64url_encode(iv + modified_ciphertext)
        modified_signature = hmac_sha256(
            ANALYSIS_SIGNING_KEY,
            f"{encoded_header}.{modified_encoded_payload}".encode("ascii"),
        )
        modified_token = f"{encoded_header}.{modified_encoded_payload}.{encoded_signature}"
        modified_verification = _verify_status(
            AuthService(
                encryption_key=ANALYSIS_ENCRYPTION_KEY,
                signing_key=ANALYSIS_SIGNING_KEY,
                token_ttl_seconds=900,
            ),
            modified_token,
        )

        walkthrough.update(
            {
                "modified_payload": modified_payload,
                "modified_payload_json": json.dumps(modified_payload, separators=(",", ":"), sort_keys=True),
                "modified_signature_hex": modified_signature.hex(),
                "modified_signature_matches": constant_time_equal(supplied_signature, modified_signature),
                "modified_token_verification": modified_verification,
                "steps": walkthrough["steps"]
                + [
                    "Replace the payload JSON with the edited version.",
                    "Re-encrypt the modified payload with the same AES key and IV.",
                    "Keep the original signature in place to model tampering.",
                    f"Verification result: {'accepted' if modified_verification['accepted'] else 'rejected'} ({modified_verification.get('error', 'valid')}).",
                ],
            }
        )
        return walkthrough

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
