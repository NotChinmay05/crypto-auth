from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from app.crypto.aes import BLOCK_SIZE, aes128_cbc_decrypt, aes128_cbc_encrypt
from app.crypto.encoding import b64url_decode, b64url_encode, json_b64url_decode, json_b64url_encode
from app.crypto.hmac import constant_time_equal, hmac_sha256
from app.crypto.sha256 import sha256

TOKEN_TYPE = "CAT"
TOKEN_ALG = "HMAC-SHA256+A128CBC"
DEFAULT_TTL_SECONDS = 15 * 60


class AuthError(Exception):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


@dataclass
class UserRecord:
    username: str
    salt: bytes
    password_hash: bytes
    claims: dict[str, Any] = field(default_factory=dict)


class AuthService:
    def __init__(
        self,
        encryption_key: bytes | None = None,
        signing_key: bytes | None = None,
        token_ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        self.encryption_key = encryption_key or _load_key("CAT_ENCRYPTION_KEY", 16)
        self.signing_key = signing_key or _load_key("CAT_SIGNING_KEY", 32)
        self.token_ttl_seconds = token_ttl_seconds
        self.users: dict[str, UserRecord] = {}
        self.revoked_jtis: dict[str, dict[str, Any]] = {}

    def register(self, username: str, password: str, claims: dict[str, Any] | None = None) -> dict[str, Any]:
        username = username.strip()
        if not username:
            raise AuthError("username is required")
        if not password:
            raise AuthError("password is required")
        if username in self.users:
            raise AuthError("username already exists", 409)
        safe_claims = claims or {}
        if not isinstance(safe_claims, dict):
            raise AuthError("claims must be an object")
        salt = os.urandom(16)
        password_hash = self._hash_password(salt, password)
        self.users[username] = UserRecord(username=username, salt=salt, password_hash=password_hash, claims=safe_claims)
        return {"ok": True, "username": username}

    def login(self, username: str, password: str) -> dict[str, Any]:
        user = self.users.get(username)
        if user is None:
            raise AuthError("invalid username or password", 401)
        candidate = self._hash_password(user.salt, password)
        if not constant_time_equal(candidate, user.password_hash):
            raise AuthError("invalid username or password", 401)
        claims = {"sub": username, **user.claims}
        token, payload = self.issue_token(claims)
        return {"token": token, "claims": payload}

    def issue_token(self, claims: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        now = int(time.time())
        payload = {
            **claims,
            "iat": now,
            "exp": now + self.token_ttl_seconds,
            "jti": str(uuid.uuid4()),
        }
        header = {"typ": TOKEN_TYPE, "alg": TOKEN_ALG}
        encoded_header = json_b64url_encode(header)
        plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        iv = os.urandom(BLOCK_SIZE)
        ciphertext = aes128_cbc_encrypt(plaintext, self.encryption_key, iv)
        encoded_payload = b64url_encode(iv + ciphertext)
        signature = hmac_sha256(self.signing_key, f"{encoded_header}.{encoded_payload}".encode("ascii"))
        return f"{encoded_header}.{encoded_payload}.{b64url_encode(signature)}", payload

    def verify(self, token: str) -> dict[str, Any]:
        payload = self._verified_payload(token)
        jti = payload.get("jti")
        if not isinstance(jti, str):
            raise AuthError("token is missing jti", 401)
        if jti in self.revoked_jtis:
            raise AuthError("token has been revoked", 401)
        exp = payload.get("exp")
        if not isinstance(exp, int):
            raise AuthError("token is missing exp", 401)
        if exp < int(time.time()):
            raise AuthError("token has expired", 401)
        return payload

    def refresh(self, token: str) -> dict[str, Any]:
        payload = self.verify(token)
        old_jti = payload["jti"]
        self.revoked_jtis[old_jti] = {"reason": "refreshed", "revoked_at": int(time.time())}
        preserved_claims = {key: value for key, value in payload.items() if key not in {"iat", "exp", "jti"}}
        new_token, new_payload = self.issue_token(preserved_claims)
        return {"token": new_token, "claims": new_payload, "revoked_jti": old_jti}

    def revoke(self, token: str, reason: str | None = None) -> dict[str, Any]:
        payload = self._verified_payload(token)
        jti = payload.get("jti")
        if not isinstance(jti, str):
            raise AuthError("token is missing jti", 401)
        self.revoked_jtis[jti] = {"reason": reason or "revoked", "revoked_at": int(time.time())}
        return {"ok": True, "jti": jti, "reason": self.revoked_jtis[jti]["reason"]}

    def inspect(self, token: str) -> dict[str, Any]:
        encoded_header, encoded_payload, encoded_signature = self._split(token)
        raw_payload = b64url_decode(encoded_payload)
        header: dict[str, Any] | None
        try:
            header = json_b64url_decode(encoded_header)
        except Exception:
            header = None
        return {
            "header": header,
            "encoded": {
                "header": encoded_header,
                "payload": encoded_payload,
                "signature": encoded_signature,
            },
            "encrypted_payload_hex": raw_payload.hex(),
            "iv_hex": raw_payload[:BLOCK_SIZE].hex() if len(raw_payload) >= BLOCK_SIZE else "",
            "ciphertext_hex": raw_payload[BLOCK_SIZE:].hex() if len(raw_payload) >= BLOCK_SIZE else "",
            "signature_hex": b64url_decode(encoded_signature).hex(),
            "warning": "Inspection does not verify the signature or decrypt claims.",
        }

    def profile(self, token: str) -> dict[str, Any]:
        payload = self.verify(token)
        username = payload.get("sub")
        if not isinstance(username, str) or username not in self.users:
            raise AuthError("user not found", 404)
        user = self.users[username]
        return {"username": user.username, "claims": user.claims, "token_claims": payload}

    def health(self) -> dict[str, Any]:
        return {"status": "ok", "timestamp": int(time.time()), "blacklisted_tokens": len(self.revoked_jtis)}

    def _hash_password(self, salt: bytes, password: str) -> bytes:
        return sha256(salt + password.encode("utf-8"))

    def _verified_payload(self, token: str) -> dict[str, Any]:
        encoded_header, encoded_payload, encoded_signature = self._split(token)
        try:
            header = json_b64url_decode(encoded_header)
        except Exception as exc:
            raise AuthError("invalid token header", 401) from exc
        if header.get("typ") != TOKEN_TYPE or header.get("alg") != TOKEN_ALG:
            raise AuthError("unsupported token header", 401)
        message = f"{encoded_header}.{encoded_payload}".encode("ascii")
        expected = hmac_sha256(self.signing_key, message)
        try:
            supplied = b64url_decode(encoded_signature)
        except Exception as exc:
            raise AuthError("invalid token signature encoding", 401) from exc
        if not constant_time_equal(expected, supplied):
            raise AuthError("invalid token signature", 401)
        try:
            encrypted = b64url_decode(encoded_payload)
            if len(encrypted) < BLOCK_SIZE * 2:
                raise ValueError("encrypted payload is too short")
            iv = encrypted[:BLOCK_SIZE]
            ciphertext = encrypted[BLOCK_SIZE:]
            plaintext = aes128_cbc_decrypt(ciphertext, self.encryption_key, iv)
            payload = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise AuthError("invalid encrypted payload", 401) from exc
        if not isinstance(payload, dict):
            raise AuthError("token payload is not an object", 401)
        return payload

    def _split(self, token: str) -> tuple[str, str, str]:
        parts = token.strip().split(".")
        if len(parts) != 3 or not all(parts):
            raise AuthError("token must have three dot-separated parts", 400)
        return parts[0], parts[1], parts[2]


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
