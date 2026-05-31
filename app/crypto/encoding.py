import base64
import json
from typing import Any


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def json_b64url_encode(value: dict[str, Any]) -> str:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return b64url_encode(raw)


def json_b64url_decode(value: str) -> dict[str, Any]:
    decoded = b64url_decode(value)
    obj = json.loads(decoded.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("decoded JSON is not an object")
    return obj
