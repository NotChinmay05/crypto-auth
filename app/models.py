from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    username: str
    password: str
    claims: dict[str, Any] = Field(default_factory=dict)


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenRequest(BaseModel):
    token: str


class RevokeRequest(BaseModel):
    token: str
    reason: str | None = None


class ErrorResponse(BaseModel):
    detail: str
