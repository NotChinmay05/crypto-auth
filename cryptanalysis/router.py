from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse

from cryptanalysis.service import CryptanalysisService

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

router = APIRouter()
service = CryptanalysisService()


@router.get("")
async def analysis_index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@router.post("/signature-forgery")
async def signature_forgery() -> dict:
    return service.signature_forgery()


@router.post("/password-attacks")
async def password_attacks() -> dict:
    return service.password_attacks()


@router.post("/replay")
async def replay_attack() -> dict:
    return service.replay_attack()


@router.post("/run-all")
async def run_all() -> dict:
    return service.run_all()
