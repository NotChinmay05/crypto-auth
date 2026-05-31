from __future__ import annotations

import io
from pathlib import Path

from fastapi import APIRouter, File, Form, UploadFile
from fastapi.responses import FileResponse, StreamingResponse

from image_signing.service import ImageSigningService

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

router = APIRouter()
service = ImageSigningService()


@router.get("")
async def image_index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@router.post("/sign")
async def sign_image(file: UploadFile = File(...), author: str = Form(default="anonymous")) -> StreamingResponse:
    signed_image, details = service.sign(await file.read(), author)
    headers = {
        "X-Image-Id": details["certificate"]["image_id"],
        "X-Signature-Algorithm": details["certificate"]["algorithm"],
    }
    return StreamingResponse(
        io.BytesIO(signed_image),
        media_type="image/png",
        headers=headers,
    )


@router.post("/verify")
async def verify_image(file: UploadFile = File(...)) -> dict:
    return service.verify(await file.read())


@router.post("/inspect")
async def inspect_image(file: UploadFile = File(...)) -> dict:
    return service.inspect(await file.read())
