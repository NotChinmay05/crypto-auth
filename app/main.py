from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.auth.service import AuthError, AuthService
from app.models import LoginRequest, RegisterRequest, RevokeRequest, TokenRequest
from cryptanalysis.router import STATIC_DIR as CRYPTANALYSIS_STATIC_DIR
from cryptanalysis.router import router as cryptanalysis_router

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"
DEMO_DIR = BASE_DIR / "demo"

app = FastAPI(
    title="CryptoAuth Token Service",
    description="Educational JWT-inspired token service with pure-Python crypto primitives.",
    version="0.1.0",
)
service = AuthService()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.mount("/demo/assets", StaticFiles(directory=DEMO_DIR), name="demo-assets")
app.mount("/analysis/assets", StaticFiles(directory=CRYPTANALYSIS_STATIC_DIR), name="cryptanalysis-assets")
app.include_router(cryptanalysis_router, prefix="/analysis")


@app.exception_handler(AuthError)
async def auth_error_handler(_, exc: AuthError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/demo")
async def demo() -> FileResponse:
    return FileResponse(DEMO_DIR / "index.html")


@app.post("/auth/register")
async def register(request: RegisterRequest) -> dict:
    return service.register(request.username, request.password, request.claims)


@app.post("/auth/login")
async def login(request: LoginRequest) -> dict:
    return service.login(request.username, request.password)


@app.post("/auth/verify")
async def verify(request: TokenRequest) -> dict:
    return {"valid": True, "claims": service.verify(request.token)}


@app.post("/auth/refresh")
async def refresh(request: TokenRequest) -> dict:
    return service.refresh(request.token)


@app.post("/auth/revoke")
async def revoke(request: RevokeRequest) -> dict:
    return service.revoke(request.token, request.reason)


@app.get("/auth/inspect")
async def inspect(token: str = Query(...)) -> dict:
    return service.inspect(token)


@app.get("/auth/me")
async def me(authorization: str | None = Header(default=None)) -> dict:
    if not authorization:
        raise AuthError("missing Authorization header", 401)
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise AuthError("Authorization header must use Bearer token", 401)
    return service.profile(token)


@app.get("/health")
async def health() -> dict:
    return service.health()
