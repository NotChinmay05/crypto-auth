# CryptoAuth Token Service

Educational JWT-inspired authentication service implemented in Python. CAT tokens use a JWT-like three-part format, but the payload is encrypted with pure-Python AES-128-CBC and the token is signed with pure-Python HMAC-SHA256.

This project intentionally implements cryptographic primitives from scratch for learning. Do not use this as production cryptography.

## Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Run

```bash
python3 -m uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/` for the static playground.

Open `http://127.0.0.1:8000/demo` for a separate sample website that registers users with a `user` or `admin` role claim, logs them in, and enables UI sections based on the verified role.

Open `http://127.0.0.1:8000/image` for the steganographic image signing studio. It signs images by embedding an HMAC-protected certificate into red-channel LSBs and verifies whether a signed PNG is authentic, tampered, or unsigned.

Open `http://127.0.0.1:8000/analysis` for the CAT cryptanalysis lab. It demonstrates signature tampering rejection, password rainbow table limitations with salts, and replay prevention through token revocation.

The same analysis dashboard also includes image-signing cryptanalysis demos for metadata stripping, JPEG conversion, pixel modification sensitivity, and LSB certificate forgery attempts.

## Test

```bash
python3 -m pytest
```

## Configuration

By default, encryption and signing keys are generated when the server starts, so tokens become invalid after restart. To keep tokens stable across restarts, set:

```bash
export CAT_ENCRYPTION_KEY=00112233445566778899aabbccddeeff
export CAT_SIGNING_KEY=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

`CAT_ENCRYPTION_KEY` must be 16 bytes. `CAT_SIGNING_KEY` must be 32 bytes. Values may be raw strings of the required length or hex strings.

## Endpoints

- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/verify`
- `POST /auth/refresh`
- `POST /auth/revoke`
- `GET /auth/inspect`
- `GET /auth/me`
- `GET /health`
- `POST /image/sign`
- `POST /image/verify`
- `POST /image/inspect`
- `POST /analysis/signature-forgery`
- `POST /analysis/password-attacks`
- `POST /analysis/replay`
- `POST /analysis/run-all`
- `POST /analysis/image/metadata-format`
- `POST /analysis/image/pixel-sensitivity`
- `POST /analysis/image/certificate-forgery`
- `POST /analysis/image/run-all`
