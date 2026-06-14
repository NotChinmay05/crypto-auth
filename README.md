# CryptoAuth Token Service

CryptoAuth is an JWT-inspired auth service implemented in Python. It issues CAT tokens with pure-Python SHA-256, HMAC-SHA256, and AES-128-CBC, then exposes a small FastAPI surface for registration, login, verification, revocation, and inspection.

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

## How It Works

1. A user registers with a username, password, and optional custom claims.
2. The password is salted and hashed with SHA-256 from the pure-Python crypto core.
3. Login verifies the stored password hash and issues a CAT token.
4. The token header is base64url-encoded JSON, and the payload is encrypted with AES-128-CBC.
5. The encrypted header and payload are signed with HMAC-SHA256.
6. Verification checks the signature first, then revocation and expiry, and only then decrypts the payload.
7. The analysis dashboard runs controlled attacks to show token forgery failure, salted password resistance, and replay protection.

## Endpoints

### Auth Service
- `POST /auth/register` - Register a user with a password and optional claims.
- `POST /auth/login` - Authenticate credentials and issue a CAT token.
- `POST /auth/verify` - Verify a CAT token and return decrypted claims.
- `POST /auth/refresh` - Reissue a valid token with fresh timing and `jti` fields.
- `POST /auth/revoke` - Add a token `jti` to the revocation list.
- `GET /auth/inspect` - Decode token structure without verifying it.
- `GET /auth/me` - Return the authenticated user profile from a bearer token.
- `GET /health` - Return service status and blacklist count.

### Cryptanalysis
- `POST /analysis/signature-forgery` - Show why token payload tampering fails signature checks.
- `POST /analysis/password-attacks` - Compare unsalted password cracking with salted hashing.
- `POST /analysis/replay` - Demonstrate token replay rejection after revocation.
- `POST /analysis/run-all` - Run all auth cryptanalysis demos in one call.

## Using This Service In Other Projects

1. Install the project as a dependency or copy the `app/auth` and `app/crypto` modules into your codebase.
2. Create an `AuthService` with stable `CAT_ENCRYPTION_KEY` and `CAT_SIGNING_KEY` values.
3. Call `register`, `login`, `verify`, `refresh`, and `revoke` from your own application logic.
4. Mount the FastAPI router from `app.main` or wrap the `AuthService` methods in your existing API layer.
5. Persist users and revocations externally if you need data to survive restarts.
6. Keep the signing and encryption keys consistent across all deployments that must accept the same tokens.
7. Add your own claims and authorization checks on top of the decrypted payload returned by `verify`.

## Encryption And Hashing

`CryptoAuth` uses two different crypto paths:

1. Password storage: `sha256(salt + password)` stores a salted password hash.
2. Token payload: `AES-128-CBC` encrypts the JSON claims before the token is returned.
3. Token integrity: `HMAC-SHA256(header + "." + payload)` signs the token parts.

The token is verified in this order:

1. Split the token into `header.payload.signature`.
2. Recompute the HMAC with the server signing key.
3. Reject immediately if the signature does not match.
4. Decode the payload IV and ciphertext.
5. Decrypt with the AES key and parse the JSON claims.

The important detail is that the payload is only decrypted after the HMAC check passes, so unauthenticated ciphertext is never opened first.


## Configuration

By default, encryption and signing keys are generated when the server starts, so tokens become invalid after restart. To keep tokens stable across restarts:

1. Copy `.env.example` to `.env`.
2. Fill in `CAT_ENCRYPTION_KEY` and `CAT_SIGNING_KEY` in `.env`.
3. Start the app with `uvicorn app.main:app --reload --env-file .env`.

`CAT_ENCRYPTION_KEY` must be 16 bytes. `CAT_SIGNING_KEY` must be 32 bytes. Values may be raw strings of the required length or hex strings.

## Token Flow

```python
# login / issue
header = {"typ": "CAT", "alg": "HMAC-SHA256+A128CBC"}
payload = {"sub": username, **claims, "iat": now, "exp": now + ttl, "jti": jti}
encoded_header = b64url(json.dumps(header))
iv, ciphertext = aes128_cbc_encrypt(json.dumps(payload), encryption_key)
encoded_payload = b64url(iv + ciphertext)
signature = hmac_sha256(signing_key, f"{encoded_header}.{encoded_payload}".encode())
token = f"{encoded_header}.{encoded_payload}.{b64url(signature)}"

# verify / decrypt
encoded_header, encoded_payload, encoded_signature = token.split(".")
expected = hmac_sha256(signing_key, f"{encoded_header}.{encoded_payload}".encode())
if constant_time_equal(b64url_decode(encoded_signature), expected):
    iv, ciphertext = b64url_decode(encoded_payload)[:16], b64url_decode(encoded_payload)[16:]
    payload = json.loads(aes128_cbc_decrypt(ciphertext, encryption_key, iv))
```
