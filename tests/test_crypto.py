import pytest

from app.auth.service import AuthError, AuthService
from app.crypto.aes import aes128_cbc_decrypt, aes128_cbc_encrypt, aes128_decrypt_block, aes128_encrypt_block
from app.crypto.hmac import hmac_sha256
from app.crypto.sha256 import sha256


def test_sha256_known_vectors():
    assert sha256(b"").hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha256(b"abc").hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_hmac_sha256_known_vector():
    digest = hmac_sha256(bytes.fromhex("0b" * 20), b"Hi There")
    assert digest.hex() == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"


def test_aes128_block_known_vector():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert aes128_encrypt_block(plaintext, key) == ciphertext
    assert aes128_decrypt_block(ciphertext, key) == plaintext


def test_aes128_cbc_round_trip():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = b"encrypted claims belong here"
    ciphertext = aes128_cbc_encrypt(plaintext, key, iv)
    assert ciphertext != plaintext
    assert aes128_cbc_decrypt(ciphertext, key, iv) == plaintext


def test_cat_round_trip_and_tamper_rejection():
    service = AuthService(encryption_key=b"E" * 16, signing_key=b"S" * 32)
    service.register("ada", "password", {"role": "admin"})
    login = service.login("ada", "password")
    claims = service.verify(login["token"])
    assert claims["sub"] == "ada"
    assert claims["role"] == "admin"

    parts = login["token"].split(".")
    with pytest.raises(AuthError):
        service.verify(".".join([parts[0], parts[1][:-1] + "A", parts[2]]))
    with pytest.raises(AuthError):
        service.verify(".".join([parts[0], parts[1], parts[2][:-1] + "A"]))


def test_expired_and_revoked_tokens_fail():
    service = AuthService(encryption_key=b"E" * 16, signing_key=b"S" * 32, token_ttl_seconds=-1)
    token, _ = service.issue_token({"sub": "ada"})
    with pytest.raises(AuthError, match="expired"):
        service.verify(token)

    service = AuthService(encryption_key=b"E" * 16, signing_key=b"S" * 32)
    token, _ = service.issue_token({"sub": "ada"})
    service.revoke(token, "test")
    with pytest.raises(AuthError, match="revoked"):
        service.verify(token)
