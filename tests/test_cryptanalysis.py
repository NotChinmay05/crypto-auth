from app.main import app
from cryptanalysis.service import CryptanalysisService


def test_signature_forgery_analysis_rejects_tampered_token():
    result = CryptanalysisService().signature_forgery(random_key_attempts=8)

    assert result["analysis"] == "signature_forgery"
    assert result["original_claims"]["role"] == "user"
    assert result["tampered_claims_attempted"]["role"] == "admin"
    assert result["tampered_token_verification"]["accepted"] is False
    assert result["tampered_token_verification"]["error"] == "invalid token signature"
    assert result["random_key_forgery"]["successful_random_forges"] == 0
    assert result["random_key_forgery"]["actual_server_key_would_match"] is False


def test_password_attack_analysis_shows_salt_effect():
    result = CryptanalysisService().password_attacks()

    assert result["analysis"] == "password_bruteforce_and_rainbow_table"
    assert result["plain_sha256"]["cracked_count"] == 4
    assert result["plain_sha256"]["cracked"]["alice"] == "password"
    assert result["plain_sha256"]["cracked"]["carol"] == "password"
    assert result["salted_sha256"]["rainbow_table_reuse_cracked"] == {}
    assert result["salted_sha256"]["dictionary_cracked"]["alice"] == "password"
    assert result["salted_sha256"]["hash_computations"] > len(result["users"])


def test_replay_analysis_rejects_revoked_token():
    result = CryptanalysisService().replay_attack()

    assert result["analysis"] == "token_replay"
    assert result["initial_access"]["accepted"] is True
    assert result["revoke_result"]["ok"] is True
    assert result["replay_after_revoke"]["accepted"] is False
    assert result["replay_after_revoke"]["error"] == "token has been revoked"
    assert result["replay_without_revocation"]["accepted"] is True


def test_analysis_routes_are_registered():
    paths = {route.path for route in app.routes}

    assert "/analysis" in paths
    assert "/analysis/signature-forgery" in paths
    assert "/analysis/password-attacks" in paths
    assert "/analysis/replay" in paths
    assert "/analysis/run-all" in paths
    assert "/analysis/image/metadata-format" in paths
    assert "/analysis/image/pixel-sensitivity" in paths
    assert "/analysis/image/certificate-forgery" in paths
    assert "/analysis/image/run-all" in paths


def test_image_metadata_and_format_analysis():
    result = CryptanalysisService().image_metadata_and_format()

    assert result["analysis"] == "image_metadata_stripping_and_format_conversion"
    assert result["metadata_stripping"]["after_strip_verification"] == "AUTHENTIC"
    assert result["metadata_stripping"]["survived"] is True
    assert result["jpeg_conversion"]["after_conversion_verification"] != "AUTHENTIC"
    assert result["jpeg_conversion"]["survived"] is False


def test_image_pixel_sensitivity_analysis():
    result = CryptanalysisService().image_pixel_sensitivity()

    assert result["analysis"] == "image_pixel_modification_sensitivity"
    assert result["baseline"]["verification"] == "AUTHENTIC"
    assert len(result["modifications"]) == 3
    assert all(item["verification"] == "TAMPERED" for item in result["modifications"])
    assert all(item["pixel_hash_valid"] is False for item in result["modifications"])
    assert all(item["hamming_distance_bits"] > 80 for item in result["modifications"])


def test_image_certificate_forgery_analysis():
    result = CryptanalysisService().image_certificate_forgery()

    assert result["analysis"] == "image_lsb_certificate_forgery"
    assert result["extracted_certificate"]["author"] == "Alice"
    assert result["forged_certificate_attempt"]["author"] == "Mallory"
    assert result["verification"]["status"] == "TAMPERED"
    assert result["verification"]["hmac_valid"] is False
