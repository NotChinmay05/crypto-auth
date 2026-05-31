import io

import pytest
from PIL import Image

from image_signing.service import (
    HEADER_SIZE,
    ImageSigningError,
    ImageSigningService,
    _bits_from_bytes,
    _bytes_from_bits,
)


def image_bytes(size=(96, 96), color=(120, 80, 160)):
    image = Image.new("RGB", size, color)
    out = io.BytesIO()
    image.save(out, format="PNG")
    return out.getvalue()


def mutate_png(png_bytes, pixel_index, channel=1):
    image = Image.open(io.BytesIO(png_bytes)).convert("RGB")
    raw = image.tobytes()
    pixels = [tuple(raw[index : index + 3]) for index in range(0, len(raw), 3)]
    red, green, blue = pixels[pixel_index]
    values = [red, green, blue]
    values[channel] ^= 1
    pixels[pixel_index] = tuple(values)
    image.putdata(pixels)
    out = io.BytesIO()
    image.save(out, format="PNG")
    return out.getvalue()


def test_bit_packing_round_trip():
    data = b"CIS1\x00\x00\x00\x02{}"
    assert _bytes_from_bits(_bits_from_bytes(data)) == data


def test_sign_verify_round_trip():
    service = ImageSigningService(signing_key=b"S" * 32)
    signed, details = service.sign(image_bytes(), "Ada")
    result = service.verify(signed)

    assert result["status"] == "AUTHENTIC"
    assert result["hmac_valid"] is True
    assert result["pixel_hash_valid"] is True
    assert result["certificate"]["author"] == "Ada"
    assert details["certificate"]["image_id"] == result["certificate"]["image_id"]


def test_too_small_image_rejected():
    service = ImageSigningService(signing_key=b"S" * 32)
    with pytest.raises(ImageSigningError, match="too small"):
        service.sign(image_bytes((8, 8)), "Ada")


def test_signature_tampering_is_detected():
    service = ImageSigningService(signing_key=b"S" * 32)
    signed, _ = service.sign(image_bytes(), "Ada")
    inspected = service.inspect(signed)
    cert_len = len(inspected["certificate_json"].encode("utf-8"))
    signature_pixel = (HEADER_SIZE + cert_len) * 8

    tampered = mutate_png(signed, signature_pixel, channel=0)
    result = service.verify(tampered)

    assert result["status"] == "TAMPERED"
    assert result["hmac_valid"] is False


def test_pixel_tampering_is_detected():
    service = ImageSigningService(signing_key=b"S" * 32)
    signed, details = service.sign(image_bytes(), "Ada")
    tampered = mutate_png(signed, details["carrier_pixels"] + 10, channel=1)
    result = service.verify(tampered)

    assert result["status"] == "TAMPERED"
    assert result["hmac_valid"] is True
    assert result["pixel_hash_valid"] is False


def test_inspect_returns_embedded_certificate_without_verification():
    service = ImageSigningService(signing_key=b"S" * 32)
    signed, details = service.sign(image_bytes(), "Grace")
    inspected = service.inspect(signed)

    assert inspected["magic"] == "CIS1"
    assert inspected["certificate"]["author"] == "Grace"
    assert inspected["signature_hex"]
    assert inspected["payload_bytes"] == details["payload_bytes"]
