"""Pure-crypto tests — no database required."""

from __future__ import annotations

import base64

import pytest
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey
from nacl.signing import SigningKey

from relay.crypto.envelope import (
    generate_api_key,
    generate_fingerprint,
    hash_api_key,
    open_message,
    seal_message,
    sign_ciphertext,
    verify_signature,
)


def test_sealed_box_round_trip():
    recipient = PrivateKey.generate()
    payload = '{"subject":"hi","body":"secret"}'
    ct = seal_message(payload, recipient.public_key.encode().hex())
    assert open_message(ct, recipient.encode()) == payload


def test_sealed_box_wrong_key_fails():
    recipient = PrivateKey.generate()
    attacker = PrivateKey.generate()
    ct = seal_message("hello", recipient.public_key.encode().hex())
    with pytest.raises(CryptoError):
        open_message(ct, attacker.encode())


def test_sign_and_verify_round_trip():
    signer = SigningKey.generate()
    data = b"\x00ciphertext bytes\xff"
    sig = sign_ciphertext(data, signer.encode())
    assert verify_signature(data, sig, signer.verify_key.encode().hex()) is True


def test_verify_rejects_tampered_data_and_signature():
    signer = SigningKey.generate()
    sig = sign_ciphertext(b"original", signer.encode())
    assert verify_signature(b"tampered", sig, signer.verify_key.encode().hex()) is False
    forged = base64.b64encode(b"\x00" * 64).decode()
    assert verify_signature(b"original", forged, signer.verify_key.encode().hex()) is False
    assert verify_signature(b"original", sig, "zz" * 32) is False


def test_fingerprint_format_and_determinism():
    enc_hex = "ab" * 32
    sign_hex = "cd" * 32
    fp = generate_fingerprint(enc_hex, sign_hex)
    assert fp == generate_fingerprint(enc_hex, sign_hex)
    parts = fp.split(" ")
    assert len(parts) == 4
    assert all(
        len(p) == 4 and p == p.upper() and all(c in "0123456789ABCDEF" for c in p) for p in parts
    )
    # Order matters: swapping keys changes the fingerprint.
    assert generate_fingerprint(sign_hex, enc_hex) != fp


def test_api_key_shape_and_hash():
    key = generate_api_key()
    assert key.startswith("am_live_")
    assert len(key) == 51
    assert hash_api_key(key) == hash_api_key(key)
    assert hash_api_key(key) != hash_api_key(generate_api_key())
