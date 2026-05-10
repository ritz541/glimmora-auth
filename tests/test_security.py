"""Tests for glimmora_auth.security module."""

import logging
import time
from datetime import timedelta

from glimmora_auth.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
)

SECRET = "test-secret-key-for-testing-only-32chars"


def test_hash_password_returns_hash():
    """hash_password('password') should not equal 'password'."""
    hashed = hash_password("password")
    assert hashed != "password"


def test_hash_password_different_for_different_inputs():
    """hash_password('a') != hash_password('b')."""
    hash_a = hash_password("a")
    hash_b = hash_password("b")
    assert hash_a != hash_b


def test_verify_password_correct():
    """verify_password('StrongPass123!', hash) should be True."""
    password = "StrongPass123!"
    hashed = hash_password(password)
    assert verify_password(password, hashed) is True


def test_verify_password_wrong():
    """verify_password('wrong', hash) should be False."""
    hashed = hash_password("correct_password")
    assert verify_password("wrong", hashed) is False


def test_verify_password_empty():
    """verify_password('', hash) should be False."""
    hashed = hash_password("non_empty_password")
    assert verify_password("", hashed) is False


def test_create_access_token():
    """create_access_token({'sub': '1'}, 'secret') returns non-empty string."""
    token = create_access_token({"sub": "1"}, SECRET)
    assert isinstance(token, str)
    assert len(token) > 0


def test_access_token_contains_claims():
    """decode_token(token, 'secret') should have 'sub'='1' and 'type'='access'."""
    token = create_access_token({"sub": "1"}, SECRET)
    payload = decode_token(token, SECRET)
    assert payload is not None
    assert payload["sub"] == "1"
    assert payload["type"] == "access"


def test_create_access_token_custom_expiry():
    """Token with timedelta(seconds=1) expires."""
    token = create_access_token({"sub": "1"}, SECRET, expires_delta=timedelta(seconds=1))
    # Token should be decodable immediately
    payload = decode_token(token, SECRET)
    assert payload is not None
    # Wait for it to expire
    time.sleep(2)
    expired_payload = decode_token(token, SECRET)
    assert expired_payload is None


def test_decode_token_expired():
    """decode_token(expired_token, 'secret') should return None."""
    token = create_access_token(
        {"sub": "1"}, SECRET, expires_delta=timedelta(seconds=-1)
    )
    payload = decode_token(token, SECRET)
    assert payload is None


def test_decode_token_wrong_secret():
    """decode_token(token, 'wrong-secret') should return None."""
    token = create_access_token({"sub": "1"}, SECRET)
    payload = decode_token(token, "wrong-secret")
    assert payload is None


def test_decode_token_invalid():
    """decode_token('garbage', 'secret') should return None."""
    payload = decode_token("garbage", SECRET)
    assert payload is None


def test_refresh_token_has_refresh_type():
    """Refresh token should have type='refresh'."""
    token = create_refresh_token({"sub": "1"}, SECRET)
    payload = decode_token(token, SECRET)
    assert payload is not None
    assert payload["type"] == "refresh"
    assert payload["sub"] == "1"


def test_hash_password_no_passlib_warnings(caplog):
    """hash_password/verify_password should not emit passlib warnings.

    Regression test: passlib + bcrypt>=4.1 logs a trapped error about
    bcrypt.__about__ being removed. This test ensures no such noise.
    """
    import io
    import sys
    import importlib

    # The trapped error fires at CryptContext() init (module import time).
    # We must do a fresh import while logging is captured.
    for key in list(sys.modules):
        if "glimmora_auth" in key or "passlib" in key:
            sys.modules.pop(key, None)

    with caplog.at_level(logging.WARNING):
        mod = importlib.import_module("glimmora_auth.security")
        _ = mod.hash_password("StrongPass123!")
        mod.verify_password("StrongPass123!", _)

    assert "trapped" not in caplog.text, (
        f"passlib emitted warnings during import. "
        f"Run with -s to see details. Captured: {caplog.text[:500]}"
    )
