"""
Unit tests for app/security.py
Tests the cryptographic layer directly — no HTTP, no database.
These are the fastest tests in the suite.
"""

import time
import pytest
from app.security import (
    hash_password, verify_password,
    create_access_token, decode_access_token,
    generate_refresh_token, hash_refresh_token,
)


# ── Password Hashing ──────────────────────────────────────────────────

def test_hash_password_returns_string():
    hashed = hash_password("Secure123")
    assert isinstance(hashed, str)
    assert len(hashed) > 20


def test_hash_password_not_plaintext():
    """Hash should not contain the original password."""
    hashed = hash_password("Secure123")
    assert "Secure123" not in hashed


def test_hash_password_different_each_time():
    """bcrypt generates a unique salt — same password hashes differently."""
    h1 = hash_password("Secure123")
    h2 = hash_password("Secure123")
    assert h1 != h2


def test_verify_password_correct():
    hashed = hash_password("Secure123")
    assert verify_password("Secure123", hashed) is True


def test_verify_password_wrong():
    hashed = hash_password("Secure123")
    assert verify_password("WrongPass", hashed) is False


def test_verify_password_case_sensitive():
    hashed = hash_password("Secure123")
    assert verify_password("secure123", hashed) is False


def test_verify_password_empty_string():
    hashed = hash_password("Secure123")
    assert verify_password("", hashed) is False


# ── JWT Access Tokens ─────────────────────────────────────────────────

def test_create_access_token_returns_tuple():
    token, jti = create_access_token(1, "rae", "user")
    assert isinstance(token, str)
    assert isinstance(jti, str)


def test_access_token_has_three_parts():
    token, _ = create_access_token(1, "rae", "user")
    assert len(token.split(".")) == 3


def test_decode_access_token_valid():
    token, jti = create_access_token(1, "rae", "user")
    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"]      == "1"
    assert payload["username"] == "rae"
    assert payload["role"]     == "user"
    assert payload["jti"]      == jti
    assert payload["type"]     == "access"


def test_decode_access_token_invalid():
    """Garbage token returns None instead of raising."""
    result = decode_access_token("not.a.token")
    assert result is None


def test_decode_access_token_empty():
    result = decode_access_token("")
    assert result is None


def test_jti_unique_per_token():
    """Each token gets a unique JTI for individual blacklisting."""
    _, jti1 = create_access_token(1, "rae", "user")
    _, jti2 = create_access_token(1, "rae", "user")
    assert jti1 != jti2


def test_access_token_different_for_different_users():
    token1, _ = create_access_token(1, "rae",   "user")
    token2, _ = create_access_token(2, "admin", "admin")
    assert token1 != token2


def test_access_token_encodes_role():
    token, _ = create_access_token(1, "rae", "admin")
    payload  = decode_access_token(token)
    assert payload["role"] == "admin"


# ── Refresh Tokens ────────────────────────────────────────────────────

def test_generate_refresh_token_returns_tuple():
    raw, hashed = generate_refresh_token()
    assert isinstance(raw,    str)
    assert isinstance(hashed, str)


def test_refresh_token_raw_and_hash_differ():
    raw, hashed = generate_refresh_token()
    assert raw != hashed


def test_refresh_token_hash_is_consistent():
    """Same raw token always produces the same hash."""
    raw, _ = generate_refresh_token()
    h1 = hash_refresh_token(raw)
    h2 = hash_refresh_token(raw)
    assert h1 == h2


def test_refresh_token_raw_not_in_hash():
    """The hash should not contain the raw token."""
    raw, hashed = generate_refresh_token()
    assert raw not in hashed


def test_refresh_tokens_unique():
    """Every generated refresh token is unique."""
    raw1, _ = generate_refresh_token()
    raw2, _ = generate_refresh_token()
    assert raw1 != raw2


def test_refresh_token_sufficient_length():
    """Refresh token should be long enough to be secure."""
    raw, _ = generate_refresh_token()
    assert len(raw) >= 32
    