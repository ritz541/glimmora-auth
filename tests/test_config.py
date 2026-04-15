"""Tests for AuthConfig."""

import os
import pytest

from glimmora_auth.config import AuthConfig


def test_default_config():
    """AuthConfig() with no args should have sensible default values."""
    cfg = AuthConfig(jwt_secret="a-secure-secret-key-at-least-32-chars-long")

    assert cfg.jwt_algorithm == "HS256"
    assert cfg.access_token_expire_minutes == 30
    assert cfg.refresh_token_expire_days == 7
    assert cfg.jwt_secret == "a-secure-secret-key-at-least-32-chars-long"


def test_custom_config():
    """Explicit values should override defaults."""
    cfg = AuthConfig(
        jwt_secret="my-secure-secret-key-at-least-32-chars-long",
        access_token_expire_minutes=60,
    )

    assert cfg.jwt_secret == "my-secure-secret-key-at-least-32-chars-long"
    assert cfg.access_token_expire_minutes == 60
    # Unchanged defaults
    assert cfg.jwt_algorithm == "HS256"
    assert cfg.refresh_token_expire_days == 7


def test_config_from_env():
    """AuthConfig should read GLIMMORA_AUTH_JWT_SECRET from the environment."""
    env_var = "GLIMMORA_AUTH_JWT_SECRET"

    original = os.environ.get(env_var)
    try:
        os.environ[env_var] = "env-secret-value-must-be-at-least-32-chars"
        cfg = AuthConfig()
        assert cfg.jwt_secret == "env-secret-value-must-be-at-least-32-chars"
    finally:
        # Restore original state
        if original is None:
            os.environ.pop(env_var, None)
        else:
            os.environ[env_var] = original
