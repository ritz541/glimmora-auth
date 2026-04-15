"""Integration tests for auth endpoints."""

import pytest
from httpx import AsyncClient, ASGITransport
from glimmora_auth.security import create_access_token, decode_token
from datetime import timedelta


# ============================================================
# REGISTRATION
# ============================================================

class TestRegister:
    async def test_register_success(self, client: AsyncClient):
        resp = await client.post("/auth/register", json={
            "email": "new@example.com",
            "password": "TestPass123!",
            "full_name": "New User",
        })
        assert resp.status_code == 201
        data = resp.json()
        user = data["user"]
        assert user["email"] == "new@example.com"
        assert user["full_name"] == "New User"
        assert "hashed_password" not in user
        assert "password" not in user
        assert "id" in user
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    async def test_register_duplicate_email(self, client: AsyncClient, registered_user):
        resp = await client.post("/auth/register", json={
            "email": registered_user["email"],
            "password": "TestPass123!",
            "full_name": "Duplicate",
        })
        assert resp.status_code == 409

    async def test_register_weak_password(self, client: AsyncClient):
        resp = await client.post("/auth/register", json={
            "email": "weak@example.com",
            "password": "weakonly",
            "full_name": "Weak User",
        })
        assert resp.status_code == 422

    async def test_register_missing_email(self, client: AsyncClient):
        resp = await client.post("/auth/register", json={
            "password": "TestPass123!",
            "full_name": "No Email",
        })
        assert resp.status_code == 422

    async def test_register_missing_password(self, client: AsyncClient):
        resp = await client.post("/auth/register", json={
            "email": "nopass@example.com",
            "full_name": "No Password",
        })
        assert resp.status_code == 422

    async def test_register_invalid_email(self, client: AsyncClient):
        resp = await client.post("/auth/register", json={
            "email": "not-an-email",
            "password": "TestPass123!",
            "full_name": "Bad Email",
        })
        assert resp.status_code == 422


# ============================================================
# LOGIN
# ============================================================

class TestLogin:
    async def test_login_success(self, client: AsyncClient, registered_user):
        resp = await client.post("/auth/login", json={
            "email": registered_user["email"],
            "password": registered_user["password"],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        # Verify access token is valid
        payload = decode_token(data["access_token"], "test-secret-key-for-testing-only")
        assert payload is not None
        assert payload["type"] == "access"

    async def test_login_wrong_password(self, client: AsyncClient, registered_user):
        resp = await client.post("/auth/login", json={
            "email": registered_user["email"],
            "password": "WrongPassword123!",
        })
        assert resp.status_code == 401

    async def test_login_nonexistent_user(self, client: AsyncClient):
        resp = await client.post("/auth/login", json={
            "email": "ghost@example.com",
            "password": "Whatever123!",
        })
        assert resp.status_code == 401


# ============================================================
# REFRESH
# ============================================================

class TestRefresh:
    async def test_refresh_success(self, client: AsyncClient, registered_user):
        # Login first
        login_resp = await client.post("/auth/login", json={
            "email": registered_user["email"],
            "password": registered_user["password"],
        })
        refresh_token = login_resp.json()["refresh_token"]

        # Refresh
        resp = await client.post("/auth/refresh", json={
            "refresh_token": refresh_token,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data  # Token rotation: new refresh token issued
        # Verify new token is valid
        payload = decode_token(data["access_token"], "test-secret-key-for-testing-only")
        assert payload is not None

    async def test_refresh_invalid_token(self, client: AsyncClient):
        resp = await client.post("/auth/refresh", json={
            "refresh_token": "garbag...here",
        })
        assert resp.status_code == 401

    async def test_refresh_token_rotation(self, client: AsyncClient, registered_user):
        """After refresh, old refresh token should be revoked (token rotation)."""
        login_resp = await client.post("/auth/login", json={
            "email": registered_user["email"],
            "password": registered_user["password"],
        })
        old_refresh_token = login_resp.json()["refresh_token"]

        # Use it once - should succeed and return new refresh token
        resp1 = await client.post("/auth/refresh", json={
            "refresh_token": old_refresh_token,
        })
        assert resp1.status_code == 200
        new_refresh_token = resp1.json()["refresh_token"]
        assert new_refresh_token != old_refresh_token

        # Old token should now be revoked - reuse detection triggers
        resp2 = await client.post("/auth/refresh", json={
            "refresh_token": old_refresh_token,
        })
        assert resp2.status_code == 401
        assert "Token reuse detected" in resp2.json()["detail"]

    async def test_refresh_reuse_detection_revokes_all(self, client: AsyncClient, registered_user):
        """Reusing a revoked refresh token should revoke ALL tokens for that user."""
        login_resp = await client.post("/auth/login", json={
            "email": registered_user["email"],
            "password": registered_user["password"],
        })
        refresh_token = login_resp.json()["refresh_token"]

        # First refresh - rotates token
        resp1 = await client.post("/auth/refresh", json={
            "refresh_token": refresh_token,
        })
        assert resp1.status_code == 200
        new_refresh_token = resp1.json()["refresh_token"]

        # Reuse old (revoked) token - should trigger reuse detection
        resp2 = await client.post("/auth/refresh", json={
            "refresh_token": refresh_token,
        })
        assert resp2.status_code == 401
        assert "Token reuse detected" in resp2.json()["detail"]

        # The new refresh token should ALSO be revoked now (all sessions revoked)
        resp3 = await client.post("/auth/refresh", json={
            "refresh_token": new_refresh_token,
        })
        assert resp3.status_code == 401


# ============================================================
# LOGOUT
# ============================================================

class TestLogout:
    async def test_logout_success(self, client: AsyncClient, registered_user):
        # Login
        login_resp = await client.post("/auth/login", json={
            "email": registered_user["email"],
            "password": registered_user["password"],
        })
        token = login_resp.json()["access_token"]
        refresh_token = login_resp.json()["refresh_token"]

        # Logout
        resp = await client.post(
            "/auth/logout",
            json={"refresh_token": refresh_token},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

        # Try using refresh token after logout - should fail
        resp2 = await client.post("/auth/refresh", json={
            "refresh_token": refresh_token,
        })
        assert resp2.status_code == 401

    async def test_logout_unauthenticated(self, client: AsyncClient):
        resp = await client.post("/auth/logout", json={"refresh_token": "whatever"})
        assert resp.status_code == 401


# ============================================================
# ME
# ============================================================

class TestMe:
    async def test_get_me(self, client: AsyncClient, registered_user):
        login_resp = await client.post("/auth/login", json={
            "email": registered_user["email"],
            "password": registered_user["password"],
        })
        token = login_resp.json()["access_token"]

        resp = await client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == registered_user["email"]
        assert data["full_name"] == registered_user["full_name"]

    async def test_get_me_unauthenticated(self, client: AsyncClient):
        resp = await client.get("/auth/me")
        assert resp.status_code == 401


# ============================================================
# CHANGE PASSWORD
# ============================================================

class TestChangePassword:
    async def test_change_password_success(self, client: AsyncClient, registered_user):
        login_resp = await client.post("/auth/login", json={
            "email": registered_user["email"],
            "password": registered_user["password"],
        })
        token = login_resp.json()["access_token"]

        resp = await client.post(
            "/auth/change-password",
            json={
                "old_password": registered_user["password"],
                "new_password": "NewStrong456!",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

        # Can login with new password
        login2 = await client.post("/auth/login", json={
            "email": registered_user["email"],
            "password": "NewStrong456!",
        })
        assert login2.status_code == 200

        # Cannot login with old password
        login3 = await client.post("/auth/login", json={
            "email": registered_user["email"],
            "password": registered_user["password"],
        })
        assert login3.status_code == 401

    async def test_change_password_wrong_old(self, client: AsyncClient, registered_user):
        login_resp = await client.post("/auth/login", json={
            "email": registered_user["email"],
            "password": registered_user["password"],
        })
        token = login_resp.json()["access_token"]

        resp = await client.post(
            "/auth/change-password",
            json={
                "old_password": "WrongOld123!",
                "new_password": "NewStrong456!",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 400

    async def test_change_password_unauthenticated(self, client: AsyncClient):
        resp = await client.post("/auth/change-password", json={
            "old_password": "Old123!",
            "new_password": "New456!",
        })
        assert resp.status_code == 401

    async def test_change_password_revokes_sessions(self, client: AsyncClient, registered_user):
        """Changing password should revoke all refresh tokens."""
        login_resp = await client.post("/auth/login", json={
            "email": registered_user["email"],
            "password": registered_user["password"],
        })
        token = login_resp.json()["access_token"]
        refresh_token = login_resp.json()["refresh_token"]

        # Change password
        resp = await client.post(
            "/auth/change-password",
            json={
                "old_password": registered_user["password"],
                "new_password": "NewStrong456!",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert "all sessions revoked" in resp.json()["message"]

        # Old refresh token should be revoked
        resp2 = await client.post("/auth/refresh", json={
            "refresh_token": refresh_token,
        })
        assert resp2.status_code == 401


# ============================================================
# FORGOT PASSWORD
# ============================================================

class TestForgotPassword:
    async def test_forgot_password(self, client: AsyncClient, registered_user):
        resp = await client.post("/auth/forgot-password", json={
            "email": registered_user["email"],
        })
        assert resp.status_code == 200

    async def test_forgot_password_unknown_email(self, client: AsyncClient):
        """Should return 200 even for unknown emails to prevent enumeration."""
        resp = await client.post("/auth/forgot-password", json={
            "email": "unknown@example.com",
        })
        assert resp.status_code == 200


# ============================================================
# RESET PASSWORD
# ============================================================

class TestResetPassword:
    async def test_reset_password(self, client: AsyncClient, db_session):
        """Register user, generate reset token, reset password."""
        from glimmora_auth.models import AuthUser, PasswordReset
        from glimmora_auth.security import hash_password
        from glimmora_auth.emailer import generate_reset_token, generate_reset_expiry

        # Create user directly (commit so other sessions can see it)
        user = AuthUser(
            email="resetme@example.com",
            hashed_password=hash_password("OldPass123!"),
            full_name="Reset User",
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # Create reset token
        token = generate_reset_token()
        reset = PasswordReset(
            token=token,
            user_id=user.id,
            expires_at=generate_reset_expiry(),
        )
        db_session.add(reset)
        await db_session.commit()

        # Reset password
        resp = await client.post("/auth/reset-password", json={
            "token": token,
            "new_password": "BrandNew123!",
        })
        assert resp.status_code == 200

        # Can login with new password
        login = await client.post("/auth/login", json={
            "email": "resetme@example.com",
            "password": "BrandNew123!",
        })
        assert login.status_code == 200

    async def test_reset_password_invalid_token(self, client: AsyncClient):
        resp = await client.post("/auth/reset-password", json={
            "token": "totally-fake-token",
            "new_password": "Whatever123!",
        })
        assert resp.status_code == 400

    async def test_reset_password_expired_token(self, client: AsyncClient, db_session):
        """Expired reset token should be rejected."""
        from glimmora_auth.models import AuthUser, PasswordReset
        from glimmora_auth.security import hash_password
        from datetime import datetime, timedelta, timezone

        user = AuthUser(
            email="expired@example.com",
            hashed_password=hash_password("OldPass123!"),
            full_name="Expired User",
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # Expired token
        reset = PasswordReset(
            token="expired-token-123",
            user_id=user.id,
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        db_session.add(reset)
        await db_session.commit()

        resp = await client.post("/auth/reset-password", json={
            "token": "***",
            "new_password": "NewPass123!",
        })
        assert resp.status_code == 400

    async def test_reset_password_revokes_sessions(self, client: AsyncClient, db_session):
        """Resetting password should revoke all refresh tokens."""
        from glimmora_auth.models import AuthUser, PasswordReset, RefreshToken
        from glimmora_auth.security import hash_password, hash_token, create_refresh_token
        from glimmora_auth.emailer import generate_reset_token, generate_reset_expiry
        from datetime import datetime, timedelta, timezone

        # Create user
        user = AuthUser(
            email="resetrev@example.com",
            hashed_password=hash_password("OldPass123!"),
            full_name="Reset Rev User",
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # Create a refresh token for the user
        refresh_str = create_refresh_token(
            data={"sub": str(user.id)},
            secret="test-secret-key-for-testing-only",
            expires_delta=timedelta(days=7),
        )
        db_session.add(RefreshToken(
            token=hash_token(refresh_str),
            user_id=user.id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        ))

        # Create reset token
        token = generate_reset_token()
        reset = PasswordReset(
            token=token,
            user_id=user.id,
            expires_at=generate_reset_expiry(),
        )
        db_session.add(reset)
        await db_session.commit()

        # Reset password
        resp = await client.post("/auth/reset-password", json={
            "token": token,
            "new_password": "BrandNew123!",
        })
        assert resp.status_code == 200

        # Old refresh token should be revoked
        resp2 = await client.post("/auth/refresh", json={
            "refresh_token": refresh_str,
        })
        assert resp2.status_code == 401
