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

    async def test_register_password_too_long(self, client: AsyncClient):
        """Password >72 bytes should be rejected (bcrypt truncation)."""
        resp = await client.post("/auth/register", json={
            "email": "longpw@example.com",
            "password": "A" * 80 + "bcd123!",  # 80 * 'A' = 80 bytes, plus rest
            "full_name": "Long PW User",
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

    async def test_login_unverified_blocked(self):
        """Login should be blocked when require_email_verification is set
        and user's email is not verified."""
        from fastapi import FastAPI
        from glimmora_auth import setup_auth
        from glimmora_auth.models import Base
        from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
        from glimmora_auth.dependencies import get_db
        from httpx import ASGITransport, AsyncClient

        app = FastAPI()
        setup_auth(
            app,
            database_url="sqlite+aiosqlite:///:memory:",
            jwt_secret="test-secret-key-for-testing-only-32chars",
            require_email_verification=True,
            rate_limits={},
        )

        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        async def override_get_db():
            async with factory() as session:
                async with session.begin():
                    yield session

        app.dependency_overrides[get_db] = override_get_db

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as cl:
            # Register — creates unverified user + verification token
            reg = await cl.post("/auth/register", json={
                "email": "unverified@example.com",
                "password": "TestPass123!",
            })
            assert reg.status_code == 201

            # Login should be blocked
            login = await cl.post("/auth/login", json={
                "email": "unverified@example.com",
                "password": "TestPass123!",
            })
            assert login.status_code == 403
            assert "not verified" in login.json()["detail"].lower()


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
        from glimmora_auth.security import hash_password, hash_token
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

        # Create reset token — store hashed, keep plain for API call
        token = generate_reset_token()
        reset = PasswordReset(
            token=hash_token(token),
            user_id=user.id,
            expires_at=generate_reset_expiry(),
        )
        db_session.add(reset)
        await db_session.commit()

        # Reset password using the plain token (endpoint hashes it internally)
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
        from glimmora_auth.security import hash_password, hash_token
        from datetime import datetime, timedelta, timezone

        user = AuthUser(
            email="expired@example.com",
            hashed_password=hash_password("OldPass123!"),
            full_name="Expired User",
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # Expired token — store hashed, use matching plain token for API call
        token = "expired-token-123"
        reset = PasswordReset(
            token=hash_token(token),
            user_id=user.id,
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        db_session.add(reset)
        await db_session.commit()

        resp = await client.post("/auth/reset-password", json={
            "token": token,
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
            secret="test-secret-key-for-testing-only-32chars",
            expires_delta=timedelta(days=7),
        )
        db_session.add(RefreshToken(
            token=hash_token(refresh_str),
            user_id=user.id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        ))

        # Create reset token — store hashed
        token = generate_reset_token()
        reset = PasswordReset(
            token=hash_token(token),
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


# ============================================================
# EMAIL VERIFICATION
# ============================================================

class TestEmailVerification:
    async def test_verify_email_success(self, client, db_session):
        """Create unverified user with token, verify via endpoint."""
        from glimmora_auth.models import AuthUser, EmailVerificationToken
        from glimmora_auth.security import hash_password, hash_token
        from glimmora_auth.emailer import generate_verification_token, generate_verification_expiry

        user = AuthUser(
            email="verify-me@example.com",
            hashed_password=hash_password("TestPass123!"),
            full_name="Verify Me",
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        token = generate_verification_token()
        verification = EmailVerificationToken(
            token=hash_token(token),
            user_id=user.id,
            expires_at=generate_verification_expiry(hours=24),
        )
        db_session.add(verification)
        await db_session.commit()

        resp = await client.post("/auth/verify-email", json={"token": token})
        assert resp.status_code == 200
        assert resp.json()["message"] == "Email verified successfully"

        # User should now be verified in DB
        await db_session.refresh(user)
        assert user.is_verified is True

        # Reusing the same token should fail
        resp2 = await client.post("/auth/verify-email", json={"token": token})
        assert resp2.status_code == 400
        assert "already used" in resp2.json()["detail"].lower()

    async def test_verify_email_invalid_token(self, client):
        resp = await client.post("/auth/verify-email", json={"token": "nonexistent-token"})
        assert resp.status_code == 400
        assert "invalid" in resp.json()["detail"].lower() or "already used" in resp.json()["detail"].lower()

    async def test_verify_email_expired_token(self, client, db_session):
        """Expired verification token should be rejected."""
        from glimmora_auth.models import AuthUser, EmailVerificationToken
        from glimmora_auth.security import hash_password, hash_token
        from datetime import datetime, timedelta, timezone

        user = AuthUser(
            email="expired-verify@example.com",
            hashed_password=hash_password("TestPass123!"),
            full_name="Expired Verify",
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        token = "expired-verify-token"
        verification = EmailVerificationToken(
            token=hash_token(token),
            user_id=user.id,
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        db_session.add(verification)
        await db_session.commit()

        resp = await client.post("/auth/verify-email", json={"token": token})
        assert resp.status_code == 400
        assert "expired" in resp.json()["detail"].lower()

    async def test_resend_verification(self, client, db_session):
        """Resend verification for an unverified user."""
        from glimmora_auth.models import AuthUser
        from glimmora_auth.security import hash_password

        user = AuthUser(
            email="resend-me@example.com",
            hashed_password=hash_password("TestPass123!"),
            full_name="Resend Me",
            is_verified=False,
        )
        db_session.add(user)
        await db_session.commit()

        resp = await client.post("/auth/resend-verification", json={"email": "resend-me@example.com"})
        assert resp.status_code == 200

    async def test_resend_verification_unknown_email(self, client):
        """Should return 200 even for unknown emails (prevent enumeration)."""
        resp = await client.post("/auth/resend-verification", json={"email": "nobody@example.com"})
        assert resp.status_code == 200

    async def test_resend_verification_already_verified(self, client, db_session):
        """Should return 200 but do nothing for already verified users."""
        from glimmora_auth.models import AuthUser
        from glimmora_auth.security import hash_password

        user = AuthUser(
            email="already-verified@example.com",
            hashed_password=hash_password("TestPass123!"),
            full_name="Already Verified",
            is_verified=True,
        )
        db_session.add(user)
        await db_session.commit()

        resp = await client.post("/auth/resend-verification", json={"email": "already-verified@example.com"})
        assert resp.status_code == 200


# ============================================================
# EVENT HOOKS
# ============================================================

class TestEventHooks:
    async def test_on_register_hook(self):
        """on_register callback should fire when user registers."""
        from fastapi import FastAPI
        from glimmora_auth import setup_auth
        from glimmora_auth.models import Base
        from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

        hook_called = False
        captured_user = None

        async def my_on_register(user, db):
            nonlocal hook_called, captured_user
            hook_called = True
            captured_user = user

        app = FastAPI()
        setup_auth(
            app,
            database_url="sqlite+aiosqlite:///:memory:",
            jwt_secret="test-secret-key-for-testing-only-32chars",
            on_register=my_on_register,
            rate_limits={},
        )

        # Create tables manually — in-memory SQLite means lifespan engine
        # and request engine are separate connections with separate DBs
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        from glimmora_auth.dependencies import get_db

        async def override_get_db():
            async with factory() as session:
                async with session.begin():
                    yield session

        app.dependency_overrides[get_db] = override_get_db

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as cl:
            resp = await cl.post("/auth/register", json={
                "email": "hooktest@example.com",
                "password": "TestPass123!",
            })
            assert resp.status_code == 201
            assert hook_called, "on_register hook was not called"
            assert captured_user is not None
            assert captured_user.email == "hooktest@example.com"

    async def test_on_login_hook(self):
        """on_login callback should fire on successful login."""
        from fastapi import FastAPI
        from glimmora_auth import setup_auth
        from glimmora_auth.models import Base
        from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

        hook_called = False
        captured_user = None

        async def my_on_login(user, db):
            nonlocal hook_called, captured_user
            hook_called = True
            captured_user = user

        app = FastAPI()
        setup_auth(
            app,
            database_url="sqlite+aiosqlite:///:memory:",
            jwt_secret="test-secret-key-for-testing-only-32chars",
            on_login=my_on_login,
            rate_limits={},
        )

        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        from glimmora_auth.dependencies import get_db

        async def override_get_db():
            async with factory() as session:
                async with session.begin():
                    yield session

        app.dependency_overrides[get_db] = override_get_db

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as cl:
            await cl.post("/auth/register", json={
                "email": "loginhook@example.com",
                "password": "TestPass123!",
            })
            resp = await cl.post("/auth/login", json={
                "email": "loginhook@example.com",
                "password": "TestPass123!",
            })
            assert resp.status_code == 200
            assert hook_called, "on_login hook was not called"
            assert captured_user is not None
            assert captured_user.email == "loginhook@example.com"

    async def test_send_reset_email_hook(self):
        """send_reset_email callback should fire on forgot-password."""
        from fastapi import FastAPI
        from glimmora_auth import setup_auth
        from glimmora_auth.models import Base
        from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

        hook_called = False
        captured_token = None

        async def my_send_reset(user, token):
            nonlocal hook_called, captured_token
            hook_called = True
            captured_token = token

        app = FastAPI()
        setup_auth(
            app,
            database_url="sqlite+aiosqlite:///:memory:",
            jwt_secret="test-secret-key-for-testing-only-32chars",
            send_reset_email=my_send_reset,
            rate_limits={},
        )

        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        from glimmora_auth.dependencies import get_db

        async def override_get_db():
            async with factory() as session:
                async with session.begin():
                    yield session

        app.dependency_overrides[get_db] = override_get_db

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as cl:
            await cl.post("/auth/register", json={
                "email": "resethook@example.com",
                "password": "TestPass123!",
            })
            resp = await cl.post("/auth/forgot-password", json={
                "email": "resethook@example.com",
            })
            assert resp.status_code == 200
            assert hook_called, "send_reset_email hook was not called"
            assert captured_token is not None
            assert len(captured_token) > 0

    async def test_send_verification_email_hook(self):
        """send_verification_email callback should fire on register with require_email_verification."""
        from fastapi import FastAPI
        from glimmora_auth import setup_auth
        from glimmora_auth.models import Base
        from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

        hook_called = False
        captured_token = None

        async def my_send_verification(user, token):
            nonlocal hook_called, captured_token
            hook_called = True
            captured_token = token

        app = FastAPI()
        setup_auth(
            app,
            database_url="sqlite+aiosqlite:///:memory:",
            jwt_secret="test-secret-key-for-testing-only-32chars",
            require_email_verification=True,
            send_verification_email=my_send_verification,
            rate_limits={},
        )

        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        from glimmora_auth.dependencies import get_db

        async def override_get_db():
            async with factory() as session:
                async with session.begin():
                    yield session

        app.dependency_overrides[get_db] = override_get_db

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as cl:
            resp = await cl.post("/auth/register", json={
                "email": "verifhook@example.com",
                "password": "TestPass123!",
            })
            assert resp.status_code == 201
            assert hook_called, "send_verification_email hook was not called"
            assert captured_token is not None
            assert len(captured_token) > 0

    async def test_hooks_noop_when_not_configured(self, client, registered_user):
        """Hooks should be no-ops when not passed to setup_auth."""
        # Just verify the standard flow works without hooks
        resp = await client.post("/auth/login", json={
            "email": registered_user["email"],
            "password": registered_user["password"],
        })
        assert resp.status_code == 200


# ============================================================
# INCLUDE / EXCLUDE ENDPOINTS
# ============================================================

async def _count_routes_by_path(app):
    """Return set of endpoint names (e.g. 'register', 'login') registered under /auth/."""
    paths = set()
    for route in app.router.routes:
        if hasattr(route, "path"):
            path = route.path.strip("/")
            # /auth/register -> parts ['auth', 'register'] -> 'register'
            parts = path.split("/")
            if len(parts) >= 2 and parts[-2] == "auth":
                paths.add(parts[-1])
    return paths


class TestEndpointFiltering:
    async def test_include_only_register(self):
        """When include_endpoints=['register'], only /auth/register should exist."""
        from fastapi import FastAPI
        from glimmora_auth import setup_auth

        app = FastAPI()
        setup_auth(
            app,
            database_url="sqlite+aiosqlite:///:memory:",
            jwt_secret="test-secret-key-for-testing-only",
            access_token_expire_minutes=30,
            include_endpoints=["register"],
        )

        paths = await _count_routes_by_path(app)
        assert paths == {"register"}, f"Expected only 'register', got {paths}"

    async def test_include_multiple(self):
        """include_endpoints can specify multiple endpoints."""
        from fastapi import FastAPI
        from glimmora_auth import setup_auth

        app = FastAPI()
        setup_auth(
            app,
            database_url="sqlite+aiosqlite:///:memory:",
            jwt_secret="test-secret-key-for-testing-only",
            include_endpoints=["register", "login"],
        )

        paths = await _count_routes_by_path(app)
        assert "register" in paths
        assert "login" in paths
        assert "logout" not in paths
        assert "me" not in paths

    async def test_exclude_forgot_password(self):
        """When exclude_endpoints=['forgot-password'], that endpoint should not exist."""
        from fastapi import FastAPI
        from glimmora_auth import setup_auth

        app = FastAPI()
        setup_auth(
            app,
            database_url="sqlite+aiosqlite:///:memory:",
            jwt_secret="test-secret-key-for-testing-only",
            exclude_endpoints=["forgot-password"],
        )

        paths = await _count_routes_by_path(app)
        assert "forgot-password" not in paths
        assert "register" in paths  # other endpoints still present

    async def test_exclude_multiple(self):
        """Excluding multiple endpoints works."""
        from fastapi import FastAPI
        from glimmora_auth import setup_auth

        app = FastAPI()
        setup_auth(
            app,
            database_url="sqlite+aiosqlite:///:memory:",
            jwt_secret="test-secret-key-for-testing-only",
            exclude_endpoints=["register", "login", "logout", "refresh", "me",
                                "change-password", "forgot-password", "reset-password",
                                "verify-email", "resend-verification"],
        )

        paths = await _count_routes_by_path(app)
        assert len(paths) == 0, f"Expected 0 routes, got {paths}"

    async def test_include_and_exclude_together(self):
        """When both include and exclude are set, both filters apply.

        Include narrows to the listed endpoints, then exclude removes from that set.
        """
        from fastapi import FastAPI
        from glimmora_auth import setup_auth

        app = FastAPI()
        setup_auth(
            app,
            database_url="sqlite+aiosqlite:///:memory:",
            jwt_secret="test-secret-key-for-testing-only",
            include_endpoints=["register", "login", "me"],
            exclude_endpoints=["login"],
        )

        paths = await _count_routes_by_path(app)
        assert "register" in paths
        assert "login" not in paths  # removed by exclude
        assert "me" in paths
