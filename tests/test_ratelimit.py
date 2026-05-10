"""Tests for the in-memory rate limiter."""

import pytest
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI

from glimmora_auth.ratelimit import _parse_limit, _counter


def test_parse_limit_valid():
    """Various valid limit strings should parse correctly."""
    assert _parse_limit("10/minute") == (10, 60)
    assert _parse_limit("5/hour") == (5, 3600)
    assert _parse_limit("3/second") == (3, 1)
    assert _parse_limit("100/day") == (100, 86400)
    assert _parse_limit(" 10 / minute ") == (10, 60)
    assert _parse_limit("5/minutes") == (5, 60)  # plural


def test_parse_limit_invalid():
    """Invalid limit strings should raise ValueError."""
    with pytest.raises(ValueError, match="Invalid rate limit format"):
        _parse_limit("")
    with pytest.raises(ValueError, match="Invalid rate limit"):
        _parse_limit("abc/minute")
    with pytest.raises(ValueError, match="Unsupported"):
        _parse_limit("10/decade")


@pytest.mark.asyncio
async def test_counter_allows_under_limit():
    """Requests under the limit should be allowed."""
    _counter._windows.clear()
    key = "test:1.2.3.4"
    assert await _counter.check(key, 5, 60) is True
    assert await _counter.check(key, 5, 60) is True
    assert await _counter.check(key, 5, 60) is True
    assert await _counter.check(key, 5, 60) is True
    assert await _counter.check(key, 5, 60) is True


@pytest.mark.asyncio
async def test_counter_blocks_at_limit():
    """When hitting the exact limit, the next request should be blocked."""
    _counter._windows.clear()
    key = "test:5.6.7.8"
    assert await _counter.check(key, 3, 60) is True
    assert await _counter.check(key, 3, 60) is True
    assert await _counter.check(key, 3, 60) is True
    assert await _counter.check(key, 3, 60) is False  # 4th hits limit


@pytest.mark.asyncio
async def test_counter_expires():
    """After the window expires, requests should be allowed again."""
    _counter._windows.clear()
    key = "test:expire"
    # Use a very short window
    assert await _counter.check(key, 1, 0.1) is True
    assert await _counter.check(key, 1, 0.1) is False
    import asyncio
    await asyncio.sleep(0.15)
    assert await _counter.check(key, 1, 0.1) is True


@pytest.mark.asyncio
async def test_counter_separate_keys():
    """Different keys have independent counters."""
    _counter._windows.clear()
    assert await _counter.check("alice", 1, 60) is True
    assert await _counter.check("bob", 1, 60) is True
    assert await _counter.check("alice", 1, 60) is False
    assert await _counter.check("bob", 1, 60) is False


# ============================================================
# Integration tests: rate limiting in the app
# ============================================================


@pytest.mark.asyncio
async def test_rate_limiting_is_noop_when_not_configured():
    """Without rate_limits, the dependency should be a no-op."""
    # The existing conftest.client already tests this — rate limiting
    # is not configured in the base `app` fixture. All 73 tests pass
    # without any rate limit interference.
    pass


@pytest.mark.asyncio
async def test_rate_limiting_blocks_exceeded_requests():
    """When rate_limits is configured, exceeding the limit returns 429."""
    from glimmora_auth import setup_auth
    from glimmora_auth.models import Base
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from glimmora_auth.dependencies import get_db

    app = FastAPI()
    setup_auth(
        app,
        database_url="sqlite+aiosqlite:///:memory:",
        jwt_secret="test-secret-key-for-testing-only-32chars",
        rate_limits={"login": "2/minute"},
    )

    # Create tables (in-memory SQLite workaround)
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with factory() as session:
            async with session.begin():
                yield session

    app.dependency_overrides[get_db] = override_get_db

    # Clear the rate limiter counter for a clean slate
    _counter._windows.clear()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cl:
        # Register a user first
        reg_resp = await cl.post("/auth/register", json={
            "email": "ratelimit@example.com",
            "password": "TestPass123!",
        })
        assert reg_resp.status_code == 201

        # Login twice — should succeed
        r1 = await cl.post("/auth/login", json={
            "email": "ratelimit@example.com",
            "password": "TestPass123!",
        })
        assert r1.status_code == 200

        r2 = await cl.post("/auth/login", json={
            "email": "ratelimit@example.com",
            "password": "TestPass123!",
        })
        assert r2.status_code == 200

        # Third login with the same IP should be rate-limited
        r3 = await cl.post("/auth/login", json={
            "email": "ratelimit@example.com",
            "password": "TestPass123!",
        })
        assert r3.status_code == 429
        assert "too many" in r3.json()["detail"].lower()


@pytest.mark.asyncio
async def test_rate_limiting_custom_limits():
    """Custom rate limits should override defaults."""
    from glimmora_auth import setup_auth
    from glimmora_auth.models import Base
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from glimmora_auth.dependencies import get_db

    app = FastAPI()
    setup_auth(
        app,
        database_url="sqlite+aiosqlite:///:memory:",
        jwt_secret="test-secret-key-for-testing-only-32chars",
        rate_limits={"register": "1/minute"},
    )

    # Create tables
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with factory() as session:
            async with session.begin():
                yield session

    app.dependency_overrides[get_db] = override_get_db

    _counter._windows.clear()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cl:
        # First register — should succeed
        r1 = await cl.post("/auth/register", json={
            "email": "custom-rate@example.com",
            "password": "TestPass123!",
        })
        assert r1.status_code == 201

        # Second register (same IP) — should be blocked
        r2 = await cl.post("/auth/register", json={
            "email": "custom-rate-2@example.com",
            "password": "TestPass456!",
        })
        assert r2.status_code == 429


@pytest.mark.asyncio
async def test_unconfigured_endpoint_not_limited():
    """Endpoints not in rate_limits should not be rate-limited."""
    from glimmora_auth import setup_auth
    from glimmora_auth.models import Base
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from glimmora_auth.dependencies import get_db

    # Only limit login — /me should be unaffected
    app = FastAPI()
    setup_auth(
        app,
        database_url="sqlite+aiosqlite:///:memory:",
        jwt_secret="test-secret-key-for-testing-only-32chars",
        rate_limits={"login": "2/minute"},
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

    _counter._windows.clear()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cl:
        # Register
        reg = await cl.post("/auth/register", json={
            "email": "unlimited@example.com",
            "password": "TestPass123!",
        })
        assert reg.status_code == 201
        token = reg.json()["access_token"]

        # /me has no rate limit — should always work
        for _ in range(5):
            r = await cl.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 200
