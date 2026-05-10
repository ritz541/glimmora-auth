import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import StaticPool
from glimmora_auth.models import Base


@pytest_asyncio.fixture
async def db_engine():
    """In-memory SQLite engine for this test function."""
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine):
    """Async session for direct DB access in tests (test setup only)."""
    factory = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session


@pytest_asyncio.fixture
async def app(db_engine):
    """Create a test FastAPI app with auth configured."""
    from fastapi import FastAPI
    from glimmora_auth import setup_auth
    from glimmora_auth.dependencies import get_db

    app = FastAPI()

    factory = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with factory() as session:
            async with session.begin():
                yield session

    setup_auth(
        app,
        database_url="sqlite+aiosqlite:///:memory:",
        jwt_secret="test-secret-key-for-testing-only",
        access_token_expire_minutes=30,
        refresh_token_expire_days=7,
        rate_limits={},  # Disable rate limiting for test suite
    )

    app.dependency_overrides[get_db] = override_get_db

    return app


@pytest_asyncio.fixture
async def client(app):
    """Async test client."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def registered_user(client):
    """Register a test user and return credentials."""
    resp = await client.post("/auth/register", json={
        "email": "test@example.com",
        "password": "TestPass123!",
        "full_name": "Test User",
    })
    assert resp.status_code == 201, f"Register failed: {resp.status_code} {resp.text}"
    return {
        "email": "test@example.com",
        "password": "TestPass123!",
        "full_name": "Test User",
        "response": resp.json(),
    }


@pytest_asyncio.fixture
async def logged_in_client(client, registered_user):
    """Client with valid auth token."""
    resp = await client.post("/auth/login", json={
        "email": registered_user["email"],
        "password": registered_user["password"],
    })
    token = resp.json()["access_token"]
    client.headers["Authorization"] = f"Bearer {token}"
    return client
