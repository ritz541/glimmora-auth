# glimmora-auth

Internal auth module for Glimmora projects. Drop-in FastAPI authentication with UUID primary keys, JWT tokens (access + refresh rotation), password reset, and email verification.

## Architecture

```
src/glimmora_auth/
  __init__.py      - setup_auth() entry point, wires everything into a FastAPI app
  models.py        - SQLAlchemy models (AuthUser, RefreshToken, PasswordReset, EmailVerificationToken)
  router.py        - All /auth/* endpoints and Pydantic schemas
  security.py      - Password hashing (bcrypt), JWT creation/decode, token hashing
  config.py        - AuthConfig (pydantic-settings, reads GLIMMORA_AUTH_* env vars)
  dependencies.py  - get_db dependency (session-per-request)
  cleanup.py       - cleanup_expired_tokens() for periodic maintenance
  emailer.py       - Token generation helpers (reset, verification)
```

### Key design decisions

- **GUID type**: Platform-independent UUID primary keys. Uses PostgreSQL UUID natively, falls back to String(36) on SQLite. Defined in `models.py` as `GUID(TypeDecorator)`.
- **Sentinel dependencies**: `_get_current_user`, `_get_config`, `_get_user_model` are placeholder functions that raise `NotImplementedError`. `setup_auth()` overrides them via `dependency_overrides` and module-level globals.
- **Token rotation**: Refresh tokens are single-use. On `/auth/refresh`, the old token is revoked and a new one issued. Reuse of a revoked token triggers "reuse detection" and revokes ALL tokens for that user.
- **Hashed storage**: Refresh tokens are stored as SHA-256 hashes in the DB. Password reset and verification tokens are **also stored as SHA-256 hashes** (same hashing). Only the plaintext token is passed to the send-email callbacks.
- **Stateless access tokens**: Access tokens (JWTs) are not stored server-side. They are validated purely by signature + expiry. This means logout and password-change only invalidate refresh tokens — the access token remains valid until its TTL (default: 30 min). This is standard JWT behavior; consider short TTLs to limit exposure.
- **Rate limiting**: In-memory sliding window per IP. Default limits: register=5/hr, login=10/min, forgot-password=3/hr, resend-verification=3/hr, refresh=10/min. Disable with `rate_limits={}` or pass custom dict. No external dependencies.
- **Email enumeration on /register**: Unlike /forgot-password, /register returns 409 for duplicate emails to inform users. If your deployment is security-sensitive, consider proxying register through a non-enumerating wrapper.

## setup_auth() Usage

```python
from glimmora_auth import setup_auth

setup_auth(
    app,
    database_url="postgresql+asyncpg://user:pass@localhost/dbname",
    jwt_secret="your-secret-at-least-32-chars-long",
    # Optional:
    user_model=MyCustomUser,          # Must inherit from AuthUser
    cors_origins=["http://localhost:3000"],
    include_endpoints=["register", "login"],  # Only expose these
    exclude_endpoints=["forgot-password"],    # Skip these
    on_register=my_register_hook,     # async (user, db) -> None
    on_login=my_login_hook,           # async (user, db) -> None
    send_reset_email=my_email_fn,     # async (user, token) -> None
    send_verification_email=my_vfn,   # async (user, token) -> None
    # Config overrides via kwargs:
    access_token_expire_minutes=60,
    refresh_token_expire_days=30,
    require_email_verification=True,
    verification_token_expire_hours=48,
    base_url="https://myapp.com",
)
```

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /auth/register | No | Register new user |
| POST | /auth/login | No | Login, get tokens |
| POST | /auth/refresh | No | Rotate refresh token |
| POST | /auth/logout | Yes | Revoke refresh token |
| GET | /auth/me | Yes | Get current user |
| POST | /auth/change-password | Yes | Change password |
| POST | /auth/forgot-password | No | Request password reset |
| POST | /auth/reset-password | No | Reset password with token |
| POST | /auth/verify-email | No | Verify email with token |
| POST | /auth/resend-verification | No | Resend verification email |

## Alembic Setup

This module uses `create_all` in its lifespan for dev convenience. **Production requires Alembic migrations.**

### Initial setup

```bash
# In your host project (not this module):
pip install alembic
alembic init alembic
```

### Configure env.py

In `alembic/env.py`, import the Base from glimmora_auth (and your custom models):

```python
from glimmora_auth.models import Base
# Import your custom user model too so Alembic sees it:
# from myapp.models import MyUser

target_metadata = Base.metadata
```

For async database URLs, use the `run_async` pattern:

```python
from sqlalchemy.ext.asyncio import create_async_engine

def run_migrations_online():
    connectable = create_async_engine(
        config.get_main_option("sqlalchemy.url"),
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()
```

### Generating migrations

```bash
# Auto-generate from model changes:
alembic revision --autogenerate -m "add email verification tokens"

# Review the generated migration before applying!
# UUID columns on SQLite may need manual handling.

# Apply:
alembic upgrade head

# Rollback one step:
alembic downgrade -1
```

### UUID + SQLite caveats

The `GUID` type stores UUIDs as `String(36)` on SQLite and native `UUID` on PostgreSQL. Alembic auto-generation handles this correctly, but if you switch databases, you may need to manually adjust column types in migrations.

### Custom user models

If you extend `AuthUser`, import your model before running `alembic revision --autogenerate` so Alembic discovers the subclass table. The `AuthUser.__tablename__` stays `"auth_users"` unless you override it.

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

Tests use in-memory SQLite (`aiosqlite`). No database setup needed.

## Custom User Model Pattern

```python
from glimmora_auth.models import AuthUser
from sqlalchemy import Column, String

class MyUser(AuthUser):
    __tablename__ = "auth_users"  # Same table, extends AuthUser
    company = Column(String(255), nullable=True)

# Pass to setup_auth:
setup_auth(app, ..., user_model=MyUser)
```

## Environment Variables

All config can be set via env vars with prefix `GLIMMORA_AUTH_`:

- `GLIMMORA_AUTH_JWT_SECRET` (required, min 32 chars)
- `GLIMMORA_AUTH_JWT_ALGORITHM` (default: HS256)
- `GLIMMORA_AUTH_ACCESS_TOKEN_EXPIRE_MINUTES` (default: 30)
- `GLIMMORA_AUTH_REFRESH_TOKEN_EXPIRE_DAYS` (default: 7)
- `GLIMMORA_AUTH_REQUIRE_EMAIL_VERIFICATION` (default: false)
- `GLIMMORA_AUTH_VERIFICATION_TOKEN_EXPIRE_HOURS` (default: 24)
- `GLIMMORA_AUTH_BASE_URL` (default: http://localhost:8000)
