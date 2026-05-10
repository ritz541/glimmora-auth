# glimmora-auth

Internal auth module for Glimmora projects. Drop-in JWT auth for FastAPI with UUID primary keys, token rotation, password reset, email verification, and rate limiting.

## Installation

```bash
pip install git+https://github.com/glimmora/glimmora-auth.git
```

## Quick Start

```python
from fastapi import FastAPI
from glimmora_auth import setup_auth

app = FastAPI()

setup_auth(
    app,
    database_url="postgresql+asyncpg://user:pass@localhost/mydb",
    jwt_secret="your-secret-at-least-32-chars-long",
)

# Run with: uvicorn main:app --reload
```

You get these endpoints automatically:

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /auth/register | No | Create account |
| POST | /auth/login | No | Login, get tokens |
| POST | /auth/refresh | No | Rotate refresh token |
| POST | /auth/logout | Yes | Invalidate refresh token |
| GET  | /auth/me | Yes | Get current user |
| POST | /auth/change-password | Yes | Change password (revokes all sessions) |
| POST | /auth/forgot-password | No | Request password reset |
| POST | /auth/reset-password | No | Reset with token (revokes all sessions) |
| POST | /auth/verify-email | No | Verify email with token |
| POST | /auth/resend-verification | No | Resend verification email |

> **Access tokens** are stateless JWTs (not stored server-side). Logout and password-change only invalidate refresh tokens; existing access tokens remain valid until their TTL (default: 30 min). Keep TTLs short.

## Running

```bash
# Install
pip install git+https://github.com/glimmora/glimmora-auth.git
pip install uvicorn

# Create a file (e.g. main.py)
echo '
from fastapi import FastAPI
from glimmora_auth import setup_auth

app = FastAPI()
setup_auth(
    app,
    database_url="postgresql+asyncpg://user:pass@localhost/mydb",
    jwt_secret="replace-with-at-least-32-chars",
)
' > main.py

# Run
uvicorn main:app --reload
```

## Full Configuration

```python
setup_auth(
    app,
    database_url="postgresql+asyncpg://user:pass@localhost/mydb",
    jwt_secret="your-secret-at-least-32-chars-long",

    # --- Endpoint filtering ---
    include_endpoints=["register", "login"],   # Only expose these
    exclude_endpoints=["forgot-password"],     # Skip these

    # --- Event hooks (email delivery, logging, etc.) ---
    on_register=my_register_hook,              # async (user, db) -> None
    on_login=my_login_hook,                    # async (user, db) -> None
    send_reset_email=my_email_fn,              # async (user, token) -> None
    send_verification_email=my_email_fn,       # async (user, token) -> None

    # --- CORS ---
    cors_origins=["http://localhost:3000"],

    # --- Rate limiting (in-memory sliding window) ---
    rate_limits={
        "register": "5/hour",
        "login": "10/minute",
        "forgot-password": "3/hour",
        "resend-verification": "3/hour",
        "refresh": "10/minute",
        # Pass {} to disable entirely
    },

    # --- Config overrides ---
    jwt_algorithm="HS256",
    access_token_expire_minutes=30,
    refresh_token_expire_days=7,
    require_email_verification=True,
    verification_token_expire_hours=48,
    base_url="https://myapp.com",
)
```

## Rate Limiting

In-memory sliding window per IP. No external dependencies.

| Endpoint | Default Limit |
|----------|--------------|
| `/auth/register` | 5/hour |
| `/auth/login` | 10/minute |
| `/auth/refresh` | 10/minute |
| `/auth/forgot-password` | 3/hour |
| `/auth/resend-verification` | 3/hour |

Disable: `rate_limits={}`. Custom limits merge with defaults.

> **Note:** Each uvicorn/gunicorn worker has its own counter — effective limits scale with worker count. For multi-worker deployments, use a shared backend like Redis.

## Custom User Fields

```python
from sqlalchemy import Column, String
from glimmora_auth import AuthUser, setup_auth

class User(AuthUser):
    __tablename__ = "auth_users"  # Extends the same table
    company = Column(String(255), nullable=True)

setup_auth(app, database_url="...", jwt_secret="...", user_model=User)
```

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

Tests use in-memory SQLite. No database setup needed.

## Environment Variables

All config can be set via env vars with prefix `GLIMMORA_AUTH_`:

| Variable | Default |
|----------|---------|
| `GLIMMORA_AUTH_JWT_SECRET` | (required, min 32 chars) |
| `GLIMMORA_AUTH_JWT_ALGORITHM` | HS256 |
| `GLIMMORA_AUTH_ACCESS_TOKEN_EXPIRE_MINUTES` | 30 |
| `GLIMMORA_AUTH_REFRESH_TOKEN_EXPIRE_DAYS` | 7 |
| `GLIMMORA_AUTH_REQUIRE_EMAIL_VERIFICATION` | false |
| `GLIMMORA_AUTH_VERIFICATION_TOKEN_EXPIRE_HOURS` | 24 |
| `GLIMMORA_AUTH_BASE_URL` | http://localhost:8000 |
