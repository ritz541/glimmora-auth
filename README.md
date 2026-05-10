# glimmora-auth

Internal auth module for Glimmora projects. Drop-in JWT auth for FastAPI.

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
    database_url="postgresql://user:pass@localhost/mydb",
    jwt_secret="your-secret-key",
)
```

That's it. You get these endpoints:

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

> **Note:** Access tokens are stateless JWTs — they aren't stored server-side. Logout and password-change only invalidate refresh tokens; existing access tokens remain valid until their TTL (default: 30 min). Keep TTLs short for tighter control.

## Configuration

```python
setup_auth(
    app,
    database_url="postgresql://...",
    jwt_secret="...",
    # Optional
    jwt_algorithm="HS256",
    access_token_expire_minutes=30,
    refresh_token_expire_days=7,
    require_email_verification=True,
    verification_token_expire_hours=48,
    send_verification_email=my_email_fn,  # async (user, token) -> None
    send_reset_email=my_email_fn,         # async (user, token) -> None
)
```

## Custom User Fields

```python
from sqlalchemy import Column, String
from glimmora_auth import AuthUser

class User(AuthUser):
    company = Column(String, nullable=True)
    department = Column(String, nullable=True)

setup_auth(
    app,
    database_url="...",
    jwt_secret="...",
    user_model=User,
)
```
