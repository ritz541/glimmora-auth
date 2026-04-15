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

- `POST /auth/register` - Create account
- `POST /auth/login` - Login, get tokens
- `POST /auth/refresh` - Refresh access token
- `POST /auth/logout` - Invalidate token
- `POST /auth/forgot-password` - Request password reset
- `POST /auth/reset-password` - Reset with token
- `GET  /auth/me` - Get current user
- `POST /auth/change-password` - Change password (authenticated)

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
    smtp_host="smtp.example.com",
    smtp_port=587,
    smtp_user="...",
    smtp_password="...",
    from_email="noreply@example.com",
    from_name="My App",
)
```

## Custom User Fields

```python
from sqlalchemy import Column, String
from glimmora_auth import AuthBase, AuthUser

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
