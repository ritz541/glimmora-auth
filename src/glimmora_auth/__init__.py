"""glimmora-auth - Internal auth module for Glimmora projects."""

from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Callable, Optional, Sequence

from fastapi import APIRouter, Depends, FastAPI, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from glimmora_auth.config import AuthConfig
from glimmora_auth.dependencies import get_db, set_session_factory
from glimmora_auth.models import AuthUser, Base, PasswordReset, RefreshToken, EmailVerificationToken
from glimmora_auth.router import _get_config, _get_current_user, _get_user_model, oauth2_scheme, router
from glimmora_auth.router import _set_user_model as _router_set_user_model
from glimmora_auth.security import decode_token, hash_token

from glimmora_auth.cleanup import cleanup_expired_tokens


def setup_auth(
    app,
    database_url: str,
    jwt_secret: str,
    user_model=None,
    cors_origins: Optional[Sequence[str]] = None,
    include_endpoints: Optional[Sequence[str]] = None,
    exclude_endpoints: Optional[Sequence[str]] = None,
    on_register: Optional[Callable] = None,
    on_login: Optional[Callable] = None,
    send_reset_email: Optional[Callable] = None,
    send_verification_email: Optional[Callable] = None,
    **kwargs,
):
    """Set up auth on a FastAPI app. Registers all /auth/* endpoints.

    Args:
        app: FastAPI application instance.
        database_url: Database connection string (async).
        jwt_secret: Secret key for JWT signing.
        user_model: Custom user model inheriting from AuthUser (optional).
        cors_origins: List of allowed CORS origins. If provided, adds CORSMiddleware.
        include_endpoints: Only register these endpoint names (e.g. ['register', 'login']).
        exclude_endpoints: Skip these endpoint names (e.g. ['forgot-password']).
        on_register: Async callback(user, db) called after user registration.
        on_login: Async callback(user, db) called after successful login.
        send_reset_email: Async callback(user, token) called to send password reset email.
        send_verification_email: Async callback(user, token) called to send email verification.
        **kwargs: Additional config options (jwt_algorithm, access_token_expire_minutes, etc.)
    """
    config = AuthConfig(jwt_secret=jwt_secret, **kwargs)

    # Store event hooks on config
    config.on_register = on_register
    config.on_login = on_login
    config.send_reset_email = send_reset_email
    config.send_verification_email = send_verification_email

    # CORS helper
    if cors_origins:
        from fastapi.middleware.cors import CORSMiddleware

        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(cors_origins),
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Set up database engine
    engine = create_async_engine(database_url, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Set global session factory for get_db dependency
    set_session_factory(session_factory)

    # Determine user model
    User = user_model or AuthUser

    # Wrap existing lifespan to include DB init
    original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan_with_db(app_instance):
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        if original_lifespan:
            async with original_lifespan(app_instance):
                yield
        else:
            yield

    app.router.lifespan_context = lifespan_with_db

    # Override sentinel dependencies
    app.dependency_overrides[_get_config] = lambda: config
    _router_set_user_model(User)

    # Create real get_current_user
    async def real_get_current_user(
        request: Request,
        db: AsyncSession = Depends(get_db),
    ) -> AuthUser:
        from fastapi import HTTPException

        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing or invalid authorization header")

        token = auth_header.split(" ", 1)[1]
        payload = decode_token(token, config.jwt_secret, config.jwt_algorithm)
        if not payload or payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid or expired token")

        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")

        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        if not user.is_active:
            raise HTTPException(status_code=403, detail="Account is deactivated")

        return user

    app.dependency_overrides[_get_current_user] = real_get_current_user

    # Register the router, with optional endpoint filtering
    if include_endpoints or exclude_endpoints:
        target_router = _filter_router(router, include_endpoints, exclude_endpoints)
    else:
        target_router = router

    app.include_router(target_router)


def _filter_router(
    source: APIRouter,
    include: Optional[Sequence[str]] = None,
    exclude: Optional[Sequence[str]] = None,
) -> APIRouter:
    """Create a new router containing only the selected routes.

    Args:
        source: The original router with all routes.
        include: Endpoint names to keep (e.g. ['register', 'login']).
        exclude: Endpoint names to skip.
    Returns:
        A new APIRouter with the filtered routes.
    """
    filtered = APIRouter(prefix=source.prefix, tags=source.tags)

    for route in source.routes:
        if not hasattr(route, "path"):
            continue
        # Strip prefix to get endpoint name, e.g. /auth/register -> register
        endpoint_name = route.path.replace(source.prefix + "/", "") if source.prefix else route.path.lstrip("/")

        if include and endpoint_name not in include:
            continue
        if exclude and endpoint_name in exclude:
            continue

        # Copy the route to the new router
        methods = getattr(route, "methods", None) or set()
        if methods:
            filtered.add_api_route(
                path=route.path,
                endpoint=route.endpoint,
                methods=list(methods),
                **{k: v for k, v in route.__dict__.items()
                   if k in ("response_model", "status_code", "tags", "summary",
                            "description", "responses", "name", "dependencies")}
                   and v is not None,
            )

    return filtered


__all__ = [
    "setup_auth",
    "AuthConfig",
    "Base",
    "AuthUser",
    "RefreshToken",
    "PasswordReset",
    "EmailVerificationToken",
    "hash_token",
    "oauth2_scheme",
    "cleanup_expired_tokens",
]
