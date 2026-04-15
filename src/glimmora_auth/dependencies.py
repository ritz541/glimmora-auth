"""FastAPI dependencies for auth."""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession


# Global session factory, set by setup_auth
_session_factory = None


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Creates and manages a database session per request."""
    if _session_factory is None:
        raise RuntimeError("Database not configured. Call setup_auth() first.")
    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


def set_session_factory(factory):
    """Set the session factory used by get_db."""
    global _session_factory
    _session_factory = factory
