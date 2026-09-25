from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


_settings = get_settings()

engine = create_engine(
    _settings.database_url,
    pool_pre_ping=True,
    future=True,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create tables that do not exist yet.

    Phase 0 uses create_all. Once the schema stabilises in Phase 1 this is
    replaced by Alembic migrations -- findings and evidence must survive
    schema changes, so we cannot stay on create_all past the MVP.
    """
    # Imported for the side effect of registering models on Base.metadata.
    from app import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
