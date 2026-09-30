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
    _add_missing_columns()


# Columns added after a table first shipped. create_all never alters an
# existing table, so these are applied idempotently on start-up until the
# schema moves to Alembic.
_ADDED_COLUMNS = {
    "email_sessions": {
        "risk_class": "VARCHAR(16)",
        "risk_score": "DOUBLE PRECISION",
        "risk_confidence": "DOUBLE PRECISION",
        "risk_detail": "JSONB",
    },
}


def _add_missing_columns() -> None:
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    with engine.begin() as conn:
        for table, columns in _ADDED_COLUMNS.items():
            if not inspector.has_table(table):
                continue
            existing = {c["name"] for c in inspector.get_columns(table)}
            for name, ddl in columns.items():
                if name not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
