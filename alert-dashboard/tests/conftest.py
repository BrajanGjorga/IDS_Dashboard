from __future__ import annotations

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from app.config import Settings
from app.database import Base
from app.main import create_app


@pytest.fixture
def client(tmp_path) -> Generator[TestClient, None, None]:
    database_path = tmp_path / "alerts-test.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    engine = create_engine(
        database_url,
        connect_args={"check_same_thread": False},
        pool_pre_ping=True,
    )
    Base.metadata.create_all(engine)
    settings = Settings(
        database_url_override=database_url,
        log_level="DEBUG",
        log_file=tmp_path / "alert-dashboard-test.log",
        session_secret="test-session-secret-with-enough-entropy",
    )
    application = create_app(settings=settings, engine=engine)

    with TestClient(application) as test_client:
        yield test_client

    Base.metadata.drop_all(engine)
    engine.dispose()
