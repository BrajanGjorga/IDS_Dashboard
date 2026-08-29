from app.config import Settings


def test_render_postgres_url_uses_installed_psycopg_driver():
    settings = Settings(
        database_url_override="postgresql://dashboard:secret@internal-host/dashboard"
    )

    assert (
        settings.database_url
        == "postgresql+psycopg://dashboard:secret@internal-host/dashboard"
    )


def test_non_postgres_database_url_is_unchanged():
    settings = Settings(database_url_override="sqlite:///alerts.db")

    assert settings.database_url == "sqlite:///alerts.db"
