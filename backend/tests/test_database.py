from database import normalize_database_url


def test_normalize_legacy_postgres_scheme():
    assert (
        normalize_database_url("postgres://user:pass@db:5432/sentineltrace")
        == "postgresql://user:pass@db:5432/sentineltrace"
    )


def test_preserve_supported_database_urls():
    sqlite_url = "sqlite:///./sentineltrace.db"
    postgres_url = "postgresql://user:pass@db:5432/sentineltrace"

    assert normalize_database_url(sqlite_url) == sqlite_url
    assert normalize_database_url(postgres_url) == postgres_url
