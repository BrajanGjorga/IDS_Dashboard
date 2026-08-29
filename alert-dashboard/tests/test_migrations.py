from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


MIGRATION_PATH = Path(__file__).parents[1] / "alembic" / "versions" / "0003_add_usernames.py"
spec = spec_from_file_location("username_migration", MIGRATION_PATH)
assert spec is not None and spec.loader is not None
username_migration = module_from_spec(spec)
spec.loader.exec_module(username_migration)


def test_existing_usernames_are_safe_unique_and_bounded():
    used: set[str] = set()

    first = username_migration._username_from_email("Analyst@example.com", 1, used)
    duplicate = username_migration._username_from_email("analyst@other.example", 2, used)
    short = username_migration._username_from_email("x@example.com", 3, used)
    symbols = username_migration._username_from_email("security.team+eu@example.com", 4, used)

    assert first == "analyst"
    assert duplicate == "analyst_2"
    assert short == "user_3"
    assert symbols == "security_team_eu"
    assert all(3 <= len(username) <= 30 for username in used)
    assert len(used) == 4
