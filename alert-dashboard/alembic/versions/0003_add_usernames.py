"""Add unique usernames to user accounts.

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-28

Existing accounts receive a stable username derived from the email prefix. If a
prefix is unavailable or already used, the user ID is appended to keep it unique.
"""
from __future__ import annotations

import re
from typing import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _username_from_email(email: str, user_id: int, used: set[str]) -> str:
    prefix = email.partition("@")[0].casefold()
    candidate = re.sub(r"[^a-z0-9_-]", "_", prefix).strip("_-")[:30]
    if len(candidate) < 3:
        candidate = f"user_{user_id}"
    base = candidate
    attempt = 0
    while candidate in used:
        suffix = f"_{user_id}" if attempt == 0 else f"_{user_id}_{attempt}"
        candidate = f"{base[: 30 - len(suffix)]}{suffix}"
        attempt += 1
    used.add(candidate)
    return candidate


def upgrade() -> None:
    op.add_column("users", sa.Column("username", sa.String(length=30), nullable=True))

    connection = op.get_bind()
    users = connection.execute(sa.text("SELECT id, email FROM users ORDER BY id")).mappings()
    used: set[str] = set()
    for user in users:
        username = _username_from_email(user["email"], user["id"], used)
        connection.execute(
            sa.text("UPDATE users SET username = :username WHERE id = :user_id"),
            {"username": username, "user_id": user["id"]},
        )

    op.alter_column("users", "username", existing_type=sa.String(length=30), nullable=False)
    op.create_index("ix_users_username", "users", ["username"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_users_username", table_name="users")
    op.drop_column("users", "username")
