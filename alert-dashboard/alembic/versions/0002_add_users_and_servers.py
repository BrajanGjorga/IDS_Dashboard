"""Add users, registered servers, and alert ownership.

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-21

Existing alerts intentionally keep a NULL server_id because their historical
server_name values were not authenticated and cannot establish ownership.
"""
from typing import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "servers",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("server_name", sa.String(length=255), nullable=False),
        sa.Column("api_token_hash", sa.String(length=64), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "server_name", name="uq_servers_user_name"),
    )
    op.create_index("ix_servers_api_token_hash", "servers", ["api_token_hash"], unique=True)
    op.create_index("ix_servers_user_id", "servers", ["user_id"], unique=False)

    op.add_column("alerts", sa.Column("server_id", sa.BigInteger(), nullable=True))
    op.create_foreign_key(
        "fk_alerts_server_id_servers",
        "alerts",
        "servers",
        ["server_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index("ix_alerts_server_id", "alerts", ["server_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_alerts_server_id", table_name="alerts")
    op.drop_constraint("fk_alerts_server_id_servers", "alerts", type_="foreignkey")
    op.drop_column("alerts", "server_id")
    op.drop_index("ix_servers_user_id", table_name="servers")
    op.drop_index("ix_servers_api_token_hash", table_name="servers")
    op.drop_table("servers")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")

