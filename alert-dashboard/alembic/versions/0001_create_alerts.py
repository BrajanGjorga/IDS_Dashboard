"""Create alerts table.

Revision ID: 0001
Revises:
Create Date: 2026-08-19
"""
from typing import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("event_id", sa.String(length=255), nullable=False),
        sa.Column("server_name", sa.String(length=255), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("prediction", sa.String(length=100), nullable=True),
        sa.Column("predicted_label", sa.String(length=100), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("source_csv", sa.Text(), nullable=True),
        sa.Column("model_version", sa.String(length=255), nullable=True),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("destination_ip", sa.String(length=45), nullable=True),
        sa.Column("source_port", sa.Integer(), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=50), nullable=True),
        sa.Column("flow_duration", sa.Float(), nullable=True),
        sa.Column("flow", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged", sa.Boolean(), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alerts_event_id", "alerts", ["event_id"], unique=True)
    op.create_index("ix_alerts_server_name", "alerts", ["server_name"], unique=False)
    op.create_index("ix_alerts_timestamp", "alerts", ["timestamp"], unique=False)
    op.create_index("ix_alerts_prediction", "alerts", ["prediction"], unique=False)
    op.create_index("ix_alerts_received_at", "alerts", ["received_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_alerts_received_at", table_name="alerts")
    op.drop_index("ix_alerts_prediction", table_name="alerts")
    op.drop_index("ix_alerts_timestamp", table_name="alerts")
    op.drop_index("ix_alerts_server_name", table_name="alerts")
    op.drop_index("ix_alerts_event_id", table_name="alerts")
    op.drop_table("alerts")
