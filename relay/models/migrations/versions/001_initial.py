"""Initial schema — agents, messages, feature_flags, audit_log.

Revision ID: a1b2c3d4e5f6
Revises:
Create Date: 2026-10-17

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── agents ──────────────────────────────────────────────────────────
    op.create_table(
        "agents",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("handle", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=True),
        sa.Column("api_key_hash", sa.Text(), nullable=False),
        sa.Column("enc_pub", sa.Text(), nullable=False),
        sa.Column("sign_pub", sa.Text(), nullable=False),
        sa.Column("key_blob", sa.Text(), nullable=False),
        sa.Column("key_epoch", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("kdf_params", JSONB(), nullable=False),
        sa.Column("quota_bytes", sa.Integer(), nullable=False, server_default=sa.text("5242880")),
        sa.Column("rate_tier", sa.Text(), nullable=False, server_default=sa.text("'free'")),
        sa.Column("footer_unread", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("footer_latest", UUID(as_uuid=False), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            r"handle ~ '^[a-z0-9][a-z0-9\-]{2,31}$'",
            name="agents_handle_format_ck",
        ),
    )
    op.create_index(
        "agents_handle_live_idx",
        "agents",
        ["handle"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_index(
        "agents_apikey_live_idx",
        "agents",
        ["api_key_hash"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )

    # ── messages ────────────────────────────────────────────────────────
    op.create_table(
        "messages",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("thread_id", UUID(as_uuid=False), nullable=False),
        sa.Column("sender_id", UUID(as_uuid=False), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("recipient_id", UUID(as_uuid=False), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("ciphertext", sa.Text(), nullable=False),
        sa.Column("sig", sa.Text(), nullable=False),
        sa.Column("key_epoch", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("idempotency_key", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("(now() + interval '30 days')")),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "messages_idem_idx",
        "messages",
        ["sender_id", "idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )
    op.create_index(
        "messages_inbox_idx",
        "messages",
        ["recipient_id", sa.text("created_at DESC")],
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_index("messages_thread_idx", "messages", ["thread_id", "created_at"])
    op.create_index("messages_sent_idx", "messages", ["sender_id", sa.text("created_at DESC")])
    op.create_index("messages_ttl_idx", "messages", ["expires_at"])

    # ── feature_flags ───────────────────────────────────────────────────
    op.create_table(
        "feature_flags",
        sa.Column(
            "agent_id",
            UUID(as_uuid=False),
            sa.ForeignKey("agents.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("flag", sa.Text(), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )

    # ── audit_log ───────────────────────────────────────────────────────
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("agent_id", UUID(as_uuid=False), nullable=True),
        sa.Column("event", sa.Text(), nullable=False),
        sa.Column("ip", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("audit_ttl_idx", "audit_log", ["created_at"])


def downgrade() -> None:
    op.drop_table("audit_log")
    op.drop_table("feature_flags")
    op.drop_table("messages")
    op.drop_table("agents")
