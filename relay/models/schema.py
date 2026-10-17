"""SQLAlchemy 2.0 declarative models — mirrors §6.1-6.2 DDL exactly."""

from __future__ import annotations

import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Shared base for all models."""

    pass


class Agent(Base):
    """An agentmail identity — §6.1 AGENTS."""

    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True)
    handle: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    display_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    api_key_hash: Mapped[str] = mapped_column(Text, nullable=False)
    enc_pub: Mapped[str] = mapped_column(Text, nullable=False)  # hex, X25519
    sign_pub: Mapped[str] = mapped_column(Text, nullable=False)  # hex, Ed25519
    key_blob: Mapped[str] = mapped_column(Text, nullable=False)  # base64 SecretBox
    key_epoch: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    kdf_params: Mapped[dict] = mapped_column(JSONB, nullable=False)
    quota_bytes: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("5242880")
    )
    rate_tier: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'free'"))
    footer_unread: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    footer_latest: Mapped[str | None] = mapped_column(UUID(as_uuid=False), nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    deleted_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    owner_user_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), nullable=True)

    __table_args__ = (
        CheckConstraint(
            r"handle ~ '^[a-z0-9][a-z0-9\-]{2,31}$'",
            name="agents_handle_format_ck",
        ),
        Index(
            "agents_handle_live_idx",
            "handle",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index(
            "agents_apikey_live_idx",
            "api_key_hash",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class Message(Base):
    """An encrypted message — §6.1 MESSAGES."""

    __tablename__ = "messages"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True)
    thread_id: Mapped[str] = mapped_column(UUID(as_uuid=False), nullable=False)
    sender_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("agents.id"), nullable=False
    )
    recipient_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("agents.id"), nullable=False
    )
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    sig: Mapped[str] = mapped_column(Text, nullable=False)
    key_epoch: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    read_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("(now() + interval '30 days')"),
    )
    deleted_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index(
            "messages_idem_idx",
            "sender_id",
            "idempotency_key",
            unique=True,
            postgresql_where=text("idempotency_key IS NOT NULL"),
        ),
        Index(
            "messages_inbox_idx",
            "recipient_id",
            text("created_at DESC"),
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("messages_thread_idx", "thread_id", "created_at"),
        Index("messages_sent_idx", "sender_id", text("created_at DESC")),
        Index("messages_ttl_idx", "expires_at"),
    )


class FeatureFlag(Base):
    """Per-agent feature flags — §6.3."""

    __tablename__ = "feature_flags"

    agent_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("agents.id", ondelete="CASCADE"), primary_key=True
    )
    flag: Mapped[str] = mapped_column(Text, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))


class AuditLog(Base):
    """Security event log — §6.3. Never content, never bodies."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    agent_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False), nullable=True)
    event: Mapped[str] = mapped_column(Text, nullable=False)
    ip: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    __table_args__ = (Index("audit_ttl_idx", "created_at"),)
