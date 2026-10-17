"""DASH-01: Account ownership, custody mode, api_key_enc, user_contacts.

Revision ID: b2c3d4e5f6a1
Revises: a1b2c3d4e5f6
Create Date: 2026-10-17

"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b2c3d4e5f6a1"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Ensure auth.users stub exists for environments without Supabase auth ──
    op.execute("CREATE SCHEMA IF NOT EXISTS auth")
    op.execute("CREATE TABLE IF NOT EXISTS auth.users (id UUID PRIMARY KEY)")

    # ── agents additions ────────────────────────────────────────────────
    op.execute(
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS owner_user_id UUID REFERENCES auth.users(id)"
    )
    op.execute(
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS custody_mode TEXT NOT NULL DEFAULT 'user_passphrase'"
    )
    op.execute("ALTER TABLE agents ADD COLUMN IF NOT EXISTS api_key_enc TEXT")

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint WHERE conname = 'agents_custody_mode_ck'
            ) THEN
                ALTER TABLE agents ADD CONSTRAINT agents_custody_mode_ck
                    CHECK (custody_mode IN ('user_passphrase', 'server_kek'));
            END IF;
        END $$;
    """)

    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS agents_owner_one_idx "
        "ON agents (owner_user_id) WHERE owner_user_id IS NOT NULL;"
    )

    # ── user_contacts ───────────────────────────────────────────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS user_contacts (
            id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
            alias         TEXT NOT NULL CHECK (alias ~ '^[a-z0-9][a-z0-9_-]{1,31}$'),
            target_handle TEXT NOT NULL CHECK (target_handle ~ '^[a-z0-9][a-z0-9-]{2,31}$'),
            note          TEXT,
            created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (owner_user_id, alias)
        );
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS user_contacts CASCADE")
    op.execute("DROP INDEX IF EXISTS agents_owner_one_idx")
    op.execute("ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_custody_mode_ck")
    op.execute("ALTER TABLE agents DROP COLUMN IF EXISTS api_key_enc")
    op.execute("ALTER TABLE agents DROP COLUMN IF EXISTS custody_mode")
    op.execute("ALTER TABLE agents DROP COLUMN IF EXISTS owner_user_id")
