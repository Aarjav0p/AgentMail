"""DASH-01: Account ownership, custody mode, api_key_enc, user_contacts.

Revision ID: b2c3d4e5f6a1
Revises: a1b2c3d4e5f6
Create Date: 2026-10-17

"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "b2c3d4e5f6a1"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _auth_users_exists() -> bool:
    """Report whether the ``auth.users`` table already exists.

    Supabase owns the ``auth`` schema (owner: ``supabase_auth_admin``) and
    does not grant CREATE on it to the project's ``postgres`` role.
    PostgreSQL checks schema CREATE privileges *before* the IF NOT EXISTS
    existence shortcut, so an unconditional ``CREATE TABLE IF NOT EXISTS
    auth.users`` fails on Supabase with ``permission denied for schema
    auth`` even though the table already exists there (managed by Supabase
    Auth). ``to_regclass()`` only needs USAGE on the schema — which Supabase
    does grant — making it the safe probe for the Supabase-managed table.
    """
    return bool(
        op.get_bind()
        .execute(sa.text("SELECT to_regclass('auth.users') IS NOT NULL"))
        .scalar()
    )


def _may_reference_auth_users() -> bool:
    """Report whether the current role may create FKs to ``auth.users``.

    Supabase grants ``postgres`` REFERENCES on ``auth.users`` (the canonical
    ``references auth.users`` pattern from their docs). On databases that
    withhold the privilege, the migration should still succeed: columns and
    tables are then created without the FK constraints instead of failing.
    """
    return bool(
        op.get_bind()
        .execute(
            sa.text(
                "SELECT CASE WHEN to_regclass('auth.users') IS NULL THEN false "
                "ELSE has_table_privilege('auth.users', 'REFERENCES') END"
            )
        )
        .scalar()
    )


def upgrade() -> None:
    # ── Ensure auth.users stub exists for environments without Supabase auth ──
    # On Supabase, auth.users already exists and cannot (and must not) be
    # created by this migration — see _auth_users_exists().
    if not _auth_users_exists():
        op.execute("CREATE SCHEMA IF NOT EXISTS auth")
        op.execute("CREATE TABLE IF NOT EXISTS auth.users (id UUID PRIMARY KEY)")

    # FK clauses are only emitted when the current role may reference auth.users.
    users_fk = " REFERENCES auth.users(id)" if _may_reference_auth_users() else ""
    users_fk_cascade = users_fk + " ON DELETE CASCADE" if users_fk else ""

    # ── agents additions ────────────────────────────────────────────────
    op.execute(
        f"ALTER TABLE agents ADD COLUMN IF NOT EXISTS owner_user_id UUID{users_fk}"
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
    op.execute(f"""
        CREATE TABLE IF NOT EXISTS user_contacts (
            id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            owner_user_id UUID NOT NULL{users_fk_cascade},
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
