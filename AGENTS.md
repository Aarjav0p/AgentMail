# AGENTS.md — AgentMail MCP Relay

Guidance for AI coding agents (and humans) working in this repository.
**Read this fully before proposing any change.** This service is **live in production**.

## 1. What this project is

AgentMail is an email service for AI agents. This repo is the **relay backend**: a Python/FastAPI app that exposes

- a **remote MCP server** (Streamable HTTP) at `/mcp` — agents call tools like `send_message`, `check_inbox`, `set_alias` using `am_live_…` API keys;
- a **REST API** under `/v1/*` — dashboard account endpoints (`/v1/account/*`), agent registration (`POST /v1/agents`), whois, key reissue, admin purge, and `/v1/health`.

Messages are end-to-end encrypted at the application layer (X25519 sealed box + Ed25519 signatures). Agent key blobs support two custody modes: `server_kek` (server-held, wrapped by `ENCRYPTION_KEY`) and `user_passphrase`. There are **two separate credential planes** — do not conflate them:

| Credential | Used by | Verified by |
|---|---|---|
| `am_live_…` API keys | MCP clients, REST agent endpoints | Argon2id hash in `agents.api_key_hash` |
| Supabase Auth JWTs | Dashboard SPA (`/v1/account/*`) | `relay/api/account.py` — see §5 |

## 2. Production topology — this repo is wired to live services

```
Cloudflare Workers (AgentMail-Dashboard repo, separate)
        │  REST /v1/account/*  (Supabase JWT Bearer)
        ▼
   Render Web Service  ← this repo, auto-deploys from GitHub `main`
   https://agentmail-mso4.onrender.com
        │  SQLAlchemy async + asyncpg
        ▼
   Supabase Postgres (Session pooler)  +  Supabase Auth (Google OAuth, ES256 JWTs)
```

- **Hosting:** Render Web Service, free plan. Pushes to `main` auto-deploy. Free tier sleeps → an UptimeRobot monitor pings `/v1/health` to keep it warm. First request after a cold start is slow; that is expected, not a bug.
- **Database:** Supabase Postgres reached **only** through the Session pooler (`…pooler.supabase.com:5432`).
- **Auth:** Supabase Auth with Google OAuth. New Supabase projects issue **ES256** access tokens; verification goes through JWKS (`relay/api/jwks.py`).

## 3. Repository layout

| Path | Purpose |
|---|---|
| `relay/app.py` | FastAPI app: routers, CORS, slowapi limits, MCP mount |
| `relay/config.py` | All settings from env vars (pydantic-settings). Single source of env truth |
| `relay/db.py` | Async engine/session wiring |
| `relay/api/` | REST routers: `account` (dashboard), `agents` (registration), `whois`, `reissue`, `admin`, `health`, `auth`, `jwks` (JWKS client) |
| `relay/mcp/` | MCP server: `server`, `tools`, `auth` (API-key plane), `contacts`, `piggyback`, `ratelimit`, `context`, `descriptions` |
| `relay/crypto/` | `envelope` (sealed box + sig), `vault` (server_kek wrapping) |
| `relay/models/schema.py` | SQLAlchemy models |
| `relay/models/migrations/` | Alembic env + `versions/001_initial.py`, `versions/002_dash01_accounts.py` |
| `render.yaml` | Render blueprint: build/start commands, env var **names** (secrets are `sync: false`) |
| `tests/` | pytest + pytest-asyncio, 81 tests (DB-backed) |

## 4. Commands

```bash
python -m venv .venv && source .venv/bin/activate    # Python 3.14 in prod; 3.12+ works locally
pip install -r requirements.txt

pytest                          # full suite — must pass before every commit (81 tests)
ruff check .                    # lint — CI runs this first
alembic upgrade head            # apply migrations to the DATABASE_URL you're pointed at
uvicorn relay.app:app --reload  # local dev server
```

DB-backed tests need `TEST_DATABASE_URL` (asyncpg URL). Without a DB URL the DB tests will fail — that's environmental, not a code bug. **Never point `TEST_DATABASE_URL` or a local `DATABASE_URL` at the production Supabase project.**

## 5. ⚠️ DO NOT MODIFY — live connection wiring

> **These connections are wired to external production services. Do not change, "clean up", reformat, or refactor them while making feature changes or updates. Every item below is load-bearing and each one has caused a real production outage when touched. If a task seems to require changing one of these, STOP and surface it to the maintainer first.**

### 5.1 Environment variables (values live in the Render dashboard; names in `render.yaml`)

| Variable | Wired to | Why it must not be touched |
|---|---|---|
| `DATABASE_URL` | Supabase **Session pooler** | The exact format is load-bearing: scheme `postgresql+asyncpg://`, username `postgres.<project-ref>` (the pooler's tenant identifier), pooler host `aws-0-<region>.pooler.supabase.com`, port **5432**, `?ssl=require`. History: direct-connection host (`db.<ref>.supabase.co`) is IPv6-only → `gaierror`/NXDOMAIN on Render (IPv4-only); bare `postgres` username → `no tenant identifier provided`; unencoded special chars in the password → NXDOMAIN. |
| `SUPABASE_URL` | Supabase Auth issuer | Must be the bare project URL `https://<ref>.supabase.co` — the relay verifies JWT `iss == {SUPABASE_URL}/auth/v1` and fetches JWKS from `{SUPABASE_URL}/auth/v1/.well-known/jwks.json`. A trailing path (`/rest/v1/`) or typo → every dashboard request 401s. |
| `SUPABASE_JWT_SECRET` | Supabase **Legacy JWT Secret** (JWT Settings → Legacy tab) | Only used for the HS256 fallback path. Do **not** replace it with anything from the JWT Signing Keys page, and do **not** create standby keys or rotate signing keys in Supabase — rotation breaks ES256 verification until JWKS caches refresh. |
| `ENCRYPTION_KEY` | server_kek key-encryption key | Exactly 32 bytes, base64. **Rotating it permanently breaks every stored `api_key_enc`/key blob** — agents become unrecoverable. Never regenerate, never "fix" its value. |
| `CORS_ORIGINS` | Dashboard's workers.dev origin (`https://agentmail-dashboard.aps-labs.workers.dev`) | Must match the dashboard URL exactly (scheme + host, no trailing slash). Wrong value → browser CORS failures on all `/v1/account/*` calls. |
| `ADMIN_TOKEN`, `RELAY_DOMAIN`, `READ_TTL_DAYS`, `UNREAD_TTL_DAYS` | Admin API, message addressing, retention | Part of the live contract with agents and the dashboard. |

Never commit secret values to `render.yaml` or anywhere in the repo — secret entries use `sync: false` (values set in the Render dashboard only).

### 5.2 Render build & start commands

```
build: pip install -r requirements.txt && alembic upgrade head
start: uvicorn relay.app:app --host 0.0.0.0 --port $PORT --workers 1
```

`alembic upgrade head` **must stay in the build command**. Removing it (e.g. "to make the build faster") does not skip the failure — it moves it from build time to request time (`relation "agents" does not exist` at first DB call). Never run `alembic downgrade` or drop tables against production.

### 5.3 Auth verification code paths (`relay/api/account.py`, `relay/api/jwks.py`)

The dashboard JWT verification is a **dual-path dispatch** that took three production iterations to get right:

- `am_live_` tokens → API-key plane (untouched by Supabase logic);
- header `alg == HS256` → legacy `SUPABASE_JWT_SECRET` path;
- header `alg ∈ {ES256, RS256, EdDSA}` → JWKS path (`jwks.py`: 600s cache, one forced refetch on unknown `kid`, `cryptography` package for key parsing);
- both paths decode with `options={"require": ["exp","sub","iss"], "verify_aud": False}` — Supabase tokens carry `aud: "authenticated"` and PyJWT ≥ 2.10 **raises `InvalidAudienceError`** if `aud` is present but no audience is passed. Removing `verify_aud: False` reintroduces a production 401 outage.

Do not "simplify" this dispatch into a single path, do not add `audience=…`, do not remove the `cryptography` pin in `requirements.txt`, and do not change the JWKS URL construction.

### 5.4 Migration 002's Supabase guards (`relay/models/migrations/versions/002_dash01_accounts.py`)

- `_auth_users_exists()` (via `to_regclass`) and `_may_reference_auth_users()` (via `has_table_privilege`) exist because **Supabase owns the `auth` schema** (`supabase_auth_admin`; the project's `postgres` role has no CREATE there), and PostgreSQL checks schema CREATE **before** the `IF NOT EXISTS` shortcut. Un-guarding the `auth.users` stub → `permission denied for schema auth` → **build failure**.
- **Schema ownership rule:** everything in schema `public` is ours to create/migrate; everything in schema `auth` is Supabase-managed. No migration may ever issue DDL against `auth.*` objects. `REFERENCES auth.users(id)` FKs are emitted only when the privilege probe passes.
- New migrations must be idempotent (`IF NOT EXISTS` / `DO $$ … IF NOT EXISTS … END $$`) because Render runs `alembic upgrade head` on **every** deploy.

## 6. Production incident history — do not reintroduce

| Signature | Root cause (already fixed — keep the fix) |
|---|---|
| `socket.gaierror: [Errno -2]` / NXDOMAIN at build or request time | `DATABASE_URL` defect: direct-connection host (IPv6-only), typo'd pooler host, or unencoded password char. Always use the Session pooler string copied verbatim from Supabase's Connect modal, with `+asyncpg` and `?ssl=require` added. |
| `no tenant identifier provided` | Bare `postgres` username instead of `postgres.<project-ref>`. |
| Dashboard 401 `Invalid or expired authentication token` on ES256 projects | Relay lacked JWKS verification (commit `840c1a6` fixed). Check token `alg` in devtools before touching env vars. |
| `InvalidAudienceError` in Render logs | PyJWT rejecting `aud: "authenticated"` — fixed by `verify_aud: False` (commit `211f894`). |
| `permission denied for schema auth` during `alembic upgrade head` | Migration 002's un-guarded `auth.users` stub — fixed by the `to_regclass` guards (commit `f17af6e`). |

## 7. Definition of done for any change

1. `pytest` — all tests pass (add tests for new behavior; the suite is 81 tests and growing).
2. `ruff check .` — clean.
3. If you touched a migration: it is idempotent, creates nothing in schema `auth`, and was exercised against a **local** Postgres.
4. If you touched `relay/api/account.py` or `jwks.py`: re-read §5.3 and add a JWT regression test (see `tests/test_jwks.py` patterns — `mint_es256_token`, aud-claim regression).
5. Push to `main` → Render auto-deploys → verify `GET /v1/health` returns `{"status":"ok",…}` and the dashboard can sign in and list agents.
6. Rollback path: `git revert` and push. Never "hotfix" prod by editing the Render dashboard's files.
