"""JWKS support for Supabase signing-key (asymmetric) access tokens.

Supabase projects created with the new API-keys system issue access tokens
signed with an asymmetric key (ES256 by default, optionally EdDSA). Their
public halves are published in a standard JWKS document at
``{SUPABASE_URL}/auth/v1/.well-known/jwks.json``.

This module fetches and caches that document and hands out verification
keys by ``kid``. It is the asymmetric counterpart to the legacy HS256
shared-secret path in :mod:`relay.api.account`.
"""

from __future__ import annotations

import json
import logging
import time
from urllib.request import Request as _HttpRequest
from urllib.request import urlopen

import jwt as pyjwt

from relay.config import settings

logger = logging.getLogger(__name__)

#: Asymmetric algorithms verified via the project JWKS (§5.2).
ASYM_ALGS: frozenset[str] = frozenset({"ES256", "RS256", "EdDSA"})

_JWKS_CACHE_TTL_SECONDS = 600
_FETCH_TIMEOUT_SECONDS = 5

# url -> (fetched_at_monotonic, document)
_jwks_cache: dict[str, tuple[float, dict]] = {}


def jwks_url() -> str:
    """JWKS endpoint for the configured Supabase project (issuer-derived)."""
    return f"{settings.supabase_url.rstrip('/')}/auth/v1/.well-known/jwks.json"


def _fetch_jwks_document(url: str) -> dict:
    """Fetch and validate a JWKS document (network touchpoint).

    Single seam for tests to monkeypatch; keep every network call inside.
    """
    req = _HttpRequest(url, headers={"Accept": "application/json"}, method="GET")
    with urlopen(req, timeout=_FETCH_TIMEOUT_SECONDS) as resp:
        doc = json.loads(resp.read().decode("utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
        raise ValueError("JWKS document is malformed (missing keys list).")
    return doc


def _cached_document(url: str, *, force: bool = False) -> dict:
    now = time.monotonic()
    hit = _jwks_cache.get(url)
    if not force and hit is not None and now - hit[0] < _JWKS_CACHE_TTL_SECONDS:
        return hit[1]
    doc = _fetch_jwks_document(url)
    _jwks_cache[url] = (now, doc)
    return doc


def _find_key(doc: dict, kid: str) -> dict | None:
    return next(
        (k for k in doc["keys"] if isinstance(k, dict) and k.get("kid") == kid),
        None,
    )


def get_verification_key(alg: str, kid: str):
    """Return the public verification key for ``kid`` from the project JWKS.

    The cached document is force-refreshed once when ``kid`` is unknown, so
    Supabase-side key rotation converges on the next request. Raises
    :class:`LookupError` when the key cannot be found, fetched, or parsed.
    """
    if not kid:
        raise LookupError("Token header is missing kid.")
    url = jwks_url()
    doc = _cached_document(url)
    entry = _find_key(doc, kid)
    if entry is None:
        doc = _cached_document(url, force=True)
        entry = _find_key(doc, kid)
    if entry is None:
        raise LookupError(f"No JWKS key matches kid {kid!r}.")
    if entry.get("alg") not in (None, alg):
        raise LookupError(f"JWKS key {kid!r} does not allow algorithm {alg}.")
    try:
        return pyjwt.PyJWK(entry).key
    except Exception as exc:
        raise LookupError(f"JWKS entry {kid!r} could not be parsed.") from exc


def clear_cache() -> None:
    """Drop cached JWKS documents (used by tests)."""
    _jwks_cache.clear()
