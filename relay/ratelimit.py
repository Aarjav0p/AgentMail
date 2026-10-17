"""Shared slowapi limiter for the REST surface (§8.1).

A single Limiter instance is shared between the app and the routers so
that limits registered via decorators share one in-memory storage.
"""
from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
