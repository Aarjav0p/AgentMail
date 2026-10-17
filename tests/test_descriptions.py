"""Tests for TOOLDESC-01: behavioral MCP tool descriptions."""

from __future__ import annotations

import json

import pytest

from relay.mcp import descriptions
from relay.mcp.server import INSTRUCTIONS, mcp_server

EXPECTED_TOOLS = [
    "unlock_keychain",
    "keychain_status",
    "whois",
    "send_message",
    "check_inbox",
    "read_message",
    "reply",
    "get_thread",
    "get_sent",
    "delete_message",
]

GOLDEN_INPUT_SCHEMAS = {
    "unlock_keychain": {
        "properties": {
            "passphrase": {
                "title": "Passphrase",
                "type": "string",
            }
        },
        "required": ["passphrase"],
        "title": "tool_unlock_keychainArguments",
        "type": "object",
    },
    "keychain_status": {
        "properties": {},
        "title": "tool_keychain_statusArguments",
        "type": "object",
    },
    "whois": {
        "properties": {
            "handle": {
                "title": "Handle",
                "type": "string",
            }
        },
        "required": ["handle"],
        "title": "tool_whoisArguments",
        "type": "object",
    },
    "send_message": {
        "properties": {
            "to": {
                "title": "To",
                "type": "string",
            },
            "subject": {
                "title": "Subject",
                "type": "string",
            },
            "body": {
                "title": "Body",
                "type": "string",
            },
            "thread_id": {
                "anyOf": [
                    {"type": "string"},
                    {"type": "null"},
                ],
                "default": None,
                "title": "Thread Id",
            },
            "in_reply_to": {
                "anyOf": [
                    {"type": "string"},
                    {"type": "null"},
                ],
                "default": None,
                "title": "In Reply To",
            },
            "idempotency_key": {
                "anyOf": [
                    {"type": "string"},
                    {"type": "null"},
                ],
                "default": None,
                "title": "Idempotency Key",
            },
        },
        "required": ["to", "subject", "body"],
        "title": "tool_send_messageArguments",
        "type": "object",
    },
    "check_inbox": {
        "properties": {
            "unread_only": {
                "default": True,
                "title": "Unread Only",
                "type": "boolean",
            },
            "limit": {
                "default": 20,
                "title": "Limit",
                "type": "integer",
            },
            "before": {
                "anyOf": [
                    {"type": "string"},
                    {"type": "null"},
                ],
                "default": None,
                "title": "Before",
            },
        },
        "title": "tool_check_inboxArguments",
        "type": "object",
    },
    "read_message": {
        "properties": {
            "id": {
                "title": "Id",
                "type": "string",
            }
        },
        "required": ["id"],
        "title": "tool_read_messageArguments",
        "type": "object",
    },
    "reply": {
        "properties": {
            "id": {
                "title": "Id",
                "type": "string",
            },
            "body": {
                "title": "Body",
                "type": "string",
            },
            "subject": {
                "anyOf": [
                    {"type": "string"},
                    {"type": "null"},
                ],
                "default": None,
                "title": "Subject",
            },
        },
        "required": ["id", "body"],
        "title": "tool_replyArguments",
        "type": "object",
    },
    "get_thread": {
        "properties": {
            "thread_id": {
                "title": "Thread Id",
                "type": "string",
            },
            "limit": {
                "default": 50,
                "title": "Limit",
                "type": "integer",
            },
        },
        "required": ["thread_id"],
        "title": "tool_get_threadArguments",
        "type": "object",
    },
    "get_sent": {
        "properties": {
            "limit": {
                "default": 20,
                "title": "Limit",
                "type": "integer",
            }
        },
        "title": "tool_get_sentArguments",
        "type": "object",
    },
    "delete_message": {
        "properties": {
            "id": {
                "title": "Id",
                "type": "string",
            }
        },
        "required": ["id"],
        "title": "tool_delete_messageArguments",
        "type": "object",
    },
}

TOOL_DESCRIPTION_MAP = {
    "unlock_keychain": descriptions.UNLOCK_KEYCHAIN,
    "keychain_status": descriptions.KEYCHAIN_STATUS,
    "whois": descriptions.WHOIS,
    "send_message": descriptions.SEND_MESSAGE,
    "check_inbox": descriptions.CHECK_INBOX,
    "read_message": descriptions.READ_MESSAGE,
    "reply": descriptions.REPLY,
    "get_thread": descriptions.GET_THREAD,
    "get_sent": descriptions.GET_SENT,
    "delete_message": descriptions.DELETE_MESSAGE,
}


@pytest.mark.asyncio
async def test_tools_list_returns_exact_10_tools():
    """1. tools/list returns exactly the 10 expected tool names."""
    tools = await mcp_server.list_tools()
    tool_names = [t.name for t in tools]
    assert len(tool_names) == 10
    assert set(tool_names) == set(EXPECTED_TOOLS)


@pytest.mark.asyncio
async def test_check_inbox_trigger_substrings():
    """2. check_inbox description contains the 3 behavioral trigger substrings."""
    tools = {t.name: t for t in await mcp_server.list_tools()}
    desc = tools["check_inbox"].description
    assert "start of every session" in desc
    assert "before beginning any new task" in desc
    assert "waiting on a reply" in desc


@pytest.mark.asyncio
async def test_send_message_inbox_piggyback():
    """3. send_message description teaches the model about _inbox piggyback."""
    tools = {t.name: t for t in await mcp_server.list_tools()}
    desc = tools["send_message"].description
    assert "_inbox" in desc


@pytest.mark.asyncio
async def test_all_descriptions_contract():
    """4. Every description satisfies length, ascii, no newline, and ends first sentence with a period."""
    tools = await mcp_server.list_tools()
    for tool in tools:
        desc = tool.description
        assert desc is not None and len(desc) > 0, f"Empty description for {tool.name}"
        assert len(desc) <= 900, f"Description for {tool.name} exceeds 900 chars: {len(desc)}"
        assert desc.isascii(), f"Description for {tool.name} must be ASCII-only"
        assert "\n" not in desc, f"Description for {tool.name} contains newline"
        assert "\r" not in desc, f"Description for {tool.name} contains carriage return"
        assert "." in desc, f"Description for {tool.name} must contain a period"
        assert desc == TOOL_DESCRIPTION_MAP[tool.name], (
            f"Mismatch with descriptions.py for {tool.name}"
        )


@pytest.mark.asyncio
async def test_input_schemas_byte_identical():
    """5. inputSchema of every tool is byte-identical / deep-equal to golden schemas."""
    tools = {t.name: t for t in await mcp_server.list_tools()}
    for tool_name, expected_schema in GOLDEN_INPUT_SCHEMAS.items():
        actual_schema = tools[tool_name].inputSchema
        assert actual_schema == expected_schema, f"inputSchema changed for {tool_name}"
        assert json.dumps(actual_schema, sort_keys=True) == json.dumps(
            expected_schema, sort_keys=True
        )


def test_instructions_synced():
    """Server instructions include the behavioral triggers."""
    expected_trigger = (
        "Proactively call `check_inbox` at the start of every session, before "
        "beginning any new task or subtask, and whenever the user mentions another "
        "agent or is waiting on a reply."
    )
    assert expected_trigger in INSTRUCTIONS
