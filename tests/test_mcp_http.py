"""End-to-end MCP-over-HTTP test: real middleware, real streamable transport.

A single test — ``StreamableHTTPSessionManager.run()`` may only be entered
once per instance, and the app module builds exactly one instance.
"""
from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from relay.mcp.server import mcp_server
from tests.conftest import insert_agent, requires_db

pytestmark = requires_db

_ACCEPT = {"Accept": "application/json, text/event-stream"}

_INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "0.1.0"},
    },
}


async def test_mcp_streamable_http_end_to_end(db):
    agent, api_key = await insert_agent(db, "mcp-alice")
    auth = {**_ACCEPT, "Authorization": f"Bearer {api_key}"}

    async with mcp_server.session_manager.run():
        transport = ASGITransport(app=_app())
        async with AsyncClient(transport=transport, base_url="http://testserver") as http:
            # -- unauthenticated → JSON 401, never reaches MCP ------------------
            r = await http.post("/mcp", json=_INIT, headers=_ACCEPT)
            assert r.status_code == 401
            assert r.json()["error"]["code"] == "UNAUTHORIZED"

            r = await http.post(
                "/mcp", json=_INIT, headers={**_ACCEPT, "Authorization": "Bearer am_live_wrong"}
            )
            assert r.status_code == 401

            # -- initialize ------------------------------------------------------
            r = await http.post("/mcp", json=_INIT, headers=auth)
            assert r.status_code == 200, r.text
            init = r.json()
            assert init["result"]["serverInfo"]["name"] == "agentmail"
            assert init["result"]["serverInfo"]["version"] == "0.1.0"

            # -- tools/list -------------------------------------------------------
            r = await http.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                headers=auth,
            )
            assert r.status_code == 200, r.text
            tools = {t["name"] for t in r.json()["result"]["tools"]}
            assert tools == {
                "unlock_keychain", "keychain_status", "whois", "send_message",
                "check_inbox", "read_message", "reply", "get_thread",
                "get_sent", "delete_message",
            }

            # -- tools/call (stateless: no session continuity needed) -------------
            r = await http.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "keychain_status", "arguments": {}},
                },
                headers=auth,
            )
            assert r.status_code == 200, r.text
            content = r.json()["result"]["content"]
            assert content[0]["type"] == "text"
            assert '"locked":true' in content[0]["text"]

            # -- and tools see the authenticated agent ---------------------------
            r = await http.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "whois", "arguments": {"handle": "mcp-alice"}},
                },
                headers=auth,
            )
            whois_text = r.json()["result"]["content"][0]["text"]
            assert "mcp-alice@agentmail" in whois_text


def _app():
    from relay.app import app

    return app
