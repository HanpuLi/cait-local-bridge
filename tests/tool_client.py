"""Minimal MCP tool client for local testing (defaults: production bridge :8795; set CLB_BASE / CLB_PASSPHRASE): does the OAuth flow once (token cached under $CLB_TOKEN_CACHE), then
exposes `call(name, **args)`. Usage:
  CLB_BASE=http://127.0.0.1:8895 CLB_PASSPHRASE=... .venv/bin/python tests/tool_client.py bridge_info
  .venv/bin/python tests/tool_client.py browser_open workspace_id=ws_x url=https://example.com
Values given as key=value are parsed as JSON when possible, else kept as strings."""
from __future__ import annotations
import asyncio, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_client import pkce, oauth_flow  # noqa
import httpx

BASE = os.environ.get("CLB_BASE", "http://127.0.0.1:8795")
PUBLIC = os.environ.get("CLB_PUBLIC")
CACHE = os.environ.get("CLB_TOKEN_CACHE", "/tmp/clb-test-token.json")


def token() -> str:
    try:
        t = json.load(open(CACHE))
        r = httpx.post(BASE + "/mcp", headers={"Authorization": f"Bearer {t['access_token']}", "Host": t.get("host", "")} if PUBLIC else {"Authorization": f"Bearer {t['access_token']}"},
                       json={"jsonrpc": "2.0", "id": 0, "method": "ping"}, timeout=20)
        if r.status_code != 401:
            return t["access_token"]
    except Exception:
        pass
    ev = oauth_flow(BASE, os.environ["CLB_PASSPHRASE"], PUBLIC)
    json.dump({"access_token": ev["access_token"], "refresh_token": ev["refresh_token"]}, open(CACHE, "w"))
    os.chmod(CACHE, 0o600)
    return ev["access_token"]


async def call_many(calls: list[tuple[str, dict]]) -> list[dict]:
    from mcp.client.streamable_http import streamable_http_client
    from mcp import ClientSession
    import urllib.parse
    headers = {"Authorization": f"Bearer {token()}"}
    if PUBLIC:
        headers["Host"] = urllib.parse.urlsplit(PUBLIC).netloc
    out = []
    async with streamable_http_client(BASE + "/mcp", http_client=httpx.AsyncClient(headers=headers, timeout=600)) as streams:
        async with ClientSession(*streams[:2]) as s:
            await s.initialize()
            for name, args in calls:
                res = await s.call_tool(name, args)
                sc = res.structured_content or json.loads(res.content[-1].text)
                out.append(sc)
    return out


def call(name: str, **args) -> dict:
    return asyncio.run(call_many([(name, args)]))[0]


if __name__ == "__main__":
    name = sys.argv[1]
    args = {}
    for kv in sys.argv[2:]:
        k, v = kv.split("=", 1)
        try:
            args[k] = json.loads(v)
        except ValueError:
            args[k] = v
    print(json.dumps(call(name, **args), ensure_ascii=False, indent=1, default=str)[:20000])
