"""Managed headless browser (Playwright, dedicated profile under the control-plane dir, never the user's Chrome profile).
Every action is an explicit primitive chosen by ChatGPT; there is no internal vision model or web agent. Sub-requests,
redirects and DNS are policed by a route handler: private / tailnet / localhost destinations are blocked unless the
page's workspace registered that dev port; the bridge's own admin port is always blocked."""
from __future__ import annotations
import asyncio, base64, time, urllib.parse, uuid
from collections import deque
from pathlib import Path
from .config import BROWSER_PROFILE_DIR, ARTIFACTS_DIR, load_config
from .policy import BridgeError, host_is_private, dev_port_allowed, workspace_get

CFG = load_config()
_pw = None
_ctx = None
_pages: dict[str, dict] = {}      # page_id -> {"page": Page, "workspace_id": str, "console": deque, "failed": deque}
_lock = asyncio.Lock()
_engine = {"channel": None}


async def _pw_start() -> None:
    global _pw
    if _pw is not None:
        return
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        raise BridgeError("missing_dependency", "playwright not installed in the bridge venv")
    _pw = await async_playwright().start()


async def _ensure() -> None:
    global _pw, _ctx
    if _ctx is not None:
        return
    await _pw_start()
    BROWSER_PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    last = None
    exe = CFG.get("browser_executable")
    headless = bool(CFG.get("browser_headless", True))
    # A configured executable (Comet with the user's cloned profile, set by `bridgectl browser use-comet`) is tried
    # first, then Google Chrome, then Playwright's bundled Chromium.
    engines = ([("custom", exe)] if exe else []) + [("chrome", None), (None, None)]
    for channel, path in engines:
        try:
            # --enable-automation (a Playwright default) sets navigator.webdriver=true, which Cloudflare's managed challenge
            # on chatgpt.com turns into an endless "Just a moment..." page (seen 2026-09-17). The bridge drives real,
            # logged-in sites on the user's behalf, so it must not announce itself as a bot.
            kw = dict(headless=headless, viewport={"width": 1280, "height": 900}, accept_downloads=True, service_workers="block",
                      args=["--disable-background-networking", "--disable-blink-features=AutomationControlled"], ignore_default_args=["--enable-automation"])
            if path:
                # Playwright adds --use-mock-keychain by default; with the user's cloned Comet profile the cookies are
                # encrypted with the real "Comet Safe Storage" Keychain key, so the mock keychain must be disabled.
                kw["executable_path"] = path
                kw["ignore_default_args"].append("--use-mock-keychain")
            else:
                kw["channel"] = channel
            _ctx = await _pw.chromium.launch_persistent_context(str(BROWSER_PROFILE_DIR), **kw)
            _engine["channel"] = path or channel or "chromium"
            break
        except Exception as e:  # engine missing / failed to start
            last = e
    if _ctx is None:
        raise BridgeError("missing_dependency", f"no browser engine available: {last}")
    await _ctx.route("**/*", _route)


async def _route(route, request) -> None:
    url = request.url
    u = urllib.parse.urlsplit(url)
    try:  # service-worker requests (cloned profiles carry SW registrations) have no frame; policy still applies below
        page = request.frame.page if request.frame else None
    except Exception:
        page = None
    entry = next((e for e in _pages.values() if e["page"] is page), None)
    ws_id = entry["workspace_id"] if entry else None
    if u.scheme in ("data", "blob", "about"):
        return await route.continue_()
    if u.scheme not in ("http", "https"):
        return await route.abort("blockedbyclient")
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    if port in (CFG["admin_port"], CFG["listen_port"]) and host_is_private(host):
        return await route.abort("blockedbyclient")
    if host_is_private(host):
        if host in ("localhost", "127.0.0.1", "::1", "[::1]") and ws_id and dev_port_allowed(ws_id, port):
            return await route.continue_()
        # A trusted-host workspace already runs arbitrary shell as the user (curl to the tailnet included), so its pages
        # may browse private/tailnet services too (dashboard :8787, Forgejo, Paperless). Sandboxed-only workspaces stay
        # blocked; the bridge's own admin/listen ports are blocked above regardless of profile.
        if ws_id:
            try:
                if "trusted-host" in workspace_get(ws_id)["profiles"]:
                    return await route.continue_()
            except BridgeError:
                pass
        if entry is not None:
            entry["failed"].append({"url": url[:300], "reason": "blocked_by_bridge_policy: private/tailnet destination", "ts": time.time()})
        return await route.abort("blockedbyclient")
    await route.continue_()


_cdp: dict[str, dict] = {}   # cdp_url -> {"browser": Browser}


def _validate_cdp_workspace(workspace_id: str, cdp_url: str) -> None:
    ws = workspace_get(workspace_id)
    if "trusted-host" not in ws["profiles"]:
        raise BridgeError("permission_denied", "attaching to the user's own browser requires a trusted-host workspace")
    u = urllib.parse.urlsplit(cdp_url)
    if u.scheme != "http" or u.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise BridgeError("permission_denied", "cdp_url must be a loopback http://127.0.0.1:<port> DevTools endpoint")


async def _connect_cdp(workspace_id: str, cdp_url: str, timeout_ms: int = 10000):
    _validate_cdp_workspace(workspace_id, cdp_url)
    await _pw_start()
    ent = _cdp.get(cdp_url)
    if ent is None or not ent["browser"].is_connected():
        try:
            br = await _pw.chromium.connect_over_cdp(cdp_url, timeout=timeout_ms)
        except Exception as e:
            raise BridgeError("offline", f"no DevTools browser at {cdp_url}: {str(e)[:200]}")
        ent = _cdp[cdp_url] = {"browser": br}
    return ent["browser"]


def _wire_page(pid: str, page, workspace_id: str, cdp_url: str | None = None, external: bool = False) -> dict:
    entry = {
        "page": page, "workspace_id": workspace_id,
        "console": deque(maxlen=500), "failed": deque(maxlen=200),
        "opened": time.time(), "external": external,
    }
    if cdp_url:
        entry["cdp"] = cdp_url
    _pages[pid] = entry
    page.on("console", lambda m: entry["console"].append({"type": m.type, "text": m.text[:1000], "ts": time.time()}))
    page.on("pageerror", lambda e: entry["console"].append({"type": "pageerror", "text": str(e)[:1000], "ts": time.time()}))
    page.on("requestfailed", lambda r: entry["failed"].append({"url": r.url[:300], "reason": (r.failure or "")[:200], "ts": time.time()}))
    page.on("response", lambda r: entry["failed"].append({"url": r.url[:300], "reason": f"http_{r.status}", "ts": time.time()}) if r.status >= 400 else None)
    return entry


async def cdp_pages(workspace_id: str, cdp_url: str = "http://127.0.0.1:9222", timeout_ms: int = 10000) -> dict:
    """List existing tabs in a loopback DevTools browser without creating or navigating anything."""
    async with _lock:
        browser = await _connect_cdp(workspace_id, cdp_url, timeout_ms)
        pages = []
        index = 0
        for context_index, ctx in enumerate(browser.contexts):
            for page in ctx.pages:
                try:
                    title = await page.title()
                except Exception:
                    title = ""
                existing = next((pid for pid, e in _pages.items() if e["page"] is page), None)
                pages.append({
                    "page_index": index,
                    "context_index": context_index,
                    "url": page.url,
                    "title": title,
                    "attached_page_id": existing,
                    "closed": page.is_closed(),
                })
                index += 1
        return {"cdp_url": cdp_url, "pages": pages, "count": len(pages)}


async def attach_existing_cdp(
    workspace_id: str,
    cdp_url: str = "http://127.0.0.1:9222",
    page_index: int | None = None,
    url_contains: str | None = None,
    title_contains: str | None = None,
    timeout_ms: int = 10000,
) -> dict:
    """Attach to one tab that is already open in the user's DevTools-enabled browser.

    This does not navigate and marks the tab as external: browser_close unregisters
    the MCP page without closing the user's pre-existing tab.
    """
    async with _lock:
        browser = await _connect_cdp(workspace_id, cdp_url, timeout_ms)
        candidates = []
        index = 0
        for ctx in browser.contexts:
            for page in ctx.pages:
                try:
                    title = await page.title()
                except Exception:
                    title = ""
                item = (index, page, title)
                if page_index is not None and index != int(page_index):
                    index += 1
                    continue
                if url_contains is not None and url_contains.lower() not in page.url.lower():
                    index += 1
                    continue
                if title_contains is not None and title_contains.lower() not in title.lower():
                    index += 1
                    continue
                candidates.append(item)
                index += 1

        if not candidates:
            raise BridgeError("not_found", "no existing CDP tab matched; call browser_cdp_pages first")
        if len(candidates) > 1:
            preview = [{"page_index": i, "url": p.url, "title": t} for i, p, t in candidates[:20]]
            raise BridgeError("conflict", f"multiple existing tabs matched; choose page_index. candidates={preview}")

        idx, page, title = candidates[0]
        existing = next((pid for pid, e in _pages.items() if e["page"] is page), None)
        if existing:
            return {"page_id": existing, "page_index": idx, "url": page.url, "title": title, "cdp_url": cdp_url, "reused": True, "external": True}
        if len(_pages) >= 8:
            raise BridgeError("rate_limited", "too many open pages; close/detach some with browser_close")
        pid = "page_" + uuid.uuid4().hex[:8]
        _wire_page(pid, page, workspace_id, cdp_url, external=True)
        return {"page_id": pid, "page_index": idx, "url": page.url, "title": title, "cdp_url": cdp_url, "reused": False, "external": True}


async def attach_cdp(workspace_id: str, cdp_url: str, url: str, wait_until: str = "load", timeout_ms: int = 30000) -> dict:
    """Open a tab in one of the user's OWN already-running Chromium browsers that exposes a loopback DevTools port.
    Trusted-host workspaces only: it is the user's real browser with existing sessions; no managed-browser route policing is
    applied because the externally launched profile already has the user's normal network access."""
    ws = workspace_get(workspace_id)
    if "trusted-host" not in ws["profiles"]:
        raise BridgeError("permission_denied", "attaching to the user's own browser requires a trusted-host workspace")
    u = urllib.parse.urlsplit(cdp_url)
    if u.scheme != "http" or u.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise BridgeError("permission_denied", "cdp_url must be a loopback http://127.0.0.1:<port> DevTools endpoint")
    async with _lock:
        await _pw_start()
        if len(_pages) >= 8:
            raise BridgeError("rate_limited", "too many open pages; close some with browser_close")
        ent = _cdp.get(cdp_url)
        if ent is None or not ent["browser"].is_connected():
            try:
                br = await _pw.chromium.connect_over_cdp(cdp_url, timeout=timeout_ms)
            except Exception as e:
                raise BridgeError("offline", f"no DevTools browser at {cdp_url}: {str(e)[:200]}")
            ent = _cdp[cdp_url] = {"browser": br}
        ctx = ent["browser"].contexts[0] if ent["browser"].contexts else await ent["browser"].new_context()
        page = await ctx.new_page()
        pid = "page_" + uuid.uuid4().hex[:8]
        entry = {"page": page, "workspace_id": workspace_id, "console": deque(maxlen=500), "failed": deque(maxlen=200), "opened": time.time(), "cdp": cdp_url}
        _pages[pid] = entry
        page.on("console", lambda m: entry["console"].append({"type": m.type, "text": m.text[:1000], "ts": time.time()}))
        page.on("pageerror", lambda e: entry["console"].append({"type": "pageerror", "text": str(e)[:1000], "ts": time.time()}))
        page.on("requestfailed", lambda r: entry["failed"].append({"url": r.url[:300], "reason": (r.failure or "")[:200], "ts": time.time()}))
    return await navigate(pid, url, wait_until, timeout_ms)


def _entry(page_id: str) -> dict:
    e = _pages.get(page_id)
    if not e:
        raise BridgeError("not_found", f"unknown page {page_id}; call browser_open first")
    return e


async def open_page(workspace_id: str, url: str, width: int = 1280, height: int = 900, color_scheme: str = "light",
                    wait_until: str = "load", timeout_ms: int = 30000, init_script: str | None = None) -> dict:
    workspace_get(workspace_id)
    async with _lock:
        await _ensure()
        if len(_pages) >= 8:
            raise BridgeError("rate_limited", "too many open pages; close some with browser_close")
        page = await _ctx.new_page()
        pid = "page_" + uuid.uuid4().hex[:8]
        entry = {"page": page, "workspace_id": workspace_id, "console": deque(maxlen=500), "failed": deque(maxlen=200), "opened": time.time()}
        _pages[pid] = entry
        page.on("console", lambda m: entry["console"].append({"type": m.type, "text": m.text[:1000], "ts": time.time()}))
        page.on("pageerror", lambda e: entry["console"].append({"type": "pageerror", "text": str(e)[:1000], "ts": time.time()}))
        page.on("requestfailed", lambda r: entry["failed"].append({"url": r.url[:300], "reason": (r.failure or "")[:200], "ts": time.time()}))
        page.on("response", lambda r: entry["failed"].append({"url": r.url[:300], "reason": f"http_{r.status}", "ts": time.time()}) if r.status >= 400 else None)
    await page.set_viewport_size({"width": width, "height": height})
    await page.emulate_media(color_scheme=color_scheme)
    if init_script:   # runs before any page script on every navigation of this page only (used by agents.py)
        await page.add_init_script(init_script)
    return await navigate(pid, url, wait_until, timeout_ms)


async def navigate(page_id: str, url: str, wait_until: str = "load", timeout_ms: int = 30000) -> dict:
    e = _entry(page_id); page = e["page"]
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https"):
        raise BridgeError("permission_denied", "only http(s) URLs")
    try:
        resp = await page.goto(url, wait_until=wait_until, timeout=timeout_ms)
    except Exception as ex:
        return {"page_id": page_id, "url": page.url, "ok": False, "error": str(ex)[:500], "blocked": any("blocked_by_bridge" in f["reason"] for f in e["failed"])}
    return {"page_id": page_id, "url": page.url, "ok": True, "status": resp.status if resp else None, "title": await page.title()}


async def snapshot(page_id: str, mode: str = "aria", max_chars: int = 30000, selector: str = "body") -> dict:
    e = _entry(page_id); page = e["page"]
    if mode == "aria":
        text = await page.locator(selector).first.aria_snapshot()
    elif mode == "text":
        text = await page.locator(selector).first.inner_text()
    elif mode == "html":
        text = await page.locator(selector).first.inner_html()
    else:
        raise BridgeError("invalid_argument", "mode must be aria|text|html")
    return {"page_id": page_id, "url": page.url, "title": await page.title(), "mode": mode, "content": text[:max_chars], "truncated": len(text) > max_chars}


async def act(page_id: str, action: str, selector: str | None = None, text: str | None = None, key: str | None = None,
              dx: int = 0, dy: int = 0, timeout_ms: int = 10000, value: str | None = None) -> dict:
    e = _entry(page_id); page = e["page"]
    loc = page.locator(selector).first if selector else None
    if action == "click":
        await loc.click(timeout=timeout_ms)
    elif action == "dblclick":
        await loc.dblclick(timeout=timeout_ms)
    elif action == "type":
        await loc.fill(text or "", timeout=timeout_ms)
    elif action == "press":
        await (loc.press(key, timeout=timeout_ms) if loc else page.keyboard.press(key))
    elif action == "hover":
        await loc.hover(timeout=timeout_ms)
    elif action == "select":
        await loc.select_option(value, timeout=timeout_ms)
    elif action == "check":
        await loc.check(timeout=timeout_ms)
    elif action == "scroll":
        await (loc.scroll_into_view_if_needed(timeout=timeout_ms) if loc else page.mouse.wheel(dx, dy))
    elif action == "wait":
        await (loc.wait_for(timeout=timeout_ms) if loc else page.wait_for_timeout(min(timeout_ms, 10000)))
    elif action == "back":
        await page.go_back(timeout=timeout_ms)
    elif action == "reload":
        await page.reload(timeout=timeout_ms)
    else:
        raise BridgeError("invalid_argument", "action must be click|dblclick|type|press|hover|select|check|scroll|wait|back|reload")
    return {"page_id": page_id, "action": action, "url": page.url, "title": await page.title()}


async def evaluate(page_id: str, expression: str) -> dict:
    e = _entry(page_id)
    try:
        val = await e["page"].evaluate(expression)
    except Exception as ex:
        return {"page_id": page_id, "ok": False, "error": str(ex)[:1000]}
    s = val if isinstance(val, (int, float, bool, type(None))) else str(val)
    return {"page_id": page_id, "ok": True, "result": s if not isinstance(s, str) else s[:50000], "truncated": isinstance(s, str) and len(s) > 50000}


async def screenshot(page_id: str, full_page: bool = False, selector: str | None = None, fmt: str = "png", quality: int = 80,
                     save_as: str | None = None) -> dict:
    e = _entry(page_id); page = e["page"]
    kw = {"type": fmt, "full_page": full_page}
    if fmt == "jpeg":
        kw["quality"] = quality
    data = await (page.locator(selector).first.screenshot(**{k: v for k, v in kw.items() if k != "full_page"}) if selector else page.screenshot(**kw))
    out = ARTIFACTS_DIR / e["workspace_id"] / "screenshots"
    out.mkdir(parents=True, exist_ok=True)
    name = save_as or f"{int(time.time())}-{uuid.uuid4().hex[:6]}.{'jpg' if fmt == 'jpeg' else 'png'}"
    p = out / Path(name).name
    p.write_bytes(data)
    return {"page_id": page_id, "url": page.url, "path": str(p), "bytes": len(data), "mime": f"image/{fmt}", "base64": base64.b64encode(data).decode()}


async def console(page_id: str, clear: bool = False) -> dict:
    e = _entry(page_id)
    out = {"page_id": page_id, "console": list(e["console"]), "network_failures": list(e["failed"])}
    if clear:
        e["console"].clear(); e["failed"].clear()
    return out


async def set_viewport(page_id: str, width: int, height: int, color_scheme: str | None = None) -> dict:
    e = _entry(page_id); page = e["page"]
    await page.set_viewport_size({"width": width, "height": height})
    if color_scheme:
        await page.emulate_media(color_scheme=color_scheme)
    return {"page_id": page_id, "width": width, "height": height, "color_scheme": color_scheme}


async def close(page_id: str | None = None, protected: set[str] | None = None) -> dict:
    """Close one page, or everything. `protected` page_ids (tabs of sub-agent runs still in progress) are never closed and keep the
    browser alive — a bare browser_close from the main session used to kill running sub-agents (TargetClosedError, 2026-09-17)."""
    global _ctx, _pw
    protected = protected or set()
    if page_id:
        if page_id in protected:
            return {"closed": [], "protected": [page_id]}
        e = _pages.pop(page_id, None)
        if e and not e.get("external"):
            await e["page"].close()
        return {"closed": [page_id] if e else [], "detached_external": bool(e and e.get("external"))}
    ids = [pid for pid in _pages if pid not in protected]
    detached_external = []
    for pid in ids:
        try:
            entry = _pages.pop(pid)
            if entry.get("external"):
                detached_external.append(pid)
            else:
                await entry["page"].close()
        except Exception:
            pass
    if protected & set(_pages):
        return {"closed": ids, "detached_external": detached_external,
                "protected": sorted(protected & set(_pages)), "browser_stopped": False}
    _pages.clear()
    # Do not call Browser.close() on CDP connections: that can close the user's
    # real browser, not merely our transport.  Stopping Playwright drops the
    # client connection while leaving external browser processes/tabs untouched.
    _cdp.clear()
    if _ctx:
        await _ctx.close(); _ctx = None
    if _pw:
        await _pw.stop(); _pw = None
    return {"closed": ids, "browser_stopped": True}


def list_pages() -> list[dict]:
    return [{
        "page_id": k, "workspace_id": v["workspace_id"], "url": v["page"].url,
        "opened": v["opened"], "browser": v.get("cdp") or "managed",
        "external": bool(v.get("external")),
    } for k, v in _pages.items()]


def engine() -> dict:
    """Configured engine (known before the lazy launch) plus whether it is currently running."""
    exe = CFG.get("browser_executable")
    return {"configured": exe or "chrome/chromium (bundled)", "headless": bool(CFG.get("browser_headless", True)),
            "running": _engine["channel"] is not None, "profile": "cloned-comet" if exe and "Comet" in exe else "empty"}
