"""Native macOS desktop control ("computer use"): screenshots, window list, synthetic mouse/keyboard events (Quartz CGEvent),
app activation, clipboard. Everything here acts on the user's real desktop as the user; it is gated by a `desktop` grant per
workspace and by macOS TCC (Screen Recording + Accessibility for the bridge's python). No model, no vision — ChatGPT looks
at the screenshot and chooses coordinates itself. Coordinates are in POINTS (the screenshot is downscaled to point size on
Retina displays so what it sees maps 1:1 onto what it clicks)."""
from __future__ import annotations
import base64, subprocess, sys, time, uuid
from pathlib import Path
import Quartz, AppKit
from ApplicationServices import AXIsProcessTrusted
from .config import ARTIFACTS_DIR
from .policy import BridgeError, grant_find

FLAGS = {"cmd": Quartz.kCGEventFlagMaskCommand, "command": Quartz.kCGEventFlagMaskCommand, "shift": Quartz.kCGEventFlagMaskShift,
         "alt": Quartz.kCGEventFlagMaskAlternate, "option": Quartz.kCGEventFlagMaskAlternate, "ctrl": Quartz.kCGEventFlagMaskControl,
         "control": Quartz.kCGEventFlagMaskControl, "fn": Quartz.kCGEventFlagMaskSecondaryFn}
KEYS = {**{c: k for c, k in zip("asdfhgzxcv", [0, 1, 2, 3, 4, 5, 6, 7, 8, 9])}, "b": 11, "q": 12, "w": 13, "e": 14, "r": 15, "y": 16, "t": 17,
        "1": 18, "2": 19, "3": 20, "4": 21, "6": 22, "5": 23, "=": 24, "9": 25, "7": 26, "-": 27, "8": 28, "0": 29, "]": 30, "o": 31, "u": 32,
        "[": 33, "i": 34, "p": 35, "return": 36, "enter": 36, "l": 37, "j": 38, "'": 39, "k": 40, ";": 41, "\\": 42, ",": 43, "/": 44, "n": 45,
        "m": 46, ".": 47, "tab": 48, "space": 49, "`": 50, "backspace": 51, "delete": 51, "escape": 53, "esc": 53, "cmd": 55, "shift": 56,
        "capslock": 57, "option": 58, "alt": 58, "control": 59, "ctrl": 59, "fn": 63, "f5": 96, "f6": 97, "f7": 98, "f3": 99, "f8": 100,
        "f9": 101, "f11": 103, "f13": 105, "f14": 107, "f10": 109, "f12": 111, "f15": 113, "home": 115, "pageup": 116, "forwarddelete": 117,
        "f4": 118, "end": 119, "f2": 120, "pagedown": 121, "f1": 122, "left": 123, "right": 124, "down": 125, "up": 126}


def _gate(workspace_id: str) -> None:
    grant_find(workspace_id, "desktop", {"screen": "*"})


def _workspace():
    """Return the AppKit workspace through a patchable seam for native unit tests."""
    return AppKit.NSWorkspace.sharedWorkspace()


def permissions() -> dict:
    exe = str(Path(sys.executable).resolve())
    return {"screen_recording": bool(Quartz.CGPreflightScreenCaptureAccess()), "accessibility": bool(AXIsProcessTrusted()),
            "bridge_executable": exe,
            "how_to_grant": "System Settings > Privacy & Security > Screen Recording AND Accessibility: add the bridge python "
                            f"({exe}; the Python.app bundle two levels up also works), then `bridgectl start`"}


def request_permissions() -> dict:
    """Trigger macOS's own permission prompts for THIS (launchd) process and open the two Privacy panes; the user clicks Allow."""
    from ApplicationServices import AXIsProcessTrustedWithOptions, kAXTrustedCheckOptionPrompt
    Quartz.CGRequestScreenCaptureAccess()
    AXIsProcessTrustedWithOptions({kAXTrustedCheckOptionPrompt: True})
    for pane in ("Privacy_ScreenCapture", "Privacy_Accessibility"):
        subprocess.run(["/usr/bin/open", f"x-apple.systempreferences:com.apple.preference.security?{pane}"], timeout=10)
    return permissions()


def info() -> dict:
    disps = []
    for d in Quartz.CGGetActiveDisplayList(16, None, None)[1]:
        b = Quartz.CGDisplayBounds(d)
        disps.append({"id": int(d), "x": b.origin.x, "y": b.origin.y, "width": b.size.width, "height": b.size.height, "main": bool(Quartz.CGDisplayIsMain(d))})
    front = _workspace().frontmostApplication()
    loc = Quartz.CGEventGetLocation(Quartz.CGEventCreate(None))
    return {"displays": disps, "scale": float(AppKit.NSScreen.mainScreen().backingScaleFactor()), "units": "points (origin top-left of main display)",
            "mouse": {"x": loc.x, "y": loc.y}, "frontmost_app": front.localizedName() if front else None, "permissions": permissions()}


def screenshot(workspace_id: str, display: int = 1, region: list[int] | None = None, fmt: str = "png", quality: int = 70, max_width: int | None = None) -> dict:
    """screencapture → downscale to point size (Retina 2x → 1x) so returned pixel coordinates == click coordinates."""
    _gate(workspace_id)
    out = ARTIFACTS_DIR / workspace_id / "desktop"; out.mkdir(parents=True, exist_ok=True)
    p = out / f"{int(time.time())}-{uuid.uuid4().hex[:4]}.{'jpg' if fmt == 'jpeg' else 'png'}"
    cmd = ["/usr/sbin/screencapture", "-x", "-t", "jpg" if fmt == "jpeg" else "png"]
    if region:
        if len(region) != 4:
            raise BridgeError("invalid_argument", "region must be [x, y, width, height] in points")
        cmd += ["-R", ",".join(str(int(v)) for v in region)]
    else:
        cmd += ["-D", str(display)]
    r = subprocess.run(cmd + [str(p)], capture_output=True, text=True, timeout=20)
    if r.returncode != 0 or not p.exists() or p.stat().st_size < 1000:
        raise BridgeError("needs_user_action", f"screencapture failed ({r.stderr.strip()[:200]}); {permissions()['how_to_grant']}")
    scale = float(AppKit.NSScreen.mainScreen().backingScaleFactor())
    dims = subprocess.run(["/usr/bin/sips", "-g", "pixelWidth", "-g", "pixelHeight", str(p)], capture_output=True, text=True).stdout
    pw = int(dims.split("pixelWidth:")[1].split()[0]); ph = int(dims.split("pixelHeight:")[1].split()[0])
    tw, th = int(pw / scale), int(ph / scale)
    if max_width and tw > max_width:
        th = int(th * max_width / tw); tw = max_width
    if (tw, th) != (pw, ph):
        subprocess.run(["/usr/bin/sips", "-z", str(th), str(tw), str(p)] + (["-s", "formatOptions", str(quality)] if fmt == "jpeg" else []), capture_output=True, timeout=20)
    data = p.read_bytes()
    return {"path": str(p), "bytes": len(data), "mime": f"image/{fmt}", "width": tw, "height": th, "origin": region[:2] if region else [0, 0],
            "coordinate_note": "image pixel (px,py) -> click at (origin.x+px*width_scale, origin.y+py*width_scale)" if max_width else "image pixels == desktop points; click at (origin.x+px, origin.y+py)",
            "width_scale": (region[2] if region else info()["displays"][0]["width"]) / tw, "base64": base64.b64encode(data).decode()}


def windows(on_screen_only: bool = True) -> list[dict]:
    opts = (Quartz.kCGWindowListOptionOnScreenOnly if on_screen_only else Quartz.kCGWindowListOptionAll) | Quartz.kCGWindowListExcludeDesktopElements
    out = []
    for w in Quartz.CGWindowListCopyWindowInfo(opts, Quartz.kCGNullWindowID) or []:
        if w.get("kCGWindowLayer", 0) != 0 and on_screen_only:
            continue
        b = w.get("kCGWindowBounds", {})
        out.append({"app": w.get("kCGWindowOwnerName"), "pid": w.get("kCGWindowOwnerPID"), "title": w.get("kCGWindowName") or "", "window_id": w.get("kCGWindowNumber"),
                    "x": b.get("X"), "y": b.get("Y"), "width": b.get("Width"), "height": b.get("Height"), "on_screen": bool(w.get("kCGWindowIsOnscreen", on_screen_only))})
    return out


def _post(ev) -> None:
    Quartz.CGEventPost(Quartz.kCGHIDEventTap, ev)


def _mouse(kind, x, y, button=Quartz.kCGMouseButtonLeft, clicks=1):
    ev = Quartz.CGEventCreateMouseEvent(None, kind, (x, y), button)
    if clicks > 1:
        Quartz.CGEventSetIntegerValueField(ev, Quartz.kCGMouseEventClickState, clicks)
    _post(ev)


_BTN = {"left": (Quartz.kCGMouseButtonLeft, Quartz.kCGEventLeftMouseDown, Quartz.kCGEventLeftMouseUp, Quartz.kCGEventLeftMouseDragged),
        "right": (Quartz.kCGMouseButtonRight, Quartz.kCGEventRightMouseDown, Quartz.kCGEventRightMouseUp, Quartz.kCGEventRightMouseDragged),
        "middle": (Quartz.kCGMouseButtonCenter, Quartz.kCGEventOtherMouseDown, Quartz.kCGEventOtherMouseUp, Quartz.kCGEventOtherMouseDragged)}


def _flags(mods: list[str] | None) -> int:
    f = 0
    for m in mods or []:
        if m.lower() not in FLAGS:
            raise BridgeError("invalid_argument", f"unknown modifier {m}; use cmd/shift/alt/ctrl/fn")
        f |= FLAGS[m.lower()]
    return f


def _key(name: str, flags: int = 0) -> None:
    n = name.lower()
    if n not in KEYS:
        raise BridgeError("invalid_argument", f"unknown key {name!r}; known: {sorted(KEYS)}")
    for down in (True, False):
        ev = Quartz.CGEventCreateKeyboardEvent(None, KEYS[n], down)
        if flags:
            Quartz.CGEventSetFlags(ev, flags)
        _post(ev)
        time.sleep(0.02)


def _type(text: str) -> None:
    for i in range(0, len(text), 20):   # CGEventKeyboardSetUnicodeString: keep chunks small for reliability
        chunk = text[i:i + 20]
        for down in (True, False):
            ev = Quartz.CGEventCreateKeyboardEvent(None, 0, down)
            Quartz.CGEventKeyboardSetUnicodeString(ev, len(chunk), chunk)
            _post(ev)
        time.sleep(0.03)


def act(workspace_id: str, action: str, x: float | None = None, y: float | None = None, x2: float | None = None, y2: float | None = None,
        button: str = "left", clicks: int = 1, text: str | None = None, key: str | None = None, modifiers: list[str] | None = None,
        dx: int = 0, dy: int = 0, ms: int = 0) -> dict:
    _gate(workspace_id)
    if not AXIsProcessTrusted():
        raise BridgeError("needs_user_action", "Accessibility permission missing for the bridge python; " + permissions()["how_to_grant"])
    btn, down, up, drag = _BTN.get(button, _BTN["left"])
    if action in ("click", "double_click", "right_click", "move", "mouse_down", "mouse_up", "drag", "scroll") and (x is None or y is None):
        raise BridgeError("invalid_argument", f"{action} needs x and y (points)")
    if action == "move":
        _mouse(Quartz.kCGEventMouseMoved, x, y)
    elif action in ("click", "double_click", "right_click"):
        if action == "right_click":
            btn, down, up, drag = _BTN["right"]
        n = 2 if action == "double_click" else clicks
        _mouse(Quartz.kCGEventMouseMoved, x, y); time.sleep(0.05)
        for c in range(1, n + 1):
            _mouse(down, x, y, btn, c); _mouse(up, x, y, btn, c); time.sleep(0.06)
    elif action == "mouse_down":
        _mouse(down, x, y, btn)
    elif action == "mouse_up":
        _mouse(up, x, y, btn)
    elif action == "drag":
        if x2 is None or y2 is None:
            raise BridgeError("invalid_argument", "drag needs x2, y2")
        _mouse(Quartz.kCGEventMouseMoved, x, y); time.sleep(0.05); _mouse(down, x, y, btn); time.sleep(0.1)
        steps = 12
        for i in range(1, steps + 1):
            _mouse(drag, x + (x2 - x) * i / steps, y + (y2 - y) * i / steps, btn); time.sleep(0.02)
        _mouse(up, x2, y2, btn)
    elif action == "scroll":
        _mouse(Quartz.kCGEventMouseMoved, x, y); time.sleep(0.03)
        _post(Quartz.CGEventCreateScrollWheelEvent(None, Quartz.kCGScrollEventUnitLine, 2, int(-dy), int(dx)))
    elif action == "type":
        if text is None:
            raise BridgeError("invalid_argument", "type needs text")
        _type(text)
    elif action == "key":
        if not key:
            raise BridgeError("invalid_argument", "key needs key, e.g. 'return' or 'c' with modifiers ['cmd']")
        _key(key, _flags(modifiers))
    elif action == "wait":
        time.sleep(min(max(ms, 0), 10000) / 1000)
    else:
        raise BridgeError("invalid_argument", "action must be click|double_click|right_click|move|mouse_down|mouse_up|drag|scroll|type|key|wait")
    if ms and action != "wait":
        time.sleep(min(ms, 10000) / 1000)
    loc = Quartz.CGEventGetLocation(Quartz.CGEventCreate(None))
    front = _workspace().frontmostApplication()
    return {"action": action, "mouse": {"x": loc.x, "y": loc.y}, "frontmost_app": front.localizedName() if front else None}


def app(workspace_id: str, action: str, name: str | None = None, path: str | None = None) -> dict:
    _gate(workspace_id)
    ws = _workspace()
    if action == "list":
        return {"running": sorted({a.localizedName() for a in ws.runningApplications() if a.activationPolicy() == 0})}
    if action == "frontmost":
        f = ws.frontmostApplication(); return {"frontmost_app": f.localizedName() if f else None, "pid": f.processIdentifier() if f else None}
    if not name and not path:
        raise BridgeError("invalid_argument", "name (or path) required")
    if action == "open":
        r = subprocess.run(["/usr/bin/open"] + (["-a", name] if name else []) + ([path] if path else []), capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            raise BridgeError("not_found", r.stderr.strip()[:300])
        time.sleep(1.0)
    elif action == "activate":
        apps = [a for a in ws.runningApplications() if a.localizedName() == name]
        if not apps:
            raise BridgeError("not_found", f"{name} is not running; use action=open")
        apps[0].activateWithOptions_(AppKit.NSApplicationActivateIgnoringOtherApps)
        time.sleep(0.4)
    elif action == "quit":
        # Never interpolate caller-controlled app names into AppleScript.  NSRunningApplication
        # gives us a structured API and keeps the name data out of executable source text.
        apps = [a for a in ws.runningApplications() if a.localizedName() == name]
        if not apps:
            raise BridgeError("not_found", f"{name} is not running; use action=open")
        if not apps[0].terminate():
            raise BridgeError("internal", f"macOS refused to terminate {name}")
    else:
        raise BridgeError("invalid_argument", "action must be list|frontmost|open|activate|quit")
    f = ws.frontmostApplication()
    return {"action": action, "name": name, "frontmost_app": f.localizedName() if f else None}


def clipboard(workspace_id: str, action: str, text: str | None = None) -> dict:
    _gate(workspace_id)
    if action == "get":
        return {"text": subprocess.run(["/usr/bin/pbpaste"], capture_output=True, text=True, timeout=10).stdout[:200000]}
    if action == "set":
        subprocess.run(["/usr/bin/pbcopy"], input=(text or "").encode(), timeout=10)
        return {"set": True, "chars": len(text or "")}
    raise BridgeError("invalid_argument", "action must be get|set")
