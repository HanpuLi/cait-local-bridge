"""Semantic macOS Accessibility control.

Accessibility-first native UI control inspired by the fail-closed element-reference
model used by DarwinRelay.  This module deliberately runs in the bridge process so
it reuses the bridge's existing TCC Accessibility identity and remains behind the
bridge's workspace/grant/audit boundary.

Element refs are observations, not permanent selectors:
    ax:<pid>:<child.path|root>:<fingerprint>

The fingerprint covers semantic identity (role/subrole/identifier/title/description).
A path may drift as transient controls are inserted; in that case we recover only
when exactly one element in a bounded search has the same fingerprint.  Changed,
missing, or ambiguous targets fail closed rather than silently rebinding.
"""
from __future__ import annotations

import hashlib
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any

import AppKit
from ApplicationServices import (
    AXIsProcessTrusted,
    AXUIElementCopyActionNames,
    AXUIElementCopyAttributeValue,
    AXUIElementCopyElementAtPosition,
    AXUIElementCopyMultipleAttributeValues,
    AXUIElementCreateApplication,
    AXUIElementPerformAction,
    AXUIElementSetAttributeValue,
    AXUIElementSetMessagingTimeout,
    AXValueGetType,
    AXValueGetValue,
    kAXCancelAction,
    kAXChildrenAttribute,
    kAXConfirmAction,
    kAXDecrementAction,
    kAXDescriptionAttribute,
    kAXEnabledAttribute,
    kAXFocusedAttribute,
    kAXFocusedUIElementAttribute,
    kAXHelpAttribute,
    kAXIdentifierAttribute,
    kAXIncrementAction,
    kAXPlaceholderValueAttribute,
    kAXPositionAttribute,
    kAXPressAction,
    kAXRaiseAction,
    kAXRoleAttribute,
    kAXRoleDescriptionAttribute,
    kAXSelectedAttribute,
    kAXShowMenuAction,
    kAXSizeAttribute,
    kAXSubroleAttribute,
    kAXTitleAttribute,
    kAXURLAttribute,
    kAXValueAttribute,
    kAXValueAXErrorType,
    kAXValueCGPointType,
    kAXValueCGSizeType,
)
from .policy import BridgeError, grant_find

_OBS_TTL = 60.0
_OBS_MAX = 64
_obs_lock = threading.Lock()
_observations: dict[str, dict[str, Any]] = {}


def _gate(workspace_id: str) -> None:
    grant_find(workspace_id, "desktop", {"screen": "*"})
    if not AXIsProcessTrusted():
        raise BridgeError(
            "needs_user_action",
            "Accessibility permission is missing for the bridge process; grant it to the bridge Python in System Settings > Privacy & Security > Accessibility",
        )


def _copy(element, attribute):
    try:
        rc, value = AXUIElementCopyAttributeValue(element, attribute, None)
    except Exception:
        return None
    return value if int(rc) == 0 else None


def _copy_many(element, attributes) -> dict[Any, Any]:
    """Batch AX IPC when available; fall back only when the batch call itself fails."""
    attrs = list(attributes)
    try:
        rc, values = AXUIElementCopyMultipleAttributeValues(element, attrs, 0, None)
    except Exception:
        rc, values = -1, ()
    if int(rc) != 0 or len(values or ()) != len(attrs):
        return {attribute: _copy(element, attribute) for attribute in attrs}

    out: dict[Any, Any] = {}
    for attribute, value in zip(attrs, values):
        is_error = False
        try:
            is_error = AXValueGetType(value) == kAXValueAXErrorType
        except Exception:
            pass
        # With option=0, unsupported/missing attributes are represented by an
        # AXValue(kAXValueAXErrorType) slot. Retrying those one by one only adds
        # IPC and returns the same absence, so normalize them to None.
        out[attribute] = None if is_error else value
    return out


def _string(element, attribute) -> str:
    value = _copy(element, attribute)
    return value if isinstance(value, str) else ""


def _bool(element, attribute) -> bool | None:
    value = _copy(element, attribute)
    if isinstance(value, bool):
        return value
    # NSNumber bridges as int on some pyobjc builds.
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    return None


def _listish(value) -> list:
    """Bridge NSArray/CFArray and Python sequences without treating a single AX element/string as a collection."""
    if value is None or isinstance(value, (str, bytes, bytearray, dict)):
        return []
    try:
        return list(value)
    except (TypeError, ValueError):
        return []


def _children(element) -> list:
    return _listish(_copy(element, kAXChildrenAttribute))


def _actions(element) -> list[str]:
    try:
        rc, value = AXUIElementCopyActionNames(element, None)
    except Exception:
        return []
    return _listish(value) if int(rc) == 0 else []


def _application_element(pid: int):
    root = AXUIElementCreateApplication(pid)
    # A wedged Accessibility client must not wedge the MCP request indefinitely.
    # DarwinRelay uses the same AX messaging-timeout concept around semantic UI work.
    try:
        AXUIElementSetMessagingTimeout(root, 1.0)
    except Exception:
        pass
    # Chromium/Electron and some complex AppKit apps expose a richer tree when
    # Enhanced User Interface is enabled. Unsupported/read-only apps simply ignore it.
    try:
        AXUIElementSetAttributeValue(root, "AXEnhancedUserInterface", True)
    except Exception:
        pass
    return root


def _target_pid(pid: int | None) -> int:
    if pid is not None:
        if int(pid) <= 0:
            raise BridgeError("invalid_argument", "pid must be a positive integer")
        return int(pid)
    app = AppKit.NSWorkspace.sharedWorkspace().frontmostApplication()
    if not app:
        raise BridgeError("not_found", "no frontmost macOS application")
    return int(app.processIdentifier())


def _point_or_size_value(value, value_type) -> tuple[float, float] | None:
    if value is None:
        return None
    try:
        ok, converted = AXValueGetValue(value, value_type, None)
    except Exception:
        return None
    if not ok or converted is None:
        return None
    if value_type == kAXValueCGPointType:
        return float(converted.x), float(converted.y)
    return float(converted.width), float(converted.height)


def _text_value(value, *, url: bool = False) -> str:
    if isinstance(value, str):
        return value
    if url and value is not None:
        try:
            return str(value.absoluteString())
        except Exception:
            pass
    return ""


def _fields(element, include_value: bool = False) -> dict[str, Any]:
    attributes = [
        kAXRoleAttribute, kAXSubroleAttribute, kAXIdentifierAttribute,
        kAXTitleAttribute, kAXDescriptionAttribute, kAXRoleDescriptionAttribute,
        kAXPlaceholderValueAttribute, kAXHelpAttribute, kAXURLAttribute,
        kAXPositionAttribute, kAXSizeAttribute, kAXEnabledAttribute,
        kAXFocusedAttribute, kAXSelectedAttribute,
    ]
    if include_value:
        attributes.append(kAXValueAttribute)
    values = _copy_many(element, attributes)

    role = _text_value(values.get(kAXRoleAttribute))
    subrole = _text_value(values.get(kAXSubroleAttribute))
    secure = "secure" in role.lower() or "secure" in subrole.lower()
    d: dict[str, Any] = {
        "role": role,
        "subrole": subrole,
        "identifier": _text_value(values.get(kAXIdentifierAttribute)),
        "title": _text_value(values.get(kAXTitleAttribute)),
        "description": _text_value(values.get(kAXDescriptionAttribute)),
    }
    for key, attribute in (
        ("role_description", kAXRoleDescriptionAttribute),
        ("placeholder", kAXPlaceholderValueAttribute),
        ("help", kAXHelpAttribute),
        ("url", kAXURLAttribute),
    ):
        text = _text_value(values.get(attribute), url=(attribute == kAXURLAttribute))
        if text:
            d[key] = text[:4000] + ("…" if len(text) > 4000 else "")

    position = _point_or_size_value(values.get(kAXPositionAttribute), kAXValueCGPointType)
    size = _point_or_size_value(values.get(kAXSizeAttribute), kAXValueCGSizeType)
    if position is not None and size is not None:
        d["frame"] = {
            "x": position[0], "y": position[1],
            "width": size[0], "height": size[1],
        }

    for key, attribute in (
        ("enabled", kAXEnabledAttribute),
        ("focused", kAXFocusedAttribute),
        ("selected", kAXSelectedAttribute),
    ):
        raw = values.get(attribute)
        if isinstance(raw, bool):
            d[key] = raw
        elif isinstance(raw, int) and raw in (0, 1):
            d[key] = bool(raw)

    if include_value:
        if secure:
            d["value"] = "<redacted>"
            d["secure"] = True
        else:
            value = values.get(kAXValueAttribute)
            if isinstance(value, (str, int, float, bool)):
                text = str(value)
                d["value"] = text[:4000] + ("…" if len(text) > 4000 else "")
    return d


def _fingerprint_from_fields(fields: dict[str, Any]) -> str:
    # Value/enabled/focused/selected are mutable state and intentionally omitted.
    # Rounded frame is part of identity: a visually reflowed target must be
    # re-observed rather than silently accepting an old coordinate relationship.
    frame = fields.get("frame") or {}
    rounded_frame = ",".join(
        str(int(round(float(frame.get(k, 0))))) if k in frame else ""
        for k in ("x", "y", "width", "height")
    )
    raw = "\x1f".join(
        [str(fields.get(k, "")) for k in ("role", "subrole", "identifier", "title", "description")]
        + [rounded_frame]
    )
    return hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _fingerprint(element) -> str:
    return _fingerprint_from_fields(_fields(element, include_value=False))


def _path_text(path: list[int]) -> str:
    return "root" if not path else ".".join(str(i) for i in path)


def _make_ref(pid: int, path: list[int], element) -> str:
    return f"ax:{pid}:{_path_text(path)}:{_fingerprint(element)}"


def _parse_ref(ref: str) -> tuple[int, list[int], str]:
    if not isinstance(ref, str):
        raise BridgeError("invalid_argument", "element ref must be a string")
    parts = ref.split(":", 3)
    if len(parts) != 4 or parts[0] != "ax":
        raise BridgeError("invalid_argument", "element ref must have form ax:<pid>:<path>:<fingerprint>")
    try:
        pid = int(parts[1])
    except ValueError as exc:
        raise BridgeError("invalid_argument", "element ref contains an invalid pid") from exc
    fp = parts[3]
    if len(fp) != 16 or any(c not in "0123456789abcdef" for c in fp):
        raise BridgeError("invalid_argument", "element ref contains an invalid fingerprint")
    if parts[2] in ("", "root"):
        path: list[int] = []
    else:
        try:
            path = [int(x) for x in parts[2].split(".")]
        except ValueError as exc:
            raise BridgeError("invalid_argument", "element ref contains an invalid child path") from exc
        if any(x < 0 for x in path):
            raise BridgeError("invalid_argument", "element ref contains a negative child index")
    if pid <= 0:
        raise BridgeError("invalid_argument", "element ref contains an invalid pid")
    return pid, path, fp


def _at_path(pid: int, path: list[int]):
    current = _application_element(pid)
    for index in path:
        children = _children(current)
        if index >= len(children):
            return None
        current = children[index]
    return current


def _find_by_fingerprint(
    pid: int,
    expected: str,
    *,
    max_depth: int = 20,
    max_elements: int = 5000,
    max_matches: int = 2,
) -> list:
    root = _application_element(pid)
    matches: list = []
    visited = 0

    def walk(element, depth: int) -> None:
        nonlocal visited
        if visited >= max_elements or len(matches) >= max_matches:
            return
        visited += 1
        if _fingerprint(element) == expected:
            matches.append(element)
            if len(matches) >= max_matches:
                return
        if depth >= max_depth:
            return
        for child in _children(element):
            walk(child, depth + 1)
            if visited >= max_elements or len(matches) >= max_matches:
                break

    walk(root, 0)
    return matches


def _resolve(ref: str):
    pid, path, expected = _parse_ref(ref)
    direct = _at_path(pid, path)

    # Never trust path+fingerprint alone when two controls have the same semantic
    # identity. Without a geometry component a sibling insertion could move an
    # indistinguishable control onto the old path. A bounded uniqueness check makes
    # that case fail closed rather than silently targeting the wrong sibling.
    matches = _find_by_fingerprint(pid, expected)
    if len(matches) != 1:
        reason = "changed or disappeared" if not matches else "is ambiguous (fingerprint is not unique)"
        raise BridgeError(
            "conflict",
            f"UI_ELEMENT_STALE: Accessibility element {reason}; run desktop_observe/desktop_query again",
        )
    if direct is not None and _fingerprint(direct) == expected:
        return pid, direct

    # The child path drifted, but exactly one element still has the observation's
    # fingerprint, so it is safe to recover that semantic target.
    return pid, matches[0]


def _describe(element, pid: int, path: list[int], include_value: bool = True) -> dict[str, Any]:
    data = _fields(element, include_value=include_value)
    data["ref"] = _make_ref(pid, path, element)
    data["actions"] = _actions(element)
    return data


def _find_paths_by_fingerprint(
    pid: int,
    expected: str,
    *,
    max_depth: int = 20,
    max_elements: int = 5000,
    max_matches: int = 2,
) -> list[tuple[list[int], Any]]:
    root = _application_element(pid)
    matches: list[tuple[list[int], Any]] = []
    visited = 0

    def walk(element, path: list[int], depth: int) -> None:
        nonlocal visited
        if visited >= max_elements or len(matches) >= max_matches:
            return
        visited += 1
        if _fingerprint(element) == expected:
            matches.append((list(path), element))
            if len(matches) >= max_matches:
                return
        if depth >= max_depth:
            return
        for index, child in enumerate(_children(element)):
            walk(child, path + [index], depth + 1)
            if visited >= max_elements or len(matches) >= max_matches:
                break

    walk(root, [], 0)
    return matches


def element_at(
    workspace_id: str,
    x: float,
    y: float,
    pid: int | None = None,
    include_value: bool = True,
) -> dict[str, Any]:
    """Bridge a visual point back to a fail-closed semantic Accessibility ref."""
    _gate(workspace_id)
    pid = _target_pid(pid)
    try:
        x = float(x)
        y = float(y)
    except (TypeError, ValueError) as exc:
        raise BridgeError("invalid_argument", "x and y must be finite numbers") from exc
    if not (-1_000_000 < x < 1_000_000 and -1_000_000 < y < 1_000_000):
        raise BridgeError("invalid_argument", "x and y are outside the supported desktop coordinate range")
    root = _application_element(pid)
    try:
        rc, hit = AXUIElementCopyElementAtPosition(root, x, y, None)
    except Exception as exc:
        raise BridgeError("not_found", f"Accessibility hit-test failed: {str(exc)[:300]}") from exc
    if int(rc) != 0 or hit is None:
        raise BridgeError("not_found", f"no Accessibility element at ({x:g}, {y:g}) for pid {pid}")
    fingerprint = _fingerprint(hit)
    matches = _find_paths_by_fingerprint(pid, fingerprint)
    if len(matches) != 1:
        reason = "not present in the bounded application tree" if not matches else "ambiguous in the bounded application tree"
        raise BridgeError(
            "conflict",
            f"UI_ELEMENT_STALE: hit-tested Accessibility element is {reason}; re-observe or use coordinate fallback",
        )
    path, element = matches[0]
    item = _describe(element, pid, path, include_value)
    obs = _register_observation(pid, {item["ref"]})
    return {
        "pid": pid,
        "point": {"x": x, "y": y},
        "element": item,
        **obs,
    }


_HIGH_SIGNAL_ROLES = {
    "AXWindow", "AXSheet", "AXDialog", "AXButton", "AXCheckBox", "AXRadioButton",
    "AXPopUpButton", "AXMenuItem", "AXTextField", "AXTextArea", "AXSearchField",
    "AXLink", "AXTabGroup", "AXRow", "AXCell", "AXSlider", "AXStaticText",
}


def _state_fact(fields: dict[str, Any], ref: str) -> dict[str, Any] | None:
    role = str(fields.get("role", ""))
    signal = (
        role in _HIGH_SIGNAL_ROLES
        or bool(fields.get("title"))
        or bool(fields.get("identifier"))
        or bool(fields.get("url"))
        or "value" in fields
        or fields.get("focused") is True
        or fields.get("selected") is True
        or fields.get("enabled") is False
    )
    if not signal:
        return None
    identity = {
        key: fields[key]
        for key in ("role", "subrole", "identifier", "title", "description", "frame", "url")
        if key in fields and fields[key] not in ("", None)
    }
    state = {
        key: fields[key]
        for key in ("value", "enabled", "focused", "selected")
        if key in fields
    }
    return {"ref": ref, "identity": identity, "state": state}


def _snapshot_state(pid: int, max_elements: int = 800, max_depth: int = 16) -> dict[str, Any]:
    root = _application_element(pid)
    facts: dict[str, dict[str, Any]] = {}
    visited = 0
    truncated = False

    def walk(element, path: list[int], depth: int) -> None:
        nonlocal visited, truncated
        if visited >= max_elements:
            truncated = True
            return
        visited += 1
        fields = _fields(element, include_value=True)
        fp = _fingerprint_from_fields(fields)
        fact = _state_fact(fields, f"ax:{pid}:{_path_text(path)}:{fp}")
        if fact is not None:
            key = fp
            if key in facts:
                # A duplicate semantic identity is still useful for observation,
                # but path-scoping avoids silently collapsing two controls.
                key = f"{fp}@{_path_text(path)}"
            facts[key] = fact
        if depth >= max_depth:
            if _children(element):
                truncated = True
            return
        for index, child in enumerate(_children(element)):
            walk(child, path + [index], depth + 1)
            if visited >= max_elements:
                break

    walk(root, [], 0)
    return {"facts": facts, "visited": visited, "truncated": truncated}


def _diff_state_maps(
    before: dict[str, dict[str, Any]],
    after: dict[str, dict[str, Any]],
    *,
    item_limit: int = 20,
) -> dict[str, Any]:
    added_keys = sorted(set(after) - set(before))
    removed_keys = sorted(set(before) - set(after))
    changed_keys = sorted(
        key for key in set(before) & set(after)
        if before[key].get("state") != after[key].get("state")
    )
    added = [after[k] for k in added_keys[:item_limit]]
    removed = [before[k] for k in removed_keys[:item_limit]]
    changed = [
        {
            "identity": after[k].get("identity") or before[k].get("identity"),
            "ref": after[k].get("ref"),
            "before": before[k].get("state", {}),
            "after": after[k].get("state", {}),
        }
        for k in changed_keys[:item_limit]
    ]
    return {
        "counts": {
            "added": len(added_keys),
            "removed": len(removed_keys),
            "changed": len(changed_keys),
        },
        "added": added,
        "removed": removed,
        "changed": changed,
        "truncated": (
            len(added_keys) > item_limit
            or len(removed_keys) > item_limit
            or len(changed_keys) > item_limit
        ),
    }


def _prune_observations(now: float | None = None) -> None:
    now = time.time() if now is None else now
    for oid in [k for k, v in _observations.items() if v["expires_at"] <= now]:
        _observations.pop(oid, None)
    if len(_observations) > _OBS_MAX:
        for oid, _ in sorted(_observations.items(), key=lambda kv: kv[1]["created_at"])[: len(_observations) - _OBS_MAX]:
            _observations.pop(oid, None)


def _register_observation(pid: int, refs: set[str]) -> dict[str, Any]:
    now = time.time()
    oid = "obs_" + uuid.uuid4().hex[:12]
    with _obs_lock:
        _prune_observations(now)
        _observations[oid] = {
            "pid": pid,
            "refs": set(refs),
            "created_at": now,
            "expires_at": now + _OBS_TTL,
        }
        _prune_observations(now)
    return {"observation_id": oid, "expires_in_seconds": int(_OBS_TTL)}


def _require_observed(observation_id: str | None, ref: str) -> None:
    if not observation_id:
        return
    now = time.time()
    with _obs_lock:
        _prune_observations(now)
        obs = _observations.get(observation_id)
        if not obs:
            raise BridgeError("conflict", "UI_OBSERVATION_EXPIRED: re-run desktop_observe/desktop_query")
        if ref not in obs["refs"]:
            raise BridgeError("permission_denied", "element ref was not issued by the supplied observation")


def observe(
    workspace_id: str,
    pid: int | None = None,
    max_depth: int = 8,
    max_elements: int = 500,
    include_values: bool = True,
) -> dict[str, Any]:
    _gate(workspace_id)
    pid = _target_pid(pid)
    max_depth = max(0, min(int(max_depth), 20))
    max_elements = max(1, min(int(max_elements), 5000))
    root = _application_element(pid)
    refs: set[str] = set()
    emitted = 0
    truncated = False

    def walk(element, path: list[int], depth: int) -> dict[str, Any]:
        nonlocal emitted, truncated
        item = _describe(element, pid, path, include_values)
        refs.add(item["ref"])
        emitted += 1
        children = _children(element)
        if depth >= max_depth or emitted >= max_elements:
            if children:
                truncated = True
            return item
        rendered = []
        for index, child in enumerate(children):
            if emitted >= max_elements:
                truncated = True
                break
            rendered.append(walk(child, path + [index], depth + 1))
        if rendered:
            item["children"] = rendered
        return item

    tree = walk(root, [], 0)
    obs = _register_observation(pid, refs)
    app = AppKit.NSRunningApplication.runningApplicationWithProcessIdentifier_(pid)
    return {
        "pid": pid,
        "app": app.localizedName() if app else None,
        "element_count": emitted,
        "truncated": truncated,
        "tree": tree,
        **obs,
    }


def _selector_matches(fields: dict[str, Any], selector: dict[str, Any]) -> bool:
    if not selector:
        return True
    exact = (
        "role", "subrole", "identifier", "title", "description", "value",
        "enabled", "focused", "selected", "role_description", "placeholder", "help", "url",
    )
    for key in exact:
        if key in selector and fields.get(key) != selector[key]:
            return False
    for key in ("title", "description", "value", "role_description", "placeholder", "help", "url"):
        contains = selector.get(key + "_contains")
        if contains is not None and str(contains).lower() not in str(fields.get(key, "")).lower():
            return False
    return True


def query(
    workspace_id: str,
    selector: dict[str, Any],
    pid: int | None = None,
    max_depth: int = 16,
    max_elements: int = 3000,
    limit: int = 50,
    include_values: bool = True,
) -> dict[str, Any]:
    _gate(workspace_id)
    if not isinstance(selector, dict) or not selector:
        raise BridgeError("invalid_argument", "selector must be a non-empty object")
    pid = _target_pid(pid)
    max_depth = max(0, min(int(max_depth), 20))
    max_elements = max(1, min(int(max_elements), 5000))
    limit = max(1, min(int(limit), 200))
    root = _application_element(pid)
    out: list[dict[str, Any]] = []
    refs: set[str] = set()
    visited = 0
    truncated = False

    def walk(element, path: list[int], depth: int) -> None:
        nonlocal visited, truncated
        if visited >= max_elements or len(out) >= limit:
            truncated = True
            return
        visited += 1
        fields = _fields(element, include_value=include_values)
        if _selector_matches(fields, selector):
            item = _describe(element, pid, path, include_values)
            refs.add(item["ref"])
            out.append(item)
            if len(out) >= limit:
                truncated = True
                return
        if depth >= max_depth:
            return
        for index, child in enumerate(_children(element)):
            walk(child, path + [index], depth + 1)
            if visited >= max_elements or len(out) >= limit:
                break

    walk(root, [], 0)
    obs = _register_observation(pid, refs)
    return {
        "pid": pid,
        "selector": selector,
        "matches": out,
        "match_count": len(out),
        "visited": visited,
        "truncated": truncated,
        **obs,
    }


_ACTIONS = {
    "press": kAXPressAction,
    "raise": kAXRaiseAction,
    "confirm": kAXConfirmAction,
    "cancel": kAXCancelAction,
    "increment": kAXIncrementAction,
    "decrement": kAXDecrementAction,
    "show_menu": kAXShowMenuAction,
}


def _check_precondition(element, precondition: dict[str, Any] | None) -> None:
    if precondition and not _selector_matches(_fields(element, include_value=True), precondition):
        raise BridgeError(
            "conflict",
            "UI_PRECONDITION_FAILED: element no longer matches the requested precondition",
        )


def action(
    workspace_id: str,
    ref: str,
    action: str,
    value: str | None = None,
    observation_id: str | None = None,
    precondition: dict[str, Any] | None = None,
    verify: dict[str, Any] | None = None,
    include_diff: bool = True,
    diff_max_elements: int = 800,
) -> dict[str, Any]:
    _gate(workspace_id)
    _require_observed(observation_id, ref)
    pid, element = _resolve(ref)
    _check_precondition(element, precondition)
    diff_max_elements = max(100, min(int(diff_max_elements), 3000))
    before_state = _snapshot_state(pid, max_elements=diff_max_elements) if include_diff else None

    name = action.lower()
    if name == "set_value":
        if value is None:
            raise BridgeError("invalid_argument", "set_value requires value")
        if len(value) > 500_000:
            raise BridgeError("invalid_argument", "value must be <= 500000 characters")
        if _fields(element, include_value=True).get("secure"):
            raise BridgeError("permission_denied", "refusing to set a secure/password Accessibility field")
        rc = AXUIElementSetAttributeValue(element, kAXValueAttribute, value)
    elif name == "focus":
        rc = AXUIElementSetAttributeValue(element, kAXFocusedAttribute, True)
    elif name in _ACTIONS:
        rc = AXUIElementPerformAction(element, _ACTIONS[name])
    else:
        raise BridgeError(
            "invalid_argument",
            "action must be set_value|focus|press|raise|confirm|cancel|increment|decrement|show_menu",
        )
    if int(rc) != 0:
        raise BridgeError("conflict", f"UI_ACTION_FAILED: AX error {int(rc)} performing {name}")

    result: dict[str, Any] = {
        "performed": True,
        "pid": pid,
        "ref": ref,
        "action": name,
        "element": _fields(element, include_value=True),
    }
    if verify is not None:
        if not isinstance(verify, dict):
            raise BridgeError("invalid_argument", "verify must be an object")
        time.sleep(0.05)
        verify_ref = verify.get("ref")
        verify_selector = verify.get("selector")
        if verify_ref is None and verify_selector is None:
            verify_ref = ref
        check = wait_for(
            workspace_id,
            ref=verify_ref,
            pid=verify.get("pid", pid),
            selector=verify_selector,
            condition=verify.get("condition", "exists"),
            expected=verify.get("expected"),
            timeout_ms=int(verify.get("timeout_ms", 3000)),
            interval_ms=int(verify.get("interval_ms", 100)),
        )
        result["verification"] = check
        if not check["matched"]:
            raise BridgeError(
                "conflict",
                "UI_POSTCONDITION_FAILED: action completed but verification did not match",
            )
    elif include_diff:
        # Give the application one run-loop turn before measuring observable state.
        time.sleep(0.05)

    if include_diff and before_state is not None:
        after_state = _snapshot_state(pid, max_elements=diff_max_elements)
        state_diff = _diff_state_maps(before_state["facts"], after_state["facts"])
        state_diff["before_visited"] = before_state["visited"]
        state_diff["after_visited"] = after_state["visited"]
        state_diff["snapshot_truncated"] = before_state["truncated"] or after_state["truncated"]
        result["state_diff"] = state_diff
    return result


def sequence(
    workspace_id: str,
    steps: list[dict[str, Any]],
    pid: int | None = None,
    include_diff: bool = True,
    diff_max_elements: int = 800,
) -> dict[str, Any]:
    """Execute a bounded deterministic semantic burst without MCP round-trip races."""
    _gate(workspace_id)
    if not isinstance(steps, list) or not 1 <= len(steps) <= 64:
        raise BridgeError("invalid_argument", "steps must contain 1..64 objects")
    if any(not isinstance(step, dict) for step in steps):
        raise BridgeError("invalid_argument", "every sequence step must be an object")

    referenced_pids = []
    for step in steps:
        ref = step.get("ref")
        if ref:
            referenced_pids.append(_parse_ref(ref)[0])
    if pid is None and referenced_pids:
        pid = referenced_pids[0]
    target_pid = _target_pid(pid)
    if any(other != target_pid for other in referenced_pids):
        raise BridgeError("invalid_argument", "all sequence refs must belong to the same target pid")

    diff_max_elements = max(100, min(int(diff_max_elements), 3000))
    before_state = _snapshot_state(target_pid, max_elements=diff_max_elements) if include_diff else None
    results: list[dict[str, Any]] = []

    for index, step in enumerate(steps):
        op = str(step.get("op", "")).lower()
        try:
            if op == "sleep":
                ms = max(0, min(int(step.get("ms", 0)), 10_000))
                time.sleep(ms / 1000)
                result = {"op": op, "slept_ms": ms}
            elif op == "action":
                ref = step.get("ref")
                name = step.get("action")
                if not ref or not name:
                    raise BridgeError("invalid_argument", "action step requires ref and action")
                result = action(
                    workspace_id,
                    ref,
                    str(name),
                    step.get("value"),
                    step.get("observation_id"),
                    step.get("precondition"),
                    step.get("verify"),
                    include_diff=False,
                )
                result["op"] = op
            elif op == "wait_for":
                result = wait_for(
                    workspace_id,
                    ref=step.get("ref"),
                    pid=target_pid,
                    selector=step.get("selector"),
                    condition=str(step.get("condition", "exists")),
                    expected=step.get("expected"),
                    timeout_ms=int(step.get("timeout_ms", 5000)),
                    interval_ms=int(step.get("interval_ms", 100)),
                )
                result["op"] = op
                if not result["matched"] and step.get("required", True):
                    raise BridgeError("conflict", "UI_SEQUENCE_WAIT_FAILED: required wait_for step did not match")
            elif op == "assert":
                result = assert_condition(
                    workspace_id,
                    ref=step.get("ref"),
                    pid=target_pid,
                    selector=step.get("selector"),
                    condition=str(step.get("condition", "exists")),
                    expected=step.get("expected"),
                )
                result["op"] = op
            else:
                raise BridgeError("invalid_argument", "sequence op must be action|wait_for|assert|sleep")
        except BridgeError as exc:
            raise BridgeError(
                exc.code,
                f"desktop sequence failed at step {index} ({op or 'missing op'}); earlier steps may already have applied: {exc}",
            ) from exc
        results.append(result)

    out: dict[str, Any] = {
        "pid": target_pid,
        "completed": len(results),
        "steps": results,
    }
    if include_diff and before_state is not None:
        after_state = _snapshot_state(target_pid, max_elements=diff_max_elements)
        state_diff = _diff_state_maps(before_state["facts"], after_state["facts"])
        state_diff["before_visited"] = before_state["visited"]
        state_diff["after_visited"] = after_state["visited"]
        state_diff["snapshot_truncated"] = before_state["truncated"] or after_state["truncated"]
        out["state_diff"] = state_diff
    return out


def _condition_for(element, condition: str, expected: Any) -> bool:
    fields = _fields(element, include_value=True)
    if condition == "exists":
        return True
    if condition == "enabled":
        return fields.get("enabled") is (True if expected is None else bool(expected))
    if condition == "focused":
        return fields.get("focused") is (True if expected is None else bool(expected))
    if condition == "selected":
        return fields.get("selected") is (True if expected is None else bool(expected))
    if condition in ("title", "value", "identifier", "description", "role", "subrole", "url"):
        return fields.get(condition, "") == ("" if expected is None else expected)
    if condition.endswith("_contains") and condition[:-9] in ("title", "value", "description", "url"):
        key = condition[:-9]
        return str(expected or "").lower() in str(fields.get(key, "")).lower()
    raise BridgeError(
        "invalid_argument",
        "condition must be exists|gone|enabled|focused|selected|title|value|identifier|description|role|subrole|url|title_contains|value_contains|description_contains|url_contains",
    )


def wait_for(
    workspace_id: str,
    ref: str | None = None,
    pid: int | None = None,
    selector: dict[str, Any] | None = None,
    condition: str = "exists",
    expected: Any = None,
    timeout_ms: int = 5000,
    interval_ms: int = 100,
) -> dict[str, Any]:
    _gate(workspace_id)
    if not ref and not selector:
        raise BridgeError("invalid_argument", "wait_for requires ref or selector")
    timeout_ms = max(0, min(int(timeout_ms), 120_000))
    interval_ms = max(25, min(int(interval_ms), 5_000))
    deadline = time.monotonic() + timeout_ms / 1000
    checks = 0
    last_element = None
    target_pid = _target_pid(pid) if not ref else _parse_ref(ref)[0]

    while True:
        checks += 1
        element = None
        if ref:
            try:
                _, element = _resolve(ref)
            except BridgeError as exc:
                if condition != "gone" and not (exc.code == "conflict" and "UI_ELEMENT_STALE" in str(exc)):
                    raise
        else:
            root = AXUIElementCreateApplication(target_pid)
            visited = 0

            def find_first(node, depth: int = 0):
                nonlocal visited
                if visited >= 3000 or depth > 16:
                    return None
                visited += 1
                if _selector_matches(_fields(node, include_value=True), selector or {}):
                    return node
                for child in _children(node):
                    hit = find_first(child, depth + 1)
                    if hit is not None:
                        return hit
                return None

            element = find_first(root)
        last_element = element
        matched = (element is None) if condition == "gone" else (element is not None and _condition_for(element, condition, expected))
        if matched:
            return {
                "matched": True,
                "timed_out": False,
                "checks": checks,
                "pid": target_pid,
                "condition": condition,
                "element": _fields(element, include_value=True) if element is not None else None,
            }
        if time.monotonic() >= deadline:
            return {
                "matched": False,
                "timed_out": True,
                "checks": checks,
                "pid": target_pid,
                "condition": condition,
                "element": _fields(last_element, include_value=True) if last_element is not None else None,
            }
        time.sleep(interval_ms / 1000)


def assert_condition(
    workspace_id: str,
    ref: str | None = None,
    pid: int | None = None,
    selector: dict[str, Any] | None = None,
    condition: str = "exists",
    expected: Any = None,
) -> dict[str, Any]:
    result = wait_for(
        workspace_id,
        ref=ref,
        pid=pid,
        selector=selector,
        condition=condition,
        expected=expected,
        timeout_ms=0,
    )
    if not result["matched"]:
        raise BridgeError("conflict", "UI_ASSERTION_FAILED: requested UI condition did not match")
    return result


# Small pure helpers intentionally exported for unit tests.
fingerprint_fields = _fingerprint_from_fields
parse_ref = _parse_ref
selector_matches = _selector_matches
diff_state_maps = _diff_state_maps
