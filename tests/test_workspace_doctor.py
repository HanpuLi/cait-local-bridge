from __future__ import annotations

import argparse
import io
import json
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from bridge import policy
from bridge.public_cli import _workspace_doctor


def row(root: Path, *, revoked: int = 0, expires_at: float | None = None) -> dict:
    return {
        "id": "ws_test",
        "name": "test",
        "root": str(root),
        "profiles": json.dumps(["sandboxed", "trusted-host"]),
        "network": "off",
        "expires_at": expires_at,
        "revoked": revoked,
        "created_at": 1.0,
        "notes": "",
    }


class WorkspaceDoctorPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="scoperail-doctor-")
        self.root = Path(self.tmp.name).resolve()
        (self.root / "inside").mkdir()
        (self.root / "inside" / "file.txt").write_text("ok\n")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_active_workspace_by_id_and_path(self) -> None:
        with patch.object(policy.db, "one", return_value=row(self.root)) as one:
            result = policy.workspace_doctor("ws_test", "inside/file.txt")

        one.assert_called_with("SELECT * FROM workspaces WHERE id=?", "ws_test")
        self.assertEqual(result["workspace"]["state"], "active")
        self.assertTrue(result["workspace"]["active"])
        self.assertTrue(result["workspace"]["root_available"])
        self.assertEqual(result["workspace"]["profiles"], ["sandboxed", "trusted-host"])
        self.assertTrue(result["path"]["allowed"])
        self.assertTrue(result["path"]["exists"])

    def test_registered_root_identifier_is_canonicalised(self) -> None:
        with patch.object(policy.db, "one", return_value=row(self.root)) as one:
            result = policy.workspace_doctor(str(self.root / "."))

        one.assert_called_with("SELECT * FROM workspaces WHERE root=?", str(self.root))
        self.assertEqual(result["workspace"]["id"], "ws_test")

    def test_revoked_expired_and_missing_root_states(self) -> None:
        cases = [
            (row(self.root, revoked=1), "revoked"),
            (row(self.root, expires_at=time.time() - 10), "expired"),
        ]
        for workspace_row, expected in cases:
            with self.subTest(expected=expected), patch.object(policy.db, "one", return_value=workspace_row):
                result = policy.workspace_doctor("ws_test")
                self.assertEqual(result["workspace"]["state"], expected)
                self.assertFalse(result["workspace"]["active"])

        missing = self.root / "missing-root"
        with patch.object(policy.db, "one", return_value=row(missing)):
            result = policy.workspace_doctor("ws_test", "new.txt")
        self.assertEqual(result["workspace"]["state"], "offline")
        self.assertFalse(result["workspace"]["root_available"])
        self.assertEqual(result["path"]["error"], "offline")

    def test_path_rejections_are_machine_readable_and_do_not_leak_symlink_target(self) -> None:
        with tempfile.TemporaryDirectory(prefix="scoperail-doctor-outside-") as td:
            outside = Path(td).resolve()
            (self.root / "escape").symlink_to(outside, target_is_directory=True)
            with patch.object(policy.db, "one", return_value=row(self.root)):
                traversal = policy.workspace_doctor("ws_test", "../outside")
                symlink = policy.workspace_doctor("ws_test", "escape/new.txt")

        self.assertFalse(traversal["path"]["allowed"])
        self.assertEqual(traversal["path"]["error"], "permission_denied")
        self.assertFalse(symlink["path"]["allowed"])
        self.assertEqual(symlink["path"]["error"], "permission_denied")
        self.assertNotIn(str(outside), symlink["path"]["message"])
        self.assertNotIn("resolved", symlink["path"])

    def test_unknown_workspace_is_stable_not_found(self) -> None:
        with patch.object(policy.db, "one", return_value=None):
            with self.assertRaises(policy.BridgeError) as ctx:
                policy.workspace_doctor("ws_missing")
        self.assertEqual(ctx.exception.code, "not_found")


class WorkspaceDoctorCliTests(unittest.TestCase):
    def sample(self) -> dict:
        return {
            "workspace": {
                "id": "ws_test",
                "name": "demo",
                "root": "/tmp/demo",
                "profiles": ["sandboxed"],
                "network": "off",
                "expires_at": None,
                "revoked": False,
                "expired": False,
                "root_available": True,
                "active": True,
                "state": "active",
            },
            "path": {
                "input": "src/new.py",
                "allowed": True,
                "resolved": "/tmp/demo/src/new.py",
                "exists": False,
            },
        }

    def test_human_output_is_concise(self) -> None:
        args = argparse.Namespace(workspace="ws_test", path="src/new.py", json=False)
        with patch.object(policy, "workspace_doctor", return_value=self.sample()):
            buf = io.StringIO()
            with redirect_stdout(buf):
                _workspace_doctor(args)
        text = buf.getvalue()
        self.assertIn("workspace ws_test (demo)", text)
        self.assertIn("state: active", text)
        self.assertIn("path: allowed (new path)", text)

    def test_json_output_preserves_machine_schema(self) -> None:
        args = argparse.Namespace(workspace="ws_test", path=None, json=True)
        sample = self.sample()
        sample.pop("path")
        with patch.object(policy, "workspace_doctor", return_value=sample):
            buf = io.StringIO()
            with redirect_stdout(buf):
                _workspace_doctor(args)
        self.assertEqual(json.loads(buf.getvalue()), sample)

    def test_json_error_is_stable_and_non_traceback(self) -> None:
        args = argparse.Namespace(workspace="ws_missing", path=None, json=True)
        err = policy.BridgeError("not_found", "unknown workspace ws_missing")
        with patch.object(policy, "workspace_doctor", side_effect=err):
            buf = io.StringIO()
            with redirect_stdout(buf), self.assertRaises(SystemExit) as ctx:
                _workspace_doctor(args)
        self.assertEqual(ctx.exception.code, 2)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["error"], "not_found")
        self.assertFalse(payload["ok"])


if __name__ == "__main__":
    unittest.main()
