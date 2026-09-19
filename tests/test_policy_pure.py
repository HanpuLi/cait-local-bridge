from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from bridge.policy import BridgeError, host_is_private, resolve_in_workspace


class WorkspacePathPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="clb-policy-")
        self.root = Path(self.tmp.name).resolve()
        self.ws = {"id": "ws_test", "root": str(self.root)}
        (self.root / "inside").mkdir()
        (self.root / "inside" / "file.txt").write_text("ok\n")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_normal_path_stays_in_workspace(self) -> None:
        self.assertEqual(
            resolve_in_workspace(self.ws, "inside/file.txt"),
            self.root / "inside" / "file.txt",
        )

    def test_parent_and_absolute_escape_fail_closed(self) -> None:
        with self.assertRaises(BridgeError):
            resolve_in_workspace(self.ws, "../outside", must_exist=False)
        with self.assertRaises(BridgeError):
            resolve_in_workspace(self.ws, "/tmp", must_exist=False)

    def test_symlink_escape_is_rejected_for_existing_and_new_children(self) -> None:
        with tempfile.TemporaryDirectory(prefix="clb-policy-outside-") as td:
            outside = Path(td).resolve()
            (outside / "secret.txt").write_text("no\n")
            (self.root / "escape").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(BridgeError):
                resolve_in_workspace(self.ws, "escape/secret.txt")
            with self.assertRaises(BridgeError):
                resolve_in_workspace(self.ws, "escape/new.txt", must_exist=False)

    def test_nested_symlink_components_cannot_escape(self) -> None:
        with tempfile.TemporaryDirectory(prefix="clb-policy-outside-") as td:
            outside = Path(td).resolve()
            (outside / "secret").mkdir()
            (self.root / "inside" / "hop").symlink_to(outside / "secret", target_is_directory=True)
            with self.assertRaises(BridgeError):
                resolve_in_workspace(self.ws, "inside/hop/new.txt", must_exist=False)

    def test_broken_symlink_parent_escape_is_rejected_for_proposed_child(self) -> None:
        with tempfile.TemporaryDirectory(prefix="clb-policy-outside-") as td:
            outside = Path(td).resolve()
            missing_outside = outside / "not-created"
            (self.root / "broken").symlink_to(missing_outside, target_is_directory=True)
            self.assertFalse((self.root / "broken").exists())
            self.assertTrue((self.root / "broken").is_symlink())
            with self.assertRaises(BridgeError):
                resolve_in_workspace(self.ws, "broken/new.txt", must_exist=False)

    def test_workspace_root_aliases_and_normalization(self) -> None:
        self.assertEqual(resolve_in_workspace(self.ws, "."), self.root)
        self.assertEqual(resolve_in_workspace(self.ws, ""), self.root)
        self.assertEqual(resolve_in_workspace(self.ws, "./inside/file.txt"), self.root / "inside" / "file.txt")
        self.assertEqual(resolve_in_workspace(self.ws, str(self.root)), self.root)

    def test_control_characters_are_rejected(self) -> None:
        for rel in ("inside/evil\x00name", "inside/evil\nname", "inside/evil\tname", "inside/evil\x7fname", "inside/evil\x85name"):
            with self.subTest(path=repr(rel)):
                with self.assertRaises(BridgeError) as ctx:
                    resolve_in_workspace(self.ws, rel, must_exist=False)
                self.assertEqual(ctx.exception.code, "invalid_argument")

    def test_root_operation_can_be_disallowed(self) -> None:
        for rel in (".", "", str(self.root)):
            with self.subTest(path=rel):
                with self.assertRaises(BridgeError) as ctx:
                    resolve_in_workspace(self.ws, rel, allow_root=False)
                self.assertEqual(ctx.exception.code, "invalid_argument")

    def test_normalized_parent_component_remains_fail_closed(self) -> None:
        with self.assertRaises(BridgeError):
            resolve_in_workspace(self.ws, "inside/../inside/file.txt")


class NetworkPolicyTests(unittest.TestCase):
    def test_private_literal_and_named_hosts_are_blocked(self) -> None:
        for host in ("localhost", "127.0.0.1", "10.0.0.1", "100.64.0.1", "host.local", "node.ts.net", "::1"):
            with self.subTest(host=host):
                self.assertTrue(host_is_private(host))

    def test_public_ip_literal_is_not_private(self) -> None:
        self.assertFalse(host_is_private("8.8.8.8"))


if __name__ == "__main__":
    unittest.main()
