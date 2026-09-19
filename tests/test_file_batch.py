from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bridge import files
from bridge.policy import BridgeError, sha256_file


class BatchWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="scoperail-batch-")
        self.root = Path(self.tmp.name).resolve()
        self.ws = {
            "id": "ws_batch",
            "root": str(self.root),
            "name": "batch",
            "profiles": ["sandboxed"],
            "network": "off",
            "expires_at": None,
            "revoked": 0,
        }
        (self.root / "a.txt").write_text("A0\n")
        (self.root / "b.txt").write_text("B0\n")
        self.workspace_patch = patch.object(files, "workspace_get", return_value=self.ws)
        self.audit_patch = patch.object(files.db, "audit")
        self.workspace_patch.start()
        self.audit = self.audit_patch.start()

    def tearDown(self) -> None:
        self.audit_patch.stop()
        self.workspace_patch.stop()
        self.tmp.cleanup()

    def sha(self, name: str) -> str:
        return sha256_file(self.root / name)

    def test_updates_two_files_after_all_preconditions_validate(self) -> None:
        a0, b0 = self.sha("a.txt"), self.sha("b.txt")
        result = files.write_batch(
            "ws_batch",
            [
                {"path": "a.txt", "content": "A1\n", "expected_sha256": a0},
                {"path": "b.txt", "content": "B1\n", "expected_sha256": b0},
            ],
            subject="tester",
        )
        self.assertTrue(result["applied"])
        self.assertEqual(result["applied_count"], 2)
        self.assertEqual((self.root / "a.txt").read_text(), "A1\n")
        self.assertEqual((self.root / "b.txt").read_text(), "B1\n")
        self.audit.assert_called_once_with(
            "file_write_batch", "count=2 applied=2", subject="tester", workspace_id="ws_batch"
        )

    def test_create_update_mix_and_verbatim_retry_are_safe(self) -> None:
        a0 = self.sha("a.txt")
        mutations = [
            {"path": "a.txt", "content": "A1\n", "expected_sha256": a0},
            {"path": "new.txt", "content": "NEW\n", "expected_sha256": "new"},
        ]
        first = files.write_batch("ws_batch", mutations)
        self.assertTrue(first["applied"])
        self.assertEqual((self.root / "new.txt").read_text(), "NEW\n")

        second = files.write_batch("ws_batch", mutations)
        self.assertFalse(second["applied"])
        self.assertTrue(second["already_applied"])
        self.assertEqual(second["applied_count"], 0)

    def test_partial_retry_applies_only_remaining_original_state(self) -> None:
        a0, b0 = self.sha("a.txt"), self.sha("b.txt")
        (self.root / "a.txt").write_text("A1\n")
        result = files.write_batch(
            "ws_batch",
            [
                {"path": "a.txt", "content": "A1\n", "expected_sha256": a0},
                {"path": "b.txt", "content": "B1\n", "expected_sha256": b0},
            ],
        )
        self.assertEqual(result["applied_count"], 1)
        by_path = {item["path"]: item for item in result["files"]}
        self.assertTrue(by_path["a.txt"]["already_applied"])
        self.assertFalse(by_path["b.txt"]["already_applied"])
        self.assertEqual((self.root / "b.txt").read_text(), "B1\n")

    def test_stale_precondition_changes_nothing(self) -> None:
        before_a = (self.root / "a.txt").read_bytes()
        before_b = (self.root / "b.txt").read_bytes()
        with self.assertRaises(BridgeError) as ctx:
            files.write_batch(
                "ws_batch",
                [
                    {"path": "a.txt", "content": "A1\n", "expected_sha256": self.sha("a.txt")},
                    {"path": "b.txt", "content": "B1\n", "expected_sha256": "0" * 64},
                ],
            )
        self.assertEqual(ctx.exception.code, "conflict")
        self.assertEqual((self.root / "a.txt").read_bytes(), before_a)
        self.assertEqual((self.root / "b.txt").read_bytes(), before_b)

    def test_duplicate_normalized_targets_are_rejected(self) -> None:
        a0 = self.sha("a.txt")
        with self.assertRaises(BridgeError) as ctx:
            files.write_batch(
                "ws_batch",
                [
                    {"path": "a.txt", "content": "one", "expected_sha256": a0},
                    {"path": "./a.txt", "content": "two", "expected_sha256": a0},
                ],
            )
        self.assertEqual(ctx.exception.code, "invalid_argument")

    def test_symlink_escape_is_rejected_before_staging(self) -> None:
        with tempfile.TemporaryDirectory(prefix="scoperail-outside-") as td:
            outside = Path(td).resolve()
            (self.root / "escape").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(BridgeError) as ctx:
                files.write_batch("ws_batch", [{"path": "escape/new.txt", "content": "no"}])
        self.assertEqual(ctx.exception.code, "permission_denied")

    def test_existing_symlink_target_is_rejected_even_when_it_points_inside(self) -> None:
        (self.root / "link.txt").symlink_to(self.root / "a.txt")
        with self.assertRaises(BridgeError) as ctx:
            files.write_batch("ws_batch", [{"path": "link.txt", "content": "replacement"}])
        self.assertEqual(ctx.exception.code, "permission_denied")
        self.assertTrue((self.root / "link.txt").is_symlink())

    def test_staging_failure_leaves_all_targets_unchanged(self) -> None:
        a0, b0 = self.sha("a.txt"), self.sha("b.txt")

        def fail(phase: str, index: int) -> None:
            if phase == "staged" and index == 0:
                raise RuntimeError("injected staging failure")

        with self.assertRaises(BridgeError) as ctx:
            files.write_batch(
                "ws_batch",
                [
                    {"path": "a.txt", "content": "A1\n", "expected_sha256": a0},
                    {"path": "b.txt", "content": "B1\n", "expected_sha256": b0},
                ],
                _failure_hook=fail,
            )
        self.assertEqual(ctx.exception.code, "internal")
        self.assertEqual((self.root / "a.txt").read_text(), "A0\n")
        self.assertEqual((self.root / "b.txt").read_text(), "B0\n")
        self.assertEqual(list(self.root.glob(".scoperail-batch-*.tmp")), [])

    def test_commit_failure_rolls_back_committed_prefix(self) -> None:
        a0, b0 = self.sha("a.txt"), self.sha("b.txt")

        def fail(phase: str, index: int) -> None:
            if phase == "after_commit" and index == 0:
                raise RuntimeError("injected commit failure")

        with self.assertRaises(BridgeError) as ctx:
            files.write_batch(
                "ws_batch",
                [
                    {"path": "a.txt", "content": "A1\n", "expected_sha256": a0},
                    {"path": "b.txt", "content": "B1\n", "expected_sha256": b0},
                ],
                _failure_hook=fail,
            )
        self.assertEqual(ctx.exception.code, "internal")
        self.assertTrue(ctx.exception.extra["rollback_ok"])
        self.assertEqual((self.root / "a.txt").read_text(), "A0\n")
        self.assertEqual((self.root / "b.txt").read_text(), "B0\n")
        self.assertEqual(list(self.root.glob(".scoperail-batch-*.tmp")), [])

    def test_create_is_removed_during_commit_rollback(self) -> None:
        a0 = self.sha("a.txt")

        def fail(phase: str, index: int) -> None:
            if phase == "after_commit" and index == 0:
                raise RuntimeError("injected commit failure")

        with self.assertRaises(BridgeError):
            files.write_batch(
                "ws_batch",
                [
                    {"path": "new.txt", "content": "NEW\n", "expected_sha256": "new"},
                    {"path": "a.txt", "content": "A1\n", "expected_sha256": a0},
                ],
                _failure_hook=fail,
            )
        self.assertFalse((self.root / "new.txt").exists())
        self.assertEqual((self.root / "a.txt").read_text(), "A0\n")

    def test_base64_payload_and_missing_parent_policy(self) -> None:
        payload = base64.b64encode(b"\x00\x01binary").decode()
        result = files.write_batch(
            "ws_batch",
            [{"path": "binary.dat", "content": payload, "base64_content": True, "expected_sha256": "new"}],
        )
        self.assertTrue(result["applied"])
        self.assertEqual((self.root / "binary.dat").read_bytes(), b"\x00\x01binary")

        with self.assertRaises(BridgeError) as ctx:
            files.write_batch("ws_batch", [{"path": "missing/child.txt", "content": "x"}])
        self.assertEqual(ctx.exception.code, "invalid_argument")


if __name__ == "__main__":
    unittest.main()
