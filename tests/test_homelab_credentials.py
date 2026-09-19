from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bridge import homelab


class HomeLabCredentialTests(unittest.TestCase):
    def test_forgejo_uses_git_credential_helper_non_interactively(self) -> None:
        completed = subprocess.CompletedProcess(
            ["git", "credential", "fill"],
            0,
            "protocol=https\nhost=forgejo.example\nusername=alice\npassword=credential-value\n",
            "",
        )
        with patch.object(homelab, "_url", return_value="https://forgejo.example"), patch.object(
            homelab.subprocess, "run", return_value=completed
        ) as run:
            self.assertEqual(homelab._forgejo_token(), "credential-value")

        argv = run.call_args.args[0]
        env = run.call_args.kwargs["env"]
        self.assertEqual(argv, ["git", "credential", "fill"])
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(env["GCM_INTERACTIVE"], "Never")
        self.assertNotIn(".git-credentials", " ".join(argv))

    def test_paperless_keychain_metadata_never_contains_credential(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            meta = Path(td) / "paperless.json"
            legacy = Path(td) / "homelab.json"
            with patch.object(homelab, "_PAPERLESS_META", meta), patch.object(
                homelab, "_LEGACY_HOMELAB", legacy
            ), patch.object(homelab, "_keychain_password", return_value="credential-value"):
                homelab.write_paperless_metadata("token", "api-token")
                saved = json.loads(meta.read_text())
                self.assertEqual(saved, {"mode": "token", "account": "api-token"})
                self.assertNotIn("credential-value", meta.read_text())
                self.assertEqual(homelab._paperless_auth(), ("__token__", "credential-value"))
                self.assertEqual(homelab._paperless_storage(), "macOS Keychain")

    def test_password_mode_uses_account_as_username(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            meta = Path(td) / "paperless.json"
            legacy = Path(td) / "homelab.json"
            with patch.object(homelab, "_PAPERLESS_META", meta), patch.object(
                homelab, "_LEGACY_HOMELAB", legacy
            ), patch.object(homelab, "_keychain_password", return_value="credential-value"):
                homelab.write_paperless_metadata("password", "alice")
                self.assertEqual(homelab._paperless_auth(), ("alice", "credential-value"))

    def test_new_metadata_is_separate_from_legacy_cleartext_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            meta = Path(td) / "paperless.json"
            legacy = Path(td) / "homelab.json"
            legacy.write_text(json.dumps({"paperless": {"token": "legacy-value"}, "other": {"kept": True}}))
            with patch.object(homelab, "_PAPERLESS_META", meta), patch.object(
                homelab, "_LEGACY_HOMELAB", legacy
            ):
                homelab.write_paperless_metadata("token", "api-token")
                self.assertEqual(json.loads(meta.read_text()), {"mode": "token", "account": "api-token"})
                self.assertEqual(json.loads(legacy.read_text())["other"], {"kept": True})
                self.assertEqual(homelab.paperless_credential_metadata(), {"mode": "token", "account": "api-token"})

    def test_legacy_state_is_read_only_compatibility(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            meta = Path(td) / "paperless.json"
            legacy = Path(td) / "homelab.json"
            legacy.write_text(json.dumps({"paperless": {"token": "legacy-value"}}))
            with patch.object(homelab, "_PAPERLESS_META", meta), patch.object(
                homelab, "_LEGACY_HOMELAB", legacy
            ):
                self.assertEqual(homelab._paperless_auth(), ("__token__", "legacy-value"))
                self.assertIn("legacy clear-text", homelab._paperless_storage())

    def test_remove_metadata_unlinks_only_new_lookup_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            meta = Path(td) / "paperless.json"
            legacy = Path(td) / "homelab.json"
            meta.write_text(json.dumps({"mode": "token", "account": "api-token"}))
            legacy.write_text(json.dumps({"other": {"kept": True}}))
            with patch.object(homelab, "_PAPERLESS_META", meta), patch.object(
                homelab, "_LEGACY_HOMELAB", legacy
            ):
                homelab.remove_paperless_metadata()
                self.assertFalse(meta.exists())
                self.assertTrue(legacy.exists())


if __name__ == "__main__":
    unittest.main()
