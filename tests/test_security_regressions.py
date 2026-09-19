from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("CLB_STATE_DIR", tempfile.mkdtemp(prefix="clb-security-test-"))
from bridge import desktop


class _FakeApp:
    def __init__(self, name: str, terminate_result: bool = True):
        self._name = name
        self._terminate_result = terminate_result
        self.terminated = False

    def localizedName(self):
        return self._name

    def terminate(self):
        self.terminated = True
        return self._terminate_result


class _FakeWorkspace:
    def __init__(self, apps):
        self._apps = apps

    def runningApplications(self):
        return self._apps

    def frontmostApplication(self):
        return None


class DesktopSecurityRegressionTests(unittest.TestCase):
    def test_quit_treats_application_name_as_data_not_applescript(self):
        injected_name = 'Example" & do shell script "touch /tmp/should-not-exist" & "'
        app = _FakeApp(injected_name)
        workspace = _FakeWorkspace([app])
        with patch.object(desktop, "_gate"), \
             patch.object(desktop, "_workspace", return_value=workspace), \
             patch.object(desktop.subprocess, "run") as subprocess_run:
            result = desktop.app("ws_test", "quit", name=injected_name)
        self.assertTrue(app.terminated)
        subprocess_run.assert_not_called()
        self.assertEqual(result["name"], injected_name)

    def test_quit_reports_os_refusal(self):
        app = _FakeApp("Refuses", terminate_result=False)
        workspace = _FakeWorkspace([app])
        with patch.object(desktop, "_gate"), \
             patch.object(desktop, "_workspace", return_value=workspace):
            with self.assertRaisesRegex(Exception, "refused to terminate"):
                desktop.app("ws_test", "quit", name="Refuses")


class SandboxProfileRegressionTests(unittest.TestCase):
    def test_workspace_home_carveout_follows_control_plane_deny(self):
        from bridge import jobs

        profile = jobs.seatbelt_profile("/tmp/clb-workspace", str(jobs.STATE_DIR / "wshome" / "ws_test"), "off", "ws_test")
        deny = profile.index(f'(deny file-write* (subpath "{jobs.STATE_DIR}")')
        carveout = profile.index(f'(allow file-write* (subpath "{jobs.STATE_DIR / "wshome" / "ws_test"}"))')
        self.assertGreater(carveout, deny)


class StdioAuthRegressionTests(unittest.TestCase):
    def test_http_mode_does_not_accept_missing_token(self):
        from bridge import server
        old = server.LOCAL_STDIO
        try:
            server.LOCAL_STDIO = False
            with patch.object(server, "get_access_token", return_value=None):
                with self.assertRaisesRegex(Exception, "no authenticated operator token"):
                    server._subject()
        finally:
            server.LOCAL_STDIO = old

    def test_local_stdio_mode_has_explicit_local_subject(self):
        from bridge import server
        old = server.LOCAL_STDIO
        try:
            server.LOCAL_STDIO = True
            with patch.object(server, "get_access_token", return_value=None):
                self.assertEqual(server._subject(), server.CFG["user_subject"])
        finally:
            server.LOCAL_STDIO = old


if __name__ == "__main__":
    unittest.main()
