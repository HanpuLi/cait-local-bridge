"""Optional ~/.last_interaction activity marker: integer epoch seconds + newline."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from bridge import server


class LastInteractionTest(unittest.TestCase):
    def test_config_override_isolated(self):
        # Import config in a fresh interpreter. The full unit suite imports bridge.config
        # from several modules, so mutating os.environ after that import is not a valid test.
        state = Path(tempfile.mkdtemp(prefix="clb-li-test-"))
        marker = state / ".last_interaction"
        env = os.environ.copy()
        env["CLB_STATE_DIR"] = str(state)
        env["CLB_LAST_INTERACTION"] = str(marker)
        cp = subprocess.run(
            [
                sys.executable,
                "-c",
                "from bridge.config import LAST_INTERACTION; print(LAST_INTERACTION)",
            ],
            cwd=Path(__file__).resolve().parents[1],
            env=env,
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(Path(cp.stdout.strip()), marker)

    def test_format_monotonic_throttled(self):
        p = Path(tempfile.mkdtemp(prefix="clb-li-")) / ".last_interaction"
        server._LAST_TOUCH = 0.0
        self.assertTrue(server._touch_last_interaction(p, now=10_000))
        self.assertEqual(p.read_text(), "10000\n")
        self.assertFalse(server._touch_last_interaction(p, now=10_010))  # 30s throttle
        self.assertTrue(server._touch_last_interaction(p, now=10_100))
        self.assertEqual(int(p.read_text().strip()), 10_100)
        server._LAST_TOUCH = 0.0
        self.assertFalse(server._touch_last_interaction(p, now=9_000))  # monotonic
        self.assertEqual(int(p.read_text().strip()), 10_100)
        self.assertFalse((p.parent / ".last_interaction.bridge-tmp").exists())

    def test_unwritable_is_silent(self):
        server._LAST_TOUCH = 0.0
        self.assertFalse(
            server._touch_last_interaction(
                Path("/nonexistent-dir/x/.last_interaction"), now=10_000
            )
        )


if __name__ == "__main__":
    unittest.main()
