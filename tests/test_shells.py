import unittest
from bridge import shells


class ShellPureTests(unittest.TestCase):
    def test_marker_parse(self):
        self.assertEqual(
            shells.parse_done_marker("\x1eCLB_DONE:abc123:7:L3RtcA==\x1e"),
            ("abc123", "7", "L3RtcA=="),
        )

    def test_shell_id_validation(self):
        self.assertEqual(shells._validate_id("build-1.ok"), "build-1.ok")
        with self.assertRaises(Exception):
            shells._validate_id("../bad")


if __name__ == "__main__":
    unittest.main()
