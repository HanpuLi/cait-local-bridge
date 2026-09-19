"""file_edit / retry-safe writes / repo_outline / coding_task loop — the pieces that make one ChatGPT turn do what a Codex turn does.
No ChatGPT, no browser: the sub-agent is faked (it edits the worktree like a model would), the test command and git are real."""
from __future__ import annotations
import asyncio, json, os, subprocess, tempfile, textwrap, unittest
from pathlib import Path
from unittest.mock import patch
os.environ.setdefault("CLB_STATE_DIR", tempfile.mkdtemp(prefix="clb-coding-test-"))
from bridge import files, outline, coding, agents, jobs, policy, db
from bridge.policy import BridgeError

unittest.addModuleCleanup(db.close_thread_connection)

ROOT = Path(tempfile.mkdtemp(prefix="clb-coding-ws-")).resolve()
WS = {"id": "ws_ct", "root": str(ROOT), "name": "t", "profiles": ["sandboxed", "trusted-host"], "network": "off", "expires_at": None, "active": True, "revoked": 0}


def git(*a, cwd=ROOT):
    return subprocess.run(["git", *a], cwd=cwd, capture_output=True, text=True, check=True, env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"})


class FileToolTests(unittest.TestCase):
    def setUp(self):
        self.ps = [patch.object(m, "workspace_get", return_value=WS) for m in (files, outline)]
        for p in self.ps: p.start()
        (ROOT / "a.py").write_text("def f():\n    return 1\n\ndef g():\n    return 1\n")
    def tearDown(self):
        for p in self.ps: p.stop()

    def test_edit_unique_match_and_retry(self):
        r = files.edit("ws_ct", "a.py", "def f():\n    return 1", "def f():\n    return 2")
        self.assertTrue(r["applied"]); self.assertEqual(r["first_line"], 1); self.assertIn("-    return 1\n+    return 2", r["diff"])
        self.assertEqual((ROOT / "a.py").read_text().count("return 2"), 1)
        again = files.edit("ws_ct", "a.py", "def f():\n    return 1", "def f():\n    return 2")   # verbatim resend after an upstream drop
        self.assertFalse(again["applied"]); self.assertTrue(again["already_applied"])

    def test_edit_ambiguous_missing_and_stale(self):
        with self.assertRaises(BridgeError) as cm:
            files.edit("ws_ct", "a.py", "    return 1", "    return 3")
        self.assertIn("occurs 2 times", cm.exception.message)
        r = files.edit("ws_ct", "a.py", "    return 1", "    return 3", replace_all=True)
        self.assertEqual(r["replacements"], 2)
        with self.assertRaises(BridgeError) as cm:
            files.edit("ws_ct", "a.py", "nope", "x")
        self.assertEqual(cm.exception.code, "conflict")
        with self.assertRaises(BridgeError):
            files.edit("ws_ct", "a.py", "return 3", "return 4", expected_sha256="0" * 64)

    def test_write_and_patch_are_retry_safe(self):
        sha = files.read("ws_ct", "a.py")["sha256"]
        r = files.write("ws_ct", "a.py", "x = 1\n", expected_sha256=sha)
        again = files.write("ws_ct", "a.py", "x = 1\n", expected_sha256=sha)   # same content, stale sha: no-op instead of conflict
        self.assertTrue(again["already_applied"]); self.assertEqual(again["sha256"], r["sha256"])
        diff = "--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n"
        self.assertTrue(files.apply_patch("ws_ct", diff)["applied"])
        second = files.apply_patch("ws_ct", diff)
        self.assertTrue(second["ok"]); self.assertFalse(second["applied"]); self.assertTrue(second["already_applied"])
        bad = files.apply_patch("ws_ct", diff.replace("-x = 1", "-x = 9").replace("+x = 2", "+x = 7"))   # neither side matches the file
        self.assertEqual(bad.get("error"), "patch_rejected")

    def test_outline_walk_and_git(self):
        (ROOT / "pkg").mkdir(exist_ok=True); (ROOT / "pkg" / "m.ts").write_text("export class K {}\nexport const h = async (x) => x\nfunction z() {}\n")
        (ROOT / "tests").mkdir(exist_ok=True); (ROOT / "tests" / "test_a.py").write_text("def test_x(): pass\n")
        o = outline.outline("ws_ct")
        self.assertEqual(o["source"], "walk")
        by = {f["path"]: f for f in o["files"]}
        self.assertEqual([s["name"] for s in by["a.py"]["symbols"]], ["f", "g"])
        self.assertEqual([s["name"] for s in by["pkg/m.ts"]["symbols"]], ["K", "h", "z"])
        self.assertTrue(by["tests/test_a.py"]["test"]); self.assertIn("tests/test_a.py", o["test_files"])


class CodingTaskTests(unittest.TestCase):
    """A real git repo with a failing test; the fake sub-agent fixes the code in round 2 (round 1 leaves it broken), the bridge verifies."""
    def setUp(self):
        self.repo = ROOT / f"proj_{self._testMethodName}"; self.repo.mkdir(exist_ok=True); self.rel = self.repo.name
        (self.repo / "calc.py").write_text("def add(a, b):\n    return a - b\n")
        (self.repo / "test_calc.py").write_text("import calc\nassert calc.add(2, 3) == 5\nprint('ok')\n")
        git("init", "-q", cwd=self.repo); git("-c", "user.name=t", "-c", "user.email=t@t", "add", "-A", cwd=self.repo)
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init", cwd=self.repo)
        self.ps = [patch.object(m, "workspace_get", return_value=WS) for m in (coding, jobs, policy)] + [patch.object(coding, "POLL_S", 0.01)]
        for p in self.ps: p.start()
        self.runs = {}
        me = self
        def fake_start(ws, prompt, agent=None, effort="high", timeout=None, subject=None, title=None, output_path=None, browser_sites=None, **kw):
            rid = f"agent_fake{len(me.runs) + 1}"; rnd = len(me.runs) + 1
            me.runs[rid] = {"polls": 0, "prompt": prompt, "round": rnd}
            wt = ROOT / prompt.split("`")[1]          # the prompt names the worktree; the fake agent edits there like a model would
            if rnd == 1:
                (wt / "calc.py").write_text("def add(a, b):\n    return a + b + 1\n")   # still wrong
                (wt / "test_calc.py").write_text("print('ok')\n")                     # and it tampers with the test — must be reverted
            else:
                (wt / "calc.py").write_text("def add(a, b):\n    return a + b\n")
            (ROOT / output_path).write_text(f"round {rnd} done\nCLB_TASK_STATUS=done\n")
            return {"run_id": rid}
        def fake_info(rid):
            r = me.runs[rid]; r["polls"] += 1
            if r["polls"] < 2:
                return {"status": "running", "phase": "waiting", "tool_calls": 3}
            return {"status": "completed", "task_status": "unverified", "tool_calls": 7, "upstream_blocks_observed": 0, "conversation_url": f"https://chatgpt.com/c/{rid}"}
        self.ps += [patch.object(agents, "start", side_effect=fake_start), patch.object(agents, "info", side_effect=fake_info)]
        for p in self.ps[-2:]: p.start()
    def tearDown(self):
        for p in self.ps: p.stop()

    def test_loop_verifies_on_round_two_and_commits_on_branch(self):
        async def go():
            t = coding.start("ws_ct", "make add() actually add", repo_path=self.rel, test_command="python3 test_calc.py", max_rounds=3, profile="trusted-host", test_timeout_seconds=60, protected_paths=["test_calc.py"])
            while coding.info(t["task_id"])["status"] in coding.STATUS_ACTIVE:
                await asyncio.sleep(0.05)
            return coding.info(t["task_id"])
        t = asyncio.run(go())
        self.assertEqual(t["status"], "verified", t)
        self.assertEqual(t["baseline"]["exit_code"], 1)
        self.assertEqual([r["test_exit"] for r in t["rounds"]], [1, 0])
        self.assertEqual(t["rounds"][0].get("protected_reverted"), ["test_calc.py"]); self.assertIsNone(t["rounds"][1].get("protected_reverted"))
        self.assertIn("round1-test.log", self.runs["agent_fake2"]["prompt"])     # round 2 was told where the failure log is
        self.assertTrue(t["branch"].startswith("clb/make-add-actually-add-"))
        # user's checkout untouched; the fix lives on the task branch
        self.assertIn("return a - b", (self.repo / "calc.py").read_text())
        self.assertEqual(git("rev-parse", "--abbrev-ref", "HEAD", cwd=self.repo).stdout.strip(), "master" if "master" in git("branch", cwd=self.repo).stdout else git("rev-parse", "--abbrev-ref", "HEAD", cwd=self.repo).stdout.strip())
        shown = git("show", f"{t['branch']}:calc.py", cwd=self.repo).stdout
        self.assertIn("return a + b\n", shown)
        self.assertIn("calc.py", t["diffstat"])
        self.assertEqual(t["metrics"]["rounds"], 2); self.assertEqual(t["metrics"]["agent_tool_calls"], 14)
        self.assertTrue((ROOT / t["summary_path"]).exists()); self.assertTrue((ROOT / t["task_dir"] / "diff.patch").read_text().count("+    return a + b"))
        self.assertIn("/.clb/", (self.repo / ".git" / "info" / "exclude").read_text())
        self.assertEqual(git("status", "--porcelain", cwd=self.repo).stdout.strip(), "")   # .clb is excluded from the user's status

    def test_rejects_non_repo_and_bad_args(self):
        (ROOT / "plain").mkdir(exist_ok=True)
        async def go():
            with self.assertRaises(BridgeError) as cm:
                coding.start("ws_ct", "x", repo_path="plain")
            self.assertIn("not inside a git repository", cm.exception.message)
            with self.assertRaises(BridgeError):
                coding.start("ws_ct", "x", repo_path=self.rel, max_rounds=99)
            with self.assertRaises(BridgeError):
                coding.start("ws_ct", "x", repo_path=self.rel, profile="nope")
        asyncio.run(go())


if __name__ == "__main__":
    unittest.main()
