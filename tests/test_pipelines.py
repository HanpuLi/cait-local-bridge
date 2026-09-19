"""agent_pipeline: validation, placeholder expansion, DAG scheduling with a fake sub-agent runner (no ChatGPT, no browser)."""
from __future__ import annotations
import asyncio, json, os, tempfile, unittest
from unittest.mock import patch
os.environ.setdefault("CLB_STATE_DIR", tempfile.mkdtemp(prefix="clb-pipe-test-"))
from bridge import agents, pipelines, db
from bridge.policy import BridgeError

unittest.addModuleCleanup(db.close_thread_connection)

WS = {"id": "ws_test", "root": tempfile.mkdtemp(prefix="clb-pipe-ws-"), "name": "t", "profiles": ["sandboxed"], "network": "off", "expires_at": None, "active": True}


class FakeRuns:
    """agents.start/info stand-in: every run finishes on the 2nd poll with the task_status scripted per stage title."""
    def __init__(self, verdicts): self.verdicts, self.runs, self.n = verdicts, {}, 0
    def start(self, ws, prompt, agent=None, effort="high", timeout=None, attach_bridge=True, title=None, keep_page=False, subject=None,
              dry_run=False, verification=None, raw=False, output_path=None, archive=None, browser_sites=None):
        self.n += 1; rid = f"agent_fake{self.n}"; sid = title.split()[-1]
        self.runs[rid] = {"polls": 0, "sid": sid, "prompt": prompt, "output_path": output_path, "sites": browser_sites}
        return {"run_id": rid}
    def info(self, rid):
        r = self.runs[rid]; r["polls"] += 1
        if r["polls"] < 2:
            return {"status": "running", "phase": "waiting", "tool_calls": 1, "conversation_url": "u"}
        ts = self.verdicts.get(r["sid"], "unverified")
        return {"status": "failed" if ts in ("blocked", "failed") else "completed", "task_status": ts, "error_code": None, "error": None,
                "conversation_url": "u", "upstream_blocks_observed": 1 if ts == "blocked" else 0}


SPEC = {"stages": [
    {"id": "cite", "prompt": "check citations"},
    {"id": "triage", "prompt": "sort mail"},
    {"id": "audit", "after": ["cite"], "prompt": "read {{cite.output}} then audit", "browser_sites": ["mail.google.com"]},
    {"id": "strategy", "after": ["cite", "audit"], "prompt": "read {{cite.output}} and {{audit.output}} in {{pipeline.dir}}"},
], "max_parallel": 2, "default_effort": "medium"}


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.p1 = patch.object(pipelines, "workspace_get", return_value=WS); self.p1.start()
        self.p2 = patch.object(pipelines, "POLL_S", 0.01); self.p2.start()
        self.p3 = patch.object(agents, "persona", return_value={}); self.p3.start()
    def tearDown(self):
        for p in (self.p1, self.p2, self.p3): p.stop()

    def test_validate_rejects_bad_specs(self):
        bad = [({"stages": []}, "non-empty"), ({"stages": [{"id": "A", "prompt": "x"}]}, "id matching"),
               ({"stages": [{"id": "a", "prompt": "x"}, {"id": "a", "prompt": "y"}]}, "unique"),
               ({"stages": [{"id": "a", "prompt": "x", "after": ["zz"]}]}, "existing stage ids"),
               ({"stages": [{"id": "a", "prompt": "{{b.output}}"}, {"id": "b", "prompt": "y"}]}, "does not list"),
               ({"stages": [{"id": "a", "prompt": "x", "after": ["b"]}, {"id": "b", "prompt": "y", "after": ["a"]}]}, "cycle"),
               ({"stages": [{"id": "a", "prompt": "x", "effort": "turbo"}]}, "bad effort"),
               ({"stages": [{"id": "a", "prompt": "x"}], "max_parallel": 99}, "max_parallel")]
        for spec, needle in bad:
            with self.assertRaises(BridgeError) as cm:
                pipelines.validate("ws_test", spec)
            self.assertIn(needle, cm.exception.message, spec)

    def test_dag_runs_in_order_passes_outputs_as_paths_and_skips_after_failure(self):
        fake = FakeRuns({"cite": "unverified", "triage": "blocked", "audit": "unverified", "strategy": "unverified"})
        async def go():
            with patch.object(agents, "start", fake.start), patch.object(agents, "info", fake.info):
                p = pipelines.start("ws_test", SPEC)
                pid = p["pipeline_id"]
                self.assertEqual(p["status"], "queued")
                await pipelines._tasks[pid]
                return pipelines.info(pid)
        out = asyncio.run(go())
        st = {s["id"]: s for s in out["stages"]}
        self.assertEqual(out["status"], "partial")                       # triage blocked -> not every stage passed
        self.assertEqual(st["triage"]["task_status"], "blocked")
        self.assertEqual(st["cite"]["status"], "completed")
        self.assertEqual(st["strategy"]["status"], "completed")
        d = out["output_dir"]; self.assertTrue(d.startswith("_pipeline/pipe_"))
        prompts = {r["sid"]: r["prompt"] for r in fake.runs.values()}
        self.assertIn(f"read {d}/cite.md then audit", prompts["audit"])          # path, not pasted text
        self.assertIn(f"{d}/cite.md and {d}/audit.md in {d}", prompts["strategy"])
        self.assertEqual({r["sid"]: r["output_path"] for r in fake.runs.values()}["audit"], f"{d}/audit.md")
        self.assertEqual([r["sites"] for r in fake.runs.values() if r["sid"] == "audit"], [["mail.google.com"]])
        self.assertTrue(os.path.exists(os.path.join(WS["root"], d, "summary.md")))
        self.assertEqual(db.one("SELECT kind FROM inbox ORDER BY id DESC LIMIT 1")["kind"], "pipeline_finished")

    def test_throttled_stage_is_requeued_once(self):
        fake = FakeRuns({"cite": "unverified"})
        orig = fake.info
        def info(rid):
            out = orig(rid)
            if rid == "agent_fake1" and out["status"] != "running":
                return {**out, "status": "failed", "error_code": "rate_limited", "error": "chatgpt.com: Too many requests"}
            return out
        async def go():
            with patch.object(agents, "start", fake.start), patch.object(agents, "info", info):
                pid = pipelines.start("ws_test", {"stages": [{"id": "cite", "prompt": "a"}]})["pipeline_id"]; await pipelines._tasks[pid]; return pipelines.info(pid)
        out = asyncio.run(go()); st = out["stages"][0]
        self.assertEqual((out["status"], st["status"], st["run_id"]), ("completed", "completed", "agent_fake2"))
        self.assertEqual(len(fake.runs), 2)

    def test_dependent_stage_is_skipped_when_upstream_blocked(self):
        fake = FakeRuns({"cite": "blocked"})
        spec = {"stages": [{"id": "cite", "prompt": "a"}, {"id": "audit", "after": ["cite"], "prompt": "b {{cite.output}}"}]}
        async def go():
            with patch.object(agents, "start", fake.start), patch.object(agents, "info", fake.info):
                pid = pipelines.start("ws_test", spec)["pipeline_id"]; await pipelines._tasks[pid]; return pipelines.info(pid)
        out = asyncio.run(go()); st = {s["id"]: s for s in out["stages"]}
        self.assertEqual((st["audit"]["status"], st["audit"]["error_code"]), ("skipped", "upstream_stage_failed"))
        self.assertEqual(len(fake.runs), 1)


if __name__ == "__main__":
    unittest.main()
