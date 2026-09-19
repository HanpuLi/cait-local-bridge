"""Offline regression tests. Isolated state; no browser/model, credentials or live DB."""
from __future__ import annotations
import atexit
import asyncio
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, patch

# Set BEFORE importing bridge modules: never open the production control plane.
# unittest discovery imports all modules before running any of them, so this
# directory must survive until process exit rather than one module's cleanup.
_STATE = tempfile.mkdtemp(prefix="clb-outcome-tests-")
atexit.register(shutil.rmtree, _STATE, True)
os.environ["CLB_STATE_DIR"] = _STATE
from bridge import agent_outcomes as ao
from bridge import agents, db, jobs, server
from bridge.config import JOBS_DIR
from bridge.policy import BridgeError

unittest.addModuleCleanup(db.close_thread_connection)

BLOCK = "This tool call was blocked by OpenAI because we couldn't determine the safety status of the request."


def message(role, text, **kw):
    return {"id": "m", "role": role, "text": text, "ct": "text", "recipient": "all", "channel": None,
            "end_turn": role == "assistant", "status": "finished_successfully", "ts": time.time(), **kw}


def transcript(*messages):
    return ao.digest({"msgs": list(messages), "model": "fixture"}, -1)


def envelope(request_id="req_test", **kw):
    return {"ok": True, "request_id": request_id, "job_id": "job_test",
            "provenance": {"host_id": agents.CFG["host_id"], "workspace_id": "ws_test"}, **kw}


class DigestTests(unittest.TestCase):
    def test_platform_block_is_not_success(self):
        d = transcript(message("tool", BLOCK), message("assistant", "Could not execute."))
        out = ao.outcome(d)
        self.assertEqual((out["status"], out["task_status"], out["error_code"]), ("failed", "blocked", "upstream_safety_blocked"))
        self.assertEqual(out["error"], BLOCK)

    def test_observed_block_detected_before_final(self):
        d = transcript(message("tool", BLOCK))
        self.assertEqual(ao.outcome(d)["error_code"], "upstream_safety_blocked")

    def test_self_report_is_not_platform_evidence(self):
        d = transcript(message("assistant", "No output.\nCLB_TASK_STATUS=blocked"))
        self.assertEqual(ao.outcome(d)["evidence_source"], "assistant_report")
        self.assertEqual(ao.outcome(d)["error_code"], "reported_safety_blocked")

    def test_legacy_result_reclassified_without_mutation(self):
        old = {"final_text": "RESULT=C:<exec_start 被安全检查阻止，未产生 stdout>"}
        original = json.dumps(old)
        self.assertEqual(ao.legacy_outcome(old)["task_status"], "blocked")
        self.assertEqual(json.dumps(old), original)

    def test_completion_does_not_prove_success(self):
        out = ao.outcome(transcript(message("assistant", "Done.")))
        self.assertEqual((out["status"], out["task_status"]), ("completed", "unverified"))

    def test_prompt_quoted_error_is_not_a_block(self):
        out = ao.outcome(transcript(message("user", BLOCK), message("assistant", "The quoted error was diagnosed.")))
        self.assertIsNone(out["error_code"])

    def test_successful_file_containing_error_is_not_a_block(self):
        env = envelope(data={"text": BLOCK})
        out = ao.outcome(transcript(message("tool", json.dumps(env)), message("assistant", "Read the test fixture.")))
        self.assertIsNone(out["error_code"])

    def test_marker_in_code_block_is_not_executed(self):
        d = transcript(message("assistant", "Example:\n```text\nCLB_TASK_STATUS=blocked\n```"))
        self.assertIsNone(ao.outcome(d)["error_code"])

    def test_hidden_reasoning_not_in_digest(self):
        d = transcript(message("assistant", "private fixture", channel="analysis"), message("assistant", "public"))
        self.assertNotIn("private fixture", json.dumps(d))

    def test_attempt_does_not_count_as_response(self):
        d = transcript(message("assistant", '{"command":"echo x"}', recipient="Cait_Local_Bridge.exec_start", end_turn=False))
        self.assertEqual((d["tool_attempts"], d["tool_responses"]), (1, 0))
        self.assertEqual(d["tool_calls"][0]["tool"], "exec_start")

    def test_transport_wrapper_and_duplicates(self):
        env = envelope()
        d = transcript(message("tool", json.dumps({"structuredContent": env, "content": [{"text": json.dumps(env)}]})))
        self.assertEqual(len(d["tool_results"]), 1)

    def test_bridge_denial_not_platform_safety_error(self):
        env = envelope(ok=False, error="permission_denied", message="profile not granted")
        d = transcript(message("tool", json.dumps(env)), message("assistant", "Cannot complete."))
        self.assertEqual(ao.outcome(d)["error_code"], "tool_error")

    def test_user_action_marker(self):
        d = transcript(message("assistant", "Approval is needed.\nCLB_TASK_STATUS=needs_user_action"))
        self.assertEqual(ao.outcome(d)["task_status"], "needs_user_action")

    def test_verification_schema_rejects_extra_fields(self):
        with self.assertRaises(ValueError):
            ao.validate_verification({"kind": "exec", "argv": ["echo"], "stdout": "", "ignore_errors": True})

    def test_verification_schema_accepts_exact_check(self):
        v = {"kind": "exec", "argv": ["/bin/echo", "x"], "stdout": "x\n"}
        self.assertEqual(ao.validate_verification(v), v)


class HostVerificationTests(unittest.TestCase):
    def setUp(self):
        db.q("DELETE FROM agent_runs")
        db.q("DELETE FROM audit")
        db.q("DELETE FROM jobs")
        self.started = time.time() - 5
        self.spec = {"verification": {"kind": "exec", "argv": ["/bin/echo", "x"], "stdout": "x\n"}, "timeout": 30}
        db.q("INSERT INTO agent_runs(id,workspace_id,effort,status,created_at,start_ts,spec,meta) VALUES(?,?,?,?,?,?,?,?)",
             "agent_test", "ws_test", "extra_high", "running", self.started, self.started, json.dumps(self.spec), "{}")
        (JOBS_DIR / "agent_test").mkdir(parents=True, exist_ok=True)

    def evidence(self, *, receipt=True, job=True, stdout="x\n", argv=None, ws="ws_test", created=None, exit_code=0, host=None):
        env = envelope()
        if host:
            env["provenance"]["host_id"] = host
        if receipt:
            db.audit("mcp.tool_result", json.dumps({"tool": "exec_start", "ok": True, "job_id": "job_test"}),
                     workspace_id=ws, request_id="req_test")
        if job:
            db.q("INSERT INTO jobs(id,workspace_id,profile,kind,spec,status,created_at,exit_code) VALUES(?,?,?,?,?,?,?,?)",
                 "job_test", ws, "trusted-host", "exec", json.dumps({"argv": argv or ["/bin/echo", "x"]}),
                 "succeeded" if exit_code == 0 else "failed", created or time.time(), exit_code)
            (JOBS_DIR / "job_test").mkdir(parents=True, exist_ok=True)
            (JOBS_DIR / "job_test" / "stdout.log").write_text(stdout)
        return transcript(message("tool", json.dumps(env)), message("assistant", "x"))

    def test_real_matching_receipt_and_job_pass(self):
        d = self.evidence()
        out = agents._assess("agent_test", d)
        self.assertEqual((out["status"], out["task_status"]), ("succeeded", "verified"))
        self.assertEqual(d["confirmed_bridge_calls"], 1)

    def test_fabricated_request_id_is_not_a_confirmed_call(self):
        # chatgpt.com's transcript never exposes tool outputs, so a quoted/fabricated request_id must not count as a bridge receipt;
        # verification may still pass through the job-window fallback (a real job the bridge itself created in this run's window).
        d = self.evidence(receipt=False)
        agents._assess("agent_test", d)
        self.assertEqual(d["confirmed_bridge_calls"], 0)
        self.assertTrue(all(r.get("source") == "job_window" for r in d.get("tool_results", []) if r.get("confirmed_on_host")))

    def test_other_workspace_cannot_pass(self):
        self.assertEqual(agents._assess("agent_test", self.evidence(ws="ws_other"))["error_code"], "verification_failed")

    def test_old_job_cannot_pass(self):
        self.assertEqual(agents._assess("agent_test", self.evidence(created=self.started-100))["error_code"], "verification_failed")

    def test_wrong_stdout_cannot_pass(self):
        self.assertEqual(agents._assess("agent_test", self.evidence(stdout="wrong\n"))["error_code"], "verification_failed")

    def test_wrong_argv_cannot_pass(self):
        self.assertEqual(agents._assess("agent_test", self.evidence(argv=["/bin/echo", "other"]))["error_code"], "verification_failed")

    def test_nonzero_exit_cannot_pass(self):
        self.assertEqual(agents._assess("agent_test", self.evidence(exit_code=1))["error_code"], "verification_failed")

    def test_other_host_receipt_is_not_confirmed(self):
        d = self.evidence(host="not-this-mac")
        agents._assess("agent_test", d)
        self.assertEqual(d["confirmed_bridge_calls"], 0)

    def test_safety_block_wins_over_matching_job(self):
        d = self.evidence()
        d["tool_results"].append({"kind": "platform_safety_block", "raw_error": BLOCK})
        self.assertEqual(agents._assess("agent_test", d)["error_code"], "upstream_safety_blocked")

    def test_result_persistence_and_inbox(self):
        d = self.evidence()
        agents._persist_result("agent_test", {"msgs": []}, d)
        agents._finish("agent_test", "succeeded", None, None)
        self.assertEqual(agents.result("agent_test")["task_status"], "verified")
        self.assertTrue((JOBS_DIR / "agent_test" / "transcript-turn-0.json").exists())
        row = db.one("SELECT payload FROM inbox WHERE kind='agent_finished' ORDER BY id DESC LIMIT 1")
        self.assertEqual(json.loads(row["payload"])["task_status"], "verified")

    def test_legacy_stored_success_surfaces_as_blocked(self):
        old = {"final_text": "RESULT=A:<exec_start 被安全检查阻止，未产生 stdout>"}
        agents._set("agent_test", status="succeeded", result=json.dumps(old))
        info = agents.info("agent_test")
        self.assertEqual((info["stored_status"], info["status"], info["task_status"]), ("succeeded", "failed", "blocked"))
        self.assertEqual(agents._row("agent_test")["status"], "succeeded")

    def test_prompt_has_no_bypass_retry(self):
        ws = [{"id": "ws_test", "root": "/fixture", "name": "fixture", "profiles": ["sandboxed"]}]
        with patch.object(agents, "workspace_list", return_value=ws):
            text = agents.compose("agent_test", "Read fixture.", None, "ws_test")
        self.assertNotIn("换一种等价写法重试", text)
        self.assertIn("原样再发一次（参数一个字都不改）", text)   # verbatim repeat once is allowed; rewording is not
        self.assertIn("不要换写法绕", text)
        self.assertIn("用你自己的联网搜索", text)
        self.assertNotIn("可以用插件的浏览器打开", text)
        with patch.object(agents, "workspace_list", return_value=ws):
            named = agents.compose("agent_test", "Read fixture.", None, "ws_test", browser_sites=["mail.google.com", " "])
        self.assertIn("可以用插件的浏览器打开：mail.google.com。", named)

    def test_unanswered_call_is_recorded_but_verbatim_retry_does_not_fail_the_run(self):
        call = json.dumps({"path": "/App/link/browser_open", "args": {"url": "https://example.org"}})
        conv = {"msgs": [
            {"id": "u", "role": "user", "ct": "text", "text": "go"},
            {"id": "a1", "role": "assistant", "ct": "code", "recipient": "api_tool.call_tool", "text": call},       # dropped upstream: no tool msg
            {"id": "a2", "role": "assistant", "ct": "code", "recipient": "api_tool.call_tool", "text": call},       # verbatim retry
            {"id": "t2", "role": "tool", "name": "api_tool.call_tool", "ct": "code", "text": ""},
            {"id": "f", "role": "assistant", "ct": "text", "recipient": "all", "text": "第一次被安全检查拦截，原样重试后成功。\n\nCLB_TASK_STATUS=done",
             "end_turn": True, "status": "finished_successfully"}]}
        d = ao.digest(conv, 0)
        self.assertEqual(d["tool_attempts"], 2)
        self.assertEqual(d["upstream_blocks_observed"], 1)
        self.assertEqual(d["unanswered_tool_calls"][0]["tool"], "browser_open")
        o = ao.outcome(d)
        self.assertEqual((o["status"], o["task_status"], o["error_code"], o["upstream_blocks_observed"]), ("completed", "unverified", None, 1))
        self.assertTrue(o["warnings"])

    def test_followup_resets_evidence_and_verification(self):
        agents._set("agent_test", status="completed", conv_id="conv", result=json.dumps({"final_text": "old"}),
                    meta=json.dumps({"preview": "old", "tool_calls": 10, "outcome": {"task_status": "verified"}}))
        async def exercise():
            with patch.object(agents, "_guard", new_callable=AsyncMock):
                await agents.send("agent_test", "New task")
                await asyncio.sleep(0)
        asyncio.run(exercise())
        r = agents._row("agent_test")
        self.assertIsNone(r["spec"]["verification"])
        self.assertIsNone(r["meta"]["outcome"])
        self.assertEqual(r["meta"]["tool_calls"], 0)
        self.assertIsNone(r["result"])


class ServerReceiptTests(unittest.IsolatedAsyncioTestCase):
    async def test_request_ids_survive_concurrency_and_match_audit(self):
        @server.guarded
        async def probe(value: int, _subject: str = ""):
            await asyncio.sleep(0)
            return server._ok({"value": value})
        with patch.object(server, "_subject", return_value="test"):
            results = await asyncio.gather(probe(value=1), probe(value=2))
        ids = [r.structured_content["request_id"] for r in results]
        self.assertEqual(len(set(ids)), 2)
        for rid in ids:
            rows = db.all_("SELECT tool, summary FROM audit WHERE request_id=?", rid)
            self.assertEqual([r["tool"] for r in rows], ["mcp.tool_received", "mcp.tool_result"])
            self.assertNotIn("value", ''.join(r["summary"] for r in rows))
        self.assertIsNone(server._REQUEST_ID.get())

    async def test_permission_failure_keeps_same_receipt_id(self):
        @server.guarded
        def denied(_subject: str = ""):
            raise BridgeError("permission_denied", "fixture denial")
        with patch.object(server, "_subject", return_value="test"):
            r = await denied()
        env = r.structured_content
        self.assertFalse(env["ok"])
        self.assertEqual(env["error"], "permission_denied")
        self.assertEqual(len(db.all_("SELECT * FROM audit WHERE request_id=?", env["request_id"])), 2)

    async def test_tool_manifest_and_annotations(self):
        manifest = server._manifest()
        self.assertIn("agent_start", manifest["names"])
        self.assertIn("agent_result", manifest["names"])
        self.assertEqual(manifest["count"], len(server._TOOL_MANIFEST))
        self.assertEqual(len(manifest["sha256"]), 64)
        self.assertFalse(server._TOOL_MANIFEST["exec_start"]["annotations"]["readOnlyHint"])
        self.assertFalse(server._TOOL_MANIFEST["agent_start"]["annotations"]["readOnlyHint"])
        self.assertIn("extra_high", server._TOOL_MANIFEST["agent_start"]["signature"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
