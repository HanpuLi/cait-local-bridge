"""New pull-view regressions; real SQLite/files and Linux-compatible process jobs.

This does not exercise MCP transport, OAuth, or macOS Seatbelt/Accessibility.
"""
from __future__ import annotations

import ast
import asyncio
import errno
import io
import json
import os
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("SCOPERAIL_STATE_DIR", tempfile.mkdtemp(prefix="scoperail-review-import-"))
from bridge import db, jobs, policy
from bridge import execution_review as review
from bridge.policy import BridgeError


class ReviewFixture(unittest.TestCase):
    def setUp(self):
        db.close_thread_connection()
        self.tmp = tempfile.TemporaryDirectory(prefix="scoperail-review-test-")
        self.root = Path(self.tmp.name)
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.patches = [patch.object(db, "DB_PATH", self.root / "state.sqlite3"),
                        patch.object(db, "ensure_dirs"), patch.object(jobs, "JOBS_DIR", self.logs)]
        for p in self.patches:
            p.start()
        self.ws = []
        for name in ("one", "two"):
            path = self.root / name
            path.mkdir()
            self.ws.append(policy.workspace_add(str(path), name, ["trusted-host"], days=None))
        self.wid = self.ws[0]["id"]

    def tearDown(self):
        db.close_thread_connection()
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def make_job(self, out=b"ok\n", err=b"", status="succeeded", exit_code=0, complete=True, extra_meta=None):
        jid = "job_" + uuid.uuid4().hex[:12]
        meta = {"output_complete": complete, **(extra_meta or {})}
        spec = {"argv": ["cmd", "password=NEVER_ECHO_ARG"], "cwd": "/Users/private/hidden", "pty": False}
        db.q("INSERT INTO jobs(id,workspace_id,profile,kind,spec,status,created_at,start_ts,end_ts,exit_code,meta) "
             "VALUES(?,?,?,?,?,?,?,?,?,?,?)", jid, self.wid, "trusted-host", "exec", json.dumps(spec),
             status, time.time()-2, time.time()-1, time.time() if status not in jobs.STATUS_ACTIVE else None,
             exit_code, json.dumps(meta))
        directory = self.logs / jid
        directory.mkdir()
        (directory / "stdout.log").write_bytes(out)
        (directory / "stderr.log").write_bytes(err)
        return jid

    def read(self, jid, **kwargs):
        return review.output(self.wid, jid, action="read", **kwargs)

    def error(self, code, fn, *args, **kwargs):
        with self.assertRaises(BridgeError) as caught:
            fn(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        return caught.exception


class SanitizerTests(unittest.TestCase):
    def clean(self, text):
        result = review.sanitize(text.encode())
        self.assertEqual(result["status"], "readable")
        return result["body"].decode()

    def test_token_families_and_assignment(self):
        values = ["ghp_"+"a"*35, "github_pat_"+"x_"*25, "sk-proj-"+"a"*30,
                  "xoxb-"+"b"*25, "AKIA"+"A"*16, "AIza"+"a"*24, "eyJabc.defghi.jklmnop"]
        for value in values:
            with self.subTest(value=value[:10]):
                self.assertNotIn(value, self.clean(value))
        for value in ('password="some words"', "token='some words'", 'api_key=xyz',
                      '{"secret":"sensitive value"}', '{"authorization":"Bearer raw-secret"}',
                      'OPENAI_API_KEY=unrecognised-value'):
            clean = self.clean(value)
            self.assertIn("[REDACTED]", clean)
            self.assertNotIn("raw-secret", clean)
            self.assertNotIn("some words", clean)

    def test_escaped_json_value_is_redacted_whole(self):
        raw = json.dumps({"password": 'start" middle "SECRET_END'})
        clean = self.clean(raw)
        self.assertNotIn("SECRET_END", clean)
        self.assertNotIn("middle", clean)

    def test_authorization_home_and_url_credentials(self):
        clean = self.clean('Authorization: Bearer private-value\nhttps://bob:secret@example.invalid/x\n'
                           '/Users/bob/file /home/alice/x C:\\Users\\carol\\file')
        for secret in ("private-value", "bob", "alice", "carol", "secret"):
            self.assertNotIn(secret, clean)
        self.assertIn("example.invalid", clean)

    def test_private_keys_including_after_first_page_and_ansi(self):
        for key in ("PRIVATE KEY", "RSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "PGP PRIVATE KEY BLOCK"):
            raw = b"ordinary\n"*2000 + f"-----BEGIN {key}-----".encode()
            self.assertEqual(review.sanitize(raw)["reason"], "private_key")
        raw = b"-----BEGIN PRI\x1b[31mVATE KEY-----"
        self.assertEqual(review.sanitize(raw)["reason"], "private_key")

    def test_binary_non_utf8_and_oversize_fail_closed(self):
        for data, reason in [(b"a\0b", "binary_output"), (b"\xff", "non_utf8_output")]:
            result = review.sanitize(data)
            self.assertEqual(result, {"status": "restricted", "reason": reason})
        with patch.object(review, "MAX_SNAPSHOT_BYTES", 8):
            self.assertEqual(review.sanitize(b"a"*9)["reason"], "snapshot_too_large")

    def test_long_nonmatching_text_does_not_explode(self):
        start = time.monotonic()
        self.assertEqual(len(self.clean("z" * 500_000)), 500_000)
        self.assertLess(time.monotonic()-start, 5.0)

    def test_controls_and_ansi_removed(self):
        self.assertEqual(self.clean("\x1b[31mhello\x1b[0m\x07\n"), "hello\n")


class OutputTests(ReviewFixture):
    def test_summary_is_metadata_not_test_verdict(self):
        jid = self.make_job(out=b"TOP_SECRET", status="failed", exit_code=3)
        with patch.object(review, "_read_log", side_effect=AssertionError("no body read")):
            result = review.summary(self.wid, jid)
        self.assertEqual(result["exit_code"], 3)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["test_verdict"], "not_assessed")
        self.assertEqual(result["task_verdict"], "not_assessed")
        self.assertTrue(result["output_complete"])
        for secret in ("TOP_SECRET", "NEVER_ECHO_ARG", "hidden", "argv", "cwd"):
            self.assertNotIn(secret, json.dumps(result))

    def test_unknown_and_other_workspace_match(self):
        jid = self.make_job()
        first = self.error("not_found", review.summary, self.ws[1]["id"], jid)
        second = self.error("not_found", review.summary, self.ws[1]["id"], "job_"+"f"*12)
        self.assertEqual(first.message, second.message)

    def test_revocation_and_expiry_rechecked_with_reference(self):
        jid = self.make_job()
        ref = self.read(jid)["snapshot_id"]
        for field, value in (("revoked", 1), ("expires_at", time.time()-10)):
            db.q(f"UPDATE workspaces SET {field}=? WHERE id=?", value, self.wid)
            self.error("permission_denied", self.read, jid, snapshot_id=ref)
            db.q("UPDATE workspaces SET revoked=0, expires_at=NULL WHERE id=?", self.wid)

    def test_revocation_during_read_blocks_release(self):
        jid = self.make_job()
        actual = review._read_log
        def revoke(*args):
            raw = actual(*args)
            db.q("UPDATE workspaces SET revoked=1 WHERE id=?", self.wid)
            return raw
        with patch.object(review, "_read_log", side_effect=revoke):
            self.error("permission_denied", self.read, jid)

    def test_bad_ids_streams_cursors_and_limits(self):
        jid = self.make_job()
        for bad in ("../../etc", "/tmp/job", "job_abc", "job_"+"a"*12+"/.."):
            self.error("invalid_argument", review.summary, self.wid, bad)
        for params in ({"stream": "../stdout"}, {"cursor": -1}, {"cursor": True}, {"max_bytes": 3},
                       {"max_bytes": 16385}, {"max_bytes": "10"}, {"snapshot_id": "no"}):
            self.error("invalid_argument", self.read, jid, **params)

    def test_list_exposes_metadata_not_body(self):
        jid = self.make_job(out=b"SENTINEL_OUTPUT")
        result = review.output(self.wid, jid)
        self.assertEqual(len(result["items"]), 2)
        self.assertNotIn("SENTINEL_OUTPUT", json.dumps(result))
        self.assertNotIn('"body"', json.dumps(result))
        self.error("invalid_argument", review.output, self.wid, jid, cursor=1)

    def test_utf8_pages_reconstruct_exact_sanitized_view(self):
        raw = ("词🙂abc\n"*101 + 'password="NEVER_PAGE_SECRET"\nEND').encode()
        jid = self.make_job(out=raw)
        parts, cursor, snapshot = [], 0, None
        while True:
            page = self.read(jid, cursor=cursor, snapshot_id=snapshot, max_bytes=7)
            self.assertLessEqual(len(page["text"].encode()), 7)
            parts.append(page["text"])
            snapshot = page["snapshot_id"]
            self.assertNotIn("NEVER_PAGE_SECRET", page["text"])
            if page["next_cursor"] is None:
                self.assertTrue(page["snapshot_eof"])
                break
            self.assertGreater(page["next_cursor"], cursor)
            cursor = page["next_cursor"]
        self.assertEqual("".join(parts).encode(), review.sanitize(raw)["body"])

    def test_secret_crossing_page_boundary_is_not_returned(self):
        raw = b"hello " + ("ghp_"+"a"*40).encode() + b" end"
        jid = self.make_job(out=raw)
        page = self.read(jid, max_bytes=12)
        self.assertNotIn("ghp_", page["text"])
        rest = self.read(jid, cursor=page["next_cursor"], snapshot_id=page["snapshot_id"])
        self.assertNotIn("aaaa", rest["text"])

    def test_continuation_requires_matching_snapshot(self):
        jid = self.make_job(out=b"hello world")
        page = self.read(jid, max_bytes=4)
        self.error("invalid_argument", self.read, jid, cursor=4)
        (self.logs/jid/"stdout.log").write_bytes(b"changed output")
        self.error("conflict", self.read, jid, cursor=4, snapshot_id=page["snapshot_id"])

    def test_snapshot_bound_to_job_and_stream(self):
        jid = self.make_job(out=b"same data", err=b"same data")
        jid2 = self.make_job(out=b"same data")
        snap = self.read(jid)["snapshot_id"]
        self.error("conflict", self.read, jid2, snapshot_id=snap)
        self.error("conflict", self.read, jid, stream="stderr", snapshot_id=snap)

    def test_invalid_unicode_offset_and_end(self):
        jid = self.make_job(out="🙂last".encode())
        snap = self.read(jid)["snapshot_id"]
        self.error("invalid_argument", self.read, jid, cursor=1, snapshot_id=snap)
        self.error("invalid_argument", self.read, jid, cursor=999, snapshot_id=snap)
        self.assertTrue(self.read(jid, cursor=8, snapshot_id=snap)["snapshot_eof"])

    def test_empty_stream_has_real_eof(self):
        jid = self.make_job(out=b"")
        page = self.read(jid)
        self.assertEqual(page["text"], "")
        self.assertTrue(page["snapshot_eof"])
        self.assertIsNone(page["next_cursor"])

    def test_running_legacy_incomplete_and_truncated_are_not_released(self):
        cases = [("running", True, {}, "pending", "job_active"),
                 ("succeeded", False, {}, "restricted", "output_completion_unverified"),
                 ("succeeded", True, {"output_truncated": True}, "restricted", "capture_truncated")]
        for status, complete, meta, expected, reason in cases:
            jid = self.make_job(status=status, complete=complete, extra_meta=meta)
            with patch.object(review, "_read_log", side_effect=AssertionError("must not read")):
                page = self.read(jid)
            self.assertEqual(page["status"], expected)
            self.assertEqual(page["reason"], reason)
            self.assertEqual(page["text"], "")
            self.assertFalse(page["snapshot_eof"])

    def test_key_after_first_page_blocks_every_page(self):
        jid = self.make_job(out=b"ok\n"*3000+b"-----BEGIN PRIVATE KEY-----\nSECRET")
        page = self.read(jid, max_bytes=10)
        self.assertEqual(page["reason"], "private_key")
        self.assertEqual(page["text"], "")

    def test_unavailable_log_is_not_empty_success(self):
        jid = self.make_job()
        (self.logs/jid/"stdout.log").unlink()
        page = self.read(jid)
        self.assertEqual(page["status"], "unavailable")
        self.assertFalse(page["snapshot_eof"])

    def test_overlarge_snapshot_is_restricted(self):
        jid = self.make_job(out=b"x"*65)
        with patch.object(review, "MAX_SNAPSHOT_BYTES", 64):
            self.assertEqual(self.read(jid)["reason"], "snapshot_too_large")

    def test_symlink_file_and_job_directory_fail_closed(self):
        jid = self.make_job()
        out = self.logs/jid/"stdout.log"
        out.unlink()
        target = self.root/"outside-secret"
        target.write_text("SECRET")
        out.symlink_to(target)
        self.error("permission_denied", self.read, jid)
        out.unlink()
        directory = self.logs/jid
        outside = self.root/"moved-job"
        directory.rename(outside)
        directory.symlink_to(outside, target_is_directory=True)
        self.error("permission_denied", self.read, jid)

    def test_hardlink_and_fifo_fail_without_blocking(self):
        jid = self.make_job()
        out = self.logs/jid/"stdout.log"
        os.link(out, self.root/"alias")
        self.error("permission_denied", self.read, jid)
        out.unlink()
        os.mkfifo(out)
        self.error("permission_denied", self.read, jid)

    def test_mutating_log_during_read_conflicts(self):
        jid = self.make_job(out=b"x"*10)
        actual = os.read
        def mutate(fd, count):
            data = actual(fd, count)
            with (self.logs/jid/"stdout.log").open("ab") as f:
                f.write(b"!")
            return data
        with patch.object(review.os, "read", side_effect=mutate):
            self.error("conflict", self.read, jid)


class PresentationTests(ReviewFixture):
    def response(self, jid, mode="auto", cap=16000, dedup=False):
        return review.run_response(jobs.info(jid), mode, cap, time.time(), dedup)

    def test_summary_does_not_read_logs_and_keeps_failure(self):
        jid = self.make_job(out=b"x"*100_000, status="failed", exit_code=9)
        with patch.object(review, "_read_log", side_effect=AssertionError("no scan")), \
             patch.object(jobs, "logs", side_effect=AssertionError("no raw read")):
            result = self.response(jid, "summary")
        self.assertEqual(result["exit_code"], 9)
        self.assertEqual(result["stdout"], "")
        self.assertTrue(result["output_deferred"])
        self.assertEqual(result["output_ref"]["tool"], "execution_output")
        self.assertLess(len(json.dumps(result)), 1200)
        self.assertNotIn("NEVER_ECHO_ARG", json.dumps(result))

    def test_auto_small_success_and_failed_output(self):
        jid = self.make_job(err=b"failed: password=private-value\n", status="failed", exit_code=5)
        result = self.response(jid)
        self.assertEqual(result["stdout"], "ok\n")
        self.assertNotIn("private-value", result["stderr"])
        self.assertEqual(result["exit_code"], 5)
        self.assertTrue(result["output_sanitized"])
        self.assertFalse(result["output_deferred"])

    def test_auto_large_has_no_scan_or_body(self):
        jid = self.make_job(out=b"a"*4096, err=b"x")
        with patch.object(review, "_read_log", side_effect=AssertionError("no eager scan")):
            result = self.response(jid)
        self.assertTrue(result["output_deferred"])
        self.assertEqual(result["stdout"], "")

    def test_auto_honours_smaller_budget_and_active_status(self):
        jid = self.make_job(out=b"a"*30)
        self.assertTrue(self.response(jid, cap=20)["output_deferred"])
        jid = self.make_job(status="running", exit_code=None, complete=False)
        result = self.response(jid)
        self.assertTrue(result["wait_exhausted"])
        self.assertIsNone(result["exit_code"])
        self.assertTrue(result["output_deferred"])

    def test_auto_restricted_never_falls_back_to_raw(self):
        jid = self.make_job(out=b"-----BEGIN PRIVATE KEY-----")
        with patch.object(jobs, "logs", side_effect=AssertionError("raw fallback")):
            result = self.response(jid)
        self.assertTrue(result["output_deferred"])
        self.assertEqual(result["stdout"], "")

    def test_explicit_inline_keeps_legacy_raw_tail(self):
        jid = self.make_job(out=b"x"*2500+b"password=private-value")
        result = self.response(jid, "inline", cap=1024)
        self.assertEqual(len(result["stdout"].encode()), 1024)
        self.assertIn("password=private-value", result["stdout"])
        self.assertFalse(result["output_sanitized"])
        self.assertTrue(result["truncated"])
        self.assertIn("argv", result)

    def test_deduplicated_flag_survives_presentation(self):
        jid = self.make_job()
        self.assertTrue(self.response(jid, dedup=True)["deduplicated"])

    def test_invalid_modes_and_budgets(self):
        for mode, cap in (("full", 500), ("auto", True), ("auto", 0), ("auto", 200001)):
            self.error("invalid_argument", review.validate_run_options, mode, cap)


class ReaderEvidenceTests(ReviewFixture):
    def test_reader_clean_eof_and_size_cap_evidence(self):
        for cap, trunc in ((20, False), (4, True)):
            with self.subTest(cap=cap):
                r, w = os.pipe()
                os.write(w, b"hello")
                os.close(w)
                outcome = {}
                out = self.root / f"captured-{cap}"
                with patch.dict(jobs.CFG, max_job_log_bytes=cap):
                    jobs._pipe_reader("unused", os.fdopen(r, "rb"), out, outcome)
                self.assertTrue(outcome["eof"])
                self.assertFalse(outcome["error"])
                self.assertEqual(outcome["truncated"], trunc)

    def test_reader_error_is_not_proof_of_drain(self):
        outcome = {}
        jobs._pipe_reader("unused", io.BytesIO(b"x"), self.root/"bad-log", outcome)
        self.assertFalse(outcome["eof"])
        self.assertTrue(outcome["error"])

    def test_pty_eio_is_eof_but_pipe_eio_is_not(self):
        for pty_mode in (True, False):
            outcome = {}
            with patch.object(jobs.os, "read", side_effect=OSError(errno.EIO, "closed")):
                if pty_mode:
                    jobs._capture_output(-1, self.root/"pty-log", True, outcome)
                    self.assertTrue(outcome["eof"])
                else:
                    with self.assertRaises(OSError):
                        jobs._capture_output(-1, self.root/"pipe-log", False, outcome)

    def test_waiter_refuses_errored_reader_even_if_thread_ended(self):
        jid = self.make_job(status="running", exit_code=None, complete=False)
        reader = SimpleNamespace(join=lambda timeout: None, is_alive=lambda: False)
        jobs._live[jid] = {"readers": [reader], "reader_outcomes": [{"eof": False, "error": True}]}
        proc = SimpleNamespace(poll=lambda: 0, pid=99999)
        jobs._waiter_body(jid, proc, 10)
        result = review.summary(self.wid, jid)
        self.assertEqual(result["status"], "succeeded")
        self.assertFalse(result["output_complete"])

    def test_waiter_drain_budget_is_bounded_for_live_reader(self):
        jid = self.make_job(status="running", exit_code=None, complete=False)
        waits = []
        reader = SimpleNamespace(join=lambda timeout: waits.append(timeout), is_alive=lambda: True)
        jobs._live[jid] = {"readers": [reader], "reader_outcomes": [{"eof": False, "error": True}]}
        jobs._waiter_body(jid, SimpleNamespace(poll=lambda: 0, pid=99999), 10)
        self.assertEqual(len(waits), 1)
        self.assertLessEqual(waits[0], 2.0)
        self.assertFalse(review.summary(self.wid, jid)["output_complete"])

    def test_real_process_drains_both_streams_and_keeps_failure(self):
        job = jobs.start(self.wid, "trusted-host", [sys.executable, "-c",
                         "import sys;sys.stdout.write('x'*200000);sys.stderr.write('FAIL\\n');sys.exit(7)"], timeout=10)
        deadline = time.monotonic()+8
        while True:
            row = review.summary(self.wid, job["job_id"])
            if row["terminal"]:
                break
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.03)
        self.assertEqual(row["exit_code"], 7)
        self.assertEqual(row["status"], "failed")
        self.assertTrue(row["output_complete"])
        self.assertEqual(self.read(job["job_id"], stream="stderr")["text"], "FAIL\n")
        self.assertEqual(self.read(job["job_id"])["raw_size_bytes"], 200000)
        # Wait for the short-lived waiter to close its own DB handle before cleanup.
        time.sleep(0.05)

    def test_real_process_idempotency_does_not_repeat_effect(self):
        count_file = Path(self.ws[0]["root"]) / "count"
        command = [sys.executable, "-c", "from pathlib import Path;p=Path('count');p.write_text(p.read_text()+'x' if p.exists() else 'x')"]
        job = jobs.start(self.wid, "trusted-host", command, idem_key="effect-once", timeout=10)
        deadline = time.monotonic()+8
        while jobs.info(job["job_id"])["status"] in jobs.STATUS_ACTIVE:
            self.assertLess(time.monotonic(), deadline)
            time.sleep(.03)
        retry = jobs.start(self.wid, "trusted-host", command, idem_key="effect-once", timeout=10)
        self.assertEqual(retry["job_id"], job["job_id"])
        self.assertTrue(retry["deduplicated"])
        self.assertEqual(count_file.read_text(), "x")
        time.sleep(.05)


class HandlerContractTests(unittest.TestCase):
    """Execute the actual function AST without importing unavailable MCP runtime.

    Decorators/envelope are inspected or substituted; NOT an HTTP/OAuth/MCP test.
    """
    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse((Path(__file__).parents[1]/"bridge/server.py").read_text())

    def handler(self, name, globals_):
        tree = ast.parse(ast.unparse(self.tree))
        node = next(n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name)
        node.decorator_list = []
        module = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), node], type_ignores=[])
        ast.fix_missing_locations(module)
        scope = dict(globals_)
        exec(compile(module, "<actual-server-handler>", "exec"), scope)  # noqa: S102 - execute the parsed handler under test
        return scope[name]

    def test_new_endpoints_keep_guard_and_readonly_registration(self):
        for name in ("execution_summary", "execution_output"):
            node = next(n for n in self.tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
            self.assertIn("guarded", [ast.unparse(d) for d in node.decorator_list])
            self.assertTrue(any(isinstance(d, ast.Call) and ast.unparse(d.func)=="tool" and ast.unparse(d.args[1])=="RO" for d in node.decorator_list))
            self.assertEqual([a.arg for a in node.args.args][:2], ["workspace_id", "job_id"])

    def test_invalid_presentation_never_launches_command(self):
        fake_jobs = SimpleNamespace(start=lambda *a: self.fail("must not execute"))
        fn = self.handler("exec_run", {"execution_review": review, "jobs": fake_jobs})
        with self.assertRaises(BridgeError):
            asyncio.run(fn("ws_one", ["touch", "file"], output_mode="invalid"))

    def test_exec_run_retains_dedup_after_poll_and_routes_mode(self):
        first = {"job_id": "job_"+"a"*12, "status": "running", "deduplicated": True}
        final = {"job_id": first["job_id"], "status": "succeeded"}
        calls = []
        async def sleep(_):
            return None
        fake_review = SimpleNamespace(validate_run_options=review.validate_run_options,
                                      run_response=lambda *a: calls.append(a) or {"stub": True})
        fake_jobs = SimpleNamespace(start=lambda *a: dict(first), info=lambda *a: dict(final), STATUS_ACTIVE=jobs.STATUS_ACTIVE)
        fn = self.handler("exec_run", {"execution_review": fake_review, "jobs": fake_jobs, "time": time,
                                       "asyncio": SimpleNamespace(sleep=sleep), "_ok": lambda d, **kw: d})
        result = asyncio.run(fn("ws_one", ["command"], output_mode="summary"))
        self.assertEqual(result, {"stub": True})
        self.assertEqual(calls[0][1], "summary")
        self.assertTrue(calls[0][4])
        self.assertEqual(calls[0][0], final)


if __name__ == "__main__":
    unittest.main()
