from __future__ import annotations

import argparse
import io
import json
import math
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from bridge import audit_export
from bridge.public_cli import _audit_export


def secret_values() -> tuple[str, str, str]:
    # Assemble secret-looking fixtures at runtime so source scanners do not see a real token pattern.
    github = "gh" + "p_" + ("A" * 36)
    bearer = "Bearer " + ("B" * 32)
    password = "password=" + ("S" * 24)
    return github, bearer, password


def audit_row(
    row_id: int,
    ts: float,
    tool: str,
    summary: str,
    *,
    subject: str = "operator",
    workspace_id: str | None = "ws_test",
    request_id: str | None = "req_test",
) -> dict:
    return {
        "id": row_id,
        "ts": ts,
        "subject": subject,
        "tool": tool,
        "workspace_id": workspace_id,
        "request_id": request_id,
        "summary": summary,
    }


class TimeBoundTests(unittest.TestCase):
    def test_epoch_and_iso_are_supported(self) -> None:
        self.assertEqual(audit_export.parse_time_bound("0"), 0.0)
        self.assertEqual(audit_export.parse_time_bound(123), 123.0)
        self.assertEqual(
            audit_export.parse_time_bound("2026-09-19T10:00:00Z"),
            audit_export.parse_time_bound("2026-09-19T10:00:00+00:00"),
        )
        self.assertEqual(
            audit_export.parse_time_bound("2026-09-19T10:00:00"),
            audit_export.parse_time_bound("2026-09-19T10:00:00Z"),
        )

    def test_invalid_or_nonfinite_time_is_rejected(self) -> None:
        for value in ("not-a-time", math.nan, math.inf, "-inf"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                audit_export.parse_time_bound(value)


class RedactionTests(unittest.TestCase):
    def test_mcp_result_whitelists_metadata_and_extracts_job_id(self) -> None:
        github, bearer, password = secret_values()
        raw = json.dumps(
            {
                "tool": "exec_start",
                "ok": True,
                "job_id": "job_123",
                "status": "running",
                "error": None,
                "token": github,
                "authorization": bearer,
                "argv": [password],
                "environment": {"PRIVATE": github},
            }
        )
        summary, job_id = audit_export._safe_summary("mcp.tool_result", raw)
        self.assertEqual(job_id, "job_123")
        parsed = json.loads(summary)
        self.assertEqual(set(parsed), {"tool", "ok", "job_id", "status", "error"})
        for secret in (github, bearer, password):
            self.assertNotIn(secret, summary)

    def test_old_job_schedule_never_exports_raw_command_tail(self) -> None:
        github, bearer, password = secret_values()
        raw = (
            "sch_deadbeef next=123.5 spec={'command': ['curl', '-H', "
            + repr(bearer)
            + ", "
            + repr(github)
            + ", "
            + repr(password)
            + "]}"
        )
        summary, job_id = audit_export._safe_summary("job_schedule", raw)
        self.assertIsNone(job_id)
        self.assertEqual(summary, "sch_deadbeef next=123.5 details=[REDACTED]")
        for secret in (github, bearer, password):
            self.assertNotIn(secret, summary)

    def test_current_job_schedule_persists_and_exports_only_bounded_metadata(self) -> None:
        github, bearer, password = secret_values()
        persisted = audit_export.schedule_audit_summary(
            "sch_safe",
            123.5,
            "sandboxed",
            "src/" + bearer,
            300,
            "nightly " + github + " " + password,
        )
        self.assertNotIn("command", persisted)
        for secret in (github, bearer, password):
            self.assertNotIn(secret, persisted)

        summary, _ = audit_export._safe_summary("job_schedule", persisted)
        parsed = json.loads(summary)
        self.assertEqual(
            set(parsed),
            {"schedule_id", "next", "profile", "cwd", "interval", "name"},
        )
        self.assertEqual(parsed["schedule_id"], "sch_safe")
        self.assertNotIn("command", summary)
        for secret in (github, bearer, password):
            self.assertNotIn(secret, summary)

    def test_unknown_tool_fails_closed(self) -> None:
        github, bearer, password = secret_values()
        raw = f"{github} {bearer} {password} arbitrary arguments"
        summary, job_id = audit_export._safe_summary("future.tool", raw)
        self.assertIsNone(job_id)
        self.assertEqual(summary, "future.tool details=[REDACTED]")
        for secret in (github, bearer, password):
            self.assertNotIn(secret, summary)

    def test_recursive_killswitch_redaction(self) -> None:
        github, bearer, password = secret_values()
        raw = json.dumps(
            {
                "reason": "operator request",
                "authorization": bearer,
                "nested": {
                    "apiKey": github,
                    "note": password,
                    "environment": {"X": github},
                },
            }
        )
        summary, _ = audit_export._safe_summary("killswitch", raw)
        for secret in (github, bearer, password):
            self.assertNotIn(secret, summary)
        self.assertIn("[REDACTED]", summary)


class ExportTests(unittest.TestCase):
    def test_export_is_deterministic_and_schema_versioned(self) -> None:
        rows = [
            audit_row(3, 20.0, "server", "later"),
            audit_row(1, 10.0, "mcp.tool_received", json.dumps({"tool": "file_read"})),
            audit_row(2, 10.0, "mcp.tool_result", json.dumps({"tool": "file_read", "ok": True})),
        ]
        with patch.object(audit_export.db, "all_", return_value=rows) as all_:
            records = audit_export.export_records(
                since=5.0,
                until=25.0,
                workspace_id="ws_test",
                limit=50,
            )

        self.assertEqual([(x["ts"], x["id"]) for x in records], [(10.0, 1), (10.0, 2), (20.0, 3)])
        self.assertTrue(all(x["schema"] == audit_export.SCHEMA for x in records))
        self.assertEqual(records[0]["timestamp"], "1970-01-01T00:00:10.000Z")
        sql, *args = all_.call_args.args
        self.assertIn("ORDER BY ts ASC, id ASC", sql)
        self.assertEqual(args, [5.0, 25.0, "ws_test", 50])

    def test_render_jsonl_and_json_are_parseable_and_secret_free(self) -> None:
        github, bearer, password = secret_values()
        rows = [
            audit_row(
                1,
                1.0,
                "mcp.tool_result",
                json.dumps(
                    {
                        "tool": "exec_start",
                        "ok": False,
                        "error": "permission_denied",
                        "token": github,
                        "headers": {"Authorization": bearer},
                        "environment": {"PASSWORD": password},
                    }
                ),
            )
        ]
        records = [audit_export._record(row) for row in rows]
        jsonl = audit_export.render(records, "jsonl")
        parsed_line = json.loads(jsonl.strip())
        self.assertEqual(parsed_line["schema"], audit_export.SCHEMA)

        document = audit_export.render(records, "json")
        parsed_doc = json.loads(document)
        self.assertEqual(parsed_doc["schema"], "scoperail.audit-export/v1")
        self.assertEqual(parsed_doc["count"], 1)

        for text in (jsonl, document):
            for secret in (github, bearer, password):
                self.assertNotIn(secret, text)

    def test_limits_and_range_are_validated(self) -> None:
        for limit in (0, audit_export.MAX_EXPORT_ROWS + 1):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                audit_export.export_records(limit=limit)
        with self.assertRaises(ValueError):
            audit_export.export_records(since=2.0, until=1.0)


class CliTests(unittest.TestCase):
    def test_cli_writes_redacted_jsonl_to_stdout(self) -> None:
        sample = [
            {
                "schema": audit_export.SCHEMA,
                "id": 1,
                "ts": 1.0,
                "timestamp": "1970-01-01T00:00:01.000Z",
                "subject": "operator",
                "tool": "server",
                "workspace_id": None,
                "request_id": None,
                "job_id": None,
                "summary": "start",
            }
        ]
        args = argparse.Namespace(
            since="1970-01-01T00:00:00Z",
            until=None,
            workspace_id=None,
            format="jsonl",
            limit=10,
        )
        with patch.object(audit_export, "export_records", return_value=sample) as export:
            buf = io.StringIO()
            with redirect_stdout(buf):
                _audit_export(args)
        self.assertEqual(json.loads(buf.getvalue())["id"], 1)
        self.assertEqual(export.call_args.args[0], 0.0)

    def test_cli_invalid_argument_exits_two_without_traceback(self) -> None:
        args = argparse.Namespace(
            since="bad-time",
            until=None,
            workspace_id=None,
            format="jsonl",
            limit=10,
        )
        err = io.StringIO()
        with redirect_stderr(err), self.assertRaises(SystemExit) as ctx:
            _audit_export(args)
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("invalid_argument:", err.getvalue())


if __name__ == "__main__":
    unittest.main()
