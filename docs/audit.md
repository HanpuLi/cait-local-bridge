# Audit export

ScopeRail records bounded control-plane audit rows in its local SQLite state. The operator can export a deterministic, redacted view for review or archival without exposing the raw database.

## Local CLI

The exporter is deliberately a **local CLI surface**, not a remote MCP tool:

```sh
scoperail audit export --since 2026-09-19T00:00:00Z > audit.jsonl
scoperail audit export \
  --since 2026-09-19T00:00:00Z \
  --until 2026-09-20T00:00:00Z \
  --workspace-id ws_abcd1234 \
  --format json > audit.json
```

Time bounds are inclusive and accept epoch seconds or ISO-8601. Naive ISO timestamps are interpreted as UTC. Output is ordered by `timestamp`, then audit row ID.

The default JSONL row schema is `scoperail.audit/v1`. JSON document output uses the envelope schema `scoperail.audit-export/v1`.

Each row contains:

- timestamp and numeric epoch;
- subject;
- audit tool/event name;
- workspace ID;
- request ID;
- job ID when the safe event schema contains one;
- a bounded, redacted summary.

## Redaction boundary

The exporter never emits OAuth bearer/refresh tokens, passwords, passphrases, credentials, API keys, cookies, full environment maps, HTTP authorization headers, browser profile/cookie material, or raw scheduled commands.

Redaction is intentionally fail-closed:

- `mcp.tool_received` exports only the tool name;
- `mcp.tool_result` exports only tool/ok/job/status/error metadata;
- scheduled-command audit rows persist metadata only, without the command;
- historical schedule rows that may contain command text are exported with that detail removed;
- unknown future audit event types export only the event name plus `details=[REDACTED]` until a specific safe-summary policy is added.

This policy protects the export, not the historical database retroactively. Older audit rows may already contain details that current code no longer writes. Do not copy or publish the raw SQLite control-plane database as a substitute for this exporter.

## Bounds

The exporter caps one invocation at 10,000 rows and summary strings at 512 characters. Use time windows for larger archives. It does not export OAuth tables, job specs, schedules, browser data, environment variables or any other control-plane table.

## Validation

Unit tests feed deliberately secret-looking values through current and legacy audit shapes and require those values to be absent from JSON/JSONL output. The repository security workflow also runs history-aware gitleaks.
