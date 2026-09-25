# Pull-based execution review

This change adapts the control-message / pull-data separation and selected output
sanitisation rules from XiaoDuoYa/codex-with-chatgpt. ScopeRail still owns execution
under its existing workspace, profile and grant policies. There is no new model,
Codex process, browser automation, credential store, or external service.

## What changes

`exec_run` gains `output_mode` with three values:

| Mode | Response |
| --- | --- |
| `auto` (new default) | Inline sanitised stdout/stderr only after the readers have drained successfully, with at most 4,096 UTF-8 bytes in total, further constrained by `max_output_bytes`. Otherwise return metadata and `output_ref`. |
| `summary` | Do not read or inline either log. Return execution status, exit code, byte counts and `output_ref`. |
| `inline` | Explicit compatibility mode: the previous raw per-stream tail, including argv/cwd. The original 1,024-byte minimum and 200,000-byte maximum tail cap remain. |

The presentation options are validated **before** starting a command. An invalid
mode cannot cause an unreported side effect. Existing idempotency keys still
identify the same process. The returned `deduplicated` flag is now preserved even
when `exec_run` polls after the initial idempotency lookup.

The default change is intentionally observable. Clients that require the former
raw stdout/stderr and argv/cwd behaviour must request `output_mode="inline"`.
Do not interpret an empty `stdout` with `output_deferred=true` as empty output.
Existing `exec_start`, `exec_poll`, and raw `exec_logs` remain available; this patch
does not convert every ScopeRail tool to the new presentation mode.

## Two read-only tools

`execution_summary(workspace_id, job_id)` returns the recorded process status,
profile, exit code, signal, timeout flag, timestamps and output-completion flags.
It does not open logs or echo command arguments, environment values or paths.
`evidence_kind="process_record"` is deliberately distinct from a test assessment:
`test_verdict` and `task_verdict` are both `"not_assessed"`. A successful command is
not evidence that the intended tests ran, that an assertion was correct, or that
the user's whole task is complete.

`execution_output` supports `action="list"` and `action="read"`. List returns the
availability, size and sanitised-view identifier for stdout and stderr, without
body text. Read returns a UTF-8-safe page, default 4,096 bytes, maximum 16,384 bytes.
It never executes the command again.

A typical exchange is:

```text
exec_run(workspace_id=..., command=..., output_mode="summary")
execution_summary(workspace_id=..., job_id=...)
execution_output(workspace_id=..., job_id=..., action="list")
execution_output(workspace_id=..., job_id=..., action="read", stream="stderr")
```

For another page, pass both `cursor=next_cursor` and the returned `snapshot_id`.
`next_cursor=null` with `snapshot_eof=true` means the selected sanitised view was
fully delivered. Pending, unavailable and restricted views have no body and do
**not** claim EOF. A view change returns `conflict`; restart from cursor zero.
These cursors index the sanitised byte sequence, not the raw `exec_logs` stream.

The snapshot digest includes schema version, workspace ID, job ID, stream and the
sanitised bytes. It identifies that view, not the raw log, and is not a bearer
capability or cryptographic attestation that the operator could not modify state.

## Completeness and bounded work

Process exit and output-reader completion are separate observations. Pipe/PTY
readers record clean EOF, read/write errors and capture truncation. The waiter
joins readers for at most two seconds in total. Inherited open pipes or reader
errors cannot turn into a verified complete-output flag. Linux PTY EIO at slave
closure is handled as EOF; an ordinary pipe EIO is a read error.

A job can therefore have `status="succeeded"` and `output_complete=false`. This is
not a contradiction: the command exited zero, but this service cannot prove that
its captured output is complete. Likewise, `output_truncated=true` reports that
capture reached the existing disk log cap. A truncated capture is not released
through the new review view, because unseen content cannot be sanitised.

Historical jobs without the new completeness metadata fail closed in the review
view. Their original raw logs are not deleted or reclassified. Running jobs are
pending, not frozen snapshots; live streaming continues to use the existing raw
API when explicitly appropriate.

Each read scans a full, **bounded** terminal log of at most 8 MiB before pagination.
This avoids per-page token-pattern bypasses and mixed-view continuations. There
is intentionally no second persisted output store or unbounded snapshot cache.
The trade-off is repeated scan/CPU cost when paging large logs. `list` also scans
the two bounded logs to classify them; use `execution_summary` for cheap polling.
Larger logs are restricted rather than silently chopped into supposedly complete
evidence. The existing disk capture cap is not changed.

## Authority and data handling

Every new endpoint rechecks workspace liveness and looks up the job using both
workspace ID and job ID. Unknown and wrong-workspace jobs share a `not_found`
response. Snapshot reads recheck the workspace after disk access. Only the fixed
stdout/stderr names can be opened. Directory-fd/no-follow reads reject job-folder
or log symlinks, hard-linked logs, non-regular files and FIFOs; size/mtime/ctime
changes during a read cause `conflict`.

**This is not per-workspace OAuth token isolation.** It preserves ScopeRail's
existing operator authentication and workspace policy. A caller who already has
authority over several workspaces can still name those workspaces. `RO` tool
annotations describe these operations but do not by themselves create a separate
read-only server, role or security boundary.

The new view removes common terminal control sequences, rejects binary/non-UTF-8
content and private-key headers, and redacts recognised credential patterns,
credential assignments, URL userinfo and home-directory usernames. Sanitisation
runs over the entire bounded log before any page is returned. It is deterministic
and heuristic, not comprehensive DLP: arbitrary prose secrets, encodings or
unknown token formats may not be recognised. Raw logs stay in the original jobs
store. `inline` and `exec_logs` remain explicit raw compatibility paths with their
existing authority. Never automatically fall back to them because review output
was restricted, and never treat log text as instructions or permission to act.

No grants, token lifetimes, token audiences, scopes, model runtime restrictions,
publication permissions or network policies are changed by this patch.

## Provenance and licence

Reference project: https://github.com/XiaoDuoYa/codex-with-chatgpt

Reviewed Git blob objects:

- `src/execution/output.ts`: `01cd1c43e91ce59eaa632feeedfaad43b648691c`
- `src/execution/sanitize.ts`: `90aa2c2dbfcb01bf350c0afbf98e85680959bbfc`
- `LICENSE`: `718f931a2eda70e424562874c367cd5cf3c9d575`

The upstream MIT notice is retained in `LICENSES/codex-with-chatgpt-MIT.txt` and in
the new Python module so it also accompanies installed package source. This is an
adaptation of those designs and selected sanitiser rules, not an import of its
TypeScript runtime. ScopeRail's surrounding project licence is unchanged.

## Tests and deployment boundary

`python -m unittest discover -s tests -p test_execution_review.py -v` exercises real
SQLite and filesystem boundaries, sanitisation, Unicode pages, presentation and
real Python subprocesses. The handler contract tests execute the actual handler
AST without its decorators and inspect the registration syntax. They are **not**
MCP transport or OAuth integration tests.

Before deployment, run the complete suite in the project's supported macOS
Python environment, refresh the client's MCP tool schema, and smoke-test both
HTTP and stdio clients against temporary workspaces. Check small output, large
output, failed commands, idempotent retries, revocation and live PTY jobs. Do not
replace a running checkout that has divergent files or uncommitted changes by
force. The delivered patch does not install, publish, restart or widen access.
