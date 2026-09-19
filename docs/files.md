# File mutation semantics

ScopeRail separates single-file atomic replacement, multi-file staged writes, and unified-diff application because the underlying filesystem guarantees are different.

## Single file: `file_write`

A whole-file write stages bytes in the destination directory, fsyncs the staged file, and replaces the destination with `os.replace`. Overwriting an existing file requires the SHA-256 observed by `file_read`.

The replacement of one directory entry is atomic on the local filesystem. The caller never observes a half-written target file.

## Multiple files: `file_write_batch`

Use `file_write_batch` when a change spans several complete files and every optimistic precondition should be checked before the first target changes.

The call accepts at most 64 mutations and 8 MiB of desired content in total. Existing originals retained for process-level rollback are also bounded to 8 MiB.

Each mutation is a whole-file operation:

```json
{
  "path": "src/example.py",
  "content": "print('new')\n",
  "expected_sha256": "<hash returned by file_read>",
  "create_only": false,
  "encoding": "utf-8",
  "base64_content": false
}
```

For a new file, omit `expected_sha256` or use `"new"`. For an existing changed file, `expected_sha256` is mandatory. A target that already contains the desired bytes is treated as already applied, so a verbatim retry and a retry after a partially observed response are safe.

The batch proceeds in three phases:

1. validate every path, duplicate target, type, content bound, and optimistic hash;
2. stage every pending payload into a temporary file in its destination directory, then re-check paths and hashes;
3. begin per-file `os.replace` commits.

No target content is changed during phases 1–2. A process-level exception during phase 3 triggers best-effort rollback of the already committed prefix from bounded in-memory originals, including removal of newly created files.

### What “atomic” does and does not mean

macOS/POSIX does not provide one rename transaction covering unrelated paths. Each individual replacement is atomic, but the collection is not one kernel transaction. Power loss, kernel failure, or a malicious same-user process racing filesystem state can still leave a committed prefix or interfere with rollback.

For that reason the API describes itself as **staged multi-file write with rollback**, not globally atomic multi-file commit. If a caller requires database-style cross-file atomicity under crash/power-failure semantics, files alone are the wrong storage primitive.

Batch writes deliberately require destination parent directories to exist and reject symlink targets. Create required directories before starting the batch.

## Unified diff: `file_patch`

`file_patch` runs GNU patch in dry-run mode before the real application and can span several files. A rejected dry-run touches nothing. GNU patch itself is not a cross-file transaction; a concurrent change or interruption during the real patch can leave a partial patch.

When the client can supply full desired file contents, prefer `file_write_batch` for stronger preflight/staging/rollback behavior. Use `file_patch` when diff semantics are materially more useful.

## Optimistic concurrency

Do not treat a `conflict` as transient. Re-read the affected files and decide whether the intervening change should be incorporated. ScopeRail never silently overwrites an existing, different file in a batch without a matching expected SHA-256.
