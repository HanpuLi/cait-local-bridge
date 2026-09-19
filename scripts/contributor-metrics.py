#!/usr/bin/env python3
"""Audit rolling 12-month merged external contributors for a GitHub repository."""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import subprocess
from pathlib import Path


def _gh_json(endpoint: str):
    cp = subprocess.run(
        ["gh", "api", "--paginate", "--slurp", endpoint],
        text=True, capture_output=True, check=True, timeout=120,
    )
    pages = json.loads(cp.stdout)
    if pages and isinstance(pages[0], list):
        return [item for page in pages for item in page]
    return pages


def _cutoff(now: dt.datetime) -> dt.datetime:
    try:
        return now.replace(year=now.year - 1)
    except ValueError:
        return now.replace(year=now.year - 1, day=28)


def _unavailable(repo: str, cutoff: dt.datetime, now: dt.datetime, reason: str) -> dict:
    return {
        "repository": repo,
        "status": "unavailable",
        "reason": reason,
        "window_start": cutoff.isoformat(),
        "window_end": now.isoformat(),
        "unique_external_authors": None,
        "authors": {},
        "qualifying_prs": [],
        "exclusions": ["repository owner", "GitHub Bot type", "login ending [bot] or -bot"],
        "note": "Audit metric only. Do not create or merge trivial PRs to change this count.",
        "last_updated": now.isoformat(),
    }


def collect(repo: str, owner: str | None = None, now: dt.datetime | None = None) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc)
    cutoff = _cutoff(now)
    owner = (owner or repo.split("/", 1)[0]).lower()
    try:
        pulls = _gh_json(f"/repos/{repo}/pulls?state=closed&sort=updated&direction=desc&per_page=100")
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        reason = "repository or GitHub API unavailable"
        if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
            reason = exc.stderr.strip().splitlines()[-1][:300]
        return _unavailable(repo, cutoff, now, reason)

    qualifying = []
    by_author: dict[str, list[dict]] = collections.defaultdict(list)
    for pr in pulls:
        merged = pr.get("merged_at")
        user = pr.get("user") or {}
        login = str(user.get("login") or "")
        if not merged or not login:
            continue
        merged_at = dt.datetime.fromisoformat(merged.replace("Z", "+00:00"))
        if merged_at < cutoff:
            continue
        lower = login.lower()
        if lower == owner or user.get("type") == "Bot" or lower.endswith("[bot]") or lower.endswith("-bot"):
            continue
        item = {
            "number": pr.get("number"),
            "url": pr.get("html_url"),
            "merged_at": merged,
            "author": login,
        }
        qualifying.append(item)
        by_author[login].append(item)

    return {
        "repository": repo,
        "status": "ok",
        "window_start": cutoff.isoformat(),
        "window_end": now.isoformat(),
        "unique_external_authors": len(by_author),
        "authors": {
            login: {"merged_pr_count": len(items), "prs": [x["url"] for x in items]}
            for login, items in sorted(by_author.items(), key=lambda kv: (-len(kv[1]), kv[0].lower()))
        },
        "qualifying_prs": sorted(qualifying, key=lambda x: x["merged_at"]),
        "exclusions": ["repository owner", "GitHub Bot type", "login ending [bot] or -bot"],
        "note": "Audit metric only. Do not create or merge trivial PRs to change this count.",
        "last_updated": now.isoformat(),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="HanpuLi/cait-local-bridge")
    ap.add_argument("--owner")
    ap.add_argument("--output", type=Path, default=Path("metrics/contributors.json"))
    ap.add_argument("--stdout", action="store_true")
    args = ap.parse_args()
    result = collect(args.repo, args.owner)
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.stdout:
        print(rendered, end="")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered)
    print(args.output)


if __name__ == "__main__":
    main()
