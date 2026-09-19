#!/usr/bin/env python3
"""Collect account-level Claude for Open Source eligibility evidence from GitHub.

This is an audit helper, not a metric-optimisation tool. It counts only public,
substantive-looking GitHub facts that can be verified from the account and keeps
unavailable ecosystem metrics explicitly unavailable.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
from pathlib import Path


def run_json(argv: list[str], timeout: int = 120):
    cp = subprocess.run(argv, text=True, capture_output=True, check=True, timeout=timeout)
    return json.loads(cp.stdout)


def gh_api(endpoint: str):
    return run_json(["gh", "api", endpoint])


def gh_search(query: str) -> list[dict]:
    pages = run_json([
        "gh", "api", "-X", "GET", "search/issues",
        "-f", f"q={query}", "-f", "per_page=100",
        "--paginate", "--slurp",
    ])
    items: list[dict] = []
    for page in pages:
        items.extend(page.get("items", []))
    dedup: dict[tuple[str, int], dict] = {}
    for item in items:
        repo = item["repository_url"].split("/repos/", 1)[-1]
        dedup[(repo, int(item["number"]))] = item
    return list(dedup.values())


def previous_year(now: dt.datetime) -> dt.datetime:
    try:
        return now.replace(year=now.year - 1)
    except ValueError:
        return now.replace(year=now.year - 1, day=28)


def public_source_repos(owner: str) -> list[dict]:
    return run_json([
        "gh", "repo", "list", owner,
        "--source", "--visibility", "public", "--limit", "100",
        "--json", "nameWithOwner,pushedAt,licenseInfo,isArchived",
    ])


def is_bot(user: dict) -> bool:
    login = str(user.get("login") or "")
    lower = login.lower()
    return (
        user.get("type") == "Bot"
        or lower.endswith("[bot]")
        or lower.endswith("-bot")
        or "dependabot" in lower
    )


def criticality(repo: str, command: str | None) -> dict:
    if not command:
        return {"value": None, "status": "unavailable", "reason": "criticality command not supplied"}
    env = dict(os.environ)
    try:
        env["GITHUB_AUTH_TOKEN"] = subprocess.check_output(["gh", "auth", "token"], text=True).strip()
        cp = subprocess.run(
            [command, "-depsdev-disable", "-format", "json", f"https://github.com/{repo}"],
            text=True, capture_output=True, check=True, timeout=120, env=env,
        )
        payload = json.loads(cp.stdout)
        return {
            "value": float(payload["default_score"]),
            "status": "measured",
            "source": "OpenSSF criticality_score",
            "method": "v2 CLI, deps.dev disabled; GitHub signals only",
            "full_default_status": "not_measured",
            "note": "The full deps.dev-enriched score may differ and requires Google Cloud ADC.",
        }
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, KeyError, ValueError) as exc:
        return {"value": None, "status": "unavailable", "reason": type(exc).__name__}


def collect(owner: str, criticality_command: str | None = None, now: dt.datetime | None = None) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc)
    cutoff = previous_year(now)
    since = cutoff.date().isoformat()

    user = gh_api(f"/users/{owner}")
    repos = [r for r in public_source_repos(owner) if not r.get("isArchived")]
    repo_names = [r["nameWithOwner"] for r in repos]

    authored = gh_search(f"is:pr is:merged author:{owner} merged:>={since}")
    owned_prs: list[dict] = []
    external_public_prs: list[dict] = []

    repo_visibility_cache: dict[str, bool] = {}
    for pr in authored:
        repo = pr["repository_url"].split("/repos/", 1)[-1]
        row = {
            "repository": repo,
            "number": pr["number"],
            "url": pr["html_url"],
            "title": pr["title"],
        }
        repo_owner = repo.split("/", 1)[0]
        if repo_owner.lower() == owner.lower():
            owned_prs.append(row)
            continue
        if repo not in repo_visibility_cache:
            try:
                repo_visibility_cache[repo] = not bool(gh_api(f"/repos/{repo}").get("private"))
            except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
                repo_visibility_cache[repo] = False
        if repo_visibility_cache[repo]:
            external_public_prs.append(row)

    per_repo: dict[str, dict] = {}
    highest_external = {"repository": None, "unique_external_humans": 0}
    highest_criticality = {"repository": None, "value": None}
    for repo in repo_names:
        prs = gh_search(f"repo:{repo} is:pr is:merged merged:>={since}")
        humans: set[str] = set()
        bots: set[str] = set()
        for pr in prs:
            u = pr.get("user") or {}
            login = str(u.get("login") or "")
            if not login or login.lower() == owner.lower():
                continue
            if is_bot(u):
                bots.add(login)
            else:
                humans.add(login)
        c = criticality(repo, criticality_command)
        per_repo[repo] = {
            "merged_prs_total_12m": len(prs),
            "unique_external_human_contributors_12m": len(humans),
            "external_human_contributors": sorted(humans),
            "excluded_bot_authors": sorted(bots),
            "openssf_criticality": c,
        }
        if len(humans) > highest_external["unique_external_humans"]:
            highest_external = {"repository": repo, "unique_external_humans": len(humans)}
        value = c.get("value")
        if value is not None and (highest_criticality["value"] is None or value > highest_criticality["value"]):
            highest_criticality = {"repository": repo, "value": value}

    pushed = [r.get("pushedAt") for r in repos if r.get("pushedAt")]
    licenses = {
        r["nameWithOwner"]: (r.get("licenseInfo") or {}).get("spdxId")
        for r in repos
        if (r.get("licenseInfo") or {}).get("spdxId")
    }

    return {
        "owner": owner,
        "status": "ok",
        "window_start": cutoff.isoformat(),
        "window_end": now.isoformat(),
        "last_updated": now.isoformat(),
        "observable_general_eligibility": {
            "github_account_created_at": user.get("created_at"),
            "public_source_repositories": len(repos),
            "latest_public_repository_push_at": max(pushed) if pushed else None,
            "repositories_with_detected_license": licenses,
            "note": "Age/residence/sanctions and Anthropic employment/household conditions require personal attestation.",
        },
        "maintainer_track": {
            "external_public_merged_prs_12m": {
                "value": len(external_public_prs),
                "threshold": 100,
                "owned_repo_merged_prs_excluded": len(owned_prs),
                "qualifying_prs": external_public_prs,
            },
            "external_human_contributors_12m": {
                "highest_repository": highest_external["repository"],
                "value": highest_external["unique_external_humans"],
                "threshold": 20,
                "per_repository": {
                    repo: data["unique_external_human_contributors_12m"]
                    for repo, data in per_repo.items()
                },
                "note": "Repository owner and obvious bot accounts are excluded.",
            },
            "openssf_criticality": {
                "highest_repository": highest_criticality["repository"],
                "value": highest_criticality["value"],
                "threshold": 0.4,
                "method": "GitHub-only measurement when a criticality command is supplied; not the full deps.dev-enriched score.",
            },
            "dependent_repositories": {
                "value": None,
                "threshold": 500,
                "status": "unavailable",
                "reason": "No reliable account-level public API count collected.",
            },
            "dependent_packages": {
                "value": None,
                "threshold": 100,
                "status": "unavailable",
                "reason": "No reliable account-level public API count collected.",
            },
            "monthly_package_downloads": {
                "value": None,
                "threshold": 200000,
                "status": "unavailable",
                "reason": "No qualifying public-registry package download evidence collected at account level.",
            },
            "recognized_foundation_or_language_role": {
                "value": None,
                "status": "requires_applicant_evidence",
            },
        },
        "repositories": per_repo,
        "anti_gaming_note": "Do not create trivial PRs, fake contributors, artificial dependents or repeated downloads to change these values.",
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--owner", default="HanpuLi")
    ap.add_argument("--criticality-command")
    ap.add_argument("--output", type=Path, default=Path("metrics/claude-oss-account.json"))
    ap.add_argument("--stdout", action="store_true")
    args = ap.parse_args()
    payload = collect(args.owner, args.criticality_command)
    text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    if args.stdout:
        print(text, end="")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text)
    print(args.output)


if __name__ == "__main__":
    main()
