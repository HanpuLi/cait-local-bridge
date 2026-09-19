#!/usr/bin/env python3
"""Collect auditable OSS health signals without inventing unavailable dependency metrics."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def gh(endpoint: str):
    cp = subprocess.run(["gh", "api", endpoint], text=True, capture_output=True, check=True, timeout=60)
    return json.loads(cp.stdout)


def http_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "scoperail-oss-health/0.1"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)


def external_pr_metrics(repo: str) -> dict | None:
    script = Path(__file__).with_name("contributor-metrics.py")
    try:
        cp = subprocess.run(
            [sys.executable, str(script), "--repo", repo, "--stdout"],
            text=True, capture_output=True, check=True, timeout=120,
        )
        return json.loads(cp.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None


def criticality_metric(repo: str, command: str | None = None) -> dict:
    tool = command or shutil.which("criticality_score")
    if not tool:
        return {
            "value": None,
            "status": "unavailable",
            "reason": "OpenSSF criticality_score executable is not installed.",
        }
    try:
        cp = subprocess.run(
            [tool, "-depsdev-disable", "-format", "json", f"https://github.com/{repo}"],
            text=True, capture_output=True, check=True, timeout=120,
        )
        result = json.loads(cp.stdout)
        value = float(result["default_score"])
        return {
            "value": value,
            "status": "measured",
            "source": "OpenSSF criticality_score",
            "method": "v2 CLI, deps.dev disabled; GitHub signals only",
            "full_default_status": "not_measured",
            "note": "The full deps.dev-enriched run may differ and requires Google Cloud ADC.",
        }
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, KeyError, ValueError) as exc:
        return {
            "value": None,
            "status": "unavailable",
            "reason": f"criticality_score failed: {type(exc).__name__}",
        }


def collect(repo: str, package: str, registry_name: str, criticality_command: str | None = None) -> dict:
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    repository_status = "ok"
    try:
        meta = gh(f"/repos/{repo}")
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        meta = {}
        repository_status = "unavailable"

    try:
        releases = gh(f"/repos/{repo}/releases?per_page=100") if meta else []
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        releases = []
    contrib = external_pr_metrics(repo)

    downloads = {"value": None, "source": "pypistats", "status": "unavailable"}
    try:
        recent = http_json(f"https://pypistats.org/api/packages/{urllib.parse.quote(package)}/recent")
        downloads = {
            "value": recent.get("data", {}).get("last_month"),
            "source": "https://pypistats.org/api/packages/<package>/recent",
            "status": "ok",
        }
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError):
        pass

    registry = {"published": False, "source": "MCP Registry", "status": "not_found_or_unavailable"}
    try:
        q = urllib.parse.quote(registry_name, safe="")
        result = http_json(f"https://registry.modelcontextprotocol.io/v0.1/servers?search={q}")
        servers = result.get("servers") or []
        exact = [s for s in servers if (s.get("server") or {}).get("name") == registry_name]
        registry = {"published": bool(exact), "matches": len(exact), "source": "MCP Registry", "status": "ok"}
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError):
        pass

    contrib_ok = contrib is not None and contrib.get("status") == "ok"
    return {
        "repository": repo,
        "repository_status": repository_status,
        "last_updated": now,
        "stars": meta.get("stargazers_count"),
        "forks": meta.get("forks_count"),
        "open_issues": meta.get("open_issues_count"),
        "releases": len(releases) if meta else None,
        "external_contributors_12m": contrib.get("unique_external_authors") if contrib_ok else None,
        "external_merged_prs_12m": len(contrib.get("qualifying_prs", [])) if contrib_ok else None,
        "package": package,
        "monthly_downloads": downloads,
        "dependent_repositories": {
            "value": None,
            "status": "unavailable",
            "reason": "GitHub does not expose a reliable public REST count for dependency-graph dependents.",
        },
        "dependent_packages": {
            "value": None,
            "status": "unavailable",
            "reason": "No reliable ecosystem-agnostic public API is assumed.",
        },
        "openssf_criticality": criticality_metric(repo, criticality_command),
        "mcp_registry": registry,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="HanpuLi/scoperail")
    ap.add_argument("--package", default="scoperail")
    ap.add_argument("--registry-name", default="io.github.hanpuli/scoperail")
    ap.add_argument("--criticality-command", help="path to the official OpenSSF criticality_score executable")
    ap.add_argument("--output", type=Path, default=Path("metrics/oss-health.json"))
    ap.add_argument("--stdout", action="store_true")
    args = ap.parse_args()
    result = collect(args.repo, args.package, args.registry_name, args.criticality_command)
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.stdout:
        print(rendered, end="")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered)
    print(args.output)


if __name__ == "__main__":
    main()
