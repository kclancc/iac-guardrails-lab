#!/usr/bin/env python3
"""Render an FCS SARIF report as a Markdown PR comment.

Usage: sarif-to-md.py <input.sarif> <output.md>

Produces a sticky-comment-friendly Markdown body with a summary line,
severity counts, and a table of findings sorted by severity.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import unquote

SEVERITY_ORDER = {"error": 0, "warning": 1, "note": 2, "none": 3}
SEVERITY_ICON = {"error": "🔴", "warning": "🟡", "note": "🔵", "none": "⚪"}


def load_results(sarif_path: Path) -> list[dict]:
    if not sarif_path.exists():
        return []
    data = json.loads(sarif_path.read_text())
    results: list[dict] = []
    for run in data.get("runs", []):
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for r in run.get("results", []):
            level = r.get("level", "warning")
            rule_id = r.get("ruleId", "")
            rule = rules.get(rule_id, {})
            msg = r.get("message", {}).get("text") or rule.get("shortDescription", {}).get("text", "")
            help_uri = r.get("helpUri") or rule.get("helpUri")
            locs = r.get("locations") or [{}]
            physical = locs[0].get("physicalLocation", {})
            uri = unquote(physical.get("artifactLocation", {}).get("uri", "?"))
            region = physical.get("region", {}) or {}
            line = region.get("startLine", "?")
            results.append(
                {
                    "level": level,
                    "rule_id": rule_id,
                    "message": msg,
                    "file": uri,
                    "line": line,
                    "help_uri": help_uri,
                }
            )
    return results


def render(results: list[dict]) -> str:
    if not results:
        return (
            "### Falcon Cloud Security — IaC Scan\n\n"
            "**No issues found.** All scanned Terraform / YAML / Dockerfile "
            "resources pass the current FCS policy set.\n"
        )

    counts = Counter(r["level"] for r in results)
    summary_parts = []
    for level in ("error", "warning", "note"):
        if counts.get(level):
            summary_parts.append(f"{SEVERITY_ICON[level]} {counts[level]} {level}")

    results.sort(key=lambda r: (SEVERITY_ORDER.get(r["level"], 99), r["file"], r["line"]))

    lines = [
        "### Falcon Cloud Security — IaC Scan",
        "",
        f"Found **{len(results)} issue(s)** in this PR — {' · '.join(summary_parts)}.",
        "",
        "| Severity | Location | Rule | Message |",
        "| --- | --- | --- | --- |",
    ]
    for r in results:
        icon = SEVERITY_ICON.get(r["level"], "⚪")
        loc = f"`{r['file']}:{r['line']}`"
        rule = f"[`{r['rule_id']}`]({r['help_uri']})" if r["help_uri"] else f"`{r['rule_id']}`"
        msg = r["message"].replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {icon} {r['level']} | {loc} | {rule} | {msg} |")

    lines.extend(
        [
            "",
            "_High-severity findings block merge via branch protection. "
            "Push a fix and this comment will update in place._",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: sarif-to-md.py <input.sarif> <output.md>", file=sys.stderr)
        return 2
    sarif = Path(sys.argv[1])
    out = Path(sys.argv[2])
    out.write_text(render(load_results(sarif)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
