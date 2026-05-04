"""Run the OWASP test suite and emit a markdown coverage report.

Usage:
    python scripts/owasp_report.py

Writes:
    docs/owasp_report.md   ← per-category pass/fail table
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPORT_PATH = Path("docs/owasp_report.md")
JSON_REPORT = Path(".pytest_owasp.json")


CATEGORY_MAP = {
    "test_llm01":      ("LLM01", "Prompt Injection (direct)"),
    "test_llm02":      ("LLM02", "Insecure Output Handling"),
    "test_llm03":      ("LLM03", "Indirect Injection (RAG / docs)"),
    "test_llm04":      ("LLM04", "Model DoS / oversize input"),
    "test_llm06":      ("LLM06", "Sensitive Information Disclosure"),
    "test_borderline": ("FP-1",  "Borderline-safe (look like attacks, are not)"),
    "test_safe":       ("FP-2",  "Plain-safe prompts pass"),
}


def main() -> int:
    print("Running pytest with JSON report...")
    rc = subprocess.run(
        [
            sys.executable, "-m", "pytest", "tests/owasp",
            "--tb=short", "-q",
            f"--json-report-file={JSON_REPORT}", "--json-report",
        ],
        check=False,
    ).returncode

    if not JSON_REPORT.exists():
        print("pytest-json-report not installed — falling back to plain report")
        REPORT_PATH.write_text(
            "# OWASP LLM Top-10 Test Report\n\n"
            "(install `pytest-json-report` for a per-test breakdown)\n"
        )
        return rc

    data = json.loads(JSON_REPORT.read_text())
    tests = data.get("tests", [])

    buckets: dict[str, list[dict]] = {}
    for t in tests:
        nodeid = t["nodeid"]
        m = re.search(r"test_([a-z]+\d*|safe)_", nodeid)
        key_prefix = nodeid.split("::")[0].split("/")[-1].replace(".py", "")
        # match test_llm01_*, test_llm02_*, etc. or test_safe_*
        cat_key = next(
            (k for k in CATEGORY_MAP if key_prefix.startswith(k)),
            "other",
        )
        buckets.setdefault(cat_key, []).append(t)

    lines = [
        "# OWASP LLM Top-10 — Coverage Report",
        "",
        f"Total tests: **{data['summary'].get('total', 0)}** · "
        f"passed: **{data['summary'].get('passed', 0)}** · "
        f"failed: **{data['summary'].get('failed', 0)}** · "
        f"duration: **{data['duration']:.1f}s**",
        "",
        "| Category | Title | Pass | Fail | Skip |",
        "|----------|-------|------|------|------|",
    ]
    for key, (code, title) in CATEGORY_MAP.items():
        items = buckets.get(key, [])
        passed = sum(1 for i in items if i["outcome"] == "passed")
        failed = sum(1 for i in items if i["outcome"] == "failed")
        skipped = sum(1 for i in items if i["outcome"] == "skipped")
        lines.append(f"| {code} | {title} | {passed} | {failed} | {skipped} |")

    lines.append("")
    lines.append("## Per-test outcomes")
    lines.append("")
    for key, (code, title) in CATEGORY_MAP.items():
        items = buckets.get(key, [])
        if not items:
            continue
        lines.append(f"### {code} · {title}")
        for t in items:
            mark = {"passed": "✅", "failed": "❌", "skipped": "⚠️"}.get(t["outcome"], "?")
            short = t["nodeid"].split("::")[-1]
            lines.append(f"- {mark} `{short}`")
        lines.append("")

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text("\n".join(lines))
    print(f"Wrote {REPORT_PATH}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
