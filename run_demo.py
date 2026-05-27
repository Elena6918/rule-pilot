#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from src.agent import RulePilotAgent
from src.reporting import write_markdown_report
from src.scenarios import build_scenario, SCENARIO_BUILDERS
from src.splunk_client import SplunkClient, SplunkClientError


LINE = "=" * 60
RULE = "-" * 60
TUNNEL_HINT = (
    "ssh -L 8000:localhost:8000 -L 8089:localhost:8089 "
    "<user>@<remote-server>"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the RulePilot hackathon demo.",
    )
    parser.add_argument(
        "--scenario",
        choices=sorted(SCENARIO_BUILDERS.keys()),
        default="failed_login",
        help="Scenario to run.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the full raw JSON report.",
    )
    parser.add_argument(
        "--show-spl",
        action="store_true",
        help="Include baseline and refined SPL in the human-readable output.",
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=1000,
        help="Maximum results to request from each Splunk search.",
    )
    parser.add_argument(
        "--earliest-time",
        default="0",
        help='Earliest Splunk search time. Default: "0".',
    )
    parser.add_argument(
        "--latest-time",
        default="now",
        help='Latest Splunk search time. Default: "now".',
    )
    parser.add_argument(
        "--write-report",
        action="store_true",
        help="Write an analyst-facing Markdown report.",
    )
    parser.add_argument(
        "--report-path",
        default="reports/failed_login_report.md",
        help="Markdown report output path. Default: reports/failed_login_report.md.",
    )
    return parser.parse_args()


def run_scenario(args: argparse.Namespace) -> dict[str, Any]:
    client = SplunkClient.from_env()
    agent = RulePilotAgent(client)
    scenario = build_scenario(args.scenario, index=client.index)
    return agent.run(
        scenario,
        earliest_time=args.earliest_time,
        latest_time=args.latest_time,
        max_results=args.max_results,
    )


def print_human_report(report: dict[str, Any], *, show_spl: bool) -> None:
    diagnostics = report.get("diagnostic_results", {})
    reason_rows = diagnostic_rows(diagnostics, "count_by_reason")
    user_rows = diagnostic_rows(diagnostics, "count_by_user")
    src_ip_rows = diagnostic_rows(diagnostics, "count_by_src_ip")
    burst_rows = diagnostic_rows(diagnostics, "suspicious_failed_login_bursts")

    print(LINE)
    print("RulePilot Demo: Failed Login Rule Refinement")
    print(LINE)
    print()
    print("Scenario:")
    print(f"  {report.get('scenario', 'unknown')}")
    print()
    print("Baseline:")
    print(f"  Result rows: {report.get('baseline_result_count', 0)}")
    if report.get("refined_result_count") is not None:
        print(f"  Refined result rows: {report.get('refined_result_count')}")
    print()
    print("Diagnostics:")
    print_top_rows("  Failed-login reasons:", reason_rows, "reason")
    print_top_rows("  Top users:", user_rows, "user")
    print_top_rows("  Top source IPs:", src_ip_rows, "src_ip")
    print("  Suspicious burst groups:")
    print(f"    {len(burst_rows)}")
    print()
    print("Agent diagnosis:")
    print_wrapped(report.get("diagnosis_text", ""), indent="  ")
    print()
    print("Refinement:")
    print_wrapped(report.get("refinement_rationale", ""), indent="  ")
    print()
    print("Output:")
    print("  Refined SPL written to:")
    print(f"    {relative_path(report.get('refined_spl_output_path', ''))}")
    if report.get("markdown_report_path"):
        print("  Report:")
        print(f"    {relative_path(report.get('markdown_report_path', ''))}")

    if show_spl:
        print()
        print("Baseline SPL:")
        print(RULE)
        print(report.get("baseline_spl", ""))
        print(RULE)
        print()
        print("Refined SPL:")
        print(RULE)
        print(report.get("refined_spl", ""))
        print(RULE)

    print()
    print(LINE)


def diagnostic_rows(
    diagnostics: Any,
    name: str,
) -> list[dict[str, Any]]:
    if not isinstance(diagnostics, dict):
        return []

    diagnostic = diagnostics.get(name, {})
    if not isinstance(diagnostic, dict):
        return []

    rows = diagnostic.get("rows", [])
    if not isinstance(rows, list):
        return []

    return [row for row in rows if isinstance(row, dict)]


def print_top_rows(label: str, rows: list[dict[str, Any]], field: str) -> None:
    print(label)
    if not rows:
        print("    - none")
        print()
        return

    for row in rows[:3]:
        value = row.get(field, "unknown")
        count = row.get("count", "0")
        print(f"    - {value}: {count}")
    print()


def print_wrapped(text: str, *, indent: str, width: int = 78) -> None:
    words = text.split()
    if not words:
        print(indent)
        return

    line = indent
    for word in words:
        next_line = f"{line} {word}" if line.strip() else f"{indent}{word}"
        if len(next_line) > width and line.strip():
            print(line)
            line = f"{indent}{word}"
        else:
            line = next_line
    print(line)


def relative_path(path_value: str) -> str:
    if not path_value:
        return "unknown"

    path = Path(path_value)
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def print_expected_error(error: SplunkClientError) -> None:
    print("RulePilot demo failed.", file=sys.stderr)
    print(str(error), file=sys.stderr)
    print(file=sys.stderr)
    print("If Splunk is remote, check that your SSH tunnel is running:", file=sys.stderr)
    print(f"  {TUNNEL_HINT}", file=sys.stderr)


def main() -> int:
    args = parse_args()

    try:
        report = run_scenario(args)
    except SplunkClientError as exc:
        print_expected_error(exc)
        return 1
    except FileNotFoundError as exc:
        print(f"RulePilot demo failed: {exc}", file=sys.stderr)
        return 1

    if args.write_report:
        report_path = write_markdown_report(report, args.report_path)
        report["markdown_report_path"] = str(report_path)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_human_report(report, show_spl=args.show_spl)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
