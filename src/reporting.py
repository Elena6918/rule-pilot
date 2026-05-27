#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
from typing import Any


def compute_before_after_metrics(report: dict[str, Any]) -> dict[str, Any]:
    diagnostics = report.get("diagnostic_results", {})
    baseline_result_count = _optional_int(report.get("baseline_result_count"))
    refined_result_count = _optional_int(report.get("refined_result_count"))

    metric_fields = report.get("metric_fields") or _infer_metric_fields(diagnostics)
    burst_name = report.get("burst_diagnostic_name") or _infer_burst_name(diagnostics)

    top_values: dict[str, dict[str, Any]] = {}
    for field in metric_fields:
        diagnostic_name = f"count_by_{field}"
        rows = _diagnostic_rows(diagnostics, diagnostic_name)
        value, count = _top_value_and_count(rows, field)
        top_values[field] = {"value": value, "count": count}

    burst_count = (
        _diagnostic_result_count(diagnostics, burst_name) if burst_name else None
    )

    metrics: dict[str, Any] = {
        "baseline_result_count": baseline_result_count,
        "refined_result_count": refined_result_count,
        "metric_fields": list(metric_fields),
        "top_values": top_values,
        "burst_diagnostic_name": burst_name,
        "burst_group_count": burst_count,
        "absolute_reduction": None,
        "percent_reduction": None,
    }

    if baseline_result_count is not None and refined_result_count is not None:
        metrics["absolute_reduction"] = baseline_result_count - refined_result_count
        if baseline_result_count > 0:
            metrics["percent_reduction"] = round(
                (metrics["absolute_reduction"] / baseline_result_count) * 100,
                1,
            )

    return metrics


def render_markdown_report(report: dict[str, Any], metrics: dict[str, Any]) -> str:
    scenario = str(report.get("scenario_title") or report.get("scenario") or "unknown")
    baseline_spl = str(report.get("baseline_spl") or "")
    refined_spl = str(report.get("refined_spl") or "")
    diagnosis = str(report.get("diagnosis_text") or "No diagnosis text was produced.")
    rationale = str(
        report.get("refinement_rationale") or "No refinement rationale was produced."
    )
    expected_effect = str(report.get("expected_effect") or "")
    risk = str(report.get("risk") or "")
    refined_path = str(report.get("refined_spl_output_path") or "unknown")

    lines = [
        f"# RulePilot Tuning Report — {scenario}",
        "",
        "## Summary",
        "",
        (
            "RulePilot executed the baseline SPL, ran diagnostic searches, generated "
            "a refined rule, and computed before/after alert-volume proxy metrics. "
            "Result counts are result rows, not confirmed false positives."
        ),
        "",
        "## Baseline Rule",
        "",
        "```spl",
        baseline_spl,
        "```",
        "",
        "## Diagnostics",
        "",
        _metric_bullet("Baseline result rows", metrics.get("baseline_result_count")),
    ]

    if metrics.get("burst_diagnostic_name"):
        lines.append(
            _metric_bullet(
                f"Burst/cluster groups ({metrics['burst_diagnostic_name']})",
                metrics.get("burst_group_count"),
            )
        )

    for field in metrics.get("metric_fields", []):
        entry = metrics.get("top_values", {}).get(field, {})
        lines.append(
            _metric_bullet_with_count(
                f"Top {field}",
                entry.get("value"),
                entry.get("count"),
            )
        )

    lines += [
        "",
        "## Refined Rule",
        "",
        "```spl",
        refined_spl,
        "```",
        "",
        "## Before/After Metrics",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        _table_row("Baseline result rows", metrics.get("baseline_result_count")),
        _table_row("Refined result rows", metrics.get("refined_result_count")),
        _table_row("Absolute reduction", metrics.get("absolute_reduction")),
        _table_row("Percent reduction", _format_percent(metrics.get("percent_reduction"))),
        "",
        "## Analyst Interpretation",
        "",
        diagnosis,
        "",
        rationale,
        "",
    ]

    if expected_effect:
        lines += ["**Expected effect:** " + expected_effect, ""]
    if risk:
        lines += ["**Risk:** " + risk, ""]

    lines += [
        "## Caveats",
        "",
        "- Result counts are an alert-volume proxy, not a measurement of detection accuracy.",
        "- Synthetic data is used for the demo; validate against representative production data.",
        "- Field availability and normalization should be checked before deploying in another environment.",
        "",
        "## Output Path",
        "",
        f"- Refined SPL: `{refined_path}`",
    ]

    return "\n".join(lines).rstrip() + "\n"


def write_markdown_report(report: dict[str, Any], output_path: str | Path) -> Path:
    path = Path(output_path)
    metrics = compute_before_after_metrics(report)
    markdown = render_markdown_report(report, metrics)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(markdown, encoding="utf-8")
    return path


def _infer_metric_fields(diagnostics: dict[str, Any]) -> list[str]:
    if not isinstance(diagnostics, dict):
        return []
    fields = []
    for name in diagnostics:
        if name.startswith("count_by_"):
            fields.append(name[len("count_by_") :])
    return fields


def _infer_burst_name(diagnostics: dict[str, Any]) -> str | None:
    if not isinstance(diagnostics, dict):
        return None
    for name in diagnostics:
        if "burst" in name or "cluster" in name:
            return name
    return None


def _diagnostic_rows(diagnostics: Any, name: str) -> list[dict[str, Any]]:
    if not isinstance(diagnostics, dict):
        return []

    diagnostic = diagnostics.get(name)
    if not isinstance(diagnostic, dict):
        return []

    rows = diagnostic.get("rows")
    if not isinstance(rows, list):
        return []

    return [row for row in rows if isinstance(row, dict)]


def _diagnostic_result_count(diagnostics: Any, name: str) -> int | None:
    if not isinstance(diagnostics, dict):
        return None

    diagnostic = diagnostics.get(name)
    if not isinstance(diagnostic, dict):
        return None

    result_count = _optional_int(diagnostic.get("result_count"))
    if result_count is not None:
        return result_count

    rows = diagnostic.get("rows")
    if isinstance(rows, list):
        return len(rows)

    return None


def _top_value_and_count(rows: list[dict[str, Any]], field: str) -> tuple[str | None, int | None]:
    if not rows:
        return None, None

    value = rows[0].get(field)
    if value in {None, ""}:
        return None, None

    return str(value), _optional_int(rows[0].get("count"))


def _optional_int(value: Any) -> int | None:
    if value in {None, ""}:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _metric_bullet(label: str, value: Any) -> str:
    return f"- {label}: {_format_value(value)}"


def _metric_bullet_with_count(label: str, value: Any, count: Any) -> str:
    if value in {None, ""}:
        return f"- {label}: N/A"
    if count in {None, ""}:
        return f"- {label}: {value}"
    return f"- {label}: {value} ({count} result rows)"


def _table_row(label: str, value: Any) -> str:
    return f"| {label} | {_format_value(value)} |"


def _format_value(value: Any) -> str:
    if value is None:
        return "N/A"
    return str(value)


def _format_percent(value: Any) -> str | None:
    if value is None:
        return None
    return f"{value}%"
