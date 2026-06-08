#!/usr/bin/env python3
"""Compute analyst-style signals from raw diagnostic rows.

The agent passes raw diagnostic search results to the LLM, but a small local
model struggles to derive insights from raw count tables. ``compute_signals``
pre-computes the kind of numbers an analyst would actually cite — "top user
accounts for X%", "burst groups cover Y% of baseline", "service accounts make
up Z% of failures" — and returns both:

  - ``insights``: a list of short human-readable strings (for the UI and the
    LLM prompt).
  - ``raw``: a flat dict of the underlying numbers (for downstream use, e.g.
    quality gating in the revise loop).
"""

from __future__ import annotations

from typing import Any


def compute_signals(
    *,
    diagnostics: dict[str, Any],
    baseline_count: int,
    metric_fields: list[str] | None = None,
    burst_diagnostic_name: str | None = None,
    service_account_prefix: str = "svc_",
) -> dict[str, Any]:
    metric_fields = metric_fields or _infer_metric_fields(diagnostics)
    burst_diagnostic_name = burst_diagnostic_name or _infer_burst_name(diagnostics)

    insights: list[str] = []
    raw: dict[str, Any] = {"baseline_count": baseline_count}

    insights.append(f"Baseline matches {baseline_count} result rows.")

    # Per-field concentration signals.
    for field in metric_fields:
        rows = _rows(diagnostics, f"count_by_{field}")
        if not rows:
            continue
        total = _sum_counts(rows)
        if total <= 0:
            continue
        top_value, top_count = _row_value_count(rows[0], field)
        top_share = _safe_pct(top_count, total)
        top3_share = _safe_pct(_sum_counts(rows[:3]), total)

        raw[f"top_{field}_value"] = top_value
        raw[f"top_{field}_share_pct"] = top_share
        raw[f"top3_{field}_share_pct"] = top3_share

        if top_value is not None and top_share is not None:
            insights.append(
                f"Top {field} `{top_value}` accounts for "
                f"{top_share}% of matching events."
            )
        if top3_share is not None and top3_share >= 60:
            insights.append(
                f"Top 3 {field} values cover {top3_share}% of matching events "
                f"(highly concentrated)."
            )

        # Service-account share — only meaningful for `user`-like fields.
        if field == "user":
            svc_count = sum(
                _to_int(row.get("count"))
                for row in rows
                if str(row.get(field, "")).startswith(service_account_prefix)
            )
            svc_share = _safe_pct(svc_count, total)
            if svc_share is not None:
                raw["service_account_share_pct"] = svc_share
                if svc_share >= 10:
                    insights.append(
                        f"Service accounts (prefix `{service_account_prefix}`) "
                        f"contribute {svc_share}% of matching events — likely "
                        f"benign noise to exclude."
                    )

    # Burst / cluster signals.
    if burst_diagnostic_name:
        burst_rows = _rows(diagnostics, burst_diagnostic_name)
        burst_groups = len(burst_rows)
        raw["burst_groups"] = burst_groups
        raw["burst_diagnostic_name"] = burst_diagnostic_name
        if burst_groups > 0:
            insights.append(
                f"{burst_groups} suspicious burst/cluster group(s) detected via "
                f"`{burst_diagnostic_name}`."
            )
        else:
            insights.append(
                f"No suspicious bursts/clusters detected via "
                f"`{burst_diagnostic_name}`."
            )

    # Pattern-style diagnostics (e.g. count_by_command_pattern):
    # surface each row as a labeled count so the LLM sees risk distribution.
    for name, diagnostic in (diagnostics or {}).items():
        if not name.endswith("_pattern"):
            continue
        rows = diagnostic.get("rows", []) if isinstance(diagnostic, dict) else []
        if not rows:
            continue
        pattern_field = name[len("count_by_") :] if name.startswith("count_by_") else "pattern"
        risky_rows = [
            row for row in rows if str(row.get(pattern_field, "other")) != "other"
        ]
        risky_total = _sum_counts(risky_rows)
        raw[f"{name}_risky_count"] = risky_total
        if risky_rows:
            parts = []
            for row in risky_rows[:6]:
                label = row.get(pattern_field, "?")
                count = _to_int(row.get("count"))
                parts.append(f"{label}={count}")
            insights.append(
                f"Risk-pattern distribution ({name}): " + ", ".join(parts) + "."
            )

    return {"insights": insights, "raw": raw}


def render_signal_block(signals: dict[str, Any]) -> str:
    insights = signals.get("insights") or []
    if not insights:
        return "(no signals computed)"
    return "\n".join(f"- {line}" for line in insights)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rows(diagnostics: Any, name: str) -> list[dict[str, Any]]:
    if not isinstance(diagnostics, dict):
        return []
    diagnostic = diagnostics.get(name)
    if not isinstance(diagnostic, dict):
        return []
    rows = diagnostic.get("rows")
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]


def _sum_counts(rows: list[dict[str, Any]]) -> int:
    return sum(_to_int(row.get("count")) for row in rows)


def _row_value_count(row: dict[str, Any], field: str) -> tuple[str | None, int]:
    value = row.get(field)
    if value in {None, ""}:
        return None, 0
    return str(value), _to_int(row.get("count"))


def _to_int(value: Any) -> int:
    if value in {None, ""}:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return 0


def _safe_pct(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round((numerator / denominator) * 100, 1)


def _infer_metric_fields(diagnostics: dict[str, Any]) -> list[str]:
    if not isinstance(diagnostics, dict):
        return []
    return [
        name[len("count_by_") :]
        for name in diagnostics
        if name.startswith("count_by_") and not name.endswith("_pattern")
    ]


def _infer_burst_name(diagnostics: dict[str, Any]) -> str | None:
    if not isinstance(diagnostics, dict):
        return None
    for name in diagnostics:
        if "burst" in name or "cluster" in name:
            return name
    return None
