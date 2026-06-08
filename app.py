#!/usr/bin/env python3
"""Streamlit UI for RulePilot.

Three tabs:
  1. Failed Login (canned demo scenario)
  2. Suspicious Command Execution (canned demo scenario)
  3. Custom Rule (user-supplied baseline SPL + intent)

A "Live / Replay" toggle in the sidebar controls whether each Run button
invokes Splunk + the LLM, or loads the most recently saved JSON report for
that scenario from ``reports/samples/``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import streamlit as st

from src.agent import RulePilotAgent
from src.reporting import compute_before_after_metrics, write_markdown_report
from src.scenarios import (
    AUTH_FIELDS,
    PROCESS_FIELDS,
    Scenario,
    build_scenario,
    custom_scenario,
)
from src.splunk_client import SplunkClient, SplunkClientError


REPO_ROOT = Path(__file__).resolve().parent
SAMPLES_DIR = REPO_ROOT / "reports" / "samples"
SAMPLES_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Splunk index resolution
# ---------------------------------------------------------------------------

def _index_from_env() -> str:
    import os
    try:
        from dotenv import load_dotenv
        load_dotenv(REPO_ROOT / ".env", override=False)
    except ModuleNotFoundError:
        pass
    return os.getenv("SPLUNK_INDEX", "security")


# ---------------------------------------------------------------------------
# Run helpers
# ---------------------------------------------------------------------------

def run_scenario(
    scenario: Scenario,
    *,
    earliest_time: str,
    latest_time: str,
    max_results: int,
) -> dict[str, Any]:
    client = SplunkClient.from_env()
    agent = RulePilotAgent(client)
    return agent.run(
        scenario,
        earliest_time=earliest_time,
        latest_time=latest_time,
        max_results=max_results,
    )


def save_sample(scenario_key: str, report: dict[str, Any]) -> Path:
    path = SAMPLES_DIR / f"{scenario_key}.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return path


def load_sample(scenario_key: str) -> dict[str, Any] | None:
    path = SAMPLES_DIR / f"{scenario_key}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _normalize_rows(rows: list[Any]) -> list[dict[str, Any]]:
    """Flatten any list/None cell values so pyarrow can build a dataframe."""
    normalized: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        clean: dict[str, Any] = {}
        for key, value in row.items():
            if isinstance(value, list):
                clean[key] = ", ".join(str(v) for v in value)
            elif value is None:
                clean[key] = ""
            else:
                clean[key] = value
        normalized.append(clean)
    return normalized


def render_report(report: dict[str, Any]) -> None:
    metrics = compute_before_after_metrics(report)

    preservation_pct = report.get("preservation_pct")
    must_preserve_total = report.get("must_preserve_total")
    show_preservation = preservation_pct is not None

    cols = st.columns(4 if show_preservation else 3)
    cols[0].metric("Baseline result rows", metrics.get("baseline_result_count") or 0)
    cols[1].metric("Refined result rows", metrics.get("refined_result_count") or 0)
    abs_change = metrics.get("absolute_reduction")
    pct = metrics.get("percent_reduction")
    if abs_change is None or pct is None:
        cols[2].metric("Change vs. baseline", "—")
    elif abs_change > 0:
        cols[2].metric(
            "FP reduction",
            f"{pct}%",
            delta=f"{abs_change} fewer rows",
            delta_color="inverse",
        )
    elif abs_change == 0:
        cols[2].metric("Change vs. baseline", "0%", delta="no change")
    else:
        # Refined returned MORE rows than baseline — surface this clearly.
        cols[2].metric(
            "Increase (refinement failed)",
            f"+{abs(pct)}%",
            delta=f"{abs(abs_change)} more rows",
            delta_color="inverse",
        )
    if show_preservation:
        preservation_label = "Must-preserve coverage"
        preservation_delta = (
            f"{must_preserve_total} key entities"
            if must_preserve_total
            else None
        )
        delta_color = "off" if preservation_pct >= 80 else "inverse"
        cols[3].metric(
            preservation_label,
            f"{preservation_pct}%",
            delta=preservation_delta,
            delta_color=delta_color,
        )

    iterations = report.get("iterations") or []
    if iterations:
        accepted = iterations[-1].get("verdict") == "accepted"
        badge = "accepted" if accepted else iterations[-1].get("verdict", "n/a")
        st.caption(
            f"Refined in {len(iterations)} iteration"
            f"{'s' if len(iterations) != 1 else ''} — final verdict: **{badge}**"
        )

    signals = report.get("signals") or {}
    insights = signals.get("insights") or []
    if insights:
        st.divider()
        st.subheader("Key signals")
        for insight in insights:
            st.markdown(f"- {insight}")

    st.divider()
    st.subheader("Diagnostics")

    diagnostics = report.get("diagnostic_results", {})
    metric_fields = metrics.get("metric_fields", [])
    if metric_fields:
        cols = st.columns(min(len(metric_fields), 3))
        for i, field in enumerate(metric_fields):
            with cols[i % len(cols)]:
                st.caption(f"Top by `{field}`")
                rows = (
                    diagnostics.get(f"count_by_{field}", {}).get("rows", [])
                    if isinstance(diagnostics, dict)
                    else []
                )
                if rows:
                    st.dataframe(
                        _normalize_rows(rows),
                        hide_index=True,
                        width="stretch",
                    )
                else:
                    st.write("_no rows_")

    burst_name = metrics.get("burst_diagnostic_name")
    if burst_name:
        st.caption(f"Burst/cluster groups: `{burst_name}`")
        burst_rows = diagnostics.get(burst_name, {}).get("rows", []) if diagnostics else []
        if burst_rows:
            st.dataframe(
                _normalize_rows(burst_rows),
                hide_index=True,
                width="stretch",
            )
        else:
            st.write(f"_{metrics.get('burst_group_count') or 0} groups_")

    with st.expander("Other diagnostics", expanded=False):
        for name, diag in (diagnostics or {}).items():
            if name in {f"count_by_{f}" for f in metric_fields} or name == burst_name:
                continue
            st.markdown(f"**{name}** — {diag.get('result_count', 0)} rows")
            st.code(diag.get("spl", ""), language="text")

    if iterations and len(iterations) > 1:
        with st.expander(
            f"Refinement iterations ({len(iterations)})", expanded=False
        ):
            for entry in iterations:
                preserve_badge = ""
                if entry.get("preservation_pct") is not None:
                    preserve_badge = (
                        f" — preserved: `{entry['preservation_pct']}%`"
                    )
                st.markdown(
                    f"**Attempt {entry.get('attempt')}** — "
                    f"result rows: `{entry.get('refined_result_count')}` — "
                    f"verdict: `{entry.get('verdict')}`"
                    f"{preserve_badge}"
                )
                st.code(entry.get("candidate_spl", ""), language="text")
                if entry.get("feedback"):
                    st.caption(entry["feedback"])
                st.markdown("---")

    st.divider()
    st.subheader("Agent reasoning")
    with st.expander("Diagnosis", expanded=True):
        st.write(report.get("diagnosis_text") or "_no diagnosis_")
    with st.expander("Refinement strategy & rationale", expanded=True):
        st.write(report.get("refinement_rationale") or "_no rationale_")
        if report.get("expected_effect"):
            st.markdown(f"**Expected effect:** {report['expected_effect']}")
        if report.get("risk"):
            st.markdown(f"**Risk:** {report['risk']}")

    st.divider()
    st.subheader("SPL comparison")
    left, right = st.columns(2)
    with left:
        st.caption("Baseline")
        st.code(report.get("baseline_spl") or "", language="text")
    with right:
        st.caption("Refined")
        st.code(report.get("refined_spl") or "", language="text")

    st.divider()
    st.subheader("Downloads")
    refined_spl = report.get("refined_spl") or ""
    scenario_key = report.get("scenario") or "rule"
    st.download_button(
        "Download refined SPL",
        data=refined_spl,
        file_name=f"{scenario_key}_refined.spl",
        mime="text/plain",
    )
    report_md_path = REPO_ROOT / "reports" / f"{scenario_key}_report.md"
    written = write_markdown_report(report, report_md_path)
    st.download_button(
        "Download Markdown report",
        data=written.read_text(encoding="utf-8"),
        file_name=written.name,
        mime="text/markdown",
    )


# ---------------------------------------------------------------------------
# Tab orchestration
# ---------------------------------------------------------------------------

def render_demo_tab(scenario_key: str, run_settings: dict[str, Any]) -> None:
    scenario = build_scenario(scenario_key, index=_index_from_env())
    st.markdown(f"**{scenario.title}**")
    st.caption(scenario.context_hint)
    with st.expander("Baseline SPL", expanded=False):
        st.code(scenario.baseline_spl, language="text")

    state_key = f"report_{scenario_key}"
    run_clicked = st.button("Run", key=f"run_{scenario_key}", type="primary")

    if run_clicked:
        report = _execute_or_replay(scenario, run_settings, state_key)
        if report is not None:
            st.session_state[state_key] = report

    report = st.session_state.get(state_key)
    if report:
        render_report(report)
    else:
        st.info("Press **Run** to generate a report.")


def render_custom_tab(run_settings: dict[str, Any]) -> None:
    st.markdown("**Custom Rule** — bring your own baseline SPL.")
    st.caption(
        "RulePilot will ask the LLM to plan diagnostic searches from your SPL, "
        "run them, then propose a refined version."
    )

    default_spl = (
        f"search index={_index_from_env()} event_type=process "
        "command_line=*powershell*"
    )
    baseline_spl = st.text_area(
        "Baseline SPL",
        value=default_spl,
        height=120,
        key="custom_spl",
    )
    context_hint = st.text_input(
        "Context / goal (what kind of detection is this?)",
        value="Detect suspicious PowerShell activity, reducing noise from routine admin scripts.",
        key="custom_context",
    )
    must_preserve = st.text_input(
        "Must-preserve behavior (the real suspicious activity the rule "
        "MUST still catch after refinement)",
        value="Encoded PowerShell commands and reverse-shell indicators.",
        key="custom_preserve",
    )
    field_set = st.selectbox(
        "Available fields",
        options=["auth", "process", "both"],
        index=2,
        key="custom_fields",
    )

    if st.button("Run", key="run_custom", type="primary"):
        available_fields = {
            "auth": AUTH_FIELDS,
            "process": PROCESS_FIELDS,
            "both": list(dict.fromkeys(AUTH_FIELDS + PROCESS_FIELDS)),
        }[field_set]
        scenario = custom_scenario(
            index=_index_from_env(),
            baseline_spl=baseline_spl,
            context_hint=context_hint,
            must_preserve=must_preserve,
            available_fields=available_fields,
        )
        report = _execute_or_replay(scenario, run_settings, "report_custom")
        if report is not None:
            st.session_state["report_custom"] = report

    report = st.session_state.get("report_custom")
    if report:
        render_report(report)
    else:
        st.info("Configure your SPL and press **Run**.")


def _execute_or_replay(
    scenario: Scenario,
    run_settings: dict[str, Any],
    state_key: str,
) -> dict[str, Any] | None:
    mode = run_settings["mode"]
    if mode == "Replay saved sample":
        sample = load_sample(scenario.key)
        if sample is None:
            st.warning(
                f"No saved sample for `{scenario.key}` yet. "
                "Switch to Live mode and run once to create one."
            )
            return None
        st.success(f"Loaded saved sample for `{scenario.key}`.")
        return sample

    with st.spinner("Running Splunk searches and calling the LLM..."):
        try:
            report = run_scenario(
                scenario,
                earliest_time=run_settings["earliest_time"],
                latest_time=run_settings["latest_time"],
                max_results=run_settings["max_results"],
            )
        except SplunkClientError as exc:
            st.error(f"Splunk error: {exc}")
            return None
        except RuntimeError as exc:
            st.error(f"Run failed: {exc}")
            return None

    saved = save_sample(scenario.key, report)
    st.success(f"Saved sample → {saved.relative_to(REPO_ROOT)}")
    return report


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    st.set_page_config(page_title="RulePilot", layout="wide")
    st.title("RulePilot")
    st.caption(
        "LLM-assisted Splunk detection tuning — reduce false positives in "
        "noisy rules without losing the events analysts care about. "
        "Pick a scenario, run it, and review the proposed refinement."
    )

    with st.sidebar:
        st.header("Run settings")
        mode = st.radio(
            "Mode",
            ["Live (Splunk + LLM)", "Replay saved sample"],
            index=0,
        )
        earliest_time = st.text_input("Earliest time", value="0")
        latest_time = st.text_input("Latest time", value="now")
        max_results = st.number_input(
            "Max results per search",
            min_value=10,
            max_value=10000,
            value=1000,
            step=100,
        )

    run_settings = {
        "mode": mode,
        "earliest_time": earliest_time,
        "latest_time": latest_time,
        "max_results": int(max_results),
    }

    tab1, tab2, tab3 = st.tabs(
        ["Failed Login", "Suspicious Command", "Custom Rule"]
    )
    with tab1:
        render_demo_tab("failed_login", run_settings)
    with tab2:
        render_demo_tab("suspicious_command", run_settings)
    with tab3:
        render_custom_tab(run_settings)


if __name__ == "__main__":
    main()
