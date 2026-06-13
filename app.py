#!/usr/bin/env python3
"""Streamlit UI for RulePilot.

Three tabs:
  1. Suspicious Command Execution (worked example)
  2. Failed Login (worked example)
  3. Custom Rule (user-supplied baseline SPL + intent)

A "Live / Replay" toggle in the sidebar controls whether each Run button
invokes Splunk + the LLM, or loads the most recently saved JSON report for
that scenario from ``reports/samples/``.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import streamlit as st

from src.agent import RulePilotAgent
from src.models import build_model_client
from src.reporting import compute_before_after_metrics, write_markdown_report
from src.scenarios import (
    AUTH_FIELDS,
    PROCESS_FIELDS,
    Scenario,
    build_scenario,
    custom_scenario,
)
from src.splunk_client import SplunkClient, SplunkClientError


# UI model label → provider key understood by build_model_client.
MODEL_PROVIDERS = {
    "Frontier (OpenAI)": "openai",
    "Local (Qwen)": "local",
    "Splunk AI Assistant (MCP)": "splunk_ai",
}


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
    provider: str,
) -> dict[str, Any]:
    client = SplunkClient.from_env()
    model_client = build_model_client(provider, index=client.index)
    agent = RulePilotAgent(client, model_client=model_client)
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


def render_save_golden_button(
    scenario_key: str,
    report: dict[str, Any],
    *,
    run_settings: dict[str, Any],
) -> None:
    """In Live mode, let the analyst promote the current run to the golden
    Replay sample. Live runs no longer auto-save, so a later unstable run cannot
    clobber a good sample — you save it on purpose."""
    if run_settings.get("mode") == "Replay saved sample":
        return
    st.divider()
    if st.button(
        "Save as golden replay sample",
        key=f"save_golden_{scenario_key}",
        help="Overwrites reports/samples/"
        f"{scenario_key}.json — Replay mode loads this. Commit it to keep it.",
    ):
        # Capture the current must-preserve check too, so Replay mode can show
        # the same compiled check (the "Generate" step is also model-dependent).
        golden = dict(report)
        golden["_golden_check_spl"] = st.session_state.get(
            f"{scenario_key}_preserve_spl", ""
        )
        golden["_golden_check_keys"] = st.session_state.get(
            f"{scenario_key}_preserve_keys", ""
        )
        path = save_sample(scenario_key, golden)
        st.success(
            f"Saved golden replay → {path.relative_to(REPO_ROOT)}. "
            "Replay mode will now load this run and its must-preserve check."
        )


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

    final_status = report.get("final_status") or "accepted"
    accepted = report.get("final_status_is_accepted")
    if accepted is None:  # legacy reports without final_status
        accepted = True

    if not accepted:
        st.error(
            f"**No acceptable refinement was produced.** "
            f"All {len(report.get('iterations') or [])} attempts ended in "
            f"`{final_status}`. The metrics, downloads, and refined SPL "
            f"below show the **last attempted** candidate for transparency — "
            f"do not treat it as a working rule. Review the iteration history "
            f"to see what went wrong."
        )

    preservation_pct = report.get("preservation_pct")
    must_preserve_total = report.get("must_preserve_total")
    show_preservation = preservation_pct is not None and accepted

    cols = st.columns(4 if show_preservation else 3)
    cols[0].metric("Baseline result rows", metrics.get("baseline_result_count") or 0)

    if not accepted:
        cols[1].metric("Refined result rows", "—", delta="no accepted refinement")
        cols[2].metric("FP reduction", "—", delta="—")
    else:
        cols[1].metric(
            "Refined result rows", metrics.get("refined_result_count") or 0
        )
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
        badge = "accepted" if accepted else final_status
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
        st.caption(
            "Refined (last attempted, NOT accepted)"
            if not accepted
            else "Refined"
        )
        st.code(report.get("refined_spl") or "", language="text")

    st.divider()
    st.subheader("Downloads")
    refined_spl = report.get("refined_spl") or ""
    scenario_key = report.get("scenario") or "rule"
    if not accepted:
        st.caption(
            "Downloads reflect the last attempted candidate, which was not "
            "accepted by RulePilot. Use only if you intend to debug the "
            "model's output."
        )
    st.download_button(
        "Download refined SPL",
        data=refined_spl,
        file_name=(
            f"{scenario_key}_refined.spl"
            if accepted
            else f"{scenario_key}_LAST_REJECTED.spl"
        ),
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

FIELD_SETS = {
    "auth": AUTH_FIELDS,
    "process": PROCESS_FIELDS,
    "both": list(dict.fromkeys(AUTH_FIELDS + PROCESS_FIELDS)),
}


def _field_set_label(fields: list[str]) -> str:
    if fields == AUTH_FIELDS:
        return "auth"
    if fields == PROCESS_FIELDS:
        return "process"
    return "both"


def _rule_input_form(
    *, key_prefix: str, defaults: dict[str, Any], provider: str
) -> dict[str, Any]:
    """Render the shared rule-input form and return the (possibly edited) values.

    The same form drives all three tabs — the two hero tabs pre-fill it from a
    curated scenario, the Custom tab pre-fills it with a worked example. This is
    what an analyst fills in to get a refinement report.
    """
    # The compiled-check fields are driven through session_state so the
    # "Generate from description" button can populate them; seed once.
    spl_key = f"{key_prefix}_preserve_spl"
    keys_key = f"{key_prefix}_preserve_keys"
    st.session_state.setdefault(spl_key, defaults["preservation_check_spl"])
    st.session_state.setdefault(keys_key, defaults["preservation_keys"])

    baseline_spl = st.text_area(
        "Baseline SPL",
        value=defaults["baseline_spl"],
        height=120,
        key=f"{key_prefix}_spl",
        placeholder="search index=<your_index> … — the noisy detection to tune",
    )
    context_hint = st.text_input(
        "Context / goal (what kind of detection is this?)",
        value=defaults["context_hint"],
        key=f"{key_prefix}_context",
        placeholder="e.g. Detect suspicious process execution, cutting routine admin noise",
    )
    must_preserve = st.text_input(
        "Must-preserve behavior (the real suspicious activity the rule "
        "MUST still catch after refinement)",
        value=defaults["must_preserve"],
        key=f"{key_prefix}_preserve",
        placeholder="In plain English: what must the rule never stop catching?",
    )

    field_options = ["auth", "process", "both"]
    field_set = st.selectbox(
        "Available fields",
        options=field_options,
        index=field_options.index(defaults["field_set"]),
        key=f"{key_prefix}_fields",
    )

    st.markdown(
        "**Must-preserve check (the verification gate).** RulePilot runs this "
        "search to learn which entities the refined rule MUST still surface, "
        "then proves it covers ≥80% of them. Describe the behavior above in "
        "plain English and let the model compile the SPL, or write/edit it "
        "directly. Leave it blank to skip verification."
    )
    if st.button(
        "Generate check from the description",
        key=f"{key_prefix}_gen_check",
    ):
        try:
            from src.agent import compile_preservation_check

            client = SplunkClient.from_env()
            with st.spinner("Compiling the must-preserve description to SPL…"):
                spl, key_fields = compile_preservation_check(
                    model_client=build_model_client(provider, index=client.index),
                    splunk_client=client,
                    must_preserve=must_preserve,
                    baseline_spl=baseline_spl,
                    available_fields=FIELD_SETS[field_set],
                    index=client.index,
                )
            st.session_state[spl_key] = spl
            st.session_state[keys_key] = ", ".join(key_fields)
            st.success("Generated. Review and edit below, then press Run.")
            st.rerun()
        except SplunkClientError as exc:
            st.error(f"Splunk error: {exc}")
        except Exception as exc:
            st.error(f"Could not generate the check: {exc}")

    preservation_spl = st.text_area(
        "Must-preserve check (SPL)",
        height=120,
        key=spl_key,
        placeholder=(
            "Click 'Generate check from the description' above, or paste a "
            "read-only search ending in `| stats count by <key fields>`."
        ),
    )
    preservation_keys_raw = st.text_input(
        "Must-preserve key fields (comma-separated entity fields the check is "
        "aggregated by)",
        key=keys_key,
        placeholder="e.g. user, src_ip",
    )
    return {
        "baseline_spl": baseline_spl,
        "context_hint": context_hint,
        "must_preserve": must_preserve,
        "preservation_check_spl": preservation_spl,
        "preservation_key_fields": [
            f.strip() for f in preservation_keys_raw.split(",") if f.strip()
        ],
        "available_fields": FIELD_SETS[field_set],
    }


def render_demo_tab(scenario_key: str, run_settings: dict[str, Any]) -> None:
    base = build_scenario(scenario_key, index=_index_from_env())
    st.markdown(f"**{base.title}**")
    st.caption(
        "Pre-filled example — these are the inputs an analyst supplies. The same "
        "form drives the Custom Rule tab; edit any field, or just press Run."
    )

    # In Replay mode, pre-fill the must-preserve check from the golden sample so
    # the demo is deterministic (the "Generate" step is model-dependent). In
    # Live mode the check starts empty — the analyst generates or pastes it.
    golden = (
        load_sample(scenario_key)
        if run_settings["mode"] == "Replay saved sample"
        else None
    ) or {}
    defaults = {
        "baseline_spl": base.baseline_spl,
        "context_hint": base.context_hint,
        "must_preserve": base.must_preserve,
        "preservation_check_spl": golden.get("_golden_check_spl", ""),
        "preservation_keys": golden.get("_golden_check_keys", ""),
        "field_set": _field_set_label(base.available_fields),
    }
    values = _rule_input_form(
        key_prefix=scenario_key,
        defaults=defaults,
        provider=run_settings["provider"],
    )

    state_key = f"report_{scenario_key}"
    if st.button("Run", key=f"run_{scenario_key}", type="primary"):
        # Keep the scenario's curated diagnostics, metric fields, and output path
        # (reliability), but let the analyst-facing fields flow through from the
        # form so the two hero tabs are genuinely the same interface as Custom.
        scenario = dataclasses.replace(
            base,
            baseline_spl=values["baseline_spl"].strip(),
            context_hint=values["context_hint"].strip(),
            must_preserve=values["must_preserve"].strip(),
            available_fields=values["available_fields"],
            preservation_check_spl=values["preservation_check_spl"].strip() or None,
            preservation_key_fields=values["preservation_key_fields"],
        )
        report = _execute_or_replay(scenario, run_settings, state_key)
        if report is not None:
            st.session_state[state_key] = report

    report = st.session_state.get(state_key)
    if report:
        render_report(report)
        render_save_golden_button(scenario_key, report, run_settings=run_settings)
    else:
        st.info("Press **Run** to generate a report.")


def render_custom_tab(run_settings: dict[str, Any]) -> None:
    st.markdown("**Custom Rule** — bring your own baseline SPL.")
    st.caption(
        "The same form as the two examples, blank for your own rule. RulePilot "
        "plans diagnostics from your SPL, refines, then verifies against your "
        "must-preserve check."
    )

    idx = _index_from_env()
    # The custom tab is "bring your own rule" — every field starts blank and is
    # guided by placeholder text in the shared form. In Replay mode the check is
    # pre-filled from the golden sample so the demo is deterministic.
    golden = (
        load_sample("custom")
        if run_settings["mode"] == "Replay saved sample"
        else None
    ) or {}
    defaults = {
        "baseline_spl": "",
        "context_hint": "",
        "must_preserve": "",
        "preservation_check_spl": golden.get("_golden_check_spl", ""),
        "preservation_keys": golden.get("_golden_check_keys", ""),
        "field_set": "both",
    }
    values = _rule_input_form(
        key_prefix="custom",
        defaults=defaults,
        provider=run_settings["provider"],
    )

    if st.button("Run", key="run_custom", type="primary"):
        scenario = custom_scenario(
            index=idx,
            baseline_spl=values["baseline_spl"],
            context_hint=values["context_hint"],
            must_preserve=values["must_preserve"],
            available_fields=values["available_fields"],
            preservation_check_spl=values["preservation_check_spl"],
            preservation_key_fields=values["preservation_key_fields"],
        )
        report = _execute_or_replay(scenario, run_settings, "report_custom")
        if report is not None:
            st.session_state["report_custom"] = report

    report = st.session_state.get("report_custom")
    if report:
        render_report(report)
        render_save_golden_button("custom", report, run_settings=run_settings)
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
                provider=run_settings["provider"],
            )
        except SplunkClientError as exc:
            st.error(f"Splunk error: {exc}")
            return None
        except RuntimeError as exc:
            st.error(f"Run failed: {exc}")
            return None

    # Do NOT auto-save here. Auto-saving every run would let a later unstable
    # run overwrite a good "golden" Replay sample. The analyst promotes a run
    # explicitly via the "Save as golden replay sample" button.
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

        provider_label = st.selectbox(
            "Model",
            options=list(MODEL_PROVIDERS.keys()),
            index=0,
            help=(
                "Which model powers diagnostics, refinement, and the "
                "natural-language → SPL must-preserve compiler. A misconfigured "
                "or unreachable model surfaces a clear error on Run."
            ),
        )

        st.divider()
        st.subheader("Splunk MCP")
        st.caption(
            "Diagnostic: verify the Splunk MCP server is reachable with the "
            "configured endpoint + encrypted token."
        )
        if st.button("Test MCP connection", key="mcp_test"):
            _render_mcp_test_result()

    run_settings = {
        "mode": mode,
        "earliest_time": earliest_time,
        "latest_time": latest_time,
        "max_results": int(max_results),
        "provider": MODEL_PROVIDERS[provider_label],
    }

    tab1, tab2, tab3 = st.tabs(
        ["Suspicious Command", "Failed Login", "Custom Rule"]
    )
    with tab1:
        render_demo_tab("suspicious_command", run_settings)
    with tab2:
        render_demo_tab("failed_login", run_settings)
    with tab3:
        render_custom_tab(run_settings)


def _render_mcp_test_result() -> None:
    try:
        from src.splunk_mcp_client import (
            SplunkMCPClient,
            SplunkMCPClientError,
        )
    except ModuleNotFoundError:
        st.error(
            "The `mcp` Python package is not installed. Run: pip install mcp"
        )
        return

    try:
        client = SplunkMCPClient.from_env()
    except SplunkMCPClientError as exc:
        st.error(str(exc))
        return

    with st.spinner("Listing MCP tools..."):
        try:
            result = client.ping()
        except SplunkMCPClientError as exc:
            st.error(f"MCP connection failed: {exc}")
            return

    st.success(
        f"Connected to {result['endpoint']} — {result['tool_count']} tools "
        f"available."
    )
    if result["sample_tool_names"]:
        st.caption("Sample tool names:")
        for name in result["sample_tool_names"]:
            st.markdown(f"- `{name}`")


if __name__ == "__main__":
    main()
