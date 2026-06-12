#!/usr/bin/env python3

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

try:
    from src.models import (
        ModelClient,
        has_balanced_parens,
        is_read_only_spl,
        model_client_from_env,
    )
    from src.prompts import (
        build_diagnostic_planning_prompt,
        build_preservation_compilation_prompt,
        build_refinement_prompt,
    )
    from src.scenarios import Scenario, failed_login_scenario
    from src.signals import compute_signals, render_signal_block
    from src.splunk_client import SplunkClient
except ModuleNotFoundError:
    from models import (
        ModelClient,
        has_balanced_parens,
        is_read_only_spl,
        model_client_from_env,
    )
    from prompts import (
        build_diagnostic_planning_prompt,
        build_preservation_compilation_prompt,
        build_refinement_prompt,
    )
    from scenarios import Scenario, failed_login_scenario
    from signals import compute_signals, render_signal_block
    from splunk_client import SplunkClient


class RulePilotAgent:
    def __init__(
        self,
        client: SplunkClient,
        *,
        model_client: ModelClient | None = None,
        max_revisions: int = 2,
    ):
        self.client = client
        self.model_client = model_client or model_client_from_env(index=client.index)
        self.max_revisions = max_revisions

    def run(
        self,
        scenario: Scenario,
        *,
        earliest_time: str = "0",
        latest_time: str = "now",
        max_results: int = 1000,
    ) -> dict[str, Any]:
        baseline_results = self.client.run_search(
            scenario.baseline_spl,
            earliest_time=earliest_time,
            latest_time=latest_time,
            max_results=max_results,
        )
        baseline_count = len(baseline_results)

        diagnostic_plan = self._resolve_diagnostic_plan(scenario)
        diagnostics = self._run_diagnostics(
            diagnostic_plan,
            earliest_time=earliest_time,
            latest_time=latest_time,
            max_results=max_results,
        )

        signals = compute_signals(
            diagnostics=diagnostics,
            baseline_count=baseline_count,
            metric_fields=scenario.metric_fields,
            burst_diagnostic_name=scenario.burst_diagnostic_name,
        )

        must_preserve_keys = self._fetch_must_preserve_keys(
            scenario,
            earliest_time=earliest_time,
            latest_time=latest_time,
            max_results=max_results,
        )

        proposal, iterations, refined_results, final_status = self._refine_with_revisions(
            scenario=scenario,
            baseline_count=baseline_count,
            diagnostics=diagnostics,
            signals=signals,
            must_preserve_keys=must_preserve_keys,
            earliest_time=earliest_time,
            latest_time=latest_time,
            max_results=max_results,
        )

        refined_spl = proposal["candidate_spl"].strip()
        # Only persist the refined SPL to disk when we actually accepted it.
        # Otherwise the on-disk artifact would silently advertise a broken rule.
        if final_status == "accepted":
            self._write_text(Path(scenario.refined_spl_output_path), refined_spl)

        return {
            "scenario": scenario.key,
            "scenario_title": scenario.title,
            "baseline_spl": scenario.baseline_spl,
            "baseline_result_count": baseline_count,
            "refined_result_count": (
                len(refined_results) if final_status == "accepted" else None
            ),
            "final_status": final_status,
            "final_status_is_accepted": final_status == "accepted",
            "diagnostic_results": diagnostics,
            "signals": signals,
            "diagnosis_text": proposal["diagnosis"],
            "refinement_rationale": (
                f"{proposal['refinement_strategy']} "
                f"{proposal['rationale']}"
            ).strip(),
            "refinement_strategy": proposal["refinement_strategy"],
            "expected_effect": proposal["expected_effect"],
            "risk": proposal["risk"],
            "refined_spl": refined_spl,
            "refined_spl_output_path": scenario.refined_spl_output_path,
            "metric_fields": scenario.metric_fields,
            "burst_diagnostic_name": scenario.burst_diagnostic_name,
            "iterations": iterations,
            "must_preserve_total": (
                len(must_preserve_keys) if must_preserve_keys is not None else None
            ),
            "preservation_pct": iterations[-1].get("preservation_pct") if iterations else None,
        }

    def run_failed_login_scenario(
        self,
        *,
        earliest_time: str = "0",
        latest_time: str = "now",
        max_results: int = 1000,
    ) -> dict[str, Any]:
        return self.run(
            failed_login_scenario(self.client.index),
            earliest_time=earliest_time,
            latest_time=latest_time,
            max_results=max_results,
        )

    def _resolve_diagnostic_plan(self, scenario: Scenario) -> dict[str, str]:
        if scenario.diagnostic_searches is not None:
            return dict(scenario.diagnostic_searches)

        messages = build_diagnostic_planning_prompt(
            baseline_spl=scenario.baseline_spl,
            context_hint=scenario.context_hint,
            must_preserve=scenario.must_preserve,
            available_fields=scenario.available_fields,
            index=self.client.index,
        )
        planned = self.model_client.generate_json(messages)
        searches = planned.get("diagnostic_searches")
        if not isinstance(searches, list) or not searches:
            raise RuntimeError(
                "Diagnostic-planning model response did not include any "
                "diagnostic searches."
            )

        # Diagnostics are characterization, not the deliverable — so a single
        # malformed planned diagnostic (the local model occasionally emits one)
        # should not abort the whole run. Skip invalid/unsafe entries and keep
        # the valid ones; only fail if nothing usable survives.
        plan: dict[str, str] = {}
        for entry in searches:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            spl = entry.get("spl")
            if not isinstance(name, str) or not isinstance(spl, str):
                continue
            spl = spl.strip()
            if not is_read_only_spl(spl):
                continue
            parser_ok, _parser_error = self.client.validate_spl(spl)
            if not parser_ok:
                continue
            plan[name] = spl

        if not plan:
            raise RuntimeError(
                "Diagnostic planning produced no valid searches "
                "(all candidates were unsafe or failed Splunk's SPL parser)."
            )
        return plan

    def _run_diagnostics(
        self,
        plan: dict[str, str],
        *,
        earliest_time: str,
        latest_time: str,
        max_results: int,
    ) -> dict[str, dict[str, Any]]:
        diagnostics: dict[str, dict[str, Any]] = {}
        for name, spl in plan.items():
            rows = self.client.run_search(
                spl,
                earliest_time=earliest_time,
                latest_time=latest_time,
                max_results=max_results,
            )
            diagnostics[name] = {
                "spl": spl,
                "result_count": len(rows),
                "rows": rows,
            }
        return diagnostics

    def _fetch_must_preserve_keys(
        self,
        scenario: Scenario,
        *,
        earliest_time: str,
        latest_time: str,
        max_results: int,
    ) -> set[tuple[str, ...]] | None:
        """Run the scenario's must-preserve SPL and return the key-field tuples it surfaces.

        Returns None when the scenario does not define a preservation check
        (e.g. the custom-rule mode). An empty set means the check ran but
        found no events to preserve — which is fine, we just skip the
        preservation gate downstream.
        """
        if not scenario.preservation_check_spl or not scenario.preservation_key_fields:
            return None
        rows = self.client.run_search(
            scenario.preservation_check_spl,
            earliest_time=earliest_time,
            latest_time=latest_time,
            max_results=max_results,
        )
        keys: set[tuple[str, ...]] = set()
        for row in rows:
            key = tuple(str(row.get(field, "")) for field in scenario.preservation_key_fields)
            if all(part for part in key):
                keys.add(key)
        return keys

    def _refine_with_revisions(
        self,
        *,
        scenario: Scenario,
        baseline_count: int,
        diagnostics: dict[str, dict[str, Any]],
        signals: dict[str, Any],
        must_preserve_keys: set[tuple[str, ...]] | None,
        earliest_time: str,
        latest_time: str,
        max_results: int,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], str]:
        """Call the model, run its candidate, and revise up to ``max_revisions`` times.

        Returns the final proposal, the iteration history (one entry per attempt),
        and the result rows from running the final candidate SPL.
        """
        diagnostic_summary = self._summarize_diagnostics(diagnostics)
        signal_block = render_signal_block(signals)

        iterations: list[dict[str, Any]] = []
        revision_feedback: str | None = None
        proposal: dict[str, str] | None = None
        refined_results: list[dict[str, Any]] = []
        seen_spls: set[str] = set()

        # Track the accepted attempt separately. If no attempt is accepted,
        # the report must signal that explicitly — we won't claim a fake
        # "100% reduction" by treating a rejected attempt as the final refinement.
        accepted_proposal: dict[str, Any] | None = None
        accepted_results: list[dict[str, Any]] = []

        for attempt in range(self.max_revisions + 1):
            messages = build_refinement_prompt(
                scenario_title=scenario.title,
                context_hint=scenario.context_hint,
                must_preserve=scenario.must_preserve,
                available_fields=scenario.available_fields,
                baseline_spl=scenario.baseline_spl,
                baseline_result_count=baseline_count,
                diagnostic_summary=diagnostic_summary,
                signal_block=signal_block,
                index=self.client.index,
                revision_feedback=revision_feedback,
            )
            proposal = self.model_client.generate_json(messages)
            candidate_spl = proposal["candidate_spl"].strip()
            self._validate_candidate(candidate_spl)

            normalized = self._normalize_spl(candidate_spl)
            is_duplicate = normalized in seen_spls
            seen_spls.add(normalized)

            # Pre-flight grammar check via Splunk's own parser. If invalid,
            # skip the actual search job and feed the parser's error back to
            # the LLM as revision feedback.
            parser_ok, parser_error = self.client.validate_spl(candidate_spl)
            if not parser_ok:
                feedback = (
                    f"Splunk's SPL parser rejected your candidate. "
                    f"Parser error: {parser_error or 'unknown'}. "
                    f"Rewrite the pipeline using valid SPL only."
                )
                iterations.append(
                    {
                        "attempt": attempt + 1,
                        "candidate_spl": candidate_spl,
                        "refined_result_count": None,
                        "verdict": "parser_rejected",
                        "feedback": feedback,
                        "preservation_pct": None,
                    }
                )
                if attempt == self.max_revisions:
                    break
                revision_feedback = feedback
                refined_results = []
                continue

            refined_results = self.client.run_search(
                candidate_spl,
                earliest_time=earliest_time,
                latest_time=latest_time,
                max_results=max_results,
            )
            refined_count = len(refined_results)

            preservation_pct, missing_keys = self._probe_preservation(
                must_preserve_keys=must_preserve_keys,
                candidate_spl=candidate_spl,
                key_fields=scenario.preservation_key_fields,
                earliest_time=earliest_time,
                latest_time=latest_time,
                max_results=max_results,
            )

            verdict = self._evaluate_candidate(
                baseline_count=baseline_count,
                refined_count=refined_count,
                candidate_spl=candidate_spl,
                is_duplicate=is_duplicate,
                preservation_pct=preservation_pct,
                missing_keys=missing_keys,
                key_fields=scenario.preservation_key_fields,
            )

            iterations.append(
                {
                    "attempt": attempt + 1,
                    "candidate_spl": candidate_spl,
                    "refined_result_count": refined_count,
                    "verdict": verdict["label"],
                    "feedback": verdict["feedback"],
                    "preservation_pct": preservation_pct,
                }
            )

            if verdict["accept"]:
                accepted_proposal = proposal
                accepted_results = refined_results
                break

            if attempt == self.max_revisions:
                break

            revision_feedback = verdict["feedback"]

        assert proposal is not None
        if accepted_proposal is not None:
            return accepted_proposal, iterations, accepted_results, "accepted"

        # No attempt was accepted. Surface the last attempt for transparency
        # but tag the run so the caller (CLI / UI / Markdown report) can render
        # honestly instead of pretending the rejected SPL was a successful
        # refinement.
        final_status = (
            iterations[-1]["verdict"] if iterations else "no_attempts"
        )
        return proposal, iterations, refined_results, final_status

    def _validate_candidate(self, candidate_spl: str) -> None:
        if not is_read_only_spl(candidate_spl):
            raise RuntimeError("Refined SPL from model contains an unsafe command.")
        if not has_balanced_parens(candidate_spl):
            raise RuntimeError("Refined SPL has unbalanced parentheses or quotes.")

    @staticmethod
    def _normalize_spl(spl: str) -> str:
        """Whitespace-normalized form used to detect repeated submissions."""
        return " ".join(spl.split()).lower()

    def _probe_preservation(
        self,
        *,
        must_preserve_keys: set[tuple[str, ...]] | None,
        candidate_spl: str,
        key_fields: list[str],
        earliest_time: str,
        latest_time: str,
        max_results: int,
    ) -> tuple[float | None, list[tuple[str, ...]]]:
        """Test whether the refined rule's filter criteria would still match
        events from the must-preserve entities.

        We extract the leading `search ...` clause of the candidate SPL (the
        portion before the first `|` command) and run it as a probe aggregated
        by the preservation key fields. This is independent of how the model
        chose to aggregate downstream — what matters is whether the FILTER
        criteria still let the suspicious events through.

        Returns (preservation_pct, missing_keys).
        """
        if must_preserve_keys is None or not key_fields:
            return None, []
        if not must_preserve_keys:
            return 100.0, []

        filter_clause = self._extract_search_clause(candidate_spl)
        if not filter_clause:
            return None, []

        probe_spl = (
            f"{filter_clause}\n"
            f"| stats count by {', '.join(key_fields)}"
        )

        try:
            rows = self.client.run_search(
                probe_spl,
                earliest_time=earliest_time,
                latest_time=latest_time,
                max_results=max_results,
            )
        except Exception:
            # If the probe fails (e.g. the filter clause has syntax issues),
            # don't penalize preservation — the candidate evaluation will catch
            # the syntax problem on its own.
            return None, []

        refined_keys: set[tuple[str, ...]] = set()
        for row in rows:
            key = tuple(str(row.get(field, "")) for field in key_fields)
            if all(part for part in key):
                refined_keys.add(key)
        preserved = must_preserve_keys & refined_keys
        missing = sorted(must_preserve_keys - refined_keys)
        pct = round(len(preserved) / len(must_preserve_keys) * 100, 1)
        return pct, missing

    @staticmethod
    def _extract_search_clause(spl: str) -> str:
        """Return the leading filter clause (everything before the first | command).

        If the SPL doesn't start with `search`, we prepend it so the probe is a
        valid Splunk search.
        """
        stripped = spl.strip()
        if not stripped or stripped.startswith("|"):
            return ""
        clause = stripped.split("|", 1)[0].strip()
        if not clause:
            return ""
        first_token = clause.split(None, 1)[0].lower()
        if first_token != "search":
            clause = "search " + clause
        return clause

    @staticmethod
    def _evaluate_candidate(
        *,
        baseline_count: int,
        refined_count: int,
        candidate_spl: str = "",
        is_duplicate: bool = False,
        preservation_pct: float | None = None,
        missing_keys: list[tuple[str, ...]] | None = None,
        key_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Decide whether a candidate is good enough to ship, or needs revision."""
        # Detect common malformed-SPL patterns up front. The 3B model occasionally
        # writes `| sort - count > 5` or `| stats ... > N` instead of using `| where`.
        syntax_issue = _detect_spl_syntax_issue(candidate_spl)
        if syntax_issue:
            return {
                "accept": False,
                "label": "malformed_spl",
                "feedback": (
                    f"Your candidate uses invalid SPL syntax: {syntax_issue} "
                    f"Use `| where <field> >= N` to threshold; never use `>` "
                    f"after `sort` or `stats`. Rewrite the pipeline cleanly."
                ),
            }

        if is_duplicate:
            return {
                "accept": False,
                "label": "duplicate_attempt",
                "feedback": (
                    "You submitted the same SPL as a previous attempt. Try a "
                    "completely different approach: e.g. add `| bucket _time "
                    "span=10m` for time windowing, or filter out service "
                    "accounts with `user!=\"svc_*\"`, or threshold with "
                    "`| where <count_field> >= N`."
                ),
            }

        if baseline_count <= 0:
            return {
                "accept": True,
                "label": "baseline_empty",
                "feedback": "Baseline had zero rows; accepting candidate as-is.",
            }

        if refined_count == 0:
            return {
                "accept": False,
                "label": "too_tight",
                "feedback": (
                    f"Your candidate returned 0 result rows, but the baseline "
                    f"returned {baseline_count}. This is too aggressive. "
                    f"Loosen the filter so the rule still surfaces the "
                    f"behavior under 'Must preserve' but with materially "
                    f"fewer rows than baseline."
                ),
            }

        reduction = baseline_count - refined_count
        reduction_pct = round((reduction / baseline_count) * 100, 1)

        if refined_count >= baseline_count:
            return {
                "accept": False,
                "label": "no_reduction",
                "feedback": (
                    f"Your candidate returned {refined_count} rows, which is "
                    f"NOT smaller than the baseline ({baseline_count}). The "
                    f"refined rule MUST reduce noise. Add aggregation "
                    f"(`| stats count by user, src_ip`), time-windowing "
                    f"(`| bucket _time span=10m`), and thresholding "
                    f"(`| where count >= 5`)."
                ),
            }

        # Preservation gate: a too-aggressive rule that drops the
        # must-preserve events is worse than no refinement.
        if preservation_pct is not None and preservation_pct < 80:
            missing_summary = _format_missing_keys(missing_keys or [], key_fields or [])
            return {
                "accept": False,
                "label": "lost_must_preserve",
                "feedback": (
                    f"Your candidate is too aggressive: it only covers "
                    f"{preservation_pct}% of the events under 'Must preserve' "
                    f"(needs at least 80%). Missing entities: {missing_summary}. "
                    f"Loosen the filter so these entities still appear in the output."
                ),
            }

        # Reduction ceiling: catch suspiciously huge reductions that may
        # indicate the model dropped real signal. Skip when preservation
        # check already passed (we know the must-catch events survived).
        if (
            preservation_pct is None
            and reduction_pct >= 95
            and refined_count <= 3
        ):
            return {
                "accept": False,
                "label": "over_reduction",
                "feedback": (
                    f"Your candidate dropped almost all events "
                    f"({reduction_pct}% reduction, only {refined_count} rows "
                    f"left). This usually means the filter is too narrow. "
                    f"Loosen it so a small but meaningful set of suspicious "
                    f"events still surfaces."
                ),
            }

        if reduction_pct < 20:
            return {
                "accept": False,
                "label": "minimal_reduction",
                "feedback": (
                    f"Your candidate reduced rows by only {reduction_pct}% "
                    f"({baseline_count} → {refined_count}). Tighten further "
                    f"so the reduction is at least ~30%, while still "
                    f"preserving the 'Must preserve' behavior."
                ),
            }

        preservation_note = (
            f" Preserved {preservation_pct}% of must-catch entities."
            if preservation_pct is not None
            else ""
        )
        return {
            "accept": True,
            "label": "accepted",
            "feedback": (
                f"Candidate reduced rows by {reduction_pct}% "
                f"({baseline_count} → {refined_count})."
                f"{preservation_note}"
            ),
        }

    @staticmethod
    def _summarize_diagnostics(
        diagnostics: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        summary: dict[str, Any] = {}
        for name, diagnostic in diagnostics.items():
            rows = diagnostic.get("rows", [])
            summary[name] = {
                "result_count": diagnostic.get("result_count", len(rows)),
                "top_rows": rows[:5] if isinstance(rows, list) else [],
            }
        return summary

    @staticmethod
    def _write_text(path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text.rstrip() + "\n", encoding="utf-8")


_SORT_COMPARISON_RE = re.compile(r"\|\s*sort\b[^|]*[<>]=?", re.IGNORECASE)
_STATS_COMPARISON_RE = re.compile(r"\|\s*stats\b[^|]*[<>]=?", re.IGNORECASE)


def _format_missing_keys(
    missing: list[tuple[str, ...]],
    key_fields: list[str],
) -> str:
    if not missing:
        return "(none)"
    parts = []
    for key in missing[:5]:
        labeled = ", ".join(
            f"{field}={value}" for field, value in zip(key_fields, key)
        )
        parts.append(labeled)
    summary = "; ".join(parts)
    if len(missing) > 5:
        summary += f"; (+{len(missing) - 5} more)"
    return summary


def compile_preservation_check(
    *,
    model_client: ModelClient,
    splunk_client: SplunkClient,
    must_preserve: str,
    baseline_spl: str,
    available_fields: list[str],
    index: str,
) -> tuple[str, list[str]]:
    """Compile a natural-language must-preserve statement into an executable
    preservation-check SPL plus its key fields.

    The analyst describes what must stay caught in plain English; the model
    compiles it to a read-only SPL oracle, which we pre-flight against Splunk's
    own parser before handing it back for the analyst to review. Raises
    RuntimeError with a human-readable reason on any failure.
    """
    if not must_preserve.strip():
        raise RuntimeError("Describe what must be preserved before generating a check.")

    messages = build_preservation_compilation_prompt(
        must_preserve=must_preserve,
        baseline_spl=baseline_spl,
        available_fields=available_fields,
        index=index,
    )
    result = model_client.generate_json(messages)

    spl = str(result.get("preservation_check_spl") or "").strip()
    raw_keys = result.get("preservation_key_fields") or []
    if isinstance(raw_keys, str):
        raw_keys = raw_keys.split(",")
    key_fields = [str(k).strip() for k in raw_keys if str(k).strip()]

    if not spl:
        raise RuntimeError("The model returned an empty preservation check.")
    if not key_fields:
        raise RuntimeError("The model did not return any key fields.")
    if not is_read_only_spl(spl):
        raise RuntimeError("The compiled check contains an unsafe SPL command.")

    parser_ok, parser_error = splunk_client.validate_spl(spl)
    if not parser_ok:
        raise RuntimeError(
            f"Splunk's parser rejected the compiled check: "
            f"{parser_error or 'unknown error'}"
        )
    return spl, key_fields


def _detect_spl_syntax_issue(spl: str) -> str | None:
    """Return a short description of a known SPL anti-pattern, or None."""
    if not spl:
        return None
    if _SORT_COMPARISON_RE.search(spl):
        return "`| sort ... > N` is not valid SPL (sort does not threshold)."
    if _STATS_COMPARISON_RE.search(spl):
        return "`| stats ... > N` is not valid SPL (stats does not threshold)."
    return None


def main() -> None:
    client = SplunkClient.from_env()
    agent = RulePilotAgent(client)
    report = agent.run_failed_login_scenario()
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
