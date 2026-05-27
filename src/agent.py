#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:
    from src.models import (
        ModelClient,
        is_read_only_spl,
        model_client_from_env,
    )
    from src.prompts import (
        build_diagnostic_planning_prompt,
        build_refinement_prompt,
    )
    from src.scenarios import Scenario, failed_login_scenario
    from src.splunk_client import SplunkClient
except ModuleNotFoundError:
    from models import ModelClient, is_read_only_spl, model_client_from_env
    from prompts import build_diagnostic_planning_prompt, build_refinement_prompt
    from scenarios import Scenario, failed_login_scenario
    from splunk_client import SplunkClient


class RulePilotAgent:
    def __init__(
        self,
        client: SplunkClient,
        *,
        model_client: ModelClient | None = None,
    ):
        self.client = client
        self.model_client = model_client or model_client_from_env(index=client.index)

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

        proposal = self._call_refinement_model(
            scenario=scenario,
            baseline_count=baseline_count,
            diagnostics=diagnostics,
        )

        refined_spl = proposal["candidate_spl"].strip()
        self._write_text(Path(scenario.refined_spl_output_path), refined_spl)

        refined_results = self.client.run_search(
            refined_spl,
            earliest_time=earliest_time,
            latest_time=latest_time,
            max_results=max_results,
        )

        return {
            "scenario": scenario.key,
            "scenario_title": scenario.title,
            "baseline_spl": scenario.baseline_spl,
            "baseline_result_count": baseline_count,
            "refined_result_count": len(refined_results),
            "diagnostic_results": diagnostics,
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
                raise RuntimeError(
                    f"Planned diagnostic {name!r} contains an unsafe SPL command."
                )
            plan[name] = spl

        if not plan:
            raise RuntimeError("Diagnostic plan was empty after validation.")
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

    def _call_refinement_model(
        self,
        *,
        scenario: Scenario,
        baseline_count: int,
        diagnostics: dict[str, dict[str, Any]],
    ) -> dict[str, str]:
        diagnostic_summary = self._summarize_diagnostics(diagnostics)
        messages = build_refinement_prompt(
            scenario_title=scenario.title,
            context_hint=scenario.context_hint,
            must_preserve=scenario.must_preserve,
            available_fields=scenario.available_fields,
            baseline_spl=scenario.baseline_spl,
            baseline_result_count=baseline_count,
            diagnostic_summary=diagnostic_summary,
            index=self.client.index,
        )
        proposal = self.model_client.generate_json(messages)
        if not is_read_only_spl(proposal["candidate_spl"]):
            raise RuntimeError("Refined SPL from model contains an unsafe command.")
        return proposal

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


def main() -> None:
    client = SplunkClient.from_env()
    agent = RulePilotAgent(client)
    report = agent.run_failed_login_scenario()
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
