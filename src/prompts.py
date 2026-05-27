#!/usr/bin/env python3

from __future__ import annotations

import json
from typing import Any


REFINEMENT_REQUIRED_KEYS = [
    "diagnosis",
    "refinement_strategy",
    "candidate_spl",
    "rationale",
    "expected_effect",
    "risk",
]

DIAGNOSTIC_PLAN_REQUIRED_KEYS = ["diagnostic_searches"]

TASK_MARKER_REFINEMENT = "RULEPILOT_TASK: refinement"
TASK_MARKER_DIAGNOSTIC_PLAN = "RULEPILOT_TASK: diagnostic_planning"

SHARED_SAFETY_RULES = """
You must only propose read-only SPL.
You must not use dangerous SPL commands such as delete, outputlookup, collect, sendemail, script, map, or rest.
You must not invent fields. Use only the available fields provided by the user.
You must return strict JSON only, with no markdown and no explanatory prose outside the JSON object.
""".strip()


def build_refinement_prompt(
    *,
    scenario_title: str,
    context_hint: str,
    must_preserve: str,
    available_fields: list[str],
    baseline_spl: str,
    baseline_result_count: int,
    diagnostic_summary: dict[str, Any],
    index: str,
) -> list[dict[str, str]]:
    system_prompt = f"""
You are a SOC rule-tuning assistant.
Your task is to refine noisy Splunk SPL detections.
{SHARED_SAFETY_RULES}
You must preserve the detection behavior described under "Must preserve".
{TASK_MARKER_REFINEMENT}
""".strip()

    expected_schema = {key: "string" for key in REFINEMENT_REQUIRED_KEYS}

    user_prompt = f"""
Refine this Splunk detection for the RulePilot framework.

Scenario:
{scenario_title}

Context:
{context_hint}

Must preserve:
{must_preserve}

Target index:
{index}

Available fields:
{json.dumps(available_fields, indent=2)}

Baseline SPL:
{baseline_spl}

Baseline result count:
{baseline_result_count}

Compact diagnostic summary:
{json.dumps(diagnostic_summary, indent=2, sort_keys=True, default=str)}

Expected JSON schema:
{json.dumps(expected_schema, indent=2)}

Return one JSON object that follows the schema exactly. The candidate_spl must be read-only SPL targeting index={index} and must preserve the behavior listed above while reducing noise highlighted by the diagnostics.
""".strip()

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


def build_diagnostic_planning_prompt(
    *,
    baseline_spl: str,
    context_hint: str,
    must_preserve: str,
    available_fields: list[str],
    index: str,
) -> list[dict[str, str]]:
    system_prompt = f"""
You are a SOC rule-tuning assistant.
Your task is to propose diagnostic Splunk searches that explain why a baseline detection is noisy.
{SHARED_SAFETY_RULES}
Each diagnostic must be a single self-contained SPL search starting with the keyword "search".
{TASK_MARKER_DIAGNOSTIC_PLAN}
""".strip()

    expected_schema = {
        "diagnostic_searches": [
            {
                "name": "snake_case_identifier",
                "purpose": "one short sentence",
                "spl": "read-only SPL string",
            }
        ]
    }

    user_prompt = f"""
Plan diagnostic searches for a noisy Splunk detection.

Context:
{context_hint}

Must preserve (the refined rule must still cover this behavior):
{must_preserve}

Target index:
{index}

Available fields:
{json.dumps(available_fields, indent=2)}

Baseline SPL:
{baseline_spl}

Return between 3 and 6 diagnostic searches in JSON form. Each diagnostic should help characterize the population of events the baseline matches (e.g. top values per field, time-window aggregations, ratio of benign vs. suspicious clusters). Use only the available fields listed above and only read-only SPL.

Expected JSON schema:
{json.dumps(expected_schema, indent=2)}
""".strip()

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


def parse_model_json_response(
    text: str,
    *,
    required_keys: list[str] | None = None,
) -> dict[str, Any]:
    keys = required_keys if required_keys is not None else REFINEMENT_REQUIRED_KEYS

    raw = text.strip()
    if not raw:
        raise ValueError("Model response was empty; expected a JSON object.")

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = _parse_embedded_json_object(raw)

    if not isinstance(parsed, dict):
        raise ValueError(
            f"Model response must be a JSON object; got {type(parsed).__name__}."
        )

    missing = [key for key in keys if key not in parsed]
    if missing:
        raise ValueError(
            f"Model response missing required key(s): {', '.join(missing)}"
        )

    return parsed


def detect_task_marker(messages: list[dict[str, str]]) -> str | None:
    """Return the task marker embedded in the system prompt, if any.

    Lets the deterministic fallback client know whether it is being asked to
    refine a rule or to plan diagnostics.
    """
    for message in messages:
        if message.get("role") != "system":
            continue
        content = message.get("content") or ""
        if TASK_MARKER_REFINEMENT in content:
            return "refinement"
        if TASK_MARKER_DIAGNOSTIC_PLAN in content:
            return "diagnostic_planning"
    return None


def _parse_embedded_json_object(text: str) -> dict[str, Any]:
    fenced = _extract_fenced_content(text)
    candidates = [fenced, text] if fenced else [text]

    for candidate in candidates:
        json_text = _extract_json_object(candidate)
        if not json_text:
            continue
        try:
            parsed = json.loads(json_text)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed

    raise ValueError("Could not parse a valid JSON object from the model response.")


def _extract_fenced_content(text: str) -> str | None:
    stripped = text.strip()
    if not stripped.startswith("```"):
        return None

    lines = stripped.splitlines()
    if len(lines) < 3:
        return None
    if not lines[-1].strip().startswith("```"):
        return None

    return "\n".join(lines[1:-1]).strip()


def _extract_json_object(text: str) -> str | None:
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape = False

    for index in range(start, len(text)):
        char = text[index]

        if escape:
            escape = False
            continue
        if char == "\\" and in_string:
            escape = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]

    return None
