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

PRESERVATION_COMPILE_REQUIRED_KEYS = [
    "preservation_check_spl",
    "preservation_key_fields",
]

TASK_MARKER_REFINEMENT = "RULEPILOT_TASK: refinement"
TASK_MARKER_DIAGNOSTIC_PLAN = "RULEPILOT_TASK: diagnostic_planning"
TASK_MARKER_PRESERVATION_COMPILE = "RULEPILOT_TASK: preservation_compilation"

SHARED_SAFETY_RULES = """
You must only propose read-only SPL.
You must not use dangerous SPL commands such as delete, outputlookup, collect, sendemail, script, map, or rest.
You must not invent fields. Use only the available fields provided by the user.
You must return strict JSON only, with no markdown and no explanatory prose outside the JSON object.
""".strip()


SPL_IDIOM_RULES = """
SPL idiom rules (follow exactly):
- To threshold by a count, write `| where count >= N` (or any other field). NEVER write `| sort - count > N` or `| stats ... > N` — those are invalid.
- To aggregate over time windows, use `| bucket _time span=10m` then `| stats ... by _time ...`.
- Separate `stats by` fields with commas: `| stats count by user, src_ip` — not `| stats count by user src_ip`.
- The pipeline must be one linear flow of `command | command | command ...` with no nested operators.
- Wrap each `| command` on its own line for clarity.
""".strip()


REFINEMENT_EXAMPLE = """
Worked example (for reference only — do not copy verbatim).

Baseline:
  search index=demo sourcetype=auth action=login (status=failed OR status=failure)
  | stats count by user, src_ip

Diagnosis: most failed logins come from a few service accounts and from isolated typos; only a small number form repeated bursts from the same user+IP.

Refined SPL:
  search index=demo sourcetype=auth action=login (status=failed OR status=failure) user!="svc_*"
  | bucket _time span=10m
  | stats count as failed_count by _time, user, src_ip
  | where failed_count >= 5
  | sort - failed_count

Why it works: filters out service-account noise, time-windows the events, aggregates per user+src_ip, and only surfaces repeated bursts (>=5 failures in 10 min).
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
    signal_block: str | None,
    index: str,
    revision_feedback: str | None = None,
) -> list[dict[str, str]]:
    system_prompt = f"""
You are a SOC rule-tuning assistant. Your job is to reduce false positives in noisy Splunk SPL detections WITHOUT dropping the events the analyst flagged under "Must preserve". A rule that fires less often but misses the real suspicious behavior is a failed refinement.
{SHARED_SAFETY_RULES}
{SPL_IDIOM_RULES}
The candidate_spl must start with "search index={index}" and be a single read-only SPL pipeline.
Keep all string values short. Do not include markdown.
{TASK_MARKER_REFINEMENT}
""".strip()

    expected_schema = {key: "string" for key in REFINEMENT_REQUIRED_KEYS}

    sections = [
        REFINEMENT_EXAMPLE,
        "",
        f"Scenario: {scenario_title}",
        f"Context: {context_hint}",
        f"Must preserve: {must_preserve}",
        f"Target index: {index}",
        f"Available fields: {json.dumps(available_fields)}",
        "",
        "Baseline SPL:",
        baseline_spl,
        "",
        f"Baseline result count: {baseline_result_count}",
    ]

    if signal_block:
        sections += ["", "Key signals from diagnostics:", signal_block]

    sections += [
        "",
        "Diagnostic top rows (compact):",
        json.dumps(diagnostic_summary, indent=2, sort_keys=True, default=str),
    ]

    if revision_feedback:
        sections += [
            "",
            "Revision feedback (previous attempt was unsatisfactory):",
            revision_feedback,
            "Propose a different candidate_spl that addresses this feedback.",
        ]

    sections += [
        "",
        "Return strict JSON matching this schema:",
        json.dumps(expected_schema, indent=2),
        "",
        "Rules for candidate_spl:",
        f"- Must target index={index}",
        "- Must use only the available fields listed above",
        "- Must aggregate or filter so the result count is meaningfully smaller than the baseline",
        "- Must still surface the behavior under 'Must preserve'",
    ]

    user_prompt = "\n".join(sections).strip()

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


def build_preservation_compilation_prompt(
    *,
    must_preserve: str,
    baseline_spl: str,
    available_fields: list[str],
    index: str,
) -> list[dict[str, str]]:
    """Compile an analyst's natural-language must-preserve statement into an
    executable preservation-check SPL + key fields.

    The output is a *verification oracle* — the search RulePilot runs to learn
    which entities the refined rule must still surface — NOT a tuned detection
    rule. It should capture the must-catch behavior generously and end by
    aggregating to one row per entity.
    """
    system_prompt = f"""
You are a SOC detection engineer. Compile the analyst's natural-language "must preserve" statement into ONE read-only Splunk SPL search that returns the entities that MUST still be caught after a noisy rule is tuned.
This is a VERIFICATION ORACLE, not a tuned detection rule: capture the must-catch behavior generously and reliably so RulePilot can later prove a refined rule still covers it. Do NOT pre-optimize for low false positives — that is the refined rule's job, not the oracle's.
{SHARED_SAFETY_RULES}
{SPL_IDIOM_RULES}
The search must target index={index}, use only the available fields, and END with `| stats count by <key fields>` so each output row identifies one must-catch entity.
{TASK_MARKER_PRESERVATION_COMPILE}
""".strip()

    expected_schema = {
        "preservation_check_spl": "read-only SPL ending in `| stats count by <key fields>`",
        "preservation_key_fields": ["field", "..."],
    }

    sections = [
        f"Target index: {index}",
        f"Available fields: {json.dumps(available_fields)}",
        "",
        "Baseline SPL (the noisy rule being tuned — for schema/context only):",
        baseline_spl,
        "",
        "Must preserve (analyst's words):",
        must_preserve,
        "",
        "Return strict JSON matching this schema:",
        json.dumps(expected_schema, indent=2),
        "",
        "Rules for preservation_check_spl:",
        f"- Must target index={index} and be read-only",
        "- Must END with `| stats count by <the key fields>` (one row per must-catch entity)",
        "- Use only the available fields listed above",
        "- preservation_key_fields must list exactly those key fields, e.g. [\"user\", \"src_ip\"]",
    ]

    user_prompt = "\n".join(sections).strip()

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
        if TASK_MARKER_PRESERVATION_COMPILE in content:
            return "preservation_compilation"
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
