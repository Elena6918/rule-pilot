#!/usr/bin/env python3

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Scenario:
    """A detection-tuning scenario the agent can run end-to-end.

    A scenario bundles everything needed to refine one rule: the baseline SPL,
    the diagnostic searches that explain *why* it is noisy, the fields the LLM
    is allowed to reference, and free-form context that shapes the refinement
    prompt. When ``diagnostic_searches`` is ``None``, the agent asks the LLM to
    plan diagnostics from the baseline SPL — that path powers the "custom rule"
    tab in the UI.
    """

    key: str
    title: str
    baseline_spl: str
    context_hint: str
    must_preserve: str
    available_fields: list[str]
    refined_spl_output_path: str
    diagnostic_searches: dict[str, str] | None = None
    metric_fields: list[str] = field(default_factory=list)
    burst_diagnostic_name: str | None = None
    preservation_check_spl: str | None = None
    preservation_key_fields: list[str] = field(default_factory=list)


AUTH_FIELDS = [
    "_time",
    "action",
    "app",
    "event_type",
    "geo",
    "reason",
    "source",
    "sourcetype",
    "src_ip",
    "status",
    "user",
    "user_agent",
]

PROCESS_FIELDS = [
    "_time",
    "command_line",
    "event_type",
    "host",
    "parent_process",
    "process",
    "source",
    "sourcetype",
    "user",
]


def failed_login_scenario(index: str) -> Scenario:
    baseline_path = _repo_root() / "detections" / "failed_login_baseline.spl"
    baseline_spl = baseline_path.read_text(encoding="utf-8").strip().format(index=index)

    diagnostics = {
        "count_by_status": (
            f"search index={index} event_type=auth action=login\n"
            "| stats count by status\n"
            "| sort - count"
        ),
        "count_by_reason": (
            f"search index={index} event_type=auth action=login "
            "(status=failed OR status=failure)\n"
            "| stats count by reason\n"
            "| sort - count"
        ),
        "count_by_user": (
            f"search index={index} event_type=auth action=login "
            "(status=failed OR status=failure)\n"
            "| stats count by user\n"
            "| sort - count\n"
            "| head 10"
        ),
        "count_by_src_ip": (
            f"search index={index} event_type=auth action=login "
            "(status=failed OR status=failure)\n"
            "| stats count by src_ip\n"
            "| sort - count\n"
            "| head 10"
        ),
        "suspicious_failed_login_bursts": (
            f"search index={index} event_type=auth action=login "
            "(status=failed OR status=failure)\n"
            "| bucket _time span=10m\n"
            "| stats count as failed_count values(reason) as reasons "
            "values(app) as apps by _time src_ip user\n"
            "| where failed_count >= 5\n"
            "| sort - failed_count\n"
            "| head 20"
        ),
    }

    preservation_spl = (
        f"search index={index} event_type=auth action=login "
        "(status=failed OR status=failure)\n"
        "| bucket _time span=10m\n"
        "| stats count as failed_count by _time, user, src_ip\n"
        "| where failed_count >= 5\n"
        "| stats values(_time) as windows by user, src_ip"
    )

    return Scenario(
        key="failed_login",
        title="Failed Login Burst Refinement",
        baseline_spl=baseline_spl,
        context_hint=(
            "This is an authentication failure detection. The baseline is too noisy "
            "because it surfaces every single failed login, including isolated typos "
            "and routine service-account churn."
        ),
        must_preserve=(
            "Suspicious burst behavior: repeated failed logins (>=5 in 10 minutes) "
            "from the same user/source-IP pair."
        ),
        available_fields=AUTH_FIELDS,
        refined_spl_output_path=str(
            _repo_root() / "detections" / "failed_login_refined.spl"
        ),
        diagnostic_searches=diagnostics,
        metric_fields=["reason", "user", "src_ip"],
        burst_diagnostic_name="suspicious_failed_login_bursts",
        preservation_check_spl=preservation_spl,
        preservation_key_fields=["user", "src_ip"],
    )


def suspicious_command_scenario(index: str) -> Scenario:
    baseline_path = _repo_root() / "detections" / "suspicious_command_baseline.spl"
    baseline_spl = baseline_path.read_text(encoding="utf-8").strip().format(index=index)

    diagnostics = {
        "count_by_process": (
            f"search index={index} event_type=process\n"
            "| stats count by process\n"
            "| sort - count\n"
            "| head 10"
        ),
        "count_by_user": (
            f"search index={index} event_type=process\n"
            "| stats count by user\n"
            "| sort - count\n"
            "| head 10"
        ),
        "count_by_parent_process": (
            f"search index={index} event_type=process\n"
            "| stats count by parent_process\n"
            "| sort - count\n"
            "| head 10"
        ),
        "count_by_command_pattern": (
            f"search index={index} event_type=process\n"
            "| eval pattern=case(\n"
            "    like(lower(command_line), \"%-enc %\") "
            "OR like(lower(command_line), \"%encodedcommand%\"), \"powershell_encoded\",\n"
            "    like(lower(command_line), \"%curl%sh%\") "
            "OR like(lower(command_line), \"%curl%bash%\"), \"curl_pipe_shell\",\n"
            "    like(lower(command_line), \"%wget%sh%\") "
            "OR like(lower(command_line), \"%wget%bash%\"), \"wget_pipe_shell\",\n"
            "    like(lower(command_line), \"%base64%-d%\") "
            "OR like(lower(command_line), \"%b64decode%\"), \"base64_decode\",\n"
            "    like(command_line, \"%/dev/tcp/%\"), \"reverse_shell_devtcp\",\n"
            "    1=1, \"other\")\n"
            "| stats count by pattern\n"
            "| sort - count"
        ),
        "suspicious_command_clusters": (
            f"search index={index} event_type=process\n"
            "| eval is_encoded=if(like(lower(command_line), \"%-enc %\") "
            "OR like(lower(command_line), \"%encodedcommand%\"), 1, 0)\n"
            "| eval is_pipe_shell=if(like(lower(command_line), \"%curl%sh%\") "
            "OR like(lower(command_line), \"%curl%bash%\") "
            "OR like(lower(command_line), \"%wget%sh%\") "
            "OR like(lower(command_line), \"%wget%bash%\"), 1, 0)\n"
            "| eval is_revshell=if(like(command_line, \"%/dev/tcp/%\"), 1, 0)\n"
            "| where is_encoded=1 OR is_pipe_shell=1 OR is_revshell=1\n"
            "| stats count as suspicious_count values(process) as processes "
            "values(parent_process) as parents by user host\n"
            "| sort - suspicious_count\n"
            "| head 20"
        ),
    }

    # Preservation set: events that BOTH match the baseline's keyword filter
    # (so the refined rule could plausibly catch them — coverage expansion
    # is out of scope) AND look genuinely suspicious. Pure /dev/tcp/ reverse
    # shells are deliberately excluded because the baseline doesn't cover
    # them; refining a rule cannot add coverage.
    preservation_spl = (
        f"search index={index} event_type=process "
        "(command_line=\"*powershell*\" OR command_line=\"*curl*\" "
        "OR command_line=\"*wget*\" OR command_line=\"*base64*\")\n"
        "| eval is_encoded=if(like(lower(command_line), \"%-enc %\") "
        "OR like(lower(command_line), \"%encodedcommand%\"), 1, 0)\n"
        "| eval is_pipe_shell=if(like(lower(command_line), \"%curl%sh%\") "
        "OR like(lower(command_line), \"%curl%bash%\") "
        "OR like(lower(command_line), \"%wget%sh%\") "
        "OR like(lower(command_line), \"%wget%bash%\"), 1, 0)\n"
        "| where is_encoded=1 OR is_pipe_shell=1\n"
        "| stats count by user, host"
    )

    return Scenario(
        key="suspicious_command",
        title="Suspicious Command Execution",
        baseline_spl=baseline_spl,
        context_hint=(
            "This is a suspicious-process detection. The baseline triggers on any "
            "use of broad keywords like 'powershell', 'curl', or 'base64', so it "
            "fires constantly on admins, CI jobs, and routine scripts."
        ),
        must_preserve=(
            "High-risk execution patterns: encoded PowerShell commands, "
            "curl/wget piped into a shell, base64-decoded payloads, and "
            "reverse-shell indicators (e.g. /dev/tcp/). Service accounts running "
            "their own scripted workloads should not trigger."
        ),
        available_fields=PROCESS_FIELDS,
        refined_spl_output_path=str(
            _repo_root() / "detections" / "suspicious_command_refined.spl"
        ),
        diagnostic_searches=diagnostics,
        metric_fields=["process", "user", "parent_process"],
        burst_diagnostic_name="suspicious_command_clusters",
        preservation_check_spl=preservation_spl,
        preservation_key_fields=["user", "host"],
    )


def custom_scenario(
    *,
    index: str,
    baseline_spl: str,
    context_hint: str,
    must_preserve: str,
    available_fields: list[str] | None = None,
) -> Scenario:
    return Scenario(
        key="custom",
        title="Custom Rule",
        baseline_spl=baseline_spl.strip(),
        context_hint=context_hint.strip(),
        must_preserve=must_preserve.strip(),
        available_fields=available_fields or (AUTH_FIELDS + PROCESS_FIELDS),
        refined_spl_output_path=str(
            _repo_root() / "detections" / "custom_refined.spl"
        ),
        diagnostic_searches=None,
        metric_fields=[],
        burst_diagnostic_name=None,
    )


SCENARIO_BUILDERS = {
    "failed_login": failed_login_scenario,
    "suspicious_command": suspicious_command_scenario,
}


def build_scenario(key: str, *, index: str) -> Scenario:
    if key not in SCENARIO_BUILDERS:
        raise ValueError(
            f"Unknown scenario key: {key!r}. "
            f"Known scenarios: {sorted(SCENARIO_BUILDERS)}."
        )
    return SCENARIO_BUILDERS[key](index)
