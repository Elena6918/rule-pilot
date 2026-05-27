#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Protocol

try:
    from src.prompts import (
        DIAGNOSTIC_PLAN_REQUIRED_KEYS,
        REFINEMENT_REQUIRED_KEYS,
        detect_task_marker,
        parse_model_json_response,
    )
except ModuleNotFoundError:
    from prompts import (
        DIAGNOSTIC_PLAN_REQUIRED_KEYS,
        REFINEMENT_REQUIRED_KEYS,
        detect_task_marker,
        parse_model_json_response,
    )


UNSAFE_SPL_COMMANDS = {
    "delete",
    "outputlookup",
    "collect",
    "sendemail",
    "script",
    "map",
    "rest",
}


class ModelClient(Protocol):
    def generate_json(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        ...


def _required_keys_for(messages: list[dict[str, str]]) -> list[str]:
    marker = detect_task_marker(messages)
    if marker == "diagnostic_planning":
        return DIAGNOSTIC_PLAN_REQUIRED_KEYS
    return REFINEMENT_REQUIRED_KEYS


class OpenAICompatibleModelClient:
    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str | None = None,
        timeout: int = 60,
        temperature: float = 0.0,
        max_tokens: int = 1200,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.temperature = temperature
        self.max_tokens = max_tokens

    def generate_text(self, messages: list[dict[str, str]]) -> str:
        body = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "response_format": {"type": "json_object"},
        }

        response = self._post_chat_completions(body)
        if response.status_code in {400, 422}:
            retry_body = dict(body)
            retry_body.pop("response_format", None)
            response = self._post_chat_completions(retry_body)

        try:
            response.raise_for_status()
        except Exception as exc:
            raise RuntimeError(
                f"Model endpoint returned HTTP {response.status_code}: {response.text[:500]}"
            ) from exc

        payload = self._response_json(response)
        try:
            content = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(f"Malformed model response: {payload!r}") from exc

        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("Model response did not contain assistant text content.")
        return content

    def generate_json(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        required = _required_keys_for(messages)
        result = parse_model_json_response(
            self.generate_text(messages),
            required_keys=required,
        )
        _enforce_response_safety(result, required)
        return result

    def _post_chat_completions(self, body: dict[str, Any]) -> Any:
        try:
            import requests
            from requests.exceptions import RequestException
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "The openai_compatible model provider requires the requests package."
            ) from exc

        headers = {"Content-Type": "application/json"}
        if self.api_key and self.api_key != "local":
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            return requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=body,
                timeout=self.timeout,
            )
        except RequestException as exc:
            raise RuntimeError(
                f"Could not reach OpenAI-compatible model endpoint at {self.base_url}: {exc}"
            ) from exc

    def _response_json(self, response: Any) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError as exc:
            raise RuntimeError(
                f"Model endpoint returned non-JSON response: {response.text[:500]}"
            ) from exc

        if not isinstance(payload, dict):
            raise RuntimeError(
                f"Model endpoint response must be a JSON object; got {type(payload).__name__}."
            )
        return payload


class DeterministicFallbackModelClient:
    """Demo-safe fallback when no LLM provider is configured.

    For refinement: returns the baseline SPL unchanged with a clear "no LLM
    available" diagnosis, so the UI still renders end-to-end.
    For diagnostic planning: returns one generic top-N search per available
    field, derived from the prompt context.
    """

    def __init__(self, *, index: str):
        self.index = index

    def generate_json(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        marker = detect_task_marker(messages)
        if marker == "diagnostic_planning":
            return self._fallback_diagnostic_plan(messages)
        return self._fallback_refinement(messages)

    def _fallback_refinement(self, messages: list[dict[str, str]]) -> dict[str, str]:
        baseline = _extract_baseline_spl(messages) or f"search index={self.index}"
        return {
            "diagnosis": (
                "Deterministic fallback used because no LLM provider is configured. "
                "The baseline SPL is returned unchanged."
            ),
            "refinement_strategy": "No-op fallback strategy.",
            "candidate_spl": baseline,
            "rationale": (
                "Configure RULEPILOT_MODEL_PROVIDER=openai_compatible to enable "
                "model-driven refinement."
            ),
            "expected_effect": "Identical result count to the baseline.",
            "risk": "No improvement until a real model provider is configured.",
        }

    def _fallback_diagnostic_plan(
        self,
        messages: list[dict[str, str]],
    ) -> dict[str, Any]:
        fields = _extract_available_fields(messages)
        candidates = [
            field
            for field in fields
            if field not in {"_time", "source", "sourcetype"}
        ][:4]

        if not candidates:
            candidates = ["user"]

        searches = []
        for field in candidates:
            searches.append(
                {
                    "name": f"count_by_{field}",
                    "purpose": f"Top values of {field} in the matching event set.",
                    "spl": (
                        f"search index={self.index}\n"
                        f"| stats count by {field}\n"
                        f"| sort - count\n"
                        f"| head 10"
                    ),
                }
            )

        return {"diagnostic_searches": searches}


class SplunkAICommandModelClient:
    def generate_json(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        raise NotImplementedError(
            "Splunk AI Toolkit / hosted models can be integrated later by issuing "
            "an SPL query using the | ai command through SplunkClient. This requires "
            "AI Toolkit configuration in Splunk and is optional for the current demo."
        )


def model_client_from_env(*, index: str) -> ModelClient:
    _load_dotenv_if_available()

    provider = os.getenv("RULEPILOT_MODEL_PROVIDER", "deterministic").strip().lower()
    if provider == "deterministic":
        return DeterministicFallbackModelClient(index=index)

    if provider == "openai_compatible":
        return OpenAICompatibleModelClient(
            base_url=os.getenv("RULEPILOT_MODEL_BASE_URL", "http://localhost:11434/v1"),
            model=os.getenv("RULEPILOT_MODEL_NAME", "llama3.2:3b"),
            api_key=os.getenv("RULEPILOT_MODEL_API_KEY", "local"),
            timeout=_env_int("RULEPILOT_MODEL_TIMEOUT", 60),
            temperature=_env_float("RULEPILOT_MODEL_TEMPERATURE", 0.0),
            max_tokens=_env_int("RULEPILOT_MODEL_MAX_TOKENS", 1200),
        )

    if provider == "splunk_ai":
        return SplunkAICommandModelClient()

    raise ValueError(
        "Unknown RULEPILOT_MODEL_PROVIDER. Expected deterministic, "
        "openai_compatible, or splunk_ai; got "
        f"{provider!r}."
    )


def is_read_only_spl(spl: str) -> bool:
    command_pattern = "|".join(re.escape(command) for command in sorted(UNSAFE_SPL_COMMANDS))
    unsafe_command = re.compile(rf"(?i)(^|\|)\s*({command_pattern})\b")
    return unsafe_command.search(spl) is None


def has_balanced_parens(spl: str) -> bool:
    """Check that parentheses are balanced outside of quoted strings."""
    depth = 0
    in_string: str | None = None
    escape = False
    for ch in spl:
        if escape:
            escape = False
            continue
        if in_string is not None:
            if ch == "\\":
                escape = True
            elif ch == in_string:
                in_string = None
            continue
        if ch in ('"', "'"):
            in_string = ch
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0 and in_string is None


def _enforce_response_safety(
    result: dict[str, Any],
    required_keys: list[str],
) -> None:
    if "candidate_spl" in required_keys:
        candidate = result.get("candidate_spl", "")
        if not isinstance(candidate, str) or not is_read_only_spl(candidate):
            raise RuntimeError("Model proposed SPL containing an unsafe command.")
        if not has_balanced_parens(candidate):
            raise RuntimeError(
                "Model proposed SPL with unbalanced parentheses or quotes."
            )
    if "diagnostic_searches" in required_keys:
        searches = result.get("diagnostic_searches", [])
        if not isinstance(searches, list):
            raise RuntimeError("Diagnostic plan must be a list.")
        for entry in searches:
            if not isinstance(entry, dict):
                continue
            spl = entry.get("spl", "")
            if not isinstance(spl, str):
                continue
            if not is_read_only_spl(spl):
                raise RuntimeError(
                    "Diagnostic plan contains an unsafe SPL command."
                )
            if not has_balanced_parens(spl):
                raise RuntimeError(
                    "Diagnostic plan contains SPL with unbalanced parentheses."
                )


def _extract_baseline_spl(messages: list[dict[str, str]]) -> str | None:
    return _extract_block(messages, "Baseline SPL:")


def _extract_available_fields(messages: list[dict[str, str]]) -> list[str]:
    block = _extract_block(messages, "Available fields:")
    if not block:
        return []
    try:
        parsed = json.loads(block)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed if isinstance(item, str)]


def _extract_block(messages: list[dict[str, str]], header: str) -> str | None:
    for message in messages:
        if message.get("role") != "user":
            continue
        content = message.get("content") or ""
        index = content.find(header)
        if index == -1:
            continue
        tail = content[index + len(header):].lstrip("\n")
        lines: list[str] = []
        for line in tail.splitlines():
            if not line.strip():
                if lines:
                    break
                continue
            if line and not line.startswith(" ") and line.endswith(":") and lines:
                break
            lines.append(line)
        block = "\n".join(lines).strip()
        if block:
            return block
    return None


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_dotenv_if_available() -> None:
    try:
        from dotenv import load_dotenv
    except ModuleNotFoundError:
        return

    load_dotenv(_repo_root() / ".env", override=False)


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer; got {raw!r}.") from exc


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number; got {raw!r}.") from exc
