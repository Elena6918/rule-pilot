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
        PRESERVATION_COMPILE_REQUIRED_KEYS,
        REFINEMENT_REQUIRED_KEYS,
        detect_task_marker,
        parse_model_json_response,
    )
except ModuleNotFoundError:
    from prompts import (
        DIAGNOSTIC_PLAN_REQUIRED_KEYS,
        PRESERVATION_COMPILE_REQUIRED_KEYS,
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
    if marker == "preservation_compilation":
        return PRESERVATION_COMPILE_REQUIRED_KEYS
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


class SplunkAIAssistantModelClient:
    """ModelClient that routes refinement through Splunk AI Assistant via MCP.

    Splunk's MCP Server (Splunkbase #7931) exposes the AI Assistant tools
    ``saia_generate_spl`` / ``saia_optimize_spl`` once AI Assistant is activated.
    We use ``saia_generate_spl`` (natural-language → SPL) for both the
    refinement and diagnostic-planning tasks: SAIA has native SPL fluency, so
    it avoids the grammar mistakes a small local model makes.

    The result is normalized into the same dict shape the rest of RulePilot
    expects (``diagnosis``, ``refinement_strategy``, ``candidate_spl``,
    ``rationale``, ``expected_effect``, ``risk`` for refinement; or
    ``diagnostic_searches`` for planning).

    NOTE: the ``saia_*`` tools call a Splunk Cloud Services backend. If that
    backend returns an entitlement error (e.g. HTTP 403), this client raises a
    clear RuntimeError rather than silently degrading — the caller can fall back
    to another provider.
    """

    def __init__(self, *, index: str, mcp_client: Any | None = None):
        self.index = index
        self._mcp_client = mcp_client

    def _client(self) -> Any:
        if self._mcp_client is None:
            try:
                from src.splunk_mcp_client import SplunkMCPClient
            except ModuleNotFoundError:
                from splunk_mcp_client import SplunkMCPClient
            self._mcp_client = SplunkMCPClient.from_env()
        return self._mcp_client

    def generate_json(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        marker = detect_task_marker(messages)
        if marker == "diagnostic_planning":
            return self._plan_diagnostics(messages)
        return self._refine(messages)

    def _refine(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        baseline = _extract_baseline_spl(messages) or f"search index={self.index}"
        index = _extract_block(messages, "Target index:") or self.index
        must_preserve = _extract_block(messages, "Must preserve:") or ""
        context = _extract_block(messages, "Context:") or ""
        revision = _extract_block(
            messages, "Revision feedback (previous attempt was unsatisfactory):"
        )

        prompt_lines = [
            "Refine this noisy Splunk detection to reduce false positives "
            "WITHOUT dropping the events flagged under 'Must preserve'.",
            f"The refined search MUST target index={index} and stay read-only.",
            "Reduce the result volume with aggregation, time-windowing, and "
            "thresholding, but keep surfacing the must-preserve behavior.",
            "",
            f"Baseline SPL:\n{baseline}",
        ]
        if context:
            prompt_lines += ["", f"Context: {context}"]
        if must_preserve:
            prompt_lines += ["", f"Must preserve: {must_preserve}"]
        if revision:
            prompt_lines += [
                "",
                "A previous candidate was rejected. Fix it. Feedback:",
                revision,
            ]
        prompt = "\n".join(prompt_lines)

        # Pass the full grounded user prompt as additional_context so SAIA sees
        # the diagnostics and signals that explain the noise.
        user_context = _last_user_content(messages)

        candidate_spl = self._call_generate_spl(
            prompt=prompt,
            additional_context=user_context,
        )

        return {
            "diagnosis": (
                "Splunk AI Assistant analyzed the baseline against the diagnostic "
                "signals and proposed a tighter, read-only pipeline."
            ),
            "refinement_strategy": (
                "Routed through Splunk AI Assistant (saia_generate_spl) via MCP "
                "for native SPL fluency."
            ),
            "candidate_spl": candidate_spl,
            "rationale": (
                "Generated by Splunk AI Assistant; validated by RulePilot's "
                "parser pre-flight and preservation probe before acceptance."
            ),
            "expected_effect": "Materially fewer result rows than the baseline.",
            "risk": (
                "AI-generated SPL is verified against Splunk's parser and the "
                "must-preserve set before being accepted."
            ),
        }

    def _plan_diagnostics(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        """Plan diagnostics via SAIA, falling back to generic top-N searches.

        ``saia_generate_spl`` returns a single SPL search, not a multi-search
        plan, so we ask it for one characterizing search per available field and
        assemble the plan. If SAIA is unavailable we reuse the deterministic
        top-N fallback so custom-rule mode still works.
        """
        fields = _extract_available_fields(messages)
        candidates = [
            field for field in fields if field not in {"_time", "source", "sourcetype"}
        ][:4] or ["user"]

        searches: list[dict[str, str]] = []
        for fieldname in candidates:
            try:
                spl = self._call_generate_spl(
                    prompt=(
                        f"Write a single read-only Splunk search on index="
                        f"{self.index} that returns the top 10 values of the "
                        f"field '{fieldname}' by event count, most frequent first."
                    ),
                    additional_context="",
                )
            except Exception:
                spl = (
                    f"search index={self.index}\n"
                    f"| stats count by {fieldname}\n"
                    f"| sort - count\n"
                    f"| head 10"
                )
            searches.append(
                {
                    "name": f"count_by_{fieldname}",
                    "purpose": f"Top values of {fieldname} in the matching event set.",
                    "spl": spl,
                }
            )
        return {"diagnostic_searches": searches}

    def _call_generate_spl(self, *, prompt: str, additional_context: str) -> str:
        arguments: dict[str, Any] = {"prompt": prompt, "spl_only": True}
        if additional_context:
            arguments["additional_context"] = additional_context

        result = self._client().call_tool("saia_generate_spl", arguments)
        text = _join_mcp_text(result.get("content"))

        if result.get("is_error"):
            raise RuntimeError(
                f"Splunk AI Assistant (saia_generate_spl) returned an error: "
                f"{text[:300] or 'unknown error'}. If this is a 403, the AI "
                f"Assistant is installed but the backing Splunk Cloud Services "
                f"API is not entitled for this account."
            )

        spl = _extract_spl_from_text(text)
        if not spl:
            raise RuntimeError(
                f"Splunk AI Assistant returned no usable SPL. Raw response: "
                f"{text[:300]!r}"
            )
        return spl


def model_client_from_env(*, index: str) -> ModelClient:
    _load_dotenv_if_available()

    provider = os.getenv("RULEPILOT_MODEL_PROVIDER", "deterministic").strip().lower()
    if provider == "deterministic":
        return DeterministicFallbackModelClient(index=index)

    if provider == "openai_compatible":
        return OpenAICompatibleModelClient(
            base_url=os.getenv("RULEPILOT_MODEL_BASE_URL", "http://localhost:11434/v1"),
            model=os.getenv("RULEPILOT_MODEL_NAME", "qwen2.5:7b"),
            api_key=os.getenv("RULEPILOT_MODEL_API_KEY", "local"),
            timeout=_env_int("RULEPILOT_MODEL_TIMEOUT", 60),
            temperature=_env_float("RULEPILOT_MODEL_TEMPERATURE", 0.0),
            max_tokens=_env_int("RULEPILOT_MODEL_MAX_TOKENS", 1200),
        )

    if provider == "splunk_ai":
        return SplunkAIAssistantModelClient(index=index)

    if provider == "splunk_ai_command":
        return SplunkAICommandModelClient()

    raise ValueError(
        "Unknown RULEPILOT_MODEL_PROVIDER. Expected deterministic, "
        "openai_compatible, splunk_ai, or splunk_ai_command; got "
        f"{provider!r}."
    )


def build_model_client(provider: str, *, index: str) -> ModelClient:
    """Construct a model client for a UI-selected provider.

    Unlike ``model_client_from_env`` (env-driven, used by the CLI), this maps the
    three UI choices — local Qwen, frontier OpenAI, Splunk AI Assistant — to
    concrete clients and raises a clear, user-facing ``RuntimeError`` when a
    provider is misconfigured (e.g. no OpenAI key). Reachability failures (local
    LLM down, SAIA 403) surface as ``RuntimeError`` from the client itself when
    it is actually called.
    """
    _load_dotenv_if_available()
    key = provider.strip().lower()
    timeout = _env_int("RULEPILOT_MODEL_TIMEOUT", 60)
    temperature = _env_float("RULEPILOT_MODEL_TEMPERATURE", 0.0)
    max_tokens = _env_int("RULEPILOT_MODEL_MAX_TOKENS", 1200)

    if key in {"local", "qwen", "local_qwen"}:
        return OpenAICompatibleModelClient(
            base_url=os.getenv(
                "RULEPILOT_LOCAL_BASE_URL", "http://localhost:11434/v1"
            ),
            model=os.getenv("RULEPILOT_LOCAL_MODEL", "qwen2.5:7b"),
            api_key="local",
            timeout=timeout,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    if key in {"openai", "frontier"}:
        api_key = os.getenv("RULEPILOT_OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")
        model_env_key = os.getenv("RULEPILOT_MODEL_API_KEY", "")
        if not api_key and model_env_key and model_env_key != "local":
            api_key = model_env_key
        if not api_key:
            raise RuntimeError(
                "No OpenAI API key configured. Add RULEPILOT_OPENAI_API_KEY "
                "(or set RULEPILOT_MODEL_API_KEY to your OpenAI key) in .env, "
                "then reload."
            )
        base_url = os.getenv("RULEPILOT_OPENAI_BASE_URL") or os.getenv(
            "RULEPILOT_MODEL_BASE_URL", "https://api.openai.com/v1"
        )
        model = os.getenv("RULEPILOT_OPENAI_MODEL") or os.getenv(
            "RULEPILOT_MODEL_NAME", "gpt-4o"
        )
        # If the shared env vars point at a local Ollama, don't reuse them for
        # the OpenAI cloud option.
        if "localhost" in base_url or "127.0.0.1" in base_url:
            base_url = "https://api.openai.com/v1"
            model = os.getenv("RULEPILOT_OPENAI_MODEL", "gpt-4o")
        return OpenAICompatibleModelClient(
            base_url=base_url,
            model=model,
            api_key=api_key,
            timeout=timeout,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    if key in {"splunk_ai", "saia", "splunk_ai_assistant"}:
        return SplunkAIAssistantModelClient(index=index)

    raise RuntimeError(
        f"Unknown model provider {provider!r}. Expected local, openai, or splunk_ai."
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
    if "preservation_check_spl" in required_keys:
        check = result.get("preservation_check_spl", "")
        if not isinstance(check, str) or not is_read_only_spl(check):
            raise RuntimeError(
                "Compiled must-preserve check contains an unsafe command."
            )
        if not has_balanced_parens(check):
            raise RuntimeError(
                "Compiled must-preserve check has unbalanced parentheses or quotes."
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


def _last_user_content(messages: list[dict[str, str]]) -> str:
    for message in reversed(messages):
        if message.get("role") == "user":
            return message.get("content") or ""
    return ""


def _join_mcp_text(content: Any) -> str:
    """Concatenate the text blocks of an MCP tool-call result."""
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            text = block.get("text")
            if isinstance(text, str):
                parts.append(text)
    return "\n".join(parts).strip()


def _extract_spl_from_text(text: str) -> str:
    """Pull an SPL pipeline out of a SAIA response.

    Handles three shapes: a bare SPL string, a fenced ```spl ... ``` block, or
    a JSON object with an ``spl``/``query``/``search`` field.
    """
    raw = (text or "").strip()
    if not raw:
        return ""

    # JSON-wrapped responses.
    if raw.startswith("{"):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            for key in ("spl", "query", "search", "result"):
                value = parsed.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()

    # Fenced code block (```spl / ```).
    fence = re.search(r"```(?:spl|splunk)?\s*\n?(.*?)```", raw, re.DOTALL | re.IGNORECASE)
    if fence:
        inner = fence.group(1).strip()
        if inner:
            return inner

    return raw


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
