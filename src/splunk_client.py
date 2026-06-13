#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import time
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv
from requests import Response
from requests.auth import HTTPBasicAuth
from requests.exceptions import ConnectionError, RequestException, Timeout
from urllib3.exceptions import InsecureRequestWarning


class SplunkClientError(RuntimeError):
    """Base error for Splunk client failures."""


class SplunkConfigError(SplunkClientError):
    """Raised when required environment configuration is missing or invalid."""


class SplunkConnectionError(SplunkClientError):
    """Raised when Splunk cannot be reached."""


class SplunkAuthenticationError(SplunkClientError):
    """Raised when Splunk rejects the configured credentials."""


class SplunkResponseError(SplunkClientError):
    """Raised when Splunk returns an unexpected response."""


class SplunkSearchError(SplunkClientError):
    """Raised when a search job fails."""


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default

    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False

    raise SplunkConfigError(
        f"{name} must be a boolean value such as true or false; got {value!r}."
    )


def _build_mcp_client_if_configured() -> Any:
    """Build a SplunkMCPClient when MCP env vars are present, else None.

    Construction does not open a connection (it just stores endpoint + token),
    so this is cheap and safe; an unreachable server surfaces only when a search
    actually runs, where run_search falls back to REST.
    """
    endpoint = (os.getenv("SPLUNK_MCP_ENDPOINT") or "").strip()
    token = (os.getenv("SPLUNK_MCP_TOKEN") or "").strip()
    if not endpoint or not token:
        return None
    try:
        try:
            from src.splunk_mcp_client import SplunkMCPClient
        except ModuleNotFoundError:
            from splunk_mcp_client import SplunkMCPClient
        return SplunkMCPClient.from_env()
    except Exception:
        return None


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        raise SplunkConfigError(f"Missing required environment variable: {name}")
    return value.strip()


@dataclass(frozen=True)
class SplunkClient:
    host: str
    api_port: int
    username: str
    password: str
    index: str
    verify_ssl: bool = False
    scheme: str = "https"
    timeout: int = 30
    poll_interval: float = 0.5
    max_wait_seconds: int = 60
    _last_spl: str = ""
    # When set, search execution is routed through the Splunk MCP Server's
    # splunk_run_query tool (REST stays as the fallback + parser pre-flight).
    mcp_client: Any = None

    @classmethod
    def from_env(cls) -> "SplunkClient":
        load_dotenv(_repo_root() / ".env", override=True)

        host = _required_env("SPLUNK_HOST")
        username = _required_env("SPLUNK_USERNAME")
        password = _required_env("SPLUNK_PASSWORD")
        index = _required_env("SPLUNK_INDEX")

        api_port_raw = _required_env("SPLUNK_API_PORT")
        try:
            api_port = int(api_port_raw)
        except ValueError as exc:
            raise SplunkConfigError(
                f"SPLUNK_API_PORT must be an integer; got {api_port_raw!r}."
            ) from exc

        verify_ssl = _env_bool("SPLUNK_VERIFY_SSL", default=False)

        return cls(
            host=host,
            api_port=api_port,
            username=username,
            password=password,
            index=index,
            verify_ssl=verify_ssl,
            mcp_client=_build_mcp_client_if_configured(),
        )

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.api_port}"

    @property
    def auth(self) -> HTTPBasicAuth:
        return HTTPBasicAuth(self.username, self.password)

    def health_check(self) -> bool:
        try:
            response = self._request(
                "GET",
                "/services/server/info",
                params={"output_mode": "json"},
            )
            self._json(response)
            return True
        except SplunkClientError:
            return False

    def validate_spl(self, spl: str) -> tuple[bool, str | None]:
        """Pre-flight validation via Splunk's own parser.

        Calls ``/services/search/parser`` with ``parse_only=true`` so Splunk's
        SPL grammar parses the search without dispatching a job. Catches
        malformed constructs (e.g. ``user STARTSWITH "svc_"``,
        ``| sort - count > 5``, unmatched quotes) using Splunk's own engine
        instead of regex heuristics on our side.

        Returns ``(is_valid, error_message)``. A valid SPL returns
        ``(True, None)``; an invalid SPL returns ``(False, "...")`` where the
        string is Splunk's own parse-error text (great as LLM feedback).
        """
        if not spl.strip():
            return False, "SPL is empty."

        normalized = self._normalize_search_spl(spl)
        url = f"{self.base_url}/services/search/parser"

        # Splunk's parser endpoint requires POST with the query in the form body.
        # A GET (or POST with the query in the URL query string) returns HTTP 405
        # "The method is not allowed." / 400 "Invalid query." — which would
        # masquerade as a parse failure and falsely reject every candidate.
        form_data = {
            "q": normalized,
            "parse_only": "true",
            "output_mode": "json",
        }

        try:
            if not self.verify_ssl:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", InsecureRequestWarning)
                    response = requests.post(
                        url,
                        data=form_data,
                        auth=self.auth,
                        verify=self.verify_ssl,
                        timeout=self.timeout,
                    )
            else:
                response = requests.post(
                    url,
                    data=form_data,
                    auth=self.auth,
                    timeout=self.timeout,
                )
        except (ConnectionError, Timeout) as exc:
            raise SplunkConnectionError(
                f"Could not reach Splunk parser at {self.base_url}: {exc}"
            ) from exc
        except RequestException as exc:
            raise SplunkConnectionError(f"Splunk parser request failed: {exc}") from exc

        if response.status_code in {401, 403}:
            raise SplunkAuthenticationError(
                "Splunk authentication failed for parser endpoint."
            )

        if 200 <= response.status_code < 300:
            return True, None

        # 400-class responses indicate a parse error. Splunk returns the
        # specific error in either JSON ``messages`` or the raw body.
        error_text = self._extract_parser_error(response) or response.text[:500].strip()
        return False, error_text

    @staticmethod
    def _extract_parser_error(response: Response) -> str | None:
        try:
            payload = response.json()
        except ValueError:
            return None
        if not isinstance(payload, dict):
            return None
        messages = payload.get("messages")
        if isinstance(messages, list):
            for entry in messages:
                if isinstance(entry, dict):
                    text = entry.get("text")
                    if isinstance(text, str) and text.strip():
                        return text.strip()
        return None

    def run_search(
        self,
        spl: str,
        *,
        earliest_time: str = "0",
        latest_time: str = "now",
        max_results: int = 1000,
    ) -> list[dict[str, Any]]:
        if not spl.strip():
            raise SplunkConfigError("Search SPL cannot be empty.")
        if max_results < 1:
            raise SplunkConfigError("max_results must be at least 1.")

        spl = self._normalize_search_spl(spl)
        object.__setattr__(self, "_last_spl", spl)

        # Default search path: the Splunk MCP Server (a listed Splunk AI
        # capability). REST is the fallback so a transient MCP error never fails
        # the run.
        if self.mcp_client is not None:
            try:
                return self.mcp_client.run_query(
                    spl,
                    earliest_time=earliest_time,
                    latest_time=latest_time,
                    max_results=max_results,
                )
            except Exception:
                pass

        sid = self._create_search_job(
            spl=spl,
            earliest_time=earliest_time,
            latest_time=latest_time,
        )
        self._wait_for_job(sid)
        return self._fetch_results(sid, max_results=max_results)

    def _create_search_job(self, *, spl: str, earliest_time: str, latest_time: str) -> str:
        response = self._request(
            "POST",
            "/services/search/jobs",
            data={
                "search": spl,
                "earliest_time": earliest_time,
                "latest_time": latest_time,
                "output_mode": "json",
            },
        )
        payload = self._json(response)
        sid = payload.get("sid")
        if not isinstance(sid, str) or not sid:
            raise SplunkResponseError(f"Malformed Splunk job creation response: {payload!r}")
        return sid

    def _normalize_search_spl(self, spl: str) -> str:
        stripped = spl.strip()
        first_token = stripped.split(None, 1)[0].lower()
        command_names = {
            "search",
            "|",
            "tstats",
            "from",
            "inputlookup",
            "makeresults",
            "metadata",
            "savedsearch",
        }

        if first_token in command_names or stripped.startswith("|"):
            return stripped
        if "=" in first_token:
            return f"search {stripped}"

        return stripped

    def _wait_for_job(self, sid: str) -> None:
        deadline = time.monotonic() + self.max_wait_seconds

        while time.monotonic() < deadline:
            payload, content = self._job_payload(sid)
            dispatch_state = content.get("dispatchState")
            is_done = str(content.get("isDone", "0")) == "1"

            if dispatch_state in {"FAILED", "CANCELED", "BAD_INPUT"}:
                messages = payload.get("messages") or content.get("messages") or []
                spl_preview = (self._last_spl or "")[:500]
                raise SplunkSearchError(
                    f"Splunk search job {sid} failed with state {dispatch_state}: "
                    f"{messages}\n--- failing SPL ---\n{spl_preview}"
                )

            if is_done or dispatch_state == "DONE":
                return

            time.sleep(self.poll_interval)

        raise SplunkSearchError(
            f"Timed out waiting for Splunk search job {sid} after {self.max_wait_seconds} seconds."
        )

    def _job_payload(self, sid: str) -> tuple[dict[str, Any], dict[str, Any]]:
        response = self._request(
            "GET",
            f"/services/search/jobs/{sid}",
            params={"output_mode": "json"},
        )
        payload = self._json(response)
        entry = payload.get("entry")
        if not isinstance(entry, list) or not entry:
            raise SplunkResponseError(f"Malformed Splunk job status response: {payload!r}")
        first_entry = entry[0]
        if not isinstance(first_entry, dict):
            raise SplunkResponseError(f"Malformed Splunk job status entry: {payload!r}")
        content = first_entry.get("content")
        if not isinstance(content, dict):
            raise SplunkResponseError(f"Malformed Splunk job status content: {payload!r}")
        return payload, content

    def _fetch_results(self, sid: str, *, max_results: int) -> list[dict[str, Any]]:
        response = self._request(
            "GET",
            f"/services/search/jobs/{sid}/results",
            params={
                "output_mode": "json",
                "count": max_results,
            },
        )
        payload = self._json(response)
        results = payload.get("results")
        if not isinstance(results, list):
            raise SplunkResponseError(f"Malformed Splunk results response: {payload!r}")
        if not all(isinstance(row, dict) for row in results):
            raise SplunkResponseError(
                f"Splunk results contained non-object rows: {results!r}"
            )
        return results

    def _request(self, method: str, path: str, **kwargs: Any) -> Response:
        url = f"{self.base_url}{path}"
        kwargs.setdefault("auth", self.auth)
        kwargs.setdefault("verify", self.verify_ssl)
        kwargs.setdefault("timeout", self.timeout)

        try:
            if not self.verify_ssl:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", InsecureRequestWarning)
                    response = requests.request(method, url, **kwargs)
            else:
                response = requests.request(method, url, **kwargs)
        except (ConnectionError, Timeout) as exc:
            raise SplunkConnectionError(
                "Could not connect to Splunk management API at "
                f"{self.base_url}. If Splunk is remote, check that your SSH tunnel is running "
                "and includes: -L 8089:localhost:8089"
            ) from exc
        except RequestException as exc:
            raise SplunkConnectionError(f"Request to Splunk failed: {exc}") from exc

        if response.status_code in {401, 403}:
            raise SplunkAuthenticationError(
                "Splunk authentication failed. Check SPLUNK_USERNAME and SPLUNK_PASSWORD."
            )

        try:
            response.raise_for_status()
        except RequestException as exc:
            raise SplunkResponseError(
                f"Splunk API returned HTTP {response.status_code}: {response.text[:500]}"
            ) from exc

        return response

    def _json(self, response: Response) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError as exc:
            raise SplunkResponseError(
                f"Splunk returned non-JSON response: {response.text[:500]}"
            ) from exc

        if not isinstance(payload, dict):
            raise SplunkResponseError(
                f"Expected JSON object from Splunk; got {type(payload).__name__}."
            )
        return payload


def main() -> None:
    client = SplunkClient.from_env()
    print(
        "Using Splunk API "
        f"{client.base_url} as {client.username!r}, "
        f"index={client.index!r}, verify_ssl={client.verify_ssl}"
    )
    rows = client.run_search(f"search index={client.index} | head 5")
    print(json.dumps(rows, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
