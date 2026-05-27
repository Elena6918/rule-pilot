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
