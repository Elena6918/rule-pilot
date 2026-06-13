#!/usr/bin/env python3
"""Sync wrapper around Splunk's official MCP server.

Splunk's MCP Server app (Splunkbase #7931) exposes a streamable HTTP endpoint —
typically https://<splunk-host>:8089/services/mcp — protected by an encrypted
bearer token generated through the MCP Server app UI.

This module provides ``SplunkMCPClient``: a thin sync interface over the
official ``mcp`` Python SDK's async streamable-HTTP client. Sync was chosen
because the rest of RulePilot is sync; we wrap each MCP call in
``asyncio.run`` rather than asyncify the entire codebase.

The client does NOT decide how MCP gets used by the agent — that wiring lives
elsewhere. Here we only expose ``list_tools`` and ``call_tool`` as
infrastructure primitives.
"""

from __future__ import annotations

import asyncio
import json
import os
import ssl
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator


class SplunkMCPClientError(RuntimeError):
    """Base error for SplunkMCPClient failures."""


class SplunkMCPConfigError(SplunkMCPClientError):
    """Missing/invalid env configuration."""


class SplunkMCPConnectionError(SplunkMCPClientError):
    """Could not reach the MCP server."""


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_dotenv_if_available() -> None:
    try:
        from dotenv import load_dotenv
    except ModuleNotFoundError:
        return
    load_dotenv(_repo_root() / ".env", override=False)


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


class SplunkMCPClient:
    """Sync interface over Splunk's MCP server."""

    def __init__(
        self,
        *,
        endpoint: str,
        token: str,
        verify_ssl: bool = False,
        request_timeout: float = 60.0,
    ):
        self.endpoint = endpoint.rstrip("/")
        self.token = token
        self.verify_ssl = verify_ssl
        self.request_timeout = request_timeout

    @classmethod
    def from_env(cls) -> "SplunkMCPClient":
        _load_dotenv_if_available()
        endpoint = (os.getenv("SPLUNK_MCP_ENDPOINT") or "").strip()
        token = (os.getenv("SPLUNK_MCP_TOKEN") or "").strip()
        if not endpoint:
            raise SplunkMCPConfigError(
                "SPLUNK_MCP_ENDPOINT is not set. Copy the endpoint from the "
                "Splunk MCP Server app UI and add it to .env."
            )
        if not token:
            raise SplunkMCPConfigError(
                "SPLUNK_MCP_TOKEN is not set. Generate an encrypted token in "
                "the Splunk MCP Server app UI ('Create MCP Encrypted Token') "
                "and add it to .env."
            )
        verify = _env_bool("SPLUNK_VERIFY_SSL", default=False)
        return cls(endpoint=endpoint, token=token, verify_ssl=verify)

    # ------------------------------------------------------------------
    # Public sync API
    # ------------------------------------------------------------------

    def list_tools(self) -> list[dict[str, Any]]:
        return asyncio.run(self._list_tools_async())

    def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return asyncio.run(self._call_tool_async(name, arguments or {}))

    def ping(self) -> dict[str, Any]:
        """Lightweight connection check: returns tool count + first 5 names."""
        tools = self.list_tools()
        return {
            "ok": True,
            "tool_count": len(tools),
            "sample_tool_names": [t["name"] for t in tools[:5]],
            "endpoint": self.endpoint,
        }

    def run_query(
        self,
        spl: str,
        *,
        earliest_time: str = "0",
        latest_time: str = "now",
        max_results: int = 1000,
    ) -> list[dict[str, Any]]:
        """Run an SPL search through the Splunk MCP Server's ``splunk_run_query``
        tool and return result rows as a list of dicts (same shape as the REST
        client). Raises SplunkMCPClientError on tool error."""
        result = self.call_tool(
            "splunk_run_query",
            {
                "query": spl,
                "earliest_time": earliest_time,
                "latest_time": latest_time,
                "row_limit": max_results,
            },
        )
        if result.get("is_error"):
            text = self._first_text(result)
            raise SplunkMCPClientError(
                f"splunk_run_query failed: {text[:300] or 'unknown error'}"
            )
        return self._extract_rows(result)

    @staticmethod
    def _first_text(result: dict[str, Any]) -> str:
        for block in result.get("content") or []:
            if isinstance(block, dict) and block.get("type") == "text":
                return block.get("text") or ""
        return ""

    @classmethod
    def _extract_rows(cls, result: dict[str, Any]) -> list[dict[str, Any]]:
        structured = result.get("structured_content")
        if isinstance(structured, dict) and isinstance(structured.get("results"), list):
            return [row for row in structured["results"] if isinstance(row, dict)]
        # Fallback: parse the JSON text block.
        text = cls._first_text(result)
        if text:
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = None
            if isinstance(data, dict) and isinstance(data.get("results"), list):
                return [row for row in data["results"] if isinstance(row, dict)]
        return []

    # ------------------------------------------------------------------
    # Async implementation
    # ------------------------------------------------------------------

    async def _list_tools_async(self) -> list[dict[str, Any]]:
        async with self._session() as session:
            result = await session.list_tools()
            return [
                {
                    "name": tool.name,
                    "description": tool.description or "",
                    "input_schema": tool.inputSchema,
                }
                for tool in result.tools
            ]

    async def _call_tool_async(
        self,
        name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        async with self._session() as session:
            result = await session.call_tool(name, arguments)
            return {
                "is_error": bool(getattr(result, "isError", False)),
                "content": self._flatten_content(result.content),
                "structured_content": getattr(result, "structuredContent", None),
            }

    @asynccontextmanager
    async def _session(self) -> AsyncIterator[Any]:
        try:
            import httpx
            from mcp import ClientSession
            from mcp.client.streamable_http import streamable_http_client
        except ModuleNotFoundError as exc:
            raise SplunkMCPConfigError(
                "The 'mcp' Python package is required. Install with: "
                "pip install mcp"
            ) from exc

        # Splunk's MCP server uses a self-signed cert by default; reuse
        # SPLUNK_VERIFY_SSL semantics so the same env var controls both REST
        # and MCP transport.
        http_client = httpx.AsyncClient(
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=httpx.Timeout(self.request_timeout, read=self.request_timeout * 5),
            verify=self.verify_ssl,
            follow_redirects=True,
        )

        try:
            async with streamable_http_client(
                self.endpoint,
                http_client=http_client,
            ) as (read, write, _meta):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    yield session
        except SplunkMCPClientError:
            raise
        except Exception as exc:
            raise SplunkMCPConnectionError(
                f"Could not reach Splunk MCP server at {self.endpoint}: {exc}"
            ) from exc
        finally:
            await http_client.aclose()

    @staticmethod
    def _flatten_content(content: Any) -> list[dict[str, Any]]:
        """Normalize MCP tool result content blocks into plain dicts."""
        if not content:
            return []
        flat: list[dict[str, Any]] = []
        for block in content:
            block_type = getattr(block, "type", None) or "unknown"
            if block_type == "text":
                flat.append({"type": "text", "text": getattr(block, "text", "")})
            elif block_type == "image":
                flat.append(
                    {
                        "type": "image",
                        "mime_type": getattr(block, "mimeType", None),
                        "data_len": len(getattr(block, "data", "") or ""),
                    }
                )
            else:
                # Unknown block type: try to serialize what we can.
                try:
                    flat.append(json.loads(block.model_dump_json()))
                except Exception:
                    flat.append({"type": block_type, "repr": repr(block)})
        return flat


def main() -> int:
    try:
        client = SplunkMCPClient.from_env()
        result = client.ping()
        print(json.dumps(result, indent=2))
        return 0
    except SplunkMCPClientError as exc:
        print(f"MCP smoke test failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
