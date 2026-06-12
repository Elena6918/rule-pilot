# RulePilot — build log & roadmap

This file tracks feature build status and future direction. For what the project
is and how to run it, see [README.md](README.md).

## Feature status

| Piece | State |
| --- | --- |
| Synthetic log generator (auth + process-execution events) | done |
| Splunk REST client (search jobs, polling, **parser pre-flight via POST**) | done |
| Scenario framework (`Scenario` dataclass, generic agent loop) | done |
| LLM-driven refinement (provider-agnostic `ModelClient`) | done |
| LLM-driven diagnostic planning (resilient — skips invalid, keeps valid) | done |
| **Natural-language → SPL must-preserve compiler** (`compile_preservation_check`) | done |
| Preservation gate (refined rule must still surface the must-catch entities) | done |
| SPL safety guardrails (read-only, balanced-paren, parser pre-flight, anti-pattern) | done |
| Honest-failure UI (`—` metrics, no disk write on rejected SPL) | done |
| Model selector — Local (Qwen) / Frontier (OpenAI) / Splunk AI Assistant | done |
| Unified rule-input form across all three tabs | done |
| Streamlit UI, Live/Replay toggle, Markdown reports | done |
| Scenario 1 — Failed Login Burst Refinement | done |
| Scenario 2 — Suspicious Command Execution | done |
| Scenario 3 — Custom Rule (blank, bring-your-own) | done |
| Splunk MCP Server connection (`SplunkMCPClient`, sidebar test) | done |
| Splunk AI Assistant as a provider (`saia_generate_spl` via MCP) | wired; blocked on tenant `saia-api-v2` entitlement (HTTP 403) |

## Splunk AI Assistant — known blocker

The MCP server exposes the `saia_*` AI Assistant tools, but every call returns
HTTP 403 from the Splunk Cloud Services backend (`…/saia-api-v2/…`). Diagnosis:
the tenant is entitled for the SAIA **v1** API (the browser assistant works) but
**not** the **v2** API the MCP tools call. This is a Splunk-side tenant
entitlement, not a code issue — the `splunk_ai` provider is fully wired and
activates the moment v2 is enabled. Until then, use **Frontier (OpenAI)** or
**Local (Qwen)**.

## Roadmap

### Done
- Repo skeleton, synthetic data, Splunk integration
- Diagnostic execution + LLM refinement + diagnostic planning
- Natural-language → SPL must-preserve compilation
- Provider-agnostic model layer with runtime selection
- SPL safety guardrails + preservation gate + honest-failure UI
- CLI + Streamlit UI + Markdown reports + Replay samples

### Future
- Splunk AI Assistant once `saia-api-v2` entitlement clears
- MCP-sourced exemplars (`splunk_get_knowledge_objects("saved_searches")`)
- Third scenario: data exfiltration (off-hours large transfers)
- Analyst approval workflow with rule-history tracking
- MITRE ATT&CK technique labeling on refined rules
- Splunk custom-app packaging; BOTS v3 dataset support

## Non-goals

RulePilot does not attempt to: fully automate detection engineering; claim
generated SPL is always correct; depend on proprietary production SOC data;
require Splunk Enterprise Security or BOTS v3.

## Guiding principle

The core workflow must work without depending on any single uncertain external
service. Splunk is required; the model provider is pluggable behind the
`ModelClient` interface, with a deterministic fallback for demo safety.
