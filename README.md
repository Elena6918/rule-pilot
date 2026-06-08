# RulePilot

RulePilot is an analyst-in-the-loop agent that **reduces false positives in noisy Splunk detection rules without dropping the real suspicious events analysts care about.**

It runs a baseline SPL search against Splunk data, plans diagnostic searches that explain *why* the rule is noisy, asks an LLM to propose a refined SPL, validates the refinement against a "must-preserve" signal set, and iterates if the candidate either fails to reduce noise OR drops too many of the events the analyst marked as critical — all behind a Streamlit UI with one tab per scenario.

---

## Project Summary

**Project name:** RulePilot
**Hackathon track:** Security
**Core idea:** Help SOC analysts cut alert volume on noisy detections without losing the signal they actually care about.

False positives are the dominant SOC pain point — analysts drown in alerts before missed detections become visible. RulePilot's framing is deliberately narrow: it is a **false-positive reducer** with a built-in preservation check, not a general detection-engineering autopilot. Coverage expansion (catching things the rule currently misses) is future work.

RulePilot does **not** claim to autonomously produce the perfect detection rule. It produces an analyst-reviewable recommendation with:

- original SPL
- diagnostic SPL results
- recommended revised SPL
- intent / refinement strategy
- expected effect and risk
- before/after comparison

---

## Current Status

| Piece | State |
| --- | --- |
| Synthetic log generator (auth + process-execution events) | done |
| Splunk client (REST API, search job polling) | done |
| Scenario framework (`Scenario` dataclass, generic agent loop) | done |
| LLM-driven refinement (OpenAI-compatible endpoint) | done |
| LLM-driven diagnostic planning (custom-rule mode) | done |
| Must-preserve check (rule must still surface flagged signal events) | done |
| SPL safety guardrails (read-only check, balanced-paren check, syntax-anti-pattern detection) | done |
| Deterministic fallback model client | done |
| Streamlit UI with 3 tabs and Live/Replay toggle | done |
| Scenario 1 — Failed Login Burst Refinement | done |
| Scenario 2 — Suspicious Command Execution | done |
| Scenario 3 — Custom Rule (user-supplied baseline + intent) | done |
| Markdown report generator | done |

---

## Architecture

```text
Synthetic security logs (auth + process events)
        |
        v
Splunk Enterprise (remote)
index=$SPLUNK_INDEX
        |
        v
RulePilot Agent
   1. Run baseline SPL
   2. Plan diagnostic searches
        - hardcoded for demo scenarios
        - LLM-planned for custom scenarios
   3. Run diagnostics
   4. Ask LLM to propose refined SPL
   5. Validate (read-only + balanced parens)
   6. Run refined SPL
   7. Compare before/after
        |
        +---> Streamlit UI (live or replay from saved JSON)
        +---> CLI report (run_demo.py)
        +---> Markdown report (reports/<scenario>_report.md)
```

The LLM-driven path is primary. A `DeterministicFallbackModelClient` is kept as a demo-safety net: if no model provider is configured, the agent still produces a valid (no-op) report instead of crashing.

---

## Scenarios

### 1. Failed Login Burst Refinement (demo)

Baseline matches every failed-login event. Refinement aggregates failed logins into 10-minute windows by `user` + `src_ip` and only surfaces repeated bursts.

### 2. Suspicious Command Execution (demo)

Baseline keyword-matches any command line containing `powershell`, `curl`, `wget`, or `base64` — fires constantly on admins, CI jobs, and routine scripts. Refinement narrows to high-risk patterns (encoded PowerShell, `curl|sh`, `wget|sh`, `/dev/tcp/` reverse shells) and excludes service accounts.

### 3. Custom Rule (the real product)

Analyst pastes their own baseline SPL plus a plain-English goal and "must preserve" intent. RulePilot asks the LLM to plan diagnostics from the SPL, runs them, and proposes a refined version. This is the framework piece that lets RulePilot extend beyond the two canned demos.

---

## Repository Structure

```text
rule-pilot/
  README.md
  app.py                          # Streamlit UI (3 tabs)
  run_demo.py                     # CLI demo entry point

  detections/
    failed_login_baseline.spl
    failed_login_refined.spl
    suspicious_command_baseline.spl
    suspicious_command_refined.spl  # written by agent
    custom_refined.spl              # written by agent

  src/
    agent.py                      # RulePilotAgent.run(scenario)
    scenarios.py                  # Scenario dataclass + builders
    prompts.py                    # refinement + diagnostic-planning prompts
    models.py                     # ModelClient impls + SPL safety checks
    splunk_client.py              # Splunk REST API client
    reporting.py                  # Markdown report renderer

  scripts/
    generate_synthetic_logs.py    # auth + process-execution events

  data/
    synthetic_security_logs.jsonl

  reports/
    failed_login_report.md
    suspicious_command_report.md
    samples/
      failed_login.json           # saved by app.py for Replay mode
      suspicious_command.json
      custom.json
```

---

## System Setup

### Local machine

The MacBook is the main development environment. It edits code, runs the Streamlit UI, opens Splunk Web via an SSH tunnel, and runs the agent (which talks to remote Splunk through the same tunnel).

### Remote server

The remote Linux server runs Splunk Enterprise:

```text
Remote Linux server: coursesrv01.cs.virginia.edu
User: ml6vq
Splunk install path: /opt/splunk
Splunk Web port: 8000
Splunk management/API port: 8089
```

Check Splunk status:

```bash
sudo /opt/splunk/bin/splunk status
```

Start Splunk if needed:

```bash
sudo /opt/splunk/bin/splunk start --accept-license --run-as-root
```

This project does **not** require Splunk Enterprise Security.

---

## Accessing Splunk from the MacBook

Open an SSH tunnel that forwards both Splunk Web (8000) and the management API (8089):

```bash
ssh -L 8000:localhost:8000 -L 8089:localhost:8089 ml6vq@coursesrv01.cs.virginia.edu
```

Keep the terminal session open. Then:

- Splunk Web: <http://localhost:8000>
- Splunk REST API (used by RulePilot): <https://localhost:8089>

---

## Python Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install streamlit python-dotenv requests
```

Or, if a `requirements.txt` is added later:

```bash
pip install -r requirements.txt
```

---

## Environment Variables

Copy the example file and edit:

```bash
cp .env.example .env
```

Required keys:

```env
SPLUNK_HOST=localhost
SPLUNK_API_PORT=8089
SPLUNK_USERNAME=elena
SPLUNK_PASSWORD=changeme
SPLUNK_INDEX=rulepilot-demo-v2
SPLUNK_VERIFY_SSL=false
```

Optional — model provider (LLM-driven refinement):

```env
RULEPILOT_MODEL_PROVIDER=openai_compatible
RULEPILOT_MODEL_BASE_URL=http://localhost:11434/v1
RULEPILOT_MODEL_NAME=llama3.2:3b
RULEPILOT_MODEL_API_KEY=local
RULEPILOT_MODEL_TIMEOUT=60
RULEPILOT_MODEL_TEMPERATURE=0.0
RULEPILOT_MODEL_MAX_TOKENS=1200
```

If `RULEPILOT_MODEL_PROVIDER` is unset or `deterministic`, the agent uses a safe no-op fallback (no LLM calls). This guarantees the demo runs even with no model endpoint reachable.

Do not commit `.env`.

---

## Splunk Index Setup

The index name is read from `SPLUNK_INDEX` — both baseline SPL files use `index={index}` as a placeholder that the scenario builders fill in at runtime, so re-versioning the index (e.g. `rulepilot-demo-v2`) requires no code changes.

Create the index in Splunk Web (`Settings → Indexes → New Index → rulepilot-demo-v2`) or via CLI:

```bash
sudo /opt/splunk/bin/splunk add index rulepilot-demo-v2
```

---

## Synthetic Dataset

Generate it with:

```bash
python3 scripts/generate_synthetic_logs.py --out data/synthetic_security_logs.jsonl --events 500
```

The generator produces two event families:

**Authentication events** (`event_type=auth`):

- benign successful logins
- isolated failed attempts
- service-account noise
- a deliberate password-spray sequence (8 failures + 1 success) for `alice` from `45.83.12.9`

**Process-execution events** (`event_type=process`):

- benign admin / dev activity (routine `powershell`, `curl`, `base64`, etc.)
- service-account scripted workloads
- a small set of genuinely suspicious commands: encoded PowerShell, `curl|sh`, `wget|sh`, `/dev/tcp/` reverse shells

Example process event:

```json
{"_time":"2026-05-27T15:19:17Z","event_type":"process","host":"host-web-01","user":"alice","process":"powershell.exe","parent_process":"winword.exe","command_line":"powershell.exe -nop -w hidden -enc JABjAD0A...","sourcetype":"process","source":"synthetic_security_logs"}
```

---

## Ingesting Synthetic Logs

### Option 1: Manual upload through Splunk Web

1. Open <http://localhost:8000>
2. `Settings → Add Data → Upload`
3. Upload `data/synthetic_security_logs.jsonl`
4. Set index to your current `SPLUNK_INDEX` value
5. Set sourcetype to `_json` (the generator emits structured JSON; per-event `sourcetype` is set inside each record)

### Option 2: Scripted ingestion

Not yet implemented. For the MVP, manual upload is the supported path.

---

## Running the Demo

### CLI

```bash
python3 run_demo.py --scenario failed_login
python3 run_demo.py --scenario suspicious_command
```

Useful flags:

```bash
python3 run_demo.py --scenario failed_login --show-spl --write-report
python3 run_demo.py --scenario suspicious_command --json
```

### Streamlit UI

```bash
streamlit run app.py
```

Then open <http://localhost:8501>.

The UI has three tabs:

1. **Failed Login** — pre-wired demo scenario.
2. **Suspicious Command** — pre-wired demo scenario.
3. **Custom Rule** — paste any baseline SPL + a goal + a must-preserve clause. The agent asks the LLM to plan diagnostics, runs them, and proposes a refined rule.

The sidebar has a **Live / Replay** toggle:

- **Live** — calls Splunk and the LLM. Auto-saves the result to `reports/samples/<scenario>.json`.
- **Replay** — loads the last saved sample. Demo-safe: lets you walk through results without depending on Splunk or the LLM being reachable.

Each report renders:

- baseline / refined / reduction-% metric cards
- diagnostics tables (top values per field, burst/cluster groups)
- agent diagnosis + refinement strategy + expected effect + risk
- side-by-side baseline vs. refined SPL
- download buttons for refined SPL and Markdown report

---

## Safety Guardrails

Applied to every LLM-proposed SPL (refinements and planned diagnostics):

- **Read-only check** — rejects `delete`, `outputlookup`, `collect`, `sendemail`, `script`, `map`, `rest`.
- **Balanced-paren check** — string-aware paren/quote counter; rejects malformed SPL before sending to Splunk.
- **SPL anti-pattern detection** — flags small-model mistakes like `| sort - count > 5` (which is invalid SPL — `sort` doesn't threshold) and rewrites the feedback to push the model toward `| where count >= N`.
- **Duplicate-attempt detection** — if the model resubmits the same SPL across iterations, the verdict becomes `duplicate_attempt` with sharper feedback so we don't burn the iteration budget on the same wrong answer.
- **Field whitelist** — the LLM prompt lists the allowed fields per scenario; the model is instructed not to invent fields.
- **Index discipline** — refined SPL must target the same `SPLUNK_INDEX`; the agent does not silently change index/sourcetype.

### Quality gates (per iteration)

After each candidate SPL runs against Splunk, the agent computes a verdict:

| Verdict | When | Behavior |
|---|---|---|
| `accepted` | ≥20% row reduction AND ≥80% must-preserve coverage | Ship it. |
| `too_tight` | refined returns 0 rows | Revise — loosen the filter. |
| `no_reduction` | refined ≥ baseline | Revise — add aggregation/thresholding. |
| `minimal_reduction` | <20% reduction | Revise — tighten further. |
| `lost_must_preserve` | <80% of must-catch entities survive in refined output | Revise — names the missing entities in the feedback. |
| `over_reduction` | ≥95% reduction AND ≤3 rows left (and no preservation check defined) | Revise — likely dropped real signal. |
| `malformed_spl` / `duplicate_attempt` | see above | Revise with sharper feedback. |

The loop runs up to 2 revisions per scenario.

If any check fails after the iteration budget is exhausted, the report still surfaces the last attempt with its verdict so the analyst sees exactly what went wrong.

---

## Agent Workflow

```text
1. Load scenario (baseline SPL + context + must-preserve clause).
2. Run baseline SPL against Splunk.
3. Resolve diagnostic plan:
     - hardcoded for demo scenarios
     - LLM-planned + validated for custom scenarios
4. Run diagnostics.
5. Build refinement prompt with diagnostic summary.
6. Ask the model for a refined SPL + diagnosis + rationale + expected effect + risk.
7. Validate the refined SPL (read-only + balanced parens).
8. Write refined SPL to disk; run it against Splunk.
9. Return a report dict (consumed by CLI, UI, and Markdown renderer).
```

---

## Roadmap

### Phase 1 — Repo skeleton (done)

- [x] Repository structure
- [x] Synthetic log generator
- [x] Sample detections
- [x] README
- [x] `.env.example`

### Phase 2 — Splunk integration (done)

- [x] Create index
- [x] Ingest synthetic logs
- [x] Python Splunk client (REST API + search job polling)
- [x] Return result rows to the agent

### Phase 3 — Rule tuning (done)

- [x] Diagnostic query execution
- [x] LLM-driven refinement
- [x] LLM-driven diagnostic planning (custom-rule mode)
- [x] Deterministic fallback
- [x] SPL safety guardrails
- [x] Before/after Markdown report

### Phase 4 — Demo interface (done)

- [x] CLI demo (`run_demo.py`)
- [x] Streamlit UI with 3 tabs + Live/Replay toggle
- [x] Shared report renderer
- [x] Per-scenario sample JSON for replay

### Phase 5 — Splunk-native AI integration (optional, post-hackathon)

- [ ] Splunk MCP Server
- [ ] Splunk AI Assistant for SPL
- [ ] Splunk Hosted Models / AI Toolkit

### Phase 6 — Packaging

- [ ] Add `requirements.txt`
- [ ] Add architecture diagram
- [ ] Add demo screenshots
- [ ] Record demo video
- [ ] Prepare Devpost submission

---

## Nice-to-Have Features

Post-hackathon directions:

1. Third demo scenario: data exfiltration (network logs, off-hours large transfers)
2. Intent classification (false_positive_reduction / coverage_expansion / mixed)
3. Analyst approval workflow (accept / reject / edit refinement)
4. Rule history panel (track refinements over time)
5. MITRE ATT&CK technique labeling on refined rules
6. Splunk MCP integration
7. BOTS v3 dataset support
8. Splunk custom app packaging

---

## Non-Goals

RulePilot does not attempt to:

- fully automate detection engineering
- claim that generated SPL is always correct
- depend on proprietary production SOC data
- require Splunk Enterprise Security
- require BOTS v3 to function

---

## Guiding Principle

The core workflow must work without depending on any single uncertain external service. Splunk is required; everything else (LLM provider, MCP, AI Toolkit) is pluggable behind interfaces, with a deterministic fallback for demo safety.
