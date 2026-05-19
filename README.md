# RulePilot

RulePilot is an analyst-in-the-loop agent for tuning Splunk detection rules.

It runs baseline SPL searches against Splunk data, summarizes what the rule currently matches, identifies noisy or under-covered patterns, proposes reviewable SPL refinements, and reports before/after evidence.

The MVP focuses on one end-to-end security scenario: tuning a noisy login detection into a more focused suspicious-login detection.

---

## Project Summary

**Project name:** RulePilot  
**Hackathon track:** Security  
**Core idea:** Use an AI-assisted workflow to help SOC analysts tune Splunk detections with evidence.

RulePilot does **not** claim to autonomously produce the perfect detection rule. Instead, it produces an analyst-reviewable recommendation with:

- original SPL
- diagnostic SPL results
- recommended revised SPL
- intent label
- tradeoff explanation
- before/after comparison

---

## System Setup

This project uses a split development/runtime setup.

### Local machine

The local machine is the main development environment.

Current expected setup:

```text
MacBook
  - Git repository
  - Python source code
  - scripts
  - README/docs
  - optional local UI
  - SSH tunnel into the remote Splunk server
```

Use the MacBook for:

- editing code
- committing to git
- pushing to GitHub
- running lightweight Python scripts
- accessing Splunk Web through a browser

### Remote server

The remote Linux server runs Splunk Enterprise.

Current expected setup:

```text
Remote Linux server: coursesrv01.cs.virginia.edu
User: ml6vq
Splunk install path: /opt/splunk
Splunk Web port: 8000
Splunk management/API port: 8089
Primary server IP: 128.143.71.100
```

Splunk Enterprise is installed on the remote server under:

```text
/opt/splunk
```

Splunk is expected to be running on the remote server. Check with:

```bash
sudo /opt/splunk/bin/splunk status
```

Start Splunk if needed:

```bash
sudo /opt/splunk/bin/splunk start --accept-license --run-as-root
```

For this prototype, Splunk Enterprise is used as the runtime backend. This project does **not** require Splunk Enterprise Security unless explicitly added later.

---

## Accessing Splunk from the MacBook

Use an SSH tunnel from the MacBook to the remote server.

Run this on the MacBook:

```bash
ssh -L 8000:localhost:8000 ml6vq@coursesrv01.cs.virginia.edu
```

Keep this terminal session open.

Then open Splunk Web locally in the MacBook browser:

```text
http://localhost:8000
```

This forwards:

```text
MacBook localhost:8000
    -> SSH tunnel
    -> remote server localhost:8000
    -> Splunk Web
```

This avoids exposing Splunk Web directly to the public network.

---

## Verifying Splunk on the Remote Server

On the remote server:

```bash
sudo ss -tulpn | grep 8000
```

Expected output should include something like:

```text
0.0.0.0:8000
```

Also test locally on the server:

```bash
curl http://localhost:8000
```

A redirect such as `303 See Other` is normal. It means Splunk Web is alive.

---

## Repository Location

Recommended setup:

```text
MacBook:
  main git repo

Remote server:
  runtime clone or deployment copy
```

The MacBook should be treated as the primary source-of-truth development environment.

The remote server should be treated as the runtime environment for Splunk, ingestion, and larger experiment execution.

Recommended remote working directory:

```text
/srv/rulepilot
```

Avoid storing large generated logs or Splunk indexes under the NFS home directory:

```text
/u/ml6vq
```

The home directory is network-mounted and quota-limited. Use local server storage or large temporary storage for datasets.

---

## Architecture

```text
Synthetic security logs
        |
        v
Splunk Enterprise on remote Linux server
index=security
        |
        v
RulePilot Python agent
        |
        +--> Run baseline SPL
        +--> Run diagnostic SPL searches
        +--> Summarize matched events
        +--> Propose revised SPL
        +--> Run revised SPL
        +--> Compare before/after behavior
        |
        v
Analyst-facing Markdown report
```

Optional future integrations:

```text
Splunk MCP Server
Splunk AI Assistant for SPL
Splunk Hosted Models / AI Toolkit
Open-source or local LLM
```

The MVP must work without relying on external LLM availability. A deterministic fallback is required.

---

## MVP Scenario: Noisy Login Detection

### Problem

A broad login detection captures too much routine login activity.

### Goal

Refine the rule to focus on suspicious repeated failures followed by success.

### Baseline SPL

```spl
index=security sourcetype=auth action=login
| stats count by user, src_ip, status
```

### Diagnostic SPL Searches

```spl
index=security sourcetype=auth action=login
| stats count by status
```

```spl
index=security sourcetype=auth action=login
| stats count by user, src_ip, status
```

### Candidate Revised SPL

```spl
index=security sourcetype=auth action=login
| stats
    count(eval(status="failure")) as failures
    count(eval(status="success")) as successes
    min(_time) as first_seen
    max(_time) as last_seen
    by user, src_ip
| where failures >= 5 AND successes >= 1
```

### Expected Agent Output

```text
Intent:
false_positive_reduction

Original behavior:
The original rule captures all login activity, including routine successful logins.

Observed issue:
Most matched events are benign successful logins or isolated failed attempts.

Recommended refinement:
Group events by user and source IP, then require repeated failures followed by at least one success.

Tradeoff:
This is more focused on password guessing or credential-stuffing behavior, but it may miss single-attempt credential misuse.

Before/after:
Original rule matched N events.
Revised rule matched M grouped entities.
```

---

## Target Repository Structure

```text
rulepilot/
  README.md
  requirements.txt
  .env.example
  .gitignore

  data/
    synthetic_security_logs.jsonl

  detections/
    failed_login_baseline.spl
    failed_login_refined.spl

  rulepilot/
    __init__.py
    splunk_client.py
    agent.py
    models.py
    prompts.py
    report.py

  scripts/
    generate_synthetic_logs.py
    ingest_logs.py
    run_demo.py

  docs/
    architecture.md
    demo_report.md
    proposal.md
```

---

## Python Environment

Create a virtual environment on the MacBook or on the remote server:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Suggested `requirements.txt`:

```text
python-dotenv
requests
pandas
rich
splunk-sdk
```

---

## Environment Variables

Copy the example environment file:

```bash
cp .env.example .env
```

Example `.env`:

```env
SPLUNK_HOST=localhost
SPLUNK_WEB_PORT=8000
SPLUNK_API_PORT=8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=changeme
SPLUNK_INDEX=security
SPLUNK_VERIFY_SSL=false
```

When using the SSH tunnel, `SPLUNK_HOST=localhost` is correct from the MacBook perspective.

If the Python scripts are run directly on the remote server, `localhost` is also correct because Splunk is running on the same machine.

Do not commit `.env`.

---

## Synthetic Dataset

The required MVP dataset is a small synthetic JSONL file.

Generate it with:

```bash
python scripts/generate_synthetic_logs.py
```

Expected output:

```text
data/synthetic_security_logs.jsonl
```

Each event should include:

```text
_time
sourcetype
action
user
src_ip
status
geo
user_agent
```

The MVP auth dataset should contain:

- many benign successful login events
- some isolated failed login events
- one suspicious sequence with repeated failures followed by success
- optional noise from service accounts
- optional internal IP activity

Example event:

```json
{"_time":"2026-05-18T23:00:01","sourcetype":"auth","action":"login","user":"alice","src_ip":"10.0.0.5","status":"failure","geo":"US","user_agent":"Mozilla/5.0"}
```

---

## Splunk Index Setup

Create a Splunk index named:

```text
security
```

This can be done manually in Splunk Web:

```text
Settings -> Indexes -> New Index -> security
```

Or through the Splunk CLI on the remote server:

```bash
sudo /opt/splunk/bin/splunk add index security
```

Restart Splunk if required:

```bash
sudo /opt/splunk/bin/splunk restart
```

---

## Ingesting Synthetic Logs

Initial MVP ingestion can be manual or scripted.

### Option 1: Manual upload through Splunk Web

1. Open Splunk Web through the SSH tunnel:

   ```text
   http://localhost:8000
   ```

2. Go to:

   ```text
   Settings -> Add Data -> Upload
   ```

3. Upload:

   ```text
   data/synthetic_security_logs.jsonl
   ```

4. Set index:

   ```text
   security
   ```

5. Set sourcetype:

   ```text
   auth
   ```

### Option 2: Scripted ingestion

Once implemented:

```bash
python scripts/ingest_logs.py --file data/synthetic_security_logs.jsonl --index security
```

The ingestion script may use either:

- Splunk REST API
- Splunk SDK
- Splunk CLI instructions

For the MVP, correctness and reproducibility matter more than elegance.

---

## Running the Demo

Once synthetic logs are ingested:

```bash
python scripts/run_demo.py --scenario failed_login
```

Expected behavior:

1. Load baseline SPL from:

   ```text
   detections/failed_login_baseline.spl
   ```

2. Run baseline SPL against Splunk.

3. Run diagnostic SPL searches.

4. Use deterministic fallback logic to generate a known-good refined rule.

5. Run the refined SPL.

6. Generate a Markdown report.

Expected report path:

```text
docs/demo_report.md
```

---

## Deterministic Fallback

The MVP must not depend on a real LLM.

Implement a deterministic model client that always produces the known failed-login refinement for the MVP scenario.

This guarantees that the demo works even if:

- hosted models are unavailable
- Splunk AI tools are inaccessible
- local LLM setup is incomplete
- external API keys are unavailable

The deterministic fallback should return:

```text
intent: false_positive_reduction
recommended_spl: detections/failed_login_refined.spl
rationale: repeated failures followed by success is more suspicious than all login activity
tradeoff: may miss single-attempt credential misuse
```

---

## Model Adapter Plan

Use an adapter interface:

```python
class ModelClient:
    def complete(self, messages: list[dict]) -> str:
        raise NotImplementedError
```

Initial implementations:

```text
DeterministicModelClient
OptionalOpenAICompatibleClient
OptionalLocalModelClient
OptionalSplunkHostedModelClient
```

Priority order:

1. deterministic fallback
2. local/open-source model
3. Splunk Hosted Models / AI Toolkit
4. Splunk AI Assistant for SPL
5. external commercial LLM only as development fallback

---

## Agent Workflow

The RulePilot agent loop:

```text
1. Load detection rule.
2. Run baseline SPL.
3. Summarize matched events.
4. Generate diagnostic SPL queries.
5. Run diagnostics.
6. Ask model or deterministic fallback for refinement.
7. Validate revised SPL.
8. Run revised SPL.
9. Compare before/after results.
10. Produce analyst-facing report.
```

Guardrails:

- Do not silently mutate index constraints.
- Do not silently mutate sourcetype constraints.
- Reject empty revised SPL.
- Require revised SPL to start with `index=`.
- Show the revised SPL for analyst review.
- Report tradeoffs instead of claiming the rule is strictly better.

---

## CLI Commands

Generate data:

```bash
python scripts/generate_synthetic_logs.py
```

Run demo:

```bash
python scripts/run_demo.py --scenario failed_login
```

Run demo and specify output path:

```bash
python scripts/run_demo.py --scenario failed_login --out docs/demo_report.md
```

Optional ingestion:

```bash
python scripts/ingest_logs.py --file data/synthetic_security_logs.jsonl --index security
```

---

## Development Workflow

Recommended workflow:

```text
MacBook:
  edit code
  commit changes
  push to GitHub

Remote server:
  run Splunk
  ingest data
  optionally pull repo and run scripts
```

Example:

```bash
# MacBook
git add .
git commit -m "add initial RulePilot skeleton"
git push
```

On the remote server:

```bash
cd /srv/rulepilot
git pull
```

If `/srv/rulepilot` does not exist yet:

```bash
sudo mkdir -p /srv/rulepilot
sudo chown -R ml6vq:csugrad /srv/rulepilot
cd /srv
git clone <repo-url> rulepilot
```

---

## Storage Notes

This environment has multiple storage areas.

Avoid using the NFS home directory for heavy experiment outputs:

```text
/u/ml6vq
```

Use it only for small files, configs, and normal shell work.

Splunk itself is installed on local disk:

```text
/opt/splunk
```

Large raw datasets can live outside the repo, for example:

```text
/bigtemp2/ml6vq/rulepilot-data
```

Do not commit large generated datasets.

---

## Git Ignore Policy

The repo should not track:

```text
.env
.venv/
__pycache__/
*.pyc
.DS_Store
docs/demo_report.md
data/*.jsonl
!data/.gitkeep
```

For the MVP, a small sample JSONL file may be committed if it is intentionally tiny and useful for demo reproducibility.

---

## Success Criteria

The MVP is successful when this command works:

```bash
python scripts/run_demo.py --scenario failed_login
```

And produces:

```text
Original SPL
Diagnostic findings
Recommended SPL
Intent label
Tradeoff explanation
Before/after count comparison
```

The minimum expected demo path:

```text
generate synthetic logs
-> ingest into Splunk index=security
-> run baseline detection
-> run diagnostics
-> recommend refined SPL
-> rerun revised SPL
-> generate report
```

---

## Roadmap

### Phase 1: Repo skeleton

- [ ] Create repository structure
- [ ] Add synthetic log generator
- [ ] Add sample detections
- [ ] Add README
- [ ] Add `.env.example`

### Phase 2: Splunk ingestion and search

- [ ] Create `security` index
- [ ] Ingest synthetic JSON logs
- [ ] Confirm SPL works in Splunk Web
- [ ] Implement Python Splunk client
- [ ] Return result rows to the agent

### Phase 3: Rule tuning logic

- [ ] Implement event summarization
- [ ] Implement diagnostic query generation
- [ ] Implement deterministic failed-login refinement
- [ ] Add revised SPL validation
- [ ] Produce before/after report

### Phase 4: Demo interface

- [ ] CLI demo
- [ ] Optional Streamlit UI
- [ ] Optional screenshots

### Phase 5: Splunk AI integration

- [ ] Try Splunk MCP Server
- [ ] If MCP works, route Splunk searches through MCP
- [ ] If available, test Splunk AI Assistant for SPL
- [ ] If available, test Splunk Hosted Models / AI Toolkit
- [ ] Keep Python SDK fallback stable

### Phase 6: Packaging

- [ ] Clean README
- [ ] Add architecture diagram
- [ ] Add demo screenshots
- [ ] Record demo video
- [ ] Prepare Devpost submission

---

## Nice-to-Have Features

High-value additions after the failed-login MVP:

1. Second scenario: suspicious command execution
2. Third scenario: possible data exfiltration
3. Intent classification:
   - false_positive_reduction
   - coverage_expansion
   - mixed_tradeoff
   - insufficient_evidence
4. Before/after metrics card
5. Analyst approval workflow
6. Rule history panel
7. Optional Splunk MCP integration
8. Optional BOTS v3 support
9. Optional MITRE ATT&CK labeling
10. Optional Splunk custom app packaging

---

## Non-Goals for MVP

The MVP should not attempt to:

- fully automate detection engineering
- claim that generated SPL is always correct
- depend on proprietary production SOC data
- require Splunk Enterprise Security
- require a real LLM
- require BOTS v3
- build a full Splunk app before the core workflow works

---

## Current Guiding Principle

Make the core workflow work first without relying on uncertain AI/tool access.

Then add Splunk-native AI or MCP integration as a bonus.
