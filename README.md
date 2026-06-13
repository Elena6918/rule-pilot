# RulePilot

**An analyst-in-the-loop agent that cuts false-positive volume on noisy Splunk
detections by 80%+ — and *proves* the tightened rule still catches what matters
before it ships.**

> Splunk Agentic Ops Hackathon · **Security** track · MIT-licensed

Alert fatigue is the #1 SOC pain: analysts drown in false positives long before
a missed detection ever surfaces. The usual fix — hand-tuning a noisy rule — is
slow and risky, because a tighter rule can silently stop catching real attacks.
RulePilot automates the tuning **and the safety proof**:

1. The analyst pastes a noisy rule and says, in **plain English**, what it must
   never stop catching.
2. RulePilot diagnoses *why* the rule is noisy (live Splunk searches), and an
   AI model proposes a tighter rule.
3. Before accepting, RulePilot **verifies** the tighter rule still surfaces the
   must-catch behavior — and **refuses to ship a regression**.

It's not a model that writes detections. It's an agent that reduces alert noise
**and proves it didn't break the detection.**

---

## Demo results (verified, live Splunk + GPT-4o)

| Scenario | Baseline alerts | Refined alerts | Reduction | Must-catch preserved |
|---|---|---|---|---|
| Failed-login brute force | 113 | 1 | **99%** | **100%** |
| Suspicious command execution | 122 | 12 | **90%** | **100%** |

Each refinement is parser-validated by Splunk itself and gated on preservation —
if a candidate can't both cut noise *and* keep the must-catch entities, it is
rejected and nothing is written to disk.

**Judges without a Splunk instance:** switch the sidebar to **Replay** and the
full report renders from saved runs in [`reports/samples/`](reports/samples) — no
Splunk, no model, no keys required.

---

## How it works

See [`architecture_diagram.md`](architecture_diagram.md) for the full picture. In short:

- **One input form** (used by all three tabs): a baseline SPL, a plain-English
  goal, and a plain-English **must-preserve** statement.
- **Natural-language → SPL compiler.** The analyst describes what must survive;
  the selected model compiles it to an executable SPL "oracle," which Splunk's
  own parser validates and the analyst reviews/approves. The analyst never has
  to hand-write the verification query.
- **Agentic refinement loop.** Run baseline → diagnose the noise → propose a
  refined SPL → **parser pre-flight** → run it → **preservation probe** against
  the approved oracle → accept, or revise with feedback (up to N iterations).
- **Runs on the Splunk MCP Server.** Every search RulePilot executes — baseline,
  diagnostics, candidates, and the preservation checks — goes through the
  **Splunk MCP Server** (`splunk_run_query`, token-authenticated), one of the
  hackathon's listed Splunk AI capabilities. REST handles SPL parser pre-flight
  and serves as a fallback.
- **Model-agnostic.** Pick the provider at runtime — **Local (Qwen)**,
  **Frontier (OpenAI)**, or **Splunk AI Assistant** (via the Splunk MCP Server).
- **Honest by construction.** When no candidate passes, the UI shows `—`, never a
  fake "100% reduction," and the on-disk rule is never overwritten by a rejected
  attempt. Refined SPL stays read-only and targets the same index.

### Why it stands out

- **Verification-first.** Most "AI writes SPL" tools generate; RulePilot
  generates **and proves no regression** against analyst-defined ground truth.
- **Splunk-native grounding.** Every candidate is checked by Splunk's own SPL
  parser before dispatch; diagnostics come from live data.
- **Trustworthy UX.** Honest-failure states, analyst approval of the oracle, no
  silent index/sourcetype changes.

---

## Quickstart

### Prerequisites

- Python 3.10+
- A reachable Splunk Enterprise instance (REST API on `:8089`)
- One model provider:
  - an **OpenAI API key** (recommended for the demo), **or**
  - a local **Ollama** running `qwen2.5:7b`, **or**
  - the **Splunk MCP Server** + AI Assistant (optional — see below)

### 1. Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
```

Edit `.env` — set your Splunk credentials and a model provider. For the demo we
use OpenAI:

```env
SPLUNK_HOST=localhost
SPLUNK_API_PORT=8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=...
SPLUNK_INDEX=rulepilot_demo
SPLUNK_VERIFY_SSL=false

RULEPILOT_MODEL_PROVIDER=openai_compatible
RULEPILOT_MODEL_BASE_URL=https://api.openai.com/v1
RULEPILOT_MODEL_NAME=gpt-4o
RULEPILOT_OPENAI_API_KEY=sk-...
RULEPILOT_MODEL_API_KEY=sk-...
```

If Splunk is remote, open a tunnel first:

```bash
ssh -L 8000:localhost:8000 -L 8089:localhost:8089 <user>@<splunk-host>
```

### 3. Load the example dataset

```bash
python3 scripts/generate_synthetic_logs.py --out data/synthetic_security_logs.jsonl --events 500
```

Create the index and ingest:

```bash
# create the index (Splunk CLI on the search head)
sudo /opt/splunk/bin/splunk add index rulepilot_demo
```

Then upload `data/synthetic_security_logs.jsonl` via **Splunk Web → Settings →
Add Data → Upload** into index `rulepilot_demo` (sourcetype `_json`).

### 4. Run

```bash
# Streamlit UI (recommended)
streamlit run app.py        # http://localhost:8501

# or the CLI
python3 run_demo.py --scenario failed_login
python3 run_demo.py --scenario suspicious_command
```

In the UI: pick a tab, choose a **Model** in the sidebar, optionally click
**Generate check from the description** to compile the must-preserve oracle, then
**Run**. Toggle **Live / Replay** in the sidebar — Replay needs neither Splunk
nor a model.

---

## The three tabs

1. **Failed Login** — a worked example, pre-filled to show good inputs.
2. **Suspicious Command** — a second worked example.
3. **Custom Rule** — blank; bring your own baseline SPL, goal, and must-preserve
   description. The same form and the same agent loop, on any rule.

---

## Models

RulePilot is model-agnostic; choose in the sidebar:

| Provider | Notes |
|---|---|
| **Frontier (OpenAI)** | e.g. `gpt-4o` via the OpenAI API. Strongest NL→SPL fidelity; used in the demo. Needs `RULEPILOT_OPENAI_API_KEY`. |
| **Local (Qwen)** | `qwen2.5:7b` via Ollama. Offline, no keys. Set `RULEPILOT_LOCAL_*`. |
| **Splunk AI Assistant** | Routes through `saia_generate_spl` over the Splunk MCP Server. Wired; currently blocked on a tenant `saia-api-v2` entitlement (see [PROGRESS.md](PROGRESS.md)). |

A misconfigured or unreachable provider (no key, local LLM down, AI Assistant not
entitled) surfaces a **clear error**, never a silent failure.

## Splunk MCP Server (the default data path)

RulePilot runs **all** its Splunk searches through the **Splunk MCP Server**
(`splunk_run_query`) — this is the Splunk AI capability it uses at runtime.
Install the **Splunk MCP Server** app (Splunkbase #7931), create an encrypted
token, and set `SPLUNK_MCP_ENDPOINT` + `SPLUNK_MCP_TOKEN` in `.env`. When these
are set, `SplunkClient.from_env()` automatically routes search execution through
MCP; REST is used only for SPL parser pre-flight and as a fallback if MCP is
briefly unreachable. The same MCP connection also exposes the Splunk AI Assistant
(`saia_*`) provider.

Verify the connection (also available as the sidebar **Test MCP connection**
button):

```bash
python3 -m src.splunk_mcp_client
```

---

## Repository structure

```text
rule-pilot/
  app.py                     # Streamlit UI (shared rule-input form, 3 tabs)
  run_demo.py                # CLI entry point
  architecture_diagram.md    # required architecture diagram (Mermaid)
  requirements.txt
  LICENSE                    # MIT

  src/
    agent.py                 # RulePilotAgent loop + compile_preservation_check
    scenarios.py             # Scenario dataclass + builders
    prompts.py               # refinement / diagnostic / NL→SPL-compile prompts
    models.py                # ModelClient protocol, providers, build_model_client
    splunk_client.py         # Splunk REST client (search jobs, parser pre-flight)
    splunk_mcp_client.py     # Splunk MCP Server client (official mcp SDK)
    signals.py               # analyst-style signals from diagnostics
    reporting.py             # Markdown report renderer

  detections/                # baseline + agent-written refined SPL
  scripts/generate_synthetic_logs.py
  data/                      # synthetic auth + process logs
  reports/samples/           # saved runs for Replay mode
```

---

## Example dataset

[`scripts/generate_synthetic_logs.py`](scripts/generate_synthetic_logs.py)
produces two event families in one JSONL file:

- **Authentication** (`event_type=auth`): benign logins, isolated typos,
  service-account churn, and a deliberate password-spray (8 failures + success)
  for `alice` from `45.83.12.9` — the genuine attack the refined rule must keep.
- **Process execution** (`event_type=process`): routine admin/dev activity, plus
  a small set of genuinely suspicious commands (encoded PowerShell, `curl|sh`,
  `/dev/tcp/` reverse shells).

The injected attacks are the "must-catch" ground truth the preservation gate
verifies against.

---

## Safety guardrails & quality gates

Applied to every model-proposed SPL (refinements, planned diagnostics, and
compiled must-preserve checks):

- **Read-only check** — rejects `delete`, `outputlookup`, `collect`, `sendemail`,
  `script`, `map`, `rest`.
- **Balanced-paren/quote check** before dispatch.
- **Splunk-native parser pre-flight** — every candidate is sent to
  `/services/search/parser?parse_only=true`; the parser's own error is fed back
  to the model as revision feedback.
- **Anti-pattern + duplicate-attempt detection** to avoid burning the iteration
  budget on the same wrong answer.
- **Field whitelist** and **index discipline** (no silent index/sourcetype change).

Per-iteration verdicts: `accepted` (≥20% reduction **and** ≥80% must-preserve),
`too_tight`, `no_reduction`, `minimal_reduction`, `lost_must_preserve`,
`over_reduction`, `parser_rejected`, `malformed_spl`, `duplicate_attempt`. If the
budget is exhausted with no acceptance, the report surfaces the last attempt and
its verdict — honestly marked as **not accepted**.

---

## License

MIT — see [LICENSE](LICENSE).

## Project status & roadmap

See [PROGRESS.md](PROGRESS.md) for the feature build log, known blockers, and
future direction.
