# MDC Assessment Tool

A Python-based command-line tool for assessing the security posture of an Azure subscription using **Microsoft Defender for Cloud (MDC)**. Designed for security consultants and Azure administrators who need a fast, repeatable way to baseline a client environment before remediation.

---

## What It Does

Connects to an Azure subscription and pulls a point-in-time snapshot of:

- **Defender Plans** — which plans are enabled (Standard) vs. disabled (Free) across all resource types
- **Secure Score** — current score, max score, and percentage
- **Active Recommendations** — all unhealthy findings, deduplicated by recommendation type, with severity (High / Medium / Low) and affected resource count
- **Security Contacts** — whether alert notification contacts are configured
- **Auto-Provisioning** — whether monitoring agents deploy automatically to new resources

Findings can be mapped to a **compliance framework** (CIS Azure Foundations Benchmark or NIST CSF 2.0). Beyond the read-only assessment, the tool also includes an optional **remediation deployment** step, an optional **AI analysis** layer (bring-your-own-API), and a local **web UI**.

Output is written to the console and saved as report files for use in client deliverables. By default all three formats are generated — JSON, HTML, and CSV.

---

## Requirements

- Python 3.8+
- An Azure subscription with **Reader** access (or higher)
- The following Python packages:

```
azure-identity
azure-mgmt-security
azure-mgmt-subscription
azure-cli-core
```

Optional, only for the corresponding features:

```
flask       # web UI (app.py)
requests    # AI analysis (ai_agent.py / --ai)
```

---

## Installation

```bash
# Clone the repo
git clone https://github.com/YOUR_ORG/mdc-assessment-tool.git
cd mdc-assessment-tool

# Create a virtual environment
python -m venv venv
```

Activate it for your platform:

```powershell
# Windows (PowerShell)
venv\Scripts\Activate.ps1
```

```bat
REM Windows (Command Prompt)
venv\Scripts\activate.bat
```

```bash
# macOS / Linux
source venv/bin/activate
```

Then install dependencies:

```bash
pip install -r requirements.txt
```

> **`python` vs `python3`:** On Windows use `python`. On many macOS/Linux systems
> the command is `python3` (and `pip3`). Once your virtual environment is
> activated, plain `python` and `pip` resolve to the venv on all platforms.

---


## Authentication

The tool uses `InteractiveBrowserCredential` — it opens a browser window for sign-in. No service principal or environment variables required for local use.

```bash
python mdc_assess.py
```

You will be prompted to select a subscription if your account has access to more than one.

To skip the selection prompt, pass your subscription ID directly:

```bash
python mdc_assess.py --subscription-id <your-subscription-id>
```

---

## Output Formats

By default the tool generates all three output files. Use `--output-format` to control which files are produced:

```bash
# All three formats (default)
python mdc_assess.py

# HTML report only
python mdc_assess.py --output-format html

# CSV spreadsheet only
python mdc_assess.py --output-format csv

# Raw JSON only (useful for scripting or piping into other tools)
python mdc_assess.py --output-format json
```

| Format | File | Description |
|--------|------|-------------|
| `json` | `mdc_report.json` | Full raw assessment data. Always saved — it is the source of truth for re-generating other formats. |
| `html` | `mdc_report.html` | Self-contained HTML report. Opens in any browser with no internet required. Includes executive summary, Defender plan status, findings by CIS section, security contacts, and auto-provisioning. |
| `csv`  | `mdc_report.csv`  | Spreadsheet-friendly export for remediation tracking. One row per finding with Platform, Severity, the active control column (e.g. `CIS ID (CIS Azure Foundations Benchmark v2.0.0)`), Section, Affected Resources, Status, and Remediation steps. Use the **Platform** column to filter down to Azure-only findings. |

> **Note:** All three output files contain real subscription data and are excluded from version control via `.gitignore`. Do not commit them.

You can also re-generate the HTML or CSV from an existing JSON file without re-running the full assessment:

```bash
# Re-generate both from an existing mdc_report.json
python report_generator.py --output-format all

# Re-generate CSV only
python report_generator.py --output-format csv
```
---

## Compliance Frameworks

Findings can be mapped to a compliance framework with `--framework`. The selected
framework controls the control IDs, the grouping of findings, and the column
headers in every report. The choice is recorded in `mdc_report.json` so the HTML
and CSV reports render consistently.

```bash
# CIS Azure Foundations Benchmark v2.0.0 (default)
python mdc_assess.py --framework cis

# NIST Cybersecurity Framework (CSF) 2.0 — groups findings by CSF function
python mdc_assess.py --framework nist

# No framework — findings are listed unmapped
python mdc_assess.py --framework none
```

| Framework | Control column | Grouping |
|-----------|----------------|----------|
| `cis`  | CIS ID    | CIS section (e.g. *1 Identity*) |
| `nist` | NIST CSF  | CSF function (e.g. *PR — Protect*) |
| `none` | Control   | Unmapped |

---

## Phase 2 — Deploy Remediations

`mdc_deploy.py` reads an existing `mdc_report.json` and closes the most common
baseline gaps it finds:

- **Defender plans** — enables Standard tier (prioritizing Arm, Storage Accounts, Key Vaults)
- **Security contact** — configures the alert notification contact
- **Auto-provisioning** — turns on automatic agent deployment
- **Activity log alerts** *(opt-in)* — alerts on critical control-plane operations (NSGs, SQL firewall rules, policy assignments, security solutions)

It is **safe by default**: nothing is changed without an explicit confirmation, and
every change is recorded to `mdc_deployment_log.json`. Before applying anything it
runs a best-effort **RBAC preflight** to confirm the signed-in account has write
access (Owner/Contributor) — group- or PIM-based grants may not be detectable, so
the check warns rather than hard-blocking. Use `--skip-permission-check` to bypass it.

```bash
# 1) Preview only — writes mdc_deployment_plan.json, makes NO changes
python mdc_deploy.py --dry-run

# 2) Apply changes (prompts for confirmation first)
python mdc_deploy.py --contact-email security@example.com

# Limit to specific Defender plans
python mdc_deploy.py --plans Arm StorageAccounts KeyVaults --contact-email security@example.com

# Also create activity log alerts (requires a resource group to hold them)
python mdc_deploy.py --contact-email security@example.com \
    --activity-alerts --alert-resource-group mdc-monitoring

# Skip the prompt in automation
python mdc_deploy.py --contact-email security@example.com --yes
```

> Activity log alerts and the RBAC preflight need extra packages:
> `pip install azure-mgmt-monitor azure-mgmt-resource azure-mgmt-authorization`.
> The resource group named by `--alert-resource-group` is created if missing
> (region set by `--alert-location`, default `eastus`).

### Validate after deploying

Use `--validate` to re-run the assessment immediately after applying changes and
diff the result against the original report. It reports what was **fixed**, what
**remains**, any **new** findings, and the Secure Score delta, then writes
`mdc_validation_report.json`.

```bash
python mdc_deploy.py --contact-email security@example.com --validate
```

---

## AI Analysis (bring-your-own-API)

The AI layer is **optional** and **provider-agnostic** — it never ships an API key
and never calls a hosted model on your behalf. You point it at an LLM you already
use (OpenAI, Azure OpenAI, Anthropic, a local Ollama / LM Studio server, or any
OpenAI-compatible endpoint).

### Configure your own API key first

Copy the example file and fill in your provider details (or export the same names
as environment variables):

```bash
# macOS / Linux
cp .env.example .env
```

```powershell
# Windows (PowerShell)
Copy-Item .env.example .env
```

```bash
# .env (or environment variables)
MDC_AI_PROVIDER=openai          # openai | azure | anthropic | openai-compatible
MDC_AI_API_KEY=sk-...           # your own key — kept local, never logged
MDC_AI_MODEL=gpt-4o-mini        # optional; a provider default is used otherwise
MDC_AI_BASE_URL=                # optional; only to override the endpoint
```

Provider examples (OpenAI, Azure OpenAI, Anthropic, Ollama, OpenRouter) are listed
in [.env.example](.env.example). Your key is read from the environment only, is
never printed or written to any output file, and remote endpoints must use HTTPS.

> If no key is configured, AI steps are skipped gracefully — the rest of the tool
> works unchanged.

### Run an analysis

```bash
# Standalone, against an existing report
python ai_agent.py --input mdc_report.json --task explain
python ai_agent.py --input mdc_report.json --task prioritize
python ai_agent.py --input mdc_report.json --task guidance
python ai_agent.py --input mdc_report.json --task review --max-iterations 3

# Or chain it onto an assessment run
python mdc_assess.py --ai                 # defaults to the "explain" task
python mdc_assess.py --ai prioritize
```

| Task | What it produces |
|------|------------------|
| `explain`    | Plain-language explanation of each finding and its real-world risk |
| `prioritize` | Risk-ranked remediation order (severity × blast radius × effort) |
| `guidance`   | Step-by-step remediation guidance per finding |
| `review`     | Iterative review loop (efficiency pass → security audit) over High findings |

Results are written to `mdc_ai_analysis.json`.

---

## Web UI

`app.py` is a small local Flask app that wraps the assessment: pick a subscription
and framework, optionally enable AI, watch progress, then view and download the
HTML / JSON / CSV reports.

With your virtual environment activated (see **Installation**) and dependencies
installed, start the server:

```powershell
# Windows (PowerShell)
python app.py            # then open http://127.0.0.1:5000
```

```bash
# macOS / Linux
python3 app.py           # then open http://127.0.0.1:5000
```

If Flask is not already installed, run `pip install flask` first. Use `--port` to
change the port (e.g. `python app.py --port 8000`); it binds to `127.0.0.1` by default.

> **Local use only.** Authentication uses `InteractiveBrowserCredential`, which
> opens a sign-in window on the machine running the server. The app binds to
> `127.0.0.1` by default — do not expose it on a shared or public host.

---

## Security

- Never commit `mdc_report.json`, `mdc_report.html`, or `mdc_report.csv` — they contain real subscription data
- The deployment, validation, and AI output files (`mdc_deployment_log.json`, `mdc_deployment_plan.json`, `mdc_validation_report.json`, `mdc_ai_analysis.json`) are also git-ignored
- Never commit your `.env` — it holds your AI provider key
- Never hardcode subscription IDs, tenant IDs, or credentials in the script
- Secret scanning and push protection are enabled on this repository

---

## Author

Built by [ArtistYay](https://github.com/ArtistYay) as part of an Azure security accelerator for Microsoft Defender for Cloud assessment and remediation workflows.