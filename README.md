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

---

## Installation

```bash
# Clone the repo
git clone https://github.com/YOUR_ORG/mdc-assessment-tool.git
cd mdc-assessment-tool

# Create and activate a virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/Scripts/activate

# Install dependencies
pip install -r requirements.txt
```

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
| `csv`  | `mdc_report.csv`  | Spreadsheet-friendly export for remediation tracking. One row per finding with Platform, Severity, CIS ID, CIS Section, Affected Resources, Status, and Remediation steps. Use the **Platform** column to filter down to Azure-only findings. |

> **Note:** All three output files contain real subscription data and are excluded from version control via `.gitignore`. Do not commit them.

You can also re-generate the HTML or CSV from an existing JSON file without re-running the full assessment:

```bash
# Re-generate both from an existing mdc_report.json
python report_generator.py --output-format all

# Re-generate CSV only
python report_generator.py --output-format csv
```
---

## Security

- Never commit `mdc_report.json`, `mdc_report.html`, or `mdc_report.csv` — they contain real subscription data
- Never hardcode subscription IDs, tenant IDs, or credentials in the script
- Secret scanning and push protection are enabled on this repository

---

## Author

Built by [ArtistYay](https://github.com/ArtistYay) as part of an Azure security accelerator for Microsoft Defender for Cloud assessment and remediation workflows.