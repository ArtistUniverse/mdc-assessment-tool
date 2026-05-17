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

Output is written to the console and saved as `mdc_report.json` for use in client deliverables.

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

## JSON Report

Full results are saved to `mdc_report.json` in the working directory. This file is excluded from version control via `.gitignore` — do not commit it as it contains subscription-specific security data.

---

## Security

- Never commit `mdc_report.json` and `mdc_report.html` — it contains real subscription data
- Never hardcode subscription IDs, tenant IDs, or credentials in the script
- Secret scanning and push protection are enabled on this repository

---

## Author

Built by [ArtistYay](https://github.com/ArtistYay) as part of an Azure security accelerator for Microsoft Defender for Cloud assessment and remediation workflows.