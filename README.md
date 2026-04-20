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
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Windows Quickstart

If you're on Windows using VS Code:

1. Open the project folder in VS Code
2. Open a **PowerShell terminal** inside VS Code (Terminal → New Terminal)
3. Activate the virtual environment:
   ```powershell
   venv\Scripts\activate
   ```
   You should see `(venv)` appear at the start of your prompt
4. If it's a fresh environment, install dependencies:
   ```powershell
   pip install azure-identity azure-mgmt-security azure-mgmt-subscription azure-cli-core
   ```
5. Run the script:
   ```powershell
   python mdc_assess.py
   ```
6. A browser window will open — sign in with your Azure account
7. Select the subscription number you want to assess

> **Note:** Always run from a PowerShell terminal in VS Code, not Command Prompt. The venv activation command differs between the two.

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

- Never commit `mdc_report.json` — it contains real subscription data
- Never hardcode subscription IDs, tenant IDs, or credentials in the script
- Secret scanning and push protection are enabled on this repository

---

## Author

Built by [ArtistYay](https://github.com/ArtistYay) as part of an Azure security accelerator for Microsoft Defender for Cloud assessment and remediation workflows.