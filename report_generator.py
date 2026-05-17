"""
report_generator.py
Microsoft Defender for Cloud — HTML Report Generator
-----------------------------------------------------
Generates a self-contained HTML report from mdc_assess.py output.
No external dependencies — all CSS is inlined so the file opens anywhere.

Usage (standalone):
    python report_generator.py                  # reads mdc_report.json
    python report_generator.py --input path/to/report.json

Usage (from mdc_assess.py):
    from report_generator import generate_html_report
    generate_html_report(report_data, output_path="mdc_report.html")
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from html import escape, unescape

try:
    from cis_mapping import lookup_control
    _CIS_AVAILABLE = True
except ImportError:
    _CIS_AVAILABLE = False


# ── Severity helpers ───────────────────────────────────────────────────────────

SEVERITY_BADGE = {
    "High":    '<span class="badge badge-high">High</span>',
    "Medium":  '<span class="badge badge-medium">Medium</span>',
    "Low":     '<span class="badge badge-low">Low</span>',
    "Unknown": '<span class="badge badge-unknown">Unknown</span>',
}

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Unknown": 3}


def _badge(severity):
    return SEVERITY_BADGE.get(severity, SEVERITY_BADGE["Unknown"])


def _esc(value):
    return escape(str(value)) if value is not None else ""


def _sanitize_html(text):
    """Sanitize MDC API remediation HTML for safe embedding in the report.
    Preserves hyperlinks (opens in new tab), converts structure to readable lines,
    and fixes common MDC formatting issues (missing spaces after periods)."""
    if not text:
        return ""

    # Save <a href> tags as placeholders so they survive the strip pass
    links = []

    def save_link(m):
        href = m.group(1)
        link_text = re.sub(r'<[^>]+>', '', m.group(2))
        links.append((href, unescape(link_text).strip()))
        return f'__LINK{len(links) - 1}__'

    text = re.sub(
        r'<a[^>]+href=["\']([^"\']*)["\'][^>]*>(.*?)</a>',
        save_link,
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )

    # Convert block/line-break elements to newlines
    # Handles <br>, <br/>, </br> (non-standard but used by MDC AWS findings)
    text = re.sub(r'</?br\s*/?>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<li[^>]*>', '\n • ', text, flags=re.IGNORECASE)
    text = re.sub(r'</li>', '', text, flags=re.IGNORECASE)
    text = re.sub(r'</?(?:ol|ul|p|div)[^>]*>', '\n', text, flags=re.IGNORECASE)

    # Strip all remaining tags
    text = re.sub(r'<[^>]+>', '', text)

    # Unescape HTML entities in the remaining text content
    text = unescape(text)

    # Fix missing space after period: "sentence.Next" → "sentence. Next"
    text = re.sub(r'\.([A-Z])', r'. \1', text)

    # Break numbered steps onto their own lines
    text = re.sub(r'(?<!\n)\s*(\d+\.)\s+', r'\n\1 ', text)

    # Normalise lines: strip extra spaces, drop blank lines
    lines = [re.sub(r' {2,}', ' ', ln).strip() for ln in text.split('\n')]
    lines = [ln for ln in lines if ln]

    # Save plain-text URLs (not already captured as <a> tags) as placeholders
    url_links = []

    def save_url(m):
        url = m.group(1).rstrip('.,;:)')
        url_links.append(url)
        return f'__URL{len(url_links) - 1}__'

    lines = [re.sub(r'(https?://\S+)', save_url, ln) for ln in lines]

    # Escape text content for HTML, join with <br>
    html = '<br>'.join(escape(ln) for ln in lines)

    # Restore saved <a href> links (from original HTML)
    for idx, (href, link_text) in enumerate(links):
        anchor = (
            f'<a href="{escape(href)}" target="_blank" rel="noopener">'
            f'{escape(link_text)}</a>'
        )
        html = html.replace(f'__LINK{idx}__', anchor)

    # Restore auto-detected plain-text URLs as hyperlinks
    for idx, url in enumerate(url_links):
        anchor = (
            f'<a href="{escape(url)}" target="_blank" rel="noopener">'
            f'{escape(url)}</a>'
        )
        html = html.replace(f'__URL{idx}__', anchor)

    return html


# ── Documentation URL lookup ───────────────────────────────────────────────────

# Ordered list of (keyword, Security Hub control page URL) for AWS findings.
# Checked against the lowercased finding name — first match wins.
# Pages follow the pattern: securityhub/.../userguide/<service>-controls.html
_AWS_FINDING_DOCS = [
    # GuardDuty
    ("guardduty",            "https://docs.aws.amazon.com/securityhub/latest/userguide/guardduty-controls.html"),
    # Macie
    ("macie",                "https://docs.aws.amazon.com/securityhub/latest/userguide/macie-controls.html"),
    # CloudTrail — check before CloudWatch so "cloudtrail ... cloudwatch" hits cloudtrail
    ("cloudtrail",           "https://docs.aws.amazon.com/securityhub/latest/userguide/cloudtrail-controls.html"),
    # CloudWatch metric filter / alarm findings
    ("log metric filter",    "https://docs.aws.amazon.com/securityhub/latest/userguide/cloudwatch-controls.html"),
    ("cloudwatch",           "https://docs.aws.amazon.com/securityhub/latest/userguide/cloudwatch-controls.html"),
    # S3 — specific phrases before generic "s3 bucket"
    ("s3 block public",      "https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html"),
    ("mfa delete",           "https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html"),
    ("object-level logging", "https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html"),
    ("lifecycle polic",      "https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html"),
    ("secure socket layer",  "https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html"),
    ("amazon s3",            "https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html"),
    ("s3 bucket",            "https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html"),
    # IAM — specific phrases before generic "iam"
    ("iam access analyzer",  "https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html"),
    ("password polic",       "https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html"),
    ("password rotation",    "https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html"),
    ("unused passwords",     "https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html"),
    ("support role",         "https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html"),
    ("root",                 "https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html"),
    ("iam role is attached", "https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html"),
    ("iam",                  "https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html"),
    # EC2 / VPC / EBS — most specific phrases first
    ("ebs default",          "https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html"),
    ("ebs optimized",        "https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html"),
    ("elastic blocks store", "https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html"),
    ("vpc endpoint",         "https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html"),
    ("vpc flow log",         "https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html"),
    ("default security group","https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html"),
    ("ec2 subnet",           "https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html"),
    ("ec2 instance",         "https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html"),
    ("network acl",          "https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html"),
    ("internet gateway",     "https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html"),
    ("security groups",      "https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html"),
    ("public ip",            "https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html"),
    ("ebs",                  "https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html"),
    ("ec2",                  "https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html"),
    ("amazon ec2",           "https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html"),
    # SNS
    ("amazon sns",           "https://docs.aws.amazon.com/securityhub/latest/userguide/sns-controls.html"),
    ("sns topic",            "https://docs.aws.amazon.com/securityhub/latest/userguide/sns-controls.html"),
    # EventBridge
    ("eventbridge",          "https://docs.aws.amazon.com/securityhub/latest/userguide/eventbridge-controls.html"),
    # Config — "aws config" before generic config
    ("aws config",           "https://docs.aws.amazon.com/securityhub/latest/userguide/config-controls.html"),
    # CloudFormation
    ("cloudformation",       "https://docs.aws.amazon.com/securityhub/latest/userguide/cloudformation-controls.html"),
    # KMS
    ("kms",                  "https://docs.aws.amazon.com/securityhub/latest/userguide/kms-controls.html"),
]

# Azure CIS section prefix → Microsoft Learn documentation URL
_AZURE_SECTION_DOCS = {
    "1 —":   "https://learn.microsoft.com/en-us/entra/identity/",
    "2.1 —": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/",
    "3 —":   "https://learn.microsoft.com/en-us/azure/storage/",
    "4 —":   "https://learn.microsoft.com/en-us/azure/azure-sql/",
    "5 —":   "https://learn.microsoft.com/en-us/azure/azure-monitor/",
    "6 —":   "https://learn.microsoft.com/en-us/azure/networking/",
    "7 —":   "https://learn.microsoft.com/en-us/azure/virtual-machines/",
    "8 —":   "https://learn.microsoft.com/en-us/azure/key-vault/",
    "9 —":   "https://learn.microsoft.com/en-us/azure/app-service/",
}

_MDC_FALLBACK_URL = (
    "https://learn.microsoft.com/en-us/azure/defender-for-cloud/recommendations-reference"
)


def _docs_url(finding_name: str, cis_section: str = "") -> str:
    """Return the most relevant documentation URL for a finding.
    Returns an empty string if no match and no Azure section is supplied."""
    name_lower = finding_name.lower()

    # Detect AWS findings: explicit "aws"/"amazon" keyword or unambiguous AWS service terms.
    # "security groups" (plural) is AWS-specific; Azure uses "NSG" / "Network Security Group".
    # "network acl", "internet gateway", "log metric filter" are all AWS-specific.
    _is_aws = (
        "aws" in name_lower
        or "amazon" in name_lower
        or "guardduty" in name_lower
        or "macie" in name_lower
        or "cloudtrail" in name_lower
        or "cloudwatch" in name_lower
        or "cloudformation" in name_lower
        or "eventbridge" in name_lower
        or " ec2 " in name_lower
        or name_lower.startswith("ec2 ")
        or "ebs " in name_lower
        or "elastic blocks" in name_lower
        or " iam " in name_lower
        or name_lower.startswith("iam ")
        or "s3 bucket" in name_lower
        or "s3 block" in name_lower
        or "log metric filter" in name_lower
        or "mfa delete" in name_lower
        or "object-level logging" in name_lower
        or "security groups" in name_lower
        or "network acl" in name_lower
        or "default security group" in name_lower
        or "internet gateway" in name_lower
        or "vpc flow log" in name_lower
        or "root'" in name_lower
    )
    if _is_aws:
        for keyword, url in _AWS_FINDING_DOCS:
            if keyword in name_lower:
                return url
        return "https://docs.aws.amazon.com/securityhub/latest/userguide/"

    # GitHub findings
    if "github" in name_lower:
        return "https://docs.github.com/en/code-security/"

    # Azure CIS-mapped findings — match by section prefix
    if cis_section:
        section_lower = cis_section.lower()
        for prefix, url in _AZURE_SECTION_DOCS.items():
            if section_lower.startswith(prefix.lower()):
                return url

    # Generic MDC fallback for any Azure finding with a detail block
    return _MDC_FALLBACK_URL if cis_section else ""


# ── Section builders ───────────────────────────────────────────────────────────

def _build_executive_summary(score, plans, recommendations):
    pct = score.get("percentage") or 0
    current = score.get("current", "—")
    maximum = score.get("max", "—")

    total_plans = len(plans)
    enabled_plans = sum(1 for v in plans.values() if v.get("enabled"))

    counts = recommendations.get("counts", {})
    high   = counts.get("High", 0)
    medium = counts.get("Medium", 0)
    low    = counts.get("Low", 0)
    total  = recommendations.get("total", 0)

    score_color = "#e74c3c" if pct < 50 else "#f39c12" if pct < 75 else "#27ae60"

    return f"""
<section class="summary-grid">
  <div class="summary-card">
    <div class="card-label">Secure Score</div>
    <div class="score-ring-wrap">
      <svg viewBox="0 0 120 120" class="score-ring">
        <circle cx="60" cy="60" r="52" class="ring-bg"/>
        <circle cx="60" cy="60" r="52" class="ring-fill"
          style="stroke:{score_color};stroke-dasharray:{round(pct * 3.267, 1)} 326.7"/>
      </svg>
      <div class="score-text">
        <div class="score-pct" style="color:{score_color}">{pct}%</div>
        <div class="score-sub">{current} / {maximum}</div>
      </div>
    </div>
  </div>

  <div class="summary-card">
    <div class="card-label">Defender Plan Coverage</div>
    <div class="big-number" style="color:{'#27ae60' if enabled_plans == total_plans else '#e74c3c'}">{enabled_plans}<span class="big-denom">/{total_plans}</span></div>
    <div class="card-sub">plans enabled</div>
  </div>

  <div class="summary-card">
    <div class="card-label">Active Findings</div>
    <div class="finding-counts">
      <div class="finding-row"><span class="badge badge-high">High</span><span class="finding-num">{high}</span></div>
      <div class="finding-row"><span class="badge badge-medium">Medium</span><span class="finding-num">{medium}</span></div>
      <div class="finding-row"><span class="badge badge-low">Low</span><span class="finding-num">{low}</span></div>
    </div>
    <div class="card-sub">{total} total findings</div>
  </div>
</section>
"""


def _build_defender_plans(plans):
    if not plans:
        return "<p class='empty'>No plan data available.</p>"

    rows = []
    for name in sorted(plans.keys()):
        info = plans[name]
        enabled = info.get("enabled", False)
        status_html = '<span class="status-on">&#10003; Enabled</span>' if enabled else '<span class="status-off">&#10007; Disabled</span>'
        rows.append(f"""
      <tr>
        <td>{_esc(name)}</td>
        <td>{status_html}</td>
      </tr>""")

    return f"""
<table>
  <thead><tr><th>Plan</th><th>Status</th></tr></thead>
  <tbody>{"".join(rows)}
  </tbody>
</table>
"""


def _build_findings_by_section(by_section):
    if not by_section:
        return "<p class='empty'>No findings data available.</p>"

    html_parts = []

    # Separate mapped sections from unmapped/multicloud
    mapped_sections   = {k: v for k, v in by_section.items() if k != "Unmapped"}
    unmapped_section  = by_section.get("Unmapped")

    for section_name in sorted(mapped_sections.keys()):
        data  = mapped_sections[section_name]
        items = sorted(data.get("items", []), key=lambda r: (SEVERITY_ORDER.get(r.get("severity"), 3), r.get("name", "")))
        h     = data.get("High", 0)
        m     = data.get("Medium", 0)
        l     = data.get("Low", 0)
        u     = data.get("Unknown", 0)

        badge_row = ""
        if h: badge_row += f'<span class="badge badge-high">{h} High</span> '
        if m: badge_row += f'<span class="badge badge-medium">{m} Medium</span> '
        if l: badge_row += f'<span class="badge badge-low">{l} Low</span> '
        if u: badge_row += f'<span class="badge badge-unknown">{u} Unknown</span>'

        rows = []
        for r in items:
            cis_id    = _esc(r.get("cis_id") or "—")
            name      = _esc(r.get("name", "Unknown"))
            severity  = r.get("severity", "Unknown")
            affected  = r.get("affected_resources", 1)
            level     = _esc(r.get("cis_level") or "—")

            current_api  = _sanitize_html(r.get("current_state") or r.get("current_cause"))
            remediation  = _sanitize_html(r.get("remediation") or r.get("control_description"))
            expected_val = r.get("expected_value")
            fail_val     = r.get("current_value_if_fail")
            cis_sec      = r.get("cis_section", "")
            # Prefer live MDC observation; fall back to the CIS "fail" label
            current_display = current_api or (_esc(fail_val) if fail_val else "")
            has_detail = bool(expected_val or current_display or remediation)
            doc_url    = r.get("cis_doc_url") or (_docs_url(r.get("name", ""), cis_sec) if has_detail else "")
            detail_html = ""
            if has_detail:
                expected_row    = f'<div class="detail-row"><span class="detail-label">Expected</span><span class="detail-value ev-good">{_esc(expected_val)}</span></div>' if expected_val else ""
                current_row     = f'<div class="detail-row"><span class="detail-label">Current</span><span class="detail-value ev-bad">{current_display}</span></div>' if current_display else ""
                remediation_row = f'<div class="detail-row"><span class="detail-label">Remediation</span><span class="detail-value">{remediation}</span></div>' if remediation else ""
                docs_row        = f'<div class="detail-row"><span class="detail-label">Documentation</span><span class="detail-value"><a href="{escape(doc_url)}" target="_blank" rel="noopener">View official documentation &#8599;</a></span></div>' if doc_url else ""
                detail_html = f'<details class="finding-detail"><summary>How to fix</summary>{expected_row}{current_row}{remediation_row}{docs_row}</details>'

            rows.append(f"""
        <tr>
          <td>{_badge(severity)}</td>
          <td class="cis-id">{cis_id}</td>
          <td><div class="finding-name">{name}</div>{detail_html}</td>
          <td class="center">{affected}</td>
          <td class="center">{level}</td>
        </tr>""")

        html_parts.append(f"""
<div class="section-block">
  <h3>{_esc(section_name)} <span class="section-badges">{badge_row}</span></h3>
  <table>
    <thead><tr>
      <th>Severity</th><th>CIS ID</th><th>Finding</th><th class="center">Resources</th><th class="center">Level</th>
    </tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
</div>""")

    # Unmapped / multicloud section
    if unmapped_section:
        items = sorted(unmapped_section.get("items", []), key=lambda r: (SEVERITY_ORDER.get(r.get("severity"), 3), r.get("name", "")))
        rows = []
        for r in items:
            name        = _esc(r.get("name", "Unknown"))
            severity    = r.get("severity", "Unknown")
            affected    = r.get("affected_resources", 1)
            current_api  = _sanitize_html(r.get("current_state") or r.get("current_cause"))
            remediation  = _sanitize_html(r.get("remediation") or r.get("control_description"))
            expected_val = r.get("expected_value")
            fail_val     = r.get("current_value_if_fail")
            current_display = current_api or (_esc(fail_val) if fail_val else "")
            has_detail = bool(expected_val or current_display or remediation)
            doc_url     = r.get("cis_doc_url") or (_docs_url(r.get("name", ""), "") if has_detail else "")
            detail_html = ""
            if has_detail:
                expected_row    = f'<div class="detail-row"><span class="detail-label">Expected</span><span class="detail-value ev-good">{_esc(expected_val)}</span></div>' if expected_val else ""
                current_row     = f'<div class="detail-row"><span class="detail-label">Current</span><span class="detail-value ev-bad">{current_display}</span></div>' if current_display else ""
                remediation_row = f'<div class="detail-row"><span class="detail-label">Remediation</span><span class="detail-value">{remediation}</span></div>' if remediation else ""
                docs_row        = f'<div class="detail-row"><span class="detail-label">Documentation</span><span class="detail-value"><a href="{escape(doc_url)}" target="_blank" rel="noopener">View official documentation &#8599;</a></span></div>' if doc_url else ""
                detail_html = f'<details class="finding-detail"><summary>How to fix</summary>{expected_row}{current_row}{remediation_row}{docs_row}</details>'
            rows.append(f"""
        <tr>
          <td>{_badge(severity)}</td>
          <td><div class="finding-name">{name}</div>{detail_html}</td>
          <td class="center">{affected}</td>
        </tr>""")

        h = unmapped_section.get("High", 0)
        m = unmapped_section.get("Medium", 0)
        l = unmapped_section.get("Low", 0)

        badge_row = ""
        if h: badge_row += f'<span class="badge badge-high">{h} High</span> '
        if m: badge_row += f'<span class="badge badge-medium">{m} Medium</span> '
        if l: badge_row += f'<span class="badge badge-low">{l} Low</span>'

        html_parts.append(f"""
<div class="section-block unmapped">
  <h3>Non-Azure / Multicloud Findings <span class="section-badges">{badge_row}</span></h3>
  <p class="unmapped-note">These findings originate from AWS, GitHub, or other non-Azure connectors and are not mapped to CIS Azure Foundations Benchmark controls.</p>
  <table>
    <thead><tr><th>Severity</th><th>Finding</th><th class="center">Resources</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
</div>""")

    return "\n".join(html_parts)


def _build_security_contacts(contacts):
    if not contacts:
        return "<p class='warning-note'>&#9888; No security contacts configured. Alert notifications will not be sent.</p>"

    rows = []
    for c in contacts:
        email = _esc(c.get("email") or "Not set")
        phone = _esc(c.get("phone") or "Not set")
        alerts = _esc(c.get("alert_notifications") or "—")
        rows.append(f"""
      <tr>
        <td>{_esc(c.get('name', '—'))}</td>
        <td>{email}</td>
        <td>{phone}</td>
        <td>{alerts}</td>
      </tr>""")

    return f"""
<table>
  <thead><tr><th>Name</th><th>Email</th><th>Phone</th><th>Alert Notifications</th></tr></thead>
  <tbody>{"".join(rows)}</tbody>
</table>
"""


def _build_auto_provisioning(auto_prov):
    if not auto_prov:
        return "<p class='empty'>No auto-provisioning data available.</p>"

    rows = []
    for name, state in sorted(auto_prov.items()):
        status_html = '<span class="status-on">&#10003; On</span>' if state == "On" else '<span class="status-off">&#10007; Off</span>'
        rows.append(f"""
      <tr>
        <td>{_esc(name)}</td>
        <td>{status_html}</td>
      </tr>""")

    return f"""
<table>
  <thead><tr><th>Agent / Component</th><th>Status</th></tr></thead>
  <tbody>{"".join(rows)}</tbody>
</table>
"""


# ── CSS ────────────────────────────────────────────────────────────────────────

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  font-size: 14px;
  background: #f4f6f9;
  color: #1a1a2e;
  line-height: 1.5;
}

header {
  background: #0f3460;
  color: #fff;
  padding: 28px 40px 20px;
}
header h1 { font-size: 22px; font-weight: 600; margin-bottom: 6px; }
header .meta { font-size: 12px; opacity: 0.75; }

main { max-width: 1100px; margin: 32px auto; padding: 0 24px 48px; }

h2 {
  font-size: 16px;
  font-weight: 600;
  color: #0f3460;
  border-bottom: 2px solid #0f3460;
  padding-bottom: 6px;
  margin: 36px 0 16px;
}
h3 {
  font-size: 14px;
  font-weight: 600;
  color: #333;
  margin: 24px 0 10px;
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

/* Summary cards */
.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 20px;
  margin-bottom: 8px;
}
.summary-card {
  background: #fff;
  border-radius: 8px;
  padding: 20px 24px;
  box-shadow: 0 1px 4px rgba(0,0,0,0.1);
  text-align: center;
}
.card-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: #666; margin-bottom: 12px; }
.card-sub   { font-size: 12px; color: #888; margin-top: 8px; }

/* Score ring */
.score-ring-wrap { position: relative; width: 110px; height: 110px; margin: 0 auto; }
.score-ring { transform: rotate(-90deg); width: 110px; height: 110px; }
.ring-bg   { fill: none; stroke: #e8ecf0; stroke-width: 10; }
.ring-fill { fill: none; stroke-width: 10; stroke-linecap: round; transition: stroke-dasharray 0.5s; }
.score-text { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; }
.score-pct  { font-size: 22px; font-weight: 700; line-height: 1.1; }
.score-sub  { font-size: 11px; color: #888; }

/* Big number for plan coverage */
.big-number { font-size: 48px; font-weight: 700; line-height: 1; margin: 8px 0 4px; }
.big-denom  { font-size: 24px; color: #aaa; font-weight: 400; }

/* Finding counts */
.finding-counts { display: flex; flex-direction: column; gap: 8px; margin: 8px 0; align-items: center; }
.finding-row    { display: flex; align-items: center; gap: 10px; width: 120px; }
.finding-num    { font-size: 20px; font-weight: 700; }

/* Badges */
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 600;
  white-space: nowrap;
}
.badge-high    { background: #fde8e8; color: #c0392b; }
.badge-medium  { background: #fef3cd; color: #b7770d; }
.badge-low     { background: #e8f4fd; color: #1a6a9a; }
.badge-unknown { background: #f0f0f0; color: #666; }

.section-badges { font-weight: 400; }

/* Status */
.status-on  { color: #27ae60; font-weight: 600; }
.status-off { color: #e74c3c; font-weight: 600; }

/* Tables */
table {
  width: 100%;
  border-collapse: collapse;
  background: #fff;
  border-radius: 8px;
  overflow: hidden;
  box-shadow: 0 1px 4px rgba(0,0,0,0.08);
  margin-bottom: 8px;
}
thead { background: #f0f4f8; }
th {
  padding: 10px 14px;
  text-align: left;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: #555;
  font-weight: 600;
}
td {
  padding: 9px 14px;
  border-top: 1px solid #f0f0f0;
  vertical-align: middle;
}
tr:hover td { background: #fafbfc; }
.center { text-align: center; }
.cis-id { font-family: monospace; font-size: 12px; color: #0f3460; white-space: nowrap; }

/* Section blocks */
.section-block { margin-bottom: 28px; }
.section-block.unmapped { opacity: 0.85; }

/* Notes */
.empty         { color: #888; font-style: italic; padding: 8px 0; }
.warning-note  { background: #fff8e1; border-left: 4px solid #f39c12; padding: 12px 16px; border-radius: 4px; color: #7d4e00; }
.unmapped-note { font-size: 12px; color: #888; margin-bottom: 10px; font-style: italic; }

/* Finding detail (remediation) */
.finding-name { margin-bottom: 2px; }
.finding-detail { margin-top: 5px; }
.finding-detail summary {
  font-size: 11px;
  color: #0f3460;
  cursor: pointer;
  user-select: none;
  font-weight: 600;
  list-style: disclosure-closed;
}
.finding-detail[open] summary { list-style: disclosure-open; }
.finding-detail summary:hover { text-decoration: underline; }
.detail-row {
  display: flex;
  gap: 8px;
  margin-top: 8px;
  font-size: 12px;
  line-height: 1.5;
  padding: 8px 10px;
  background: #f8f9fb;
  border-left: 3px solid #0f3460;
  border-radius: 0 4px 4px 0;
}
.detail-label {
  flex-shrink: 0;
  width: 90px;
  font-weight: 600;
  color: #555;
}
.detail-value { color: #333; }
.ev-good { color: #1a7f37; font-weight: 600; }
.ev-bad  { color: #cf222e; font-weight: 600; }

footer {
  text-align: center;
  font-size: 11px;
  color: #aaa;
  padding: 24px;
  border-top: 1px solid #e8ecf0;
  margin-top: 48px;
}
"""


# ── Main generator ─────────────────────────────────────────────────────────────

def generate_html_report(report_data: dict, output_path: str = "mdc_report.html") -> str:
    """
    Generate a self-contained HTML report from report data.
    Returns the output path.
    """
    meta          = report_data.get("report_metadata", {})
    sub_id        = meta.get("subscription_id", "Unknown")
    generated_at  = meta.get("generated_at", datetime.now(timezone.utc).isoformat())
    score         = report_data.get("secure_score", {})
    plans         = report_data.get("defender_plans", {})
    recommendations = report_data.get("recommendations", {})
    contacts      = report_data.get("security_contacts", [])
    auto_prov     = report_data.get("auto_provisioning", {})
    by_section    = recommendations.get("by_cis_section", {})

    # Backfill expected_value / current_value_if_fail from CIS mapping for JSON
    # snapshots that were generated before these fields were added.
    if _CIS_AVAILABLE:
        for section_data in by_section.values():
            for rec in section_data.get("items", []):
                if rec.get("expected_value") is None or rec.get("cis_doc_url") is None:
                    m = lookup_control(rec.get("name", ""))
                    if m:
                        if rec.get("expected_value") is None:
                            rec["expected_value"]        = m.get("expected_value")
                            rec["current_value_if_fail"] = m.get("current_value_if_fail")
                        rec["cis_doc_url"] = m.get("doc_url")

    # Format timestamp for display
    try:
        dt = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
        display_time = dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        display_time = generated_at

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MDC Assessment Report — {_esc(sub_id)}</title>
  <style>{CSS}</style>
</head>
<body>

<header>
  <h1>Microsoft Defender for Cloud &mdash; Assessment Report</h1>
  <div class="meta">
    Subscription: {_esc(sub_id)} &nbsp;&bull;&nbsp; Generated: {_esc(display_time)}
  </div>
</header>

<main>

  <h2>Executive Summary</h2>
  {_build_executive_summary(score, plans, recommendations)}

  <h2>Defender Plans</h2>
  {_build_defender_plans(plans)}

  <h2>Findings by CIS Section</h2>
  {_build_findings_by_section(by_section)}

  <h2>Security Contacts</h2>
  {_build_security_contacts(contacts)}

  <h2>Auto-Provisioning</h2>
  {_build_auto_provisioning(auto_prov)}

</main>

<footer>
  Generated by mdc_assess.py &bull; CIS Azure Foundations Benchmark v2.0.0
</footer>

</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path


# ── Standalone entry point ─────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Generate HTML report from mdc_report.json")
    parser.add_argument("--input", default="mdc_report.json", help="Path to JSON report (default: mdc_report.json)")
    parser.add_argument("--output", default="mdc_report.html", help="Output HTML path (default: mdc_report.html)")
    args = parser.parse_args()

    try:
        with open(args.input, encoding="utf-8") as f:
            report_data = json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] Input file not found: {args.input}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON in {args.input}: {e}")
        sys.exit(1)

    out = generate_html_report(report_data, args.output)
    print(f"[INFO] HTML report saved to: {out}")


if __name__ == "__main__":
    main()
