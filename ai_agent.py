#!/usr/bin/env python3
"""
ai_agent.py — Optional AI analysis layer for the MDC assessment tool.

This module is *bring-your-own-API*: it never ships an API key and never calls a
hosted model on your behalf. You point it at whatever LLM you already pay for
(OpenAI, Azure OpenAI, Anthropic, a local Ollama/LM Studio server, OpenRouter,
or any OpenAI-compatible endpoint) by setting a few environment variables.

Configuration (environment variables or a local .env file):

    MDC_AI_PROVIDER   openai | azure | anthropic | openai-compatible   (default: openai)
    MDC_AI_API_KEY    your secret key                                  (required)
    MDC_AI_MODEL      model / deployment name                          (provider default)
    MDC_AI_BASE_URL   override the API base URL                        (provider default)
    MDC_AI_API_VERSION  Azure OpenAI api-version                       (azure only)

If MDC_AI_API_KEY is not set, every task degrades gracefully: it prints setup
instructions and exits 0 without making any network calls.

Tasks:
    explain     Plain-language explanation of what each finding means and why it matters
    prioritize  Risk-ranked remediation order (severity x blast radius x effort)
    guidance    Step-by-step remediation guidance per finding
    review      Iterative review loop: efficiency pass -> security audit, repeated
                until no High-severity findings remain in the working set (bounded)

Usage:
    python ai_agent.py --input mdc_report.json --task explain
    python ai_agent.py --input mdc_report.json --task review --max-iterations 3

Security notes:
    - The API key is read from the environment only and is never logged, printed,
      or written to the output file.
    - Remote (non-localhost) endpoints must use https://.
    - Only the assessment findings are sent to the model — no credentials, tokens,
      or raw Azure resource IDs beyond what already appears in the report.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone


# ── Configuration ──────────────────────────────────────────────────────────────

DEFAULT_BASE_URLS = {
    "openai":            "https://api.openai.com/v1",
    "azure":             None,   # must be supplied (https://<resource>.openai.azure.com)
    "anthropic":         "https://api.anthropic.com",
    "openai-compatible": "http://localhost:11434/v1",  # Ollama default
}

DEFAULT_MODELS = {
    "openai":            "gpt-4o-mini",
    "azure":             None,   # deployment name, must be supplied
    "anthropic":         "claude-3-5-sonnet-latest",
    "openai-compatible": "llama3.1",
}

OUTPUT_PATH = "mdc_ai_analysis.json"


def _load_dotenv(path=".env"):
    """Minimal .env loader so users can drop secrets in a local file.

    Does not override variables already present in the environment. Intentionally
    tiny — no dependency on python-dotenv.
    """
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except OSError:
        pass


class AIConfig:
    """Resolved AI provider configuration. Never carries the key into output."""

    def __init__(self):
        self.provider = os.environ.get("MDC_AI_PROVIDER", "openai").strip().lower()
        self.api_key = os.environ.get("MDC_AI_API_KEY", "").strip()
        self.model = (os.environ.get("MDC_AI_MODEL", "").strip()
                      or DEFAULT_MODELS.get(self.provider))
        self.base_url = (os.environ.get("MDC_AI_BASE_URL", "").strip()
                         or DEFAULT_BASE_URLS.get(self.provider))
        self.api_version = os.environ.get("MDC_AI_API_VERSION", "2024-06-01").strip()

    @property
    def configured(self):
        return bool(self.api_key)

    def validate(self):
        """Return a list of human-readable problems, empty if usable."""
        problems = []
        if self.provider not in DEFAULT_BASE_URLS:
            problems.append(
                f"Unknown MDC_AI_PROVIDER '{self.provider}'. "
                f"Choose one of: {', '.join(DEFAULT_BASE_URLS)}."
            )
        if not self.base_url:
            problems.append(
                "MDC_AI_BASE_URL is required for this provider "
                "(e.g. https://<resource>.openai.azure.com for azure)."
            )
        elif not _is_safe_base_url(self.base_url):
            problems.append(
                f"MDC_AI_BASE_URL '{self.base_url}' must use https:// "
                "(http:// is only allowed for localhost / 127.0.0.1)."
            )
        if not self.model:
            problems.append("MDC_AI_MODEL is required for this provider.")
        return problems


def _is_safe_base_url(url):
    """Allow https everywhere; allow http only for loopback addresses."""
    low = url.lower()
    if low.startswith("https://"):
        return True
    if low.startswith("http://"):
        host = low[len("http://"):].split("/", 1)[0].split(":", 1)[0]
        return host in ("localhost", "127.0.0.1", "::1")
    return False


def setup_instructions():
    return (
        "\n[AI] No AI provider configured — skipping AI analysis.\n"
        "\nTo enable AI analysis, set these environment variables (or add them to a\n"
        "local .env file next to this script):\n\n"
        "    export MDC_AI_PROVIDER=openai        # openai | azure | anthropic | openai-compatible\n"
        "    export MDC_AI_API_KEY=sk-...         # your own key (kept local, never logged)\n"
        "    export MDC_AI_MODEL=gpt-4o-mini      # optional, provider default used otherwise\n"
        "    export MDC_AI_BASE_URL=...           # optional, only to override the endpoint\n\n"
        "See .env.example for provider-specific examples. The tool runs fully without\n"
        "AI — this step is optional.\n"
    )


# ── LLM client ─────────────────────────────────────────────────────────────────

class AIError(RuntimeError):
    pass


def _require_requests():
    try:
        import requests  # noqa: F401
        return __import__("requests")
    except ImportError:
        raise AIError(
            "The 'requests' package is required for AI analysis. "
            "Install it with:  pip install requests"
        )


def call_llm(config, system_prompt, user_prompt, temperature=0.2, max_tokens=1500):
    """Dispatch a single chat completion to the configured provider.

    Returns the assistant's text content. Raises AIError on failure.
    """
    requests = _require_requests()

    if config.provider == "anthropic":
        return _call_anthropic(requests, config, system_prompt, user_prompt,
                               temperature, max_tokens)
    return _call_openai_compatible(requests, config, system_prompt, user_prompt,
                                   temperature, max_tokens)


def _call_openai_compatible(requests, config, system_prompt, user_prompt,
                            temperature, max_tokens):
    if config.provider == "azure":
        url = (f"{config.base_url.rstrip('/')}/openai/deployments/"
               f"{config.model}/chat/completions"
               f"?api-version={config.api_version}")
        headers = {"api-key": config.api_key, "Content-Type": "application/json"}
        payload = {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
    else:
        url = f"{config.base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {config.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": config.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=120)
    except Exception as e:
        raise AIError(f"Request to AI endpoint failed: {e}")

    if resp.status_code >= 400:
        raise AIError(f"AI endpoint returned HTTP {resp.status_code}: "
                      f"{_safe_body(resp)}")
    try:
        data = resp.json()
        return data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, ValueError) as e:
        raise AIError(f"Unexpected response shape from AI endpoint: {e}")


def _call_anthropic(requests, config, system_prompt, user_prompt,
                    temperature, max_tokens):
    url = f"{config.base_url.rstrip('/')}/v1/messages"
    headers = {
        "x-api-key": config.api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }
    payload = {
        "model": config.model,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=120)
    except Exception as e:
        raise AIError(f"Request to AI endpoint failed: {e}")

    if resp.status_code >= 400:
        raise AIError(f"AI endpoint returned HTTP {resp.status_code}: "
                      f"{_safe_body(resp)}")
    try:
        data = resp.json()
        parts = data.get("content", [])
        text = "".join(p.get("text", "") for p in parts if p.get("type") == "text")
        return text.strip()
    except (KeyError, ValueError) as e:
        raise AIError(f"Unexpected response shape from AI endpoint: {e}")


def _safe_body(resp):
    """Truncate an error body and avoid echoing anything sensitive back."""
    try:
        body = resp.text
    except Exception:
        return "<unreadable body>"
    return body[:500]


# ── Report summarization ───────────────────────────────────────────────────────

def _all_findings(report):
    """Flatten every finding across sections into a single list."""
    findings = []
    by_section = (report.get("recommendations", {}) or {}).get("by_cis_section", {}) or {}
    for section_name, section in by_section.items():
        for item in section.get("items", []):
            f = dict(item)
            f.setdefault("section", section_name)
            findings.append(f)
    # Fall back to top_recommendations if sections are empty
    if not findings:
        findings = list((report.get("recommendations", {}) or {})
                        .get("top_recommendations", []))
    return findings


def summarize_report(report, severities=None):
    """Build a compact, model-friendly text summary of the findings.

    Sends only finding-level detail — no credentials or tokens. Optionally filters
    to a subset of severities (e.g. ["High"] for the review loop).
    """
    meta = report.get("report_metadata", {})
    fw = meta.get("framework", {})
    score = report.get("secure_score", {}) or {}
    findings = _all_findings(report)
    if severities:
        findings = [f for f in findings if f.get("severity") in severities]

    sev_rank = {"High": 0, "Medium": 1, "Low": 2}
    findings.sort(key=lambda f: (sev_rank.get(f.get("severity"), 9),
                                 f.get("name", "")))

    lines = []
    lines.append(f"Framework: {fw.get('label', 'Unmapped')}")
    if score.get("percentage") is not None:
        lines.append(f"Secure Score: {score.get('percentage')}% "
                     f"({score.get('current')}/{score.get('max')})")
    lines.append(f"Total findings included: {len(findings)}")
    lines.append("")

    control_label = fw.get("control_label", "Control")
    for i, f in enumerate(findings, 1):
        lines.append(f"{i}. [{f.get('severity', 'Unknown')}] {f.get('name', 'Unnamed finding')}")
        if f.get("cis_id"):
            lines.append(f"   {control_label}: {f.get('cis_id')}"
                         + (f" — {f.get('section')}" if f.get("section") else ""))
        if f.get("affected_resources"):
            lines.append(f"   Affected resources: {f.get('affected_resources')} "
                         f"({f.get('resource_type', 'Unknown')})")
        if f.get("current_state"):
            lines.append(f"   Current: {f.get('current_state')}")
        if f.get("control_description"):
            lines.append(f"   Expected: {f.get('control_description')}")
        if f.get("remediation"):
            lines.append(f"   MDC remediation hint: {f.get('remediation')}")
        lines.append("")

    return "\n".join(lines).strip()


# ── Tasks ──────────────────────────────────────────────────────────────────────

_SYSTEM_BASE = (
    "You are a senior Microsoft Defender for Cloud and Azure security engineer. "
    "You receive a list of security findings from an automated assessment and help "
    "the operator understand and remediate them. Be precise, actionable, and concise. "
    "Do not invent findings that are not in the provided list."
)


def explain_findings(report, config):
    summary = summarize_report(report)
    user = (
        "Explain the following Microsoft Defender for Cloud findings in plain "
        "language. For each, state in one or two sentences what it means, the real "
        "risk if left unfixed, and which Azure resource type it affects. Group by "
        "severity (High first).\n\n"
        f"{summary}"
    )
    return call_llm(config, _SYSTEM_BASE, user, max_tokens=2000)


def prioritize(report, config):
    summary = summarize_report(report)
    user = (
        "Produce a remediation priority list for the findings below. Rank them by a "
        "combination of severity, blast radius (number of affected resources), and "
        "implementation effort. For each item give: rank, finding name, a one-line "
        "rationale, and an effort estimate (Low/Medium/High). Put quick high-impact "
        "wins at the top.\n\n"
        f"{summary}"
    )
    return call_llm(config, _SYSTEM_BASE, user, max_tokens=2000)


def remediation_guidance(report, config):
    summary = summarize_report(report)
    user = (
        "Provide step-by-step remediation guidance for each finding below. Prefer "
        "Azure CLI commands and portal navigation paths. Where a setting can be "
        "enabled by the companion deployment script (Defender plans, security "
        "contacts, auto-provisioning), note that. Keep each finding's steps tight.\n\n"
        f"{summary}"
    )
    return call_llm(config, _SYSTEM_BASE, user, max_tokens=2500)


def review_loop(report, config, max_iterations=3):
    """Iterative review: efficiency pass -> security audit, repeated.

    The model first proposes an efficient remediation plan for the current set of
    High-severity findings, then performs a security audit of that plan. Each
    iteration narrows the plan. Bounded by max_iterations to avoid runaway calls.
    Operates on the High-severity working set described in the report (this tool
    does not re-scan Azure between iterations — use mdc_deploy.py --validate for
    that).
    """
    high_summary = summarize_report(report, severities=["High"])
    if not high_summary or "Total findings included: 0" in high_summary:
        return "No High-severity findings to review. Nothing to do."

    transcript = []
    plan = None
    for iteration in range(1, max_iterations + 1):
        # 1) Efficiency pass
        if plan is None:
            eff_user = (
                "Draft the most efficient remediation plan to resolve these "
                "High-severity findings with the fewest, highest-leverage steps. "
                "Output a numbered plan.\n\n" + high_summary
            )
        else:
            eff_user = (
                "Here is the current remediation plan:\n\n" + plan +
                "\n\nRefine it to be more efficient — merge overlapping steps and "
                "remove redundancy — while still covering every High finding below.\n\n"
                + high_summary
            )
        plan = call_llm(config, _SYSTEM_BASE, eff_user, max_tokens=1500)
        transcript.append(f"### Iteration {iteration} — Efficiency pass\n{plan}")

        # 2) Security audit
        audit_user = (
            "Security-audit the remediation plan below. Identify any High-severity "
            "finding it fails to fully resolve, any step that could introduce a new "
            "risk, and any missing validation. End your answer with a line that is "
            "exactly 'STATUS: CLEAN' if every High finding is fully addressed and the "
            "plan introduces no new risk, otherwise 'STATUS: NEEDS_WORK'.\n\n"
            "PLAN:\n" + plan + "\n\nHIGH FINDINGS:\n" + high_summary
        )
        audit = call_llm(config, _SYSTEM_BASE, audit_user, max_tokens=1500)
        transcript.append(f"### Iteration {iteration} — Security audit\n{audit}")

        if "STATUS: CLEAN" in audit.upper():
            transcript.append(f"\nReview converged after {iteration} iteration(s).")
            break
    else:
        transcript.append(
            f"\nReached max iterations ({max_iterations}) without a clean audit. "
            "Review the latest plan manually."
        )

    return "\n\n".join(transcript)


TASKS = {
    "explain": explain_findings,
    "prioritize": prioritize,
    "guidance": remediation_guidance,
    "review": review_loop,
}


# ── Orchestration ──────────────────────────────────────────────────────────────

def run_task(report, task, config=None, max_iterations=3, output_path=OUTPUT_PATH,
             quiet=False):
    """Run a single AI task against an in-memory report dict.

    Returns the result dict (also written to output_path) or None if AI is not
    configured. Never raises on a missing key — degrades gracefully.
    """
    _load_dotenv()
    config = config or AIConfig()

    if not config.configured:
        if not quiet:
            print(setup_instructions())
        return None

    problems = config.validate()
    if problems:
        if not quiet:
            print("\n[AI] Configuration problems:")
            for p in problems:
                print(f"  - {p}")
        return None

    if task not in TASKS:
        raise ValueError(f"Unknown task '{task}'. Choose from: {', '.join(TASKS)}.")

    if not quiet:
        print(f"[AI] Provider: {config.provider} | Model: {config.model}")
        print(f"[AI] Running task: {task} ...\n")

    func = TASKS[task]
    if task == "review":
        content = func(report, config, max_iterations=max_iterations)
    else:
        content = func(report, config)

    result = {
        "task": task,
        "provider": config.provider,
        "model": config.model,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "content": content,
    }

    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        if not quiet:
            print(content)
            print(f"\n[AI] Analysis saved to: {output_path}")
    except OSError as e:
        if not quiet:
            print(f"[AI] [WARN] Could not write {output_path}: {e}")
            print(content)

    return result


def load_report(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def main():
    parser = argparse.ArgumentParser(
        description="Optional AI analysis of an MDC assessment report (bring-your-own-API)."
    )
    parser.add_argument("--input", default="mdc_report.json",
                        help="Assessment report JSON to analyze (default: mdc_report.json)")
    parser.add_argument("--task", choices=list(TASKS), default="explain",
                        help="AI task to run (default: explain)")
    parser.add_argument("--max-iterations", type=int, default=3,
                        help="Max iterations for the review loop (default: 3)")
    parser.add_argument("--output", default=OUTPUT_PATH,
                        help=f"Where to write the analysis (default: {OUTPUT_PATH})")
    args = parser.parse_args()

    try:
        report = load_report(args.input)
    except FileNotFoundError:
        print(f"[ERROR] Report not found: {args.input}. "
              "Run mdc_assess.py first to generate it.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Could not parse {args.input}: {e}")
        sys.exit(1)

    try:
        result = run_task(report, args.task, max_iterations=args.max_iterations,
                          output_path=args.output)
    except AIError as e:
        print(f"[AI] [ERROR] {e}")
        sys.exit(1)

    if result is None:
        # Not configured — non-fatal so it can be chained after an assessment.
        sys.exit(0)


if __name__ == "__main__":
    main()
