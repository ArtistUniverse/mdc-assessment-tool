"""
mdc_deploy.py
Microsoft Defender for Cloud — Baseline Deployment Script (Phase 2)
-------------------------------------------------------------------
Reads the mdc_report.json produced by mdc_assess.py (Phase 1) and remediates
the gaps it found in an Azure subscription:

  - Enables Defender for Cloud plans that are off
    (prioritising Arm / StorageAccounts / KeyVaults)
  - Configures a security contact if none is set
  - Enables auto-provisioning of monitoring components

Every change requires explicit confirmation. All changes are logged with
before/after values to mdc_deployment_log.json.

Requirements:
    pip install azure-identity azure-mgmt-security azure-mgmt-subscription

Authentication:
    Uses InteractiveBrowserCredential (same as mdc_assess.py). A browser window
    opens on first run; the token is then cached.

    NOTE: Deployment requires write access (Contributor or Owner) on the
    subscription. Phase 1 assessment only needs Reader.

Usage:
    python mdc_deploy.py
    python mdc_deploy.py --input mdc_report.json --subscription-id <sub-id>
    python mdc_deploy.py --contact-email security@example.com
    python mdc_deploy.py --yes        # skip the confirmation prompt
"""

import argparse
import json
import sys
from datetime import datetime, timezone


# Defender plans to remediate first, per Issue 9.
PRIORITY_PLANS = ["Arm", "StorageAccounts", "KeyVaults"]


# ── Plan building (pure — no Azure calls, safe to unit test) ────────────────────

def load_report(path):
    """Load the Phase 1 assessment JSON report."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] Report not found: {path}")
        print("        Run `python mdc_assess.py` first to generate it.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON in {path}: {e}")
        sys.exit(1)


def _plan_priority(name):
    """Sort key: priority plans first (in listed order), then alphabetical."""
    try:
        return (0, PRIORITY_PLANS.index(name))
    except ValueError:
        return (1, name)


def build_action_plan(report, contact_email=None, contact_phone=None,
                      enable_auto_provisioning=True, plans=None):
    """
    Derive an ordered list of remediation actions from an assessment report.

    Each action is a plain dict (JSON-serialisable) so the same plan can drive
    both a dry-run preview (Issue 10) and live execution. No Azure SDK calls are
    made here.

    Args:
        report: parsed mdc_report.json dict
        contact_email: email to set if no security contact exists
        contact_phone: optional phone for the security contact
        enable_auto_provisioning: whether to include auto-provisioning actions
        plans: optional explicit list of plan names to enable; if None, every
               disabled plan found in the report is included.
    """
    actions = []

    # 1 — Defender plans that are off
    defender_plans = report.get("defender_plans", {}) or {}
    disabled = [name for name, info in defender_plans.items()
                if not info.get("enabled", False)]
    if plans:
        wanted = {p.lower() for p in plans}
        disabled = [name for name in disabled if name.lower() in wanted]
    for name in sorted(disabled, key=_plan_priority):
        info = defender_plans.get(name, {})
        actions.append({
            "category": "defender_plan",
            "target": name,
            "description": f"Enable Microsoft Defender plan: {name}",
            "current": info.get("tier", "Free"),
            "expected": "Standard",
        })

    # 2 — Security contact (only if none configured)
    contacts = report.get("security_contacts", []) or []
    if not contacts:
        if contact_email:
            actions.append({
                "category": "security_contact",
                "target": "default",
                "description": f"Configure security contact: {contact_email}",
                "current": "No security contact configured",
                "expected": contact_email,
                "params": {"email": contact_email, "phone": contact_phone or ""},
            })
        else:
            actions.append({
                "category": "security_contact",
                "target": "default",
                "description": "Configure security contact (SKIPPED — no --contact-email supplied)",
                "current": "No security contact configured",
                "expected": "Security contact configured",
                "skip": True,
                "skip_reason": "Provide --contact-email to enable this action.",
            })

    # 3 — Auto-provisioning of monitoring components
    if enable_auto_provisioning:
        auto_prov = report.get("auto_provisioning", {}) or {}
        off_settings = {name: state for name, state in auto_prov.items()
                        if str(state).lower() != "on"}
        # If the report has no auto-provisioning data, still offer the default.
        targets = off_settings or ({"default": "Off"} if not auto_prov else {})
        for name, state in targets.items():
            actions.append({
                "category": "auto_provisioning",
                "target": name,
                "description": f"Enable auto-provisioning: {name}",
                "current": state,
                "expected": "On",
            })

    return actions


# ── Plan presentation ───────────────────────────────────────────────────────────

def print_plan(actions):
    """Print the proposed action plan as a readable table."""
    print("\n" + "=" * 64)
    print("  MDC BASELINE DEPLOYMENT — PROPOSED CHANGES")
    print("=" * 64)

    active = [a for a in actions if not a.get("skip")]
    skipped = [a for a in actions if a.get("skip")]

    if not active and not skipped:
        print("  Nothing to remediate — the subscription already meets the baseline.")
        print("=" * 64 + "\n")
        return active

    for i, a in enumerate(active, 1):
        print(f"\n  [{i}] {a['description']}")
        print(f"      Current:  {a.get('current')}")
        print(f"      Expected: {a.get('expected')}")

    if skipped:
        print("\n  ── Skipped ──────────────────────────────────────────────")
        for a in skipped:
            print(f"  • {a['description']}")
            if a.get("skip_reason"):
                print(f"      {a['skip_reason']}")

    print("\n" + "=" * 64)
    print(f"  {len(active)} change(s) to apply, {len(skipped)} skipped.")
    print("=" * 64 + "\n")
    return active


def confirm(prompt="Proceed with deployment?"):
    """Ask the user to confirm before making changes."""
    try:
        answer = input(f"{prompt} Type 'yes' to continue: ").strip().lower()
    except EOFError:
        return False
    return answer in ("yes", "y")


# ── Execution (Azure SDK calls) ─────────────────────────────────────────────────

def _enable_defender_plan(client, scope, name):
    """Set a Defender plan to the Standard tier. Tolerates SDK signature drift."""
    from azure.mgmt.security.models import Pricing
    pricing = Pricing(pricing_tier="Standard")
    try:
        # Newer SDK: scope-aware signature
        return client.pricings.update(scope, name, pricing)
    except TypeError:
        # Older SDK: subscription-scoped signature
        return client.pricings.update(name, pricing)


def _configure_security_contact(client, params):
    """Create/replace the default security contact."""
    from azure.mgmt.security.models import SecurityContact
    email = params.get("email")
    phone = params.get("phone") or None
    # Field names vary across SDK versions; try the modern shape first.
    try:
        contact = SecurityContact(
            emails=email,
            phone=phone,
            alert_notifications={"state": "On"},
            notifications_by_role={"state": "On", "roles": ["Owner"]},
        )
    except TypeError:
        contact = SecurityContact(email=email, phone=phone)
    try:
        return client.security_contacts.create("default", contact)
    except TypeError:
        return client.security_contacts.create(security_contact_name="default",
                                               security_contact=contact)


def _enable_auto_provisioning(client, name):
    """Turn auto-provisioning On for the named setting."""
    from azure.mgmt.security.models import AutoProvisioningSetting
    setting = AutoProvisioningSetting(auto_provision="On")
    try:
        return client.auto_provisioning_settings.create(name, setting)
    except TypeError:
        return client.auto_provisioning_settings.create(
            setting_name=name, auto_provisioning_setting=setting)


def execute_action(client, scope, action):
    """
    Apply a single action against Azure. Returns a result dict with before/after
    values and a status. Never raises — failures are captured in the result.
    """
    result = {
        "category": action["category"],
        "target": action["target"],
        "description": action["description"],
        "before": action.get("current"),
        "after": action.get("expected"),
        "status": "applied",
        "error": None,
    }
    try:
        cat = action["category"]
        if cat == "defender_plan":
            _enable_defender_plan(client, scope, action["target"])
        elif cat == "security_contact":
            _configure_security_contact(client, action.get("params", {}))
        elif cat == "auto_provisioning":
            _enable_auto_provisioning(client, action["target"])
        else:
            result["status"] = "skipped"
            result["error"] = f"Unknown action category: {cat}"
    except Exception as e:  # noqa: BLE001 — record any SDK error, keep going
        result["status"] = "failed"
        result["after"] = action.get("current")
        result["error"] = str(e)
    return result


def write_deployment_log(results, subscription_id, path="mdc_deployment_log.json"):
    """Persist the deployment results with before/after values."""
    applied = sum(1 for r in results if r["status"] == "applied")
    failed = sum(1 for r in results if r["status"] == "failed")
    log = {
        "deployment_metadata": {
            "subscription_id": subscription_id,
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "tool": "mdc_deploy.py",
            "applied": applied,
            "failed": failed,
            "total": len(results),
        },
        "results": results,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2)
    return path


# ── Entry point ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="MDC Baseline Deployment (Phase 2)")
    parser.add_argument("--input", default="mdc_report.json",
                        help="Path to the Phase 1 JSON report (default: mdc_report.json)")
    parser.add_argument("--subscription-id",
                        help="Azure subscription ID (defaults to the one in the report)")
    parser.add_argument("--contact-email",
                        help="Security contact email to set if none is configured")
    parser.add_argument("--contact-phone", help="Optional security contact phone")
    parser.add_argument("--plans", nargs="*",
                        help="Limit Defender plan enablement to these plan names")
    parser.add_argument("--no-auto-provisioning", action="store_true",
                        help="Do not enable auto-provisioning")
    parser.add_argument("--yes", action="store_true",
                        help="Skip the confirmation prompt and apply changes")
    args = parser.parse_args()

    report = load_report(args.input)
    subscription_id = (args.subscription_id
                       or report.get("report_metadata", {}).get("subscription_id"))
    if not subscription_id:
        print("[ERROR] No subscription ID in report; pass --subscription-id.")
        sys.exit(1)

    actions = build_action_plan(
        report,
        contact_email=args.contact_email,
        contact_phone=args.contact_phone,
        enable_auto_provisioning=not args.no_auto_provisioning,
        plans=args.plans,
    )

    active = print_plan(actions)
    if not active:
        return

    if not args.yes and not confirm():
        print("[INFO] Deployment cancelled. No changes made.")
        return

    print("\n[INFO] Authenticating — a browser window will open on first run.\n")
    try:
        from azure.identity import (InteractiveBrowserCredential,
                                    TokenCachePersistenceOptions)
        from azure.mgmt.security import SecurityCenter
    except ImportError as e:
        print(f"[ERROR] Azure SDK not installed: {e}")
        print("        pip install azure-identity azure-mgmt-security")
        sys.exit(1)

    try:
        credential = InteractiveBrowserCredential(
            cache_persistence_options=TokenCachePersistenceOptions(name="mdc_assess")
        )
    except Exception as e:
        print(f"[ERROR] Authentication failed: {e}")
        sys.exit(1)

    client = SecurityCenter(credential, subscription_id)
    scope = f"/subscriptions/{subscription_id}"

    print(f"[INFO] Deploying baseline to subscription: {subscription_id}\n")
    results = []
    for i, action in enumerate(active, 1):
        print(f"  [{i}/{len(active)}] {action['description']} ...", end=" ")
        result = execute_action(client, scope, action)
        results.append(result)
        if result["status"] == "applied":
            print("done")
        else:
            print(f"FAILED ({result['error']})")

    log_path = write_deployment_log(results, subscription_id)
    applied = sum(1 for r in results if r["status"] == "applied")
    failed = sum(1 for r in results if r["status"] == "failed")
    print(f"\n[INFO] Deployment complete: {applied} applied, {failed} failed.")
    print(f"[INFO] Change log saved to: {log_path}\n")


if __name__ == "__main__":
    main()
