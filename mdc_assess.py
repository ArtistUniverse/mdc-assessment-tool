"""
mdc_assess.py
Microsoft Defender for Cloud — Subscription Assessment Script
-------------------------------------------------------------
Connects to an Azure subscription and reads the current MDC state:
  - Defender plan enablement per resource type
  - Secure Score
  - Top recommendations by severity
  - Security contacts
  - Auto-provisioning settings

Output: Console summary + JSON report saved to ./mdc_report.json

Requirements:
    pip install azure-identity azure-mgmt-security azure-mgmt-resource

Authentication:
    Run `az login` before executing this script.
    DefaultAzureCredential will pick up your CLI session automatically.

Usage:
    python mdc_assess.py
    python mdc_assess.py --subscription-id <your-sub-id>
"""

import argparse
import json
import os
import sys
import warnings
from contextlib import contextmanager
from datetime import datetime, timezone

@contextmanager
def suppress_stderr():
    """Redirect stderr to /dev/null to suppress noisy SDK discriminator messages.
    These come from the Azure SDK's deserialization layer when handling multicloud
    resources — they're informational noise, not errors."""
    with open(os.devnull, 'w') as devnull:
        old_stderr = sys.stderr
        sys.stderr = devnull
        try:
            yield
        finally:
            sys.stderr = old_stderr

from azure.identity import InteractiveBrowserCredential
from azure.mgmt.security import SecurityCenter
from azure.mgmt.subscription import SubscriptionClient


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_subscription_id(credential, supplied_id=None):
    """Return the subscription ID to assess.
    If one was passed via --subscription-id, use it.
    Otherwise list available subscriptions and prompt the user to pick one.
    """
    if supplied_id:
        return supplied_id

    client = SubscriptionClient(credential)
    subs = list(client.subscriptions.list())

    if not subs:
        print("[ERROR] No subscriptions found for this account.")
        sys.exit(1)

    if len(subs) == 1:
        sub = subs[0]
        print(f"[INFO] Using subscription: {sub.display_name} ({sub.subscription_id})\n")
        return sub.subscription_id

    print("Available subscriptions:")
    for i, sub in enumerate(subs):
        print(f"  [{i}] {sub.display_name} — {sub.subscription_id}")

    choice = int(input("\nSelect subscription number: "))
    return subs[choice].subscription_id


def severity_label(severity):
    """Map MDC severity strings to display labels with emoji indicators."""
    return {
        "High":   "🔴 High",
        "Medium": "🟡 Medium",
        "Low":    "🔵 Low",
    }.get(severity, severity)


# ── Assessment functions ───────────────────────────────────────────────────────

def assess_defender_plans(client):
    """
    Check which Defender plans are enabled on the subscription.
    MDC uses 'pricings' to represent plan tiers per resource type.
    Tier 'Standard' = Defender plan ON. 'Free' = OFF.
    The newer SDK returns a PricingList object with a .value list, not an iterable directly.
    """
    print("Checking Defender plans...")

    plans = {}
    try:
        scope = f"/subscriptions/{client._config.subscription_id}"
        result = client.pricings.list(scope_id=scope)

        # Newer SDK returns PricingList with .value attribute
        items = getattr(result, 'value', None)
        if items is None:
            # Older SDK returns iterable directly
            items = list(result)

        for pricing in items:
            name = pricing.name
            tier = pricing.pricing_tier   # 'Standard' or 'Free'
            plans[name] = {
                "enabled": tier == "Standard",
                "tier": tier
            }
    except Exception as e:
        print(f"  [WARN] Could not retrieve Defender plans: {e}")

    return plans


def assess_secure_score(client):
    """
    Pull the overall Secure Score for the subscription.
    The SDK shape changed across versions — we inspect the object directly
    rather than assuming a fixed attribute path.
    """
    print("Checking Secure Score...")

    score_data = {}
    try:
        scores = list(client.secure_scores.list())
        for score in scores:
            if score.name == "ascScore":
                # Try every known attribute path across SDK versions
                current, maximum = None, None

                # Path 1: score.score.current / score.score.max (older SDK)
                score_obj = getattr(score, 'score', None)
                if score_obj and hasattr(score_obj, 'current'):
                    current = getattr(score_obj, 'current', None)
                    maximum = getattr(score_obj, 'max', None)

                # Path 2: score.current_score / score.max_score
                if current is None:
                    current = getattr(score, 'current_score', None)
                    maximum = getattr(score, 'max_score', None)

                # Path 3: score.weight (some versions store as integer points)
                if current is None:
                    current = getattr(score, 'weight', None)
                    maximum = getattr(score, 'max', None)

                if current is not None and maximum and float(maximum) > 0:
                    score_data = {
                        "current": round(float(current), 1),
                        "max": round(float(maximum), 1),
                        "percentage": round((float(current) / float(maximum)) * 100, 1)
                    }
                else:
                    # Return raw object dump for debugging if nothing works
                    score_data = {
                        "current": current,
                        "max": maximum,
                        "percentage": None,
                        "raw_keys": [k for k in vars(score).keys()
                                     if not k.startswith('_')]
                    }
                break
    except Exception as e:
        print(f"  [WARN] Could not retrieve Secure Score: {e}")

    return score_data


def assess_recommendations(client, limit=20):
    """
    Retrieve active security recommendations, sorted by severity.
    Severity is not hydrated on individual assessment objects from the list API —
    it lives in the assessments_metadata definitions. We build a lookup dict first,
    then join it to each unhealthy assessment by name.
    Deduplicates by recommendation name and counts affected resources.
    """
    print("Checking recommendations...")

    severity_order = {"High": 0, "Medium": 1, "Low": 2}

    # Step 1 — build severity lookup from metadata definitions
    severity_lookup = {}
    try:
        for meta in client.assessments_metadata.list():
            # meta.name is the assessment type GUID used as the key
            sev = getattr(meta, 'severity', None)
            if meta.name and sev:
                severity_lookup[meta.name.lower()] = sev
    except Exception as e:
        print(f"  [WARN] Could not retrieve assessment metadata: {e}")

    # Step 2 — pull unhealthy assessments and join severity
    seen = {}  # display_name -> {severity, affected_resources, resource_type}
    try:
        scope = f"/subscriptions/{client._config.subscription_id}"
        with suppress_stderr():
            all_assessments = list(client.assessments.list(scope=scope))
        for a in all_assessments:
            status = a.status.code if a.status else None
            if not status or status.lower() != "unhealthy":
                continue

            display = getattr(a, 'display_name', None) or getattr(a, 'name', 'Unknown')

            # Extract the assessment type name from the resource ID
            # ID format: .../assessments/{assessmentTypeName}
            assessment_key = None
            if a.name:
                assessment_key = a.name.lower()
            elif a.id:
                assessment_key = a.id.split("/assessments/")[-1].lower()

            severity = severity_lookup.get(assessment_key, "Unknown")

            if display in seen:
                seen[display]["affected_resources"] += 1
            else:
                seen[display] = {
                    "severity": severity,
                    "affected_resources": 1,
                    "resource_type": getattr(a, 'type', "Unknown"),
                }

    except Exception as e:
        print(f"  [WARN] Could not retrieve recommendations: {e}")

    # Build sorted deduplicated list
    recs = [
        {"name": name,
         "severity": v["severity"],
         "affected_resources": v["affected_resources"],
         "resource_type": v["resource_type"]}
        for name, v in seen.items()
    ]
    recs.sort(key=lambda r: (severity_order.get(r["severity"], 99), r["name"]))

    counts = {"High": 0, "Medium": 0, "Low": 0}
    for r in recs:
        sev = r["severity"]
        if sev in counts:
            counts[sev] += 1

    return {
        "total": len(recs),
        "counts": counts,
        "top_recommendations": recs[:limit]
    }


def assess_security_contacts(client):
    """
    Check whether security contact info is configured.
    MDC uses security contacts to send alerts and notifications.
    Missing contacts = no one receives breach notifications.
    """
    print("Checking security contacts...")

    contacts = []
    try:
        for contact in client.security_contacts.list():
            contacts.append({
                "name": contact.name,
                "email": getattr(contact, 'email', None),
                "phone": getattr(contact, 'phone', None),
                "alert_notifications": getattr(contact, 'alert_notifications', None),
                "alerts_to_admins": getattr(contact, 'alerts_to_admins', None),
            })
    except Exception as e:
        print(f"  [WARN] Could not retrieve security contacts: {e}")

    return contacts


def assess_auto_provisioning(client):
    """
    Check auto-provisioning settings.
    MDC can automatically deploy monitoring agents to VMs.
    If auto-provisioning is off, new VMs won't be monitored.
    """
    print("Checking auto-provisioning settings...")

    settings = {}
    try:
        for setting in client.auto_provisioning_settings.list():
            settings[setting.name] = setting.auto_provision   # 'On' or 'Off'
    except Exception as e:
        print(f"  [WARN] Could not retrieve auto-provisioning settings: {e}")

    return settings


# ── Report output ─────────────────────────────────────────────────────────────

def print_report(subscription_id, plans, score, recommendations, contacts, auto_prov):
    """Print a human-readable summary to the console."""

    print("\n" + "=" * 60)
    print("  MICROSOFT DEFENDER FOR CLOUD — ASSESSMENT REPORT")
    print("=" * 60)
    print(f"  Subscription : {subscription_id}")
    print(f"  Generated    : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print("=" * 60)

    # Secure Score
    print("\n── Secure Score ─────────────────────────────────────────")
    if score:
        bar_fill = int((score['percentage'] or 0) / 5)
        bar = "█" * bar_fill + "░" * (20 - bar_fill)
        print(f"  [{bar}] {score['percentage']}%")
        print(f"  Current: {score['current']} / Max: {score['max']}")
    else:
        print("  Could not retrieve Secure Score.")

    # Defender Plans
    print("\n── Defender Plans ───────────────────────────────────────")
    if plans:
        enabled  = [k for k, v in plans.items() if v["enabled"]]
        disabled = [k for k, v in plans.items() if not v["enabled"]]
        for p in sorted(enabled):
            print(f"  ✅ {p}")
        for p in sorted(disabled):
            print(f"  ❌ {p}")
    else:
        print("  No plan data available.")

    # Recommendations
    print("\n── Active Recommendations ───────────────────────────────")
    rec_counts = recommendations.get("counts", {})
    print(f"  Total actionable : {recommendations.get('total', 0)}")
    print(f"  🔴 High          : {rec_counts.get('High', 0)}")
    print(f"  🟡 Medium        : {rec_counts.get('Medium', 0)}")
    print(f"  🔵 Low           : {rec_counts.get('Low', 0)}")
    print()
    top = recommendations.get("top_recommendations", [])
    if top:
        print("  Top findings:")
        for r in top[:10]:
            affected = r.get("affected_resources", 1)
            suffix = f" ({affected} resources)" if affected > 1 else ""
            print(f"    {severity_label(r['severity']):<14}  {r['name']}{suffix}")

    # Security Contacts
    print("\n── Security Contacts ────────────────────────────────────")
    if contacts:
        for c in contacts:
            print(f"  {c['name']}: {c['email'] or 'No email'} | Phone: {c['phone'] or 'None'}")
    else:
        print("  ⚠️  No security contacts configured.")

    # Auto-Provisioning
    print("\n── Auto-Provisioning ────────────────────────────────────")
    if auto_prov:
        for name, state in auto_prov.items():
            icon = "✅" if state == "On" else "❌"
            print(f"  {icon} {name}: {state}")
    else:
        print("  No auto-provisioning data available.")

    print("\n" + "=" * 60)
    print("  Full report saved to: mdc_report.json")
    print("=" * 60 + "\n")


def save_report(subscription_id, plans, score, recommendations, contacts, auto_prov):
    """Save the full report as a JSON file for use in client deliverables."""

    report = {
        "report_metadata": {
            "subscription_id": subscription_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool": "mdc_assess.py"
        },
        "secure_score": score,
        "defender_plans": plans,
        "recommendations": recommendations,
        "security_contacts": contacts,
        "auto_provisioning": auto_prov,
    }

    path = "mdc_report.json"
    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    return path


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="MDC Subscription Assessment")
    parser.add_argument("--subscription-id", help="Azure subscription ID (optional — will prompt if not supplied)")
    args = parser.parse_args()

    print("\n[INFO] A browser window will open — sign in with your Azure account.\n")

    try:
        credential = InteractiveBrowserCredential()
    except Exception as e:
        print(f"[ERROR] Authentication failed: {e}")
        sys.exit(1)

    subscription_id = get_subscription_id(credential, args.subscription_id)

    # The SecurityCenter client is the main Azure SDK client for MDC
    client = SecurityCenter(credential, subscription_id)

    print(f"[INFO] Assessing subscription: {subscription_id}\n")

    # Run all assessment sections
    plans       = assess_defender_plans(client)
    score       = assess_secure_score(client)
    recs        = assess_recommendations(client)
    contacts    = assess_security_contacts(client)
    auto_prov   = assess_auto_provisioning(client)

    # Output
    print_report(subscription_id, plans, score, recs, contacts, auto_prov)
    save_report(subscription_id, plans, score, recs, contacts, auto_prov)


if __name__ == "__main__":
    main()
