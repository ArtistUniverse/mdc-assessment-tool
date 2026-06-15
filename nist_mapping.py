"""
nist_mapping.py
NIST Cybersecurity Framework (CSF) 2.0 — MDC Recommendation Mapping
--------------------------------------------------------------------
Maps MDC assessment recommendation display names to NIST CSF 2.0
Functions and Subcategories.

This module mirrors the public interface of cis_mapping.py so the two are
interchangeable behind frameworks.get_framework():

    lookup_control(name)            -> dict | None
    enrich_recommendations(list)    -> list
    get_section_summary(list)       -> dict

Rather than hand-maintaining a second parallel dictionary, the NIST mapping
is derived from the authoritative recommendation keys already curated in
cis_mapping.CIS_MAPPING. Every finding that has a CIS control therefore also
receives a NIST CSF Subcategory, guaranteeing full coverage. The CSF
Subcategory is chosen by keyword (most specific first) and falls back to a
sensible default per CIS section.

Reference: NIST CSF 2.0 (https://www.nist.gov/cyberframework)

Note on field names: to remain a drop-in replacement for cis_mapping, the
enriched records reuse the same keys (cis_id, cis_title, cis_section,
cis_level, cis_doc_url). For this module those keys carry NIST CSF values —
e.g. cis_id holds the CSF Subcategory ID such as "PR.AA-01". The framework
"control_label" (see frameworks.py) tells the report layer how to label them.
"""

from cis_mapping import CIS_MAPPING


# ── CSF Subcategory catalogue ──────────────────────────────────────────────────
# (subcategory_id, subcategory_title, function_grouping)

_GV_OV = ("GV.OV-01", "Cybersecurity risk management strategy outcomes are reviewed", "GV — Govern")

_ID_AM = ("ID.AM-08", "Systems, hardware, software, services, and data are managed throughout their life cycles", "ID — Identify")
_ID_RA = ("ID.RA-01", "Vulnerabilities in assets are identified, validated, and recorded", "ID — Identify")

_PR_AA_IDENT = ("PR.AA-01", "Identities and credentials for authorized users, services, and hardware are managed", "PR — Protect")
_PR_AA_AUTH  = ("PR.AA-03", "Users, services, and hardware are authenticated", "PR — Protect")
_PR_AA_LEAST = ("PR.AA-05", "Access permissions, entitlements, and authorizations are managed incorporating least privilege and separation of duties", "PR — Protect")
_PR_DS_REST  = ("PR.DS-01", "The confidentiality, integrity, and availability of data-at-rest are protected", "PR — Protect")
_PR_DS_TRANS = ("PR.DS-02", "The confidentiality, integrity, and availability of data-in-transit are protected", "PR — Protect")
_PR_DS_BACK  = ("PR.DS-11", "Backups of data are created, protected, maintained, and tested", "PR — Protect")
_PR_IR_NET   = ("PR.IR-01", "Networks and environments are protected from unauthorized logical access and usage", "PR — Protect")
_PR_PS_LOG   = ("PR.PS-04", "Log records are generated and made available for continuous monitoring", "PR — Protect")
_PR_PS_PATCH = ("PR.PS-02", "Software is maintained, replaced, and removed commensurate with risk", "PR — Protect")
_PR_PS_SW    = ("PR.PS-05", "Installation and execution of unauthorized software are prevented", "PR — Protect")
_PR_PS_CFG   = ("PR.PS-01", "Configuration management practices are established and applied", "PR — Protect")

_DE_CM_MON   = ("DE.CM-09", "Computing hardware and software, runtime environments, and their data are monitored", "DE — Detect")
_DE_CM_NET   = ("DE.CM-01", "Networks and network services are monitored to find potentially adverse events", "DE — Detect")
_DE_AE_AN    = ("DE.AE-02", "Potentially adverse events are analyzed to better understand associated activities", "DE — Detect")

_RS_CO       = ("RS.CO-02", "Internal and external stakeholders are notified of incidents", "RS — Respond")


# Default CSF Subcategory per CIS section (used when no keyword rule matches).
_SECTION_DEFAULTS = {
    "1 — Identity and Access Management": _PR_AA_LEAST,
    "2.1 — Microsoft Defender for Cloud": _DE_CM_MON,
    "3 — Storage Accounts": _PR_DS_REST,
    "4 — Database Services": _PR_DS_REST,
    "5 — Logging and Monitoring": _PR_PS_LOG,
    "6 — Networking": _PR_IR_NET,
    "7 — Virtual Machines": _PR_PS_PATCH,
    "8 — Key Vault": _PR_DS_REST,
    "9 — AppService": _PR_PS_PATCH,
}

# Keyword rules, evaluated in order (most specific first). The first whose
# keyword appears in the lowercased recommendation name wins.
_KEYWORD_RULES = [
    # Authentication / MFA
    ("multi-factor", _PR_AA_AUTH),
    ("mfa ", _PR_AA_AUTH),
    ("managed identity", _PR_AA_IDENT),
    ("register with azure", _PR_AA_IDENT),
    ("active directory administrator", _PR_AA_IDENT),
    ("active directory admin", _PR_AA_IDENT),

    # Least-privilege / identity governance
    ("owner permissions", _PR_AA_LEAST),
    ("read permissions", _PR_AA_LEAST),
    ("write permissions", _PR_AA_LEAST),
    ("guest account", _PR_AA_LEAST),
    ("external account", _PR_AA_LEAST),
    ("deprecated account", _PR_AA_LEAST),
    ("owner assigned", _PR_AA_LEAST),
    ("owners should be designated", _PR_AA_LEAST),
    ("owners of the subscription", _PR_AA_LEAST),
    ("custom rbac", _PR_AA_LEAST),
    ("rbac permission model", _PR_AA_LEAST),
    ("local authentication", _PR_AA_LEAST),
    ("privileged", _PR_AA_LEAST),

    # Data-in-transit
    ("secure transfer", _PR_DS_TRANS),
    ("https", _PR_DS_TRANS),
    ("tls", _PR_DS_TRANS),
    ("ssl", _PR_DS_TRANS),
    ("ftps", _PR_DS_TRANS),
    ("secure socket", _PR_DS_TRANS),

    # Data-at-rest / encryption
    ("customer-managed key", _PR_DS_REST),
    ("customer managed key", _PR_DS_REST),
    ("transparent data encryption", _PR_DS_REST),
    ("infrastructure encryption", _PR_DS_REST),
    ("infrastructure double encryption", _PR_DS_REST),
    ("double encrypted", _PR_DS_REST),
    ("encrypt data at rest", _PR_DS_REST),
    ("encryption at rest", _PR_DS_REST),
    ("expiration date", _PR_DS_REST),

    # Backup / recoverability
    ("soft delete", _PR_DS_BACK),
    ("purge protection", _PR_DS_BACK),

    # Networking
    ("rdp access", _PR_IR_NET),
    ("ssh access", _PR_IR_NET),
    ("network watcher", _DE_CM_NET),
    ("firewall", _PR_IR_NET),
    ("private link", _PR_IR_NET),
    ("private endpoint", _PR_IR_NET),
    ("public network access", _PR_IR_NET),
    ("public access", _PR_IR_NET),
    ("restrict network", _PR_IR_NET),
    ("network access", _PR_IR_NET),
    ("flow log", _DE_CM_NET),

    # Endpoint / malware
    ("endpoint protection", _PR_PS_SW),

    # Vulnerability identification
    ("vulnerabilit", _ID_RA),
    ("security configuration", _PR_PS_CFG),

    # Patch / version maintenance
    ("system updates", _PR_PS_PATCH),
    ("missing system updates", _PR_PS_PATCH),
    ("check for missing", _PR_PS_PATCH),
    ("php version", _PR_PS_PATCH),
    ("python version", _PR_PS_PATCH),
    ("java version", _PR_PS_PATCH),
    ("http version", _PR_PS_PATCH),

    # Platform / configuration management
    ("managed disks", _PR_PS_CFG),
    ("vm extensions", _PR_PS_SW),
    ("approved extensions", _PR_PS_SW),

    # Defender plan enablement -> continuous monitoring capability
    ("defender for", _DE_CM_MON),
    ("azure defender", _DE_CM_MON),
    ("auto provisioning", _DE_CM_MON),
    ("auto-provisioning", _DE_CM_MON),
    ("periodically check", _DE_CM_MON),

    # Alerting / event analysis
    ("activity log alert", _DE_AE_AN),
    ("log alert", _DE_AE_AN),

    # Logging / audit trail
    ("activity log", _PR_PS_LOG),
    ("resource logs", _PR_PS_LOG),
    ("log profile", _PR_PS_LOG),
    ("log checkpoints", _PR_PS_LOG),
    ("log connections", _PR_PS_LOG),
    ("disconnections should be logged", _PR_PS_LOG),
    ("connection throttling", _PR_PS_LOG),
    ("audit retention", _PR_PS_LOG),
    ("audit profile", _PR_PS_LOG),
    ("security and audit", _PR_PS_LOG),
    ("logging for", _PR_PS_LOG),
    ("logs enabled", _PR_PS_LOG),

    # Incident notification
    ("contact email", _RS_CO),
    ("email notification", _RS_CO),
    ("security contact", _RS_CO),
    ("notify about alerts", _RS_CO),
]


def _derive_csf(name: str, cis_entry: dict):
    """Pick a CSF (id, title, function) for a recommendation name."""
    name_lower = name.lower()
    for keyword, csf in _KEYWORD_RULES:
        if keyword in name_lower:
            return csf
    return _SECTION_DEFAULTS.get(cis_entry.get("section"), _ID_AM)


def _build_mapping():
    mapping = {}
    for name, entry in CIS_MAPPING.items():
        csf_id, csf_title, csf_function = _derive_csf(name, entry)
        mapping[name] = {
            "cis_id": csf_id,
            "cis_title": csf_title,
            "section": csf_function,
            "level": csf_function.split(" ")[0],  # function code, e.g. "PR"
            "expected_value": entry.get("expected_value"),
            "current_value_if_fail": entry.get("current_value_if_fail"),
            "doc_url": entry.get("doc_url"),
        }
    return mapping


NIST_MAPPING = _build_mapping()


# ── Public interface (mirrors cis_mapping) ─────────────────────────────────────

def lookup_control(recommendation_name: str) -> dict:
    """
    Look up a NIST CSF Subcategory by MDC recommendation name.
    Case-insensitive. Tries exact match first, then partial match.
    Returns None if no mapping found.
    """
    name_lower = recommendation_name.lower().strip()

    if name_lower in NIST_MAPPING:
        return NIST_MAPPING[name_lower]

    for key, value in NIST_MAPPING.items():
        if key in name_lower or name_lower in key:
            return value

    return None


def enrich_recommendations(recommendations: list) -> list:
    """
    Adds NIST CSF mapping fields to each recommendation dict.
    Returns enriched list without mutating originals.
    """
    enriched = []
    for rec in recommendations:
        entry = dict(rec)
        mapping = lookup_control(rec.get("name", ""))
        if mapping:
            entry["cis_id"]                = mapping["cis_id"]
            entry["cis_title"]             = mapping["cis_title"]
            entry["cis_section"]           = mapping["section"]
            entry["cis_level"]             = mapping["level"]
            entry["expected_value"]        = mapping.get("expected_value")
            entry["current_value_if_fail"] = mapping.get("current_value_if_fail")
            entry["cis_doc_url"]           = mapping.get("doc_url")
        else:
            entry["cis_id"]                = None
            entry["cis_title"]             = None
            entry["cis_section"]           = "Unmapped"
            entry["cis_level"]             = None
            entry["expected_value"]        = None
            entry["current_value_if_fail"] = None
            entry["cis_doc_url"]           = None
        enriched.append(entry)
    return enriched


def get_section_summary(recommendations: list) -> dict:
    """
    Groups enriched recommendations by NIST CSF function.
    Returns {function_name: {"High": n, "Medium": n, "Low": n, "Unknown": n, "items": [...]}}
    """
    sections = {}
    for rec in recommendations:
        section = rec.get("cis_section", "Unmapped")
        if section not in sections:
            sections[section] = {"High": 0, "Medium": 0, "Low": 0, "Unknown": 0, "items": []}
        sev = rec.get("severity", "Unknown")
        if sev in ("High", "Medium", "Low"):
            sections[section][sev] += 1
        else:
            sections[section]["Unknown"] += 1
        sections[section]["items"].append(rec)
    return dict(sorted(sections.items()))
