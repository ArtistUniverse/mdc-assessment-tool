"""
frameworks.py
Compliance Framework Selector
------------------------------
Provides a single entry point — get_framework(name) — that returns a Framework
adapter exposing a uniform interface regardless of the underlying mapping
module:

    framework.lookup_control(name)          -> dict | None
    framework.enrich_recommendations(list)  -> list
    framework.get_section_summary(list)     -> dict
    framework.name                          -> "cis" | "nist" | "none"
    framework.label                         -> human-readable framework name
    framework.control_label                 -> column/label for control IDs

Supported frameworks:
    cis   - CIS Microsoft Azure Foundations Benchmark v2.0.0 (default)
    nist  - NIST Cybersecurity Framework (CSF) 2.0
    none  - raw MDC output, no framework mapping

To add a new framework, create a module exposing lookup_control,
enrich_recommendations, and get_section_summary (see cis_mapping.py as the
reference), then register it in _FRAMEWORKS below.
"""

SUPPORTED_FRAMEWORKS = ("cis", "nist", "none")


class Framework:
    """Adapter wrapping a mapping module behind a uniform interface."""

    def __init__(self, name, label, control_label,
                 lookup_control, enrich_recommendations, get_section_summary):
        self.name = name
        self.label = label
        self.control_label = control_label
        self.lookup_control = lookup_control
        self.enrich_recommendations = enrich_recommendations
        self.get_section_summary = get_section_summary


# ── "none" framework — passthrough with no control mapping ──────────────────────

def _none_lookup_control(recommendation_name: str):
    return None


def _none_enrich_recommendations(recommendations: list) -> list:
    enriched = []
    for rec in recommendations:
        entry = dict(rec)
        entry["cis_id"]                = None
        entry["cis_title"]             = None
        entry["cis_section"]           = "Unmapped"
        entry["cis_level"]             = None
        entry.setdefault("expected_value", None)
        entry.setdefault("current_value_if_fail", None)
        entry["cis_doc_url"]           = None
        enriched.append(entry)
    return enriched


def _none_get_section_summary(recommendations: list) -> dict:
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


def get_framework(name: str = "cis") -> Framework:
    """
    Return a Framework adapter for the requested framework name.
    Falls back to CIS if the name is unrecognised.
    """
    key = (name or "cis").lower().strip()

    if key == "nist":
        import nist_mapping as m
        return Framework(
            name="nist",
            label="NIST Cybersecurity Framework (CSF) 2.0",
            control_label="NIST CSF",
            lookup_control=m.lookup_control,
            enrich_recommendations=m.enrich_recommendations,
            get_section_summary=m.get_section_summary,
        )

    if key == "none":
        return Framework(
            name="none",
            label="No framework mapping (raw MDC output)",
            control_label="Control",
            lookup_control=_none_lookup_control,
            enrich_recommendations=_none_enrich_recommendations,
            get_section_summary=_none_get_section_summary,
        )

    # Default: CIS
    import cis_mapping as m
    return Framework(
        name="cis",
        label="CIS Azure Foundations Benchmark v2.0.0",
        control_label="CIS ID",
        lookup_control=m.lookup_control,
        enrich_recommendations=m.enrich_recommendations,
        get_section_summary=m.get_section_summary,
    )
