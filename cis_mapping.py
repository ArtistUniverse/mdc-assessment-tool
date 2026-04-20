"""
cis_mapping.py
CIS Microsoft Azure Foundations Benchmark v2.0.0 — MDC Recommendation Mapping
------------------------------------------------------------------------------
Maps MDC assessment recommendation display names to their corresponding
CIS Azure Foundations Benchmark control IDs and section titles.

Source: Microsoft Learn — CIS Azure Foundations Benchmark 2.0.0
https://learn.microsoft.com/en-us/azure/governance/policy/samples/cis-azure-2-0-0
"""

CIS_MAPPING = {

    # Section 1 - Identity and Access Management
    "privileged roles should not have permanent access at the subscription and resource group level": {
        "cis_id": "1.21", "cis_title": "Ensure That 'Restrict access to Azure AD administration portal' Is Set to 'Yes'",
        "section": "1 — Identity and Access Management", "level": "L1"
    },
    "guest accounts with owner permissions on azure resources should be removed": {
        "cis_id": "1.5", "cis_title": "Ensure Guest Users Are Reviewed on a Regular Basis",
        "section": "1 — Identity and Access Management", "level": "L1"
    },
    "guest accounts with read permissions on azure resources should be removed": {
        "cis_id": "1.5", "cis_title": "Ensure Guest Users Are Reviewed on a Regular Basis",
        "section": "1 — Identity and Access Management", "level": "L1"
    },
    "guest accounts with write permissions on azure resources should be removed": {
        "cis_id": "1.5", "cis_title": "Ensure Guest Users Are Reviewed on a Regular Basis",
        "section": "1 — Identity and Access Management", "level": "L1"
    },
    "there should be more than one owner assigned to your subscription": {
        "cis_id": "1.14", "cis_title": "Ensure That There Are No More Than 3 Active Owners of the Subscription",
        "section": "1 — Identity and Access Management", "level": "L1"
    },
    "a maximum of 3 owners should be designated for your subscription": {
        "cis_id": "1.15", "cis_title": "Ensure That There Are No More Than 3 Active Owners of the Subscription",
        "section": "1 — Identity and Access Management", "level": "L1"
    },
    "mfa should be enabled on accounts with owner permissions on your subscription": {
        "cis_id": "1.1", "cis_title": "Ensure That Multi-Factor Authentication Is Enabled for All Privileged Users",
        "section": "1 — Identity and Access Management", "level": "L1"
    },
    "mfa should be enabled for accounts with write permissions on your subscription": {
        "cis_id": "1.2", "cis_title": "Ensure That Multi-Factor Authentication Is Enabled for All Non-Privileged Users",
        "section": "1 — Identity and Access Management", "level": "L1"
    },
    "mfa should be enabled on accounts with read permissions on your subscription": {
        "cis_id": "1.3", "cis_title": "Ensure That Multi-Factor Authentication Is Enabled for All Non-Privileged Users",
        "section": "1 — Identity and Access Management", "level": "L2"
    },
    "external accounts with owner permissions should be removed from your subscription": {
        "cis_id": "1.6", "cis_title": "Ensure That External Accounts With Owner Permissions Are Removed",
        "section": "1 — Identity and Access Management", "level": "L1"
    },
    "deprecated accounts should be removed from your subscription": {
        "cis_id": "1.9", "cis_title": "Ensure That Deprecated Accounts Are Removed From Your Subscription",
        "section": "1 — Identity and Access Management", "level": "L1"
    },

    # Section 2.1 - Defender Plans
    "microsoft defender for servers should be enabled": {
        "cis_id": "2.1.1", "cis_title": "Ensure That Microsoft Defender for Servers Is Set to 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "azure defender for servers should be enabled": {
        "cis_id": "2.1.1", "cis_title": "Ensure That Microsoft Defender for Servers Is Set to 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "microsoft defender for app service should be enabled": {
        "cis_id": "2.1.2", "cis_title": "Ensure That Microsoft Defender for App Services Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "azure defender for app service should be enabled": {
        "cis_id": "2.1.2", "cis_title": "Ensure That Microsoft Defender for App Services Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "azure defender for azure sql database servers should be enabled": {
        "cis_id": "2.1.3", "cis_title": "Ensure That Microsoft Defender for Databases Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "azure defender for sql servers on machines should be enabled": {
        "cis_id": "2.1.3", "cis_title": "Ensure That Microsoft Defender for Databases Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "azure defender for open-source relational databases should be enabled": {
        "cis_id": "2.1.3", "cis_title": "Ensure That Microsoft Defender for Databases Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "microsoft defender for azure cosmos db should be enabled": {
        "cis_id": "2.1.3", "cis_title": "Ensure That Microsoft Defender for Databases Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "microsoft defender for storage should be enabled": {
        "cis_id": "2.1.4", "cis_title": "Ensure That Microsoft Defender for Storage Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "microsoft defender for storage plan should be enabled": {
        "cis_id": "2.1.4", "cis_title": "Ensure That Microsoft Defender for Storage Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "azure defender for storage should be enabled": {
        "cis_id": "2.1.4", "cis_title": "Ensure That Microsoft Defender for Storage Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "microsoft defender for containers should be enabled": {
        "cis_id": "2.1.5", "cis_title": "Ensure That Microsoft Defender for Containers Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "azure defender for kubernetes should be enabled": {
        "cis_id": "2.1.5", "cis_title": "Ensure That Microsoft Defender for Containers Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "azure defender for container registries should be enabled": {
        "cis_id": "2.1.5", "cis_title": "Ensure That Microsoft Defender for Containers Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "azure defender for key vault should be enabled": {
        "cis_id": "2.1.6", "cis_title": "Ensure That Microsoft Defender for Azure Key Vault Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "microsoft defender for key vault should be enabled": {
        "cis_id": "2.1.6", "cis_title": "Ensure That Microsoft Defender for Azure Key Vault Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "azure defender for dns should be enabled": {
        "cis_id": "2.1.7", "cis_title": "Ensure That Microsoft Defender for DNS Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "microsoft defender for dns should be enabled": {
        "cis_id": "2.1.7", "cis_title": "Ensure That Microsoft Defender for DNS Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "azure defender for resource manager should be enabled": {
        "cis_id": "2.1.8", "cis_title": "Ensure That Microsoft Defender for Resource Manager Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "microsoft defender for resource manager should be enabled": {
        "cis_id": "2.1.8", "cis_title": "Ensure That Microsoft Defender for Resource Manager Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "microsoft defender for apis should be enabled": {
        "cis_id": "2.1.9", "cis_title": "Ensure That Microsoft Defender for APIs Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },

    # Section 2.1 - MDC Configuration
    "machines should be configured to periodically check for missing system updates": {
        "cis_id": "2.1.13", "cis_title": "Ensure That Microsoft Defender Recommendation for 'Apply system updates' Is 'Completed'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "auto provisioning of the log analytics agent should be enabled": {
        "cis_id": "2.1.17", "cis_title": "Ensure That Auto Provisioning of Monitoring Components Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "subscriptions should have a contact email address for security issues": {
        "cis_id": "2.1.19", "cis_title": "Ensure 'Additional email addresses' Is Configured With a Security Contact Email",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "email notification for high severity alerts should be enabled": {
        "cis_id": "2.1.20", "cis_title": "Ensure That 'Notify about alerts with the following severity' Is Set to 'High'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },
    "email notification to subscription owner for high severity alerts should be enabled": {
        "cis_id": "2.1.20", "cis_title": "Ensure That 'Notify about alerts with the following severity' Is Set to 'High'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1"
    },

    # Section 3 - Storage Accounts
    "secure transfer to storage accounts should be enabled": {
        "cis_id": "3.1", "cis_title": "Ensure That 'Secure transfer required' Is Set to 'Enabled'",
        "section": "3 — Storage Accounts", "level": "L1"
    },
    "storage account public access should be disallowed": {
        "cis_id": "3.7", "cis_title": "Ensure That 'Public access level' Is Set to Private for Blob Containers",
        "section": "3 — Storage Accounts", "level": "L1"
    },
    "storage accounts should restrict network access": {
        "cis_id": "3.7", "cis_title": "Ensure That 'Public access level' Is Set to Private for Blob Containers",
        "section": "3 — Storage Accounts", "level": "L1"
    },
    "storage accounts should use customer-managed key for encryption": {
        "cis_id": "3.9", "cis_title": "Ensure Storage for Critical Data Are Encrypted With Customer Managed Keys",
        "section": "3 — Storage Accounts", "level": "L2"
    },

    # Section 4 - Database Services
    "sql servers should have an azure active directory administrator provisioned": {
        "cis_id": "4.1.4", "cis_title": "Ensure That Azure Active Directory Admin Is Configured for SQL Servers",
        "section": "4 — Database Services", "level": "L1"
    },
    "transparent data encryption on sql databases should be enabled": {
        "cis_id": "4.1.1", "cis_title": "Ensure That 'Encryption at Rest' Is Set to On",
        "section": "4 — Database Services", "level": "L1"
    },
    "sql server audit retention should be set to at least 90 days": {
        "cis_id": "4.1.6", "cis_title": "Ensure that 'Auditing' Retention Is 'Greater than 90 days'",
        "section": "4 — Database Services", "level": "L1"
    },

    # Section 5 - Logging and Monitoring
    "activity log should be retained for at least one year": {
        "cis_id": "5.1.2", "cis_title": "Ensure That Activity Retention Log Is Set To 'At Least One Year'",
        "section": "5 — Logging and Monitoring", "level": "L1"
    },
    "an activity log alert should exist for create or update network security group": {
        "cis_id": "5.2.2", "cis_title": "Ensure That Activity Alerts Exist For Create or Update Network Security Group",
        "section": "5 — Logging and Monitoring", "level": "L1"
    },
    "an activity log alert should exist for delete network security group": {
        "cis_id": "5.2.3", "cis_title": "Ensure That Activity Alerts Exist For Delete Network Security Group",
        "section": "5 — Logging and Monitoring", "level": "L1"
    },
    "an activity log alert should exist for create or update network security group rule": {
        "cis_id": "5.2.4", "cis_title": "Ensure That Activity Alerts Exist For Create or Update Network Security Group Rule",
        "section": "5 — Logging and Monitoring", "level": "L1"
    },
    "an activity log alert should exist for create or update sql server firewall rule": {
        "cis_id": "5.2.7", "cis_title": "Ensure That Activity Alerts Exist For Create or Update SQL Server Firewall Rule",
        "section": "5 — Logging and Monitoring", "level": "L1"
    },
    "an activity log alert should exist for delete sql server firewall rule": {
        "cis_id": "5.2.8", "cis_title": "Ensure That Activity Alerts Exist For Delete SQL Server Firewall Rule",
        "section": "5 — Logging and Monitoring", "level": "L1"
    },

    # Section 6 - Networking
    "rdp access from the internet should be blocked": {
        "cis_id": "6.1", "cis_title": "Ensure That RDP Access From the Internet Is Evaluated and Restricted",
        "section": "6 — Networking", "level": "L1"
    },
    "ssh access from the internet should be blocked": {
        "cis_id": "6.2", "cis_title": "Ensure That SSH Access From the Internet Is Evaluated and Restricted",
        "section": "6 — Networking", "level": "L1"
    },
    "network watcher should be enabled": {
        "cis_id": "6.5", "cis_title": "Ensure That Network Watcher Is 'Enabled'",
        "section": "6 — Networking", "level": "L1"
    },

    # Section 7 - Virtual Machines
    "endpoint protection should be installed on machines": {
        "cis_id": "7.6", "cis_title": "Ensure That Endpoint Protection Is Installed On Virtual Machines",
        "section": "7 — Virtual Machines", "level": "L1"
    },
    "system updates should be installed on your machines": {
        "cis_id": "7.7", "cis_title": "Ensure That System Updates Are Applied To Machines",
        "section": "7 — Virtual Machines", "level": "L1"
    },
    "vulnerabilities in security configuration on your machines should be remediated": {
        "cis_id": "7.8", "cis_title": "Ensure That Security Configurations Are Remediated",
        "section": "7 — Virtual Machines", "level": "L1"
    },

    # Section 8 - Key Vault
    "key vault should have purge protection enabled": {
        "cis_id": "8.5", "cis_title": "Ensure That Azure Key Vault Enables Purge Protection",
        "section": "8 — Key Vault", "level": "L1"
    },
    "key vault should have soft delete enabled": {
        "cis_id": "8.4", "cis_title": "Ensure That Azure Key Vault Enables Soft Delete",
        "section": "8 — Key Vault", "level": "L1"
    },
    "resource logs in key vault should be enabled": {
        "cis_id": "8.7", "cis_title": "Ensure That Logging for Azure Key Vault Is 'Enabled'",
        "section": "8 — Key Vault", "level": "L1"
    },

    # Section 9 - AppService
    "web application should only be accessible over https": {
        "cis_id": "9.1", "cis_title": "Ensure App Service Authentication Is Set Up For Apps in Azure App Service",
        "section": "9 — AppService", "level": "L1"
    },
    "function app should only be accessible over https": {
        "cis_id": "9.1", "cis_title": "Ensure App Service Authentication Is Set Up For Apps in Azure App Service",
        "section": "9 — AppService", "level": "L1"
    },
    "latest tls version should be used in your web app": {
        "cis_id": "9.3", "cis_title": "Ensure Web App Is Using the Latest Version of TLS Encryption",
        "section": "9 — AppService", "level": "L1"
    },
    "latest tls version should be used in your function app": {
        "cis_id": "9.3", "cis_title": "Ensure Web App Is Using the Latest Version of TLS Encryption",
        "section": "9 — AppService", "level": "L1"
    },
}


def lookup_control(recommendation_name: str) -> dict:
    """
    Look up a CIS control by MDC recommendation name.
    Case-insensitive. Tries exact match first, then partial match.
    Returns None if no mapping found.
    """
    name_lower = recommendation_name.lower().strip()

    if name_lower in CIS_MAPPING:
        return CIS_MAPPING[name_lower]

    for key, value in CIS_MAPPING.items():
        if key in name_lower or name_lower in key:
            return value

    return None


def enrich_recommendations(recommendations: list) -> list:
    """
    Adds CIS mapping fields to each recommendation dict.
    Returns enriched list without mutating originals.
    """
    enriched = []
    for rec in recommendations:
        entry = dict(rec)
        mapping = lookup_control(rec.get("name", ""))
        if mapping:
            entry["cis_id"]      = mapping["cis_id"]
            entry["cis_title"]   = mapping["cis_title"]
            entry["cis_section"] = mapping["section"]
            entry["cis_level"]   = mapping["level"]
        else:
            entry["cis_id"]      = None
            entry["cis_title"]   = None
            entry["cis_section"] = "Unmapped"
            entry["cis_level"]   = None
        enriched.append(entry)
    return enriched


def get_section_summary(recommendations: list) -> dict:
    """
    Groups enriched recommendations by CIS section.
    Returns {section_name: {"High": n, "Medium": n, "Low": n, "Unknown": n, "items": [...]}}
    Counting is done here so the display layer never has to re-derive it.
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