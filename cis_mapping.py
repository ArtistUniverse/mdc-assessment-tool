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
        "section": "1 — Identity and Access Management", "level": "L1",
        "expected_value": "No permanent privileged access",
        "current_value_if_fail": "Permanent privileged access granted",
        "doc_url": "https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-deployment-plan",
    },
    "guest accounts with owner permissions on azure resources should be removed": {
        "cis_id": "1.5", "cis_title": "Ensure Guest Users Are Reviewed on a Regular Basis",
        "section": "1 — Identity and Access Management", "level": "L1",
        "expected_value": "No guest accounts with owner permissions",
        "current_value_if_fail": "Guest accounts have owner permissions",
        "doc_url": "https://learn.microsoft.com/en-us/entra/identity/users/clean-up-stale-guest-accounts",
    },
    "guest accounts with read permissions on azure resources should be removed": {
        "cis_id": "1.5", "cis_title": "Ensure Guest Users Are Reviewed on a Regular Basis",
        "section": "1 — Identity and Access Management", "level": "L1",
        "expected_value": "No guest accounts with read permissions",
        "current_value_if_fail": "Guest accounts have read permissions",
        "doc_url": "https://learn.microsoft.com/en-us/entra/identity/users/clean-up-stale-guest-accounts",
    },
    "guest accounts with write permissions on azure resources should be removed": {
        "cis_id": "1.5", "cis_title": "Ensure Guest Users Are Reviewed on a Regular Basis",
        "section": "1 — Identity and Access Management", "level": "L1",
        "expected_value": "No guest accounts with write permissions",
        "current_value_if_fail": "Guest accounts have write permissions",
        "doc_url": "https://learn.microsoft.com/en-us/entra/identity/users/clean-up-stale-guest-accounts",
    },
    "there should be more than one owner assigned to your subscription": {
        "cis_id": "1.14", "cis_title": "Ensure That There Are No More Than 3 Active Owners of the Subscription",
        "section": "1 — Identity and Access Management", "level": "L1",
        "expected_value": "≥ 2 owners assigned",
        "current_value_if_fail": "< 2 owners assigned",
        "doc_url": "https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal",
    },
    "a maximum of 3 owners should be designated for your subscription": {
        "cis_id": "1.15", "cis_title": "Ensure That There Are No More Than 3 Active Owners of the Subscription",
        "section": "1 — Identity and Access Management", "level": "L1",
        "expected_value": "≤ 3 owners assigned",
        "current_value_if_fail": "> 3 owners assigned",
        "doc_url": "https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal",
    },
    "mfa should be enabled on accounts with owner permissions on your subscription": {
        "cis_id": "1.1", "cis_title": "Ensure That Multi-Factor Authentication Is Enabled for All Privileged Users",
        "section": "1 — Identity and Access Management", "level": "L1",
        "expected_value": "MFA enabled",
        "current_value_if_fail": "MFA not enabled",
        "doc_url": "https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mandatory-multifactor-authentication",
    },
    "mfa should be enabled for accounts with write permissions on your subscription": {
        "cis_id": "1.2", "cis_title": "Ensure That Multi-Factor Authentication Is Enabled for All Non-Privileged Users",
        "section": "1 — Identity and Access Management", "level": "L1",
        "expected_value": "MFA enabled",
        "current_value_if_fail": "MFA not enabled",
        "doc_url": "https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mandatory-multifactor-authentication",
    },
    "mfa should be enabled on accounts with read permissions on your subscription": {
        "cis_id": "1.3", "cis_title": "Ensure That Multi-Factor Authentication Is Enabled for All Non-Privileged Users",
        "section": "1 — Identity and Access Management", "level": "L2",
        "expected_value": "MFA enabled",
        "current_value_if_fail": "MFA not enabled",
        "doc_url": "https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mandatory-multifactor-authentication",
    },
    "external accounts with owner permissions should be removed from your subscription": {
        "cis_id": "1.6", "cis_title": "Ensure That External Accounts With Owner Permissions Are Removed",
        "section": "1 — Identity and Access Management", "level": "L1",
        "expected_value": "No external accounts with owner permissions",
        "current_value_if_fail": "External accounts have owner permissions",
        "doc_url": "https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal",
    },
    "deprecated accounts should be removed from your subscription": {
        "cis_id": "1.9", "cis_title": "Ensure That Deprecated Accounts Are Removed From Your Subscription",
        "section": "1 — Identity and Access Management", "level": "L1",
        "expected_value": "No deprecated accounts",
        "current_value_if_fail": "Deprecated accounts present",
        "doc_url": "https://learn.microsoft.com/en-us/entra/identity/users/users-bulk-delete",
    },

    # Section 2.1 - Defender Plans
    "microsoft defender for servers should be enabled": {
        "cis_id": "2.1.1", "cis_title": "Ensure That Microsoft Defender for Servers Is Set to 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "On",
        "current_value_if_fail": "Off",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/tutorial-enable-servers-plan",
    },
    "azure defender for servers should be enabled": {
        "cis_id": "2.1.1", "cis_title": "Ensure That Microsoft Defender for Servers Is Set to 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "On",
        "current_value_if_fail": "Off",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/tutorial-enable-servers-plan",
    },
    "microsoft defender for app service should be enabled": {
        "cis_id": "2.1.2", "cis_title": "Ensure That Microsoft Defender for App Services Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "On",
        "current_value_if_fail": "Off",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-app-service-introduction",
    },
    "azure defender for app service should be enabled": {
        "cis_id": "2.1.2", "cis_title": "Ensure That Microsoft Defender for App Services Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "On",
        "current_value_if_fail": "Off",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-app-service-introduction",
    },
    "azure defender for azure sql database servers should be enabled": {
        "cis_id": "2.1.3", "cis_title": "Ensure That Microsoft Defender for Databases Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "On",
        "current_value_if_fail": "Off",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-databases-overview",
    },
    "azure defender for sql servers on machines should be enabled": {
        "cis_id": "2.1.3", "cis_title": "Ensure That Microsoft Defender for Databases Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "On",
        "current_value_if_fail": "Off",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-databases-overview",
    },
    "azure defender for open-source relational databases should be enabled": {
        "cis_id": "2.1.3", "cis_title": "Ensure That Microsoft Defender for Databases Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "On",
        "current_value_if_fail": "Off",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-databases-overview",
    },
    "microsoft defender for azure cosmos db should be enabled": {
        "cis_id": "2.1.3", "cis_title": "Ensure That Microsoft Defender for Databases Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "On",
        "current_value_if_fail": "Off",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-databases-overview",
    },
    "microsoft defender for storage should be enabled": {
        "cis_id": "2.1.4", "cis_title": "Ensure That Microsoft Defender for Storage Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "On",
        "current_value_if_fail": "Off",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-storage-introduction",
    },
    "microsoft defender for storage plan should be enabled": {
        "cis_id": "2.1.4", "cis_title": "Ensure That Microsoft Defender for Storage Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "On",
        "current_value_if_fail": "Off",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-storage-introduction",
    },
    "azure defender for storage should be enabled": {
        "cis_id": "2.1.4", "cis_title": "Ensure That Microsoft Defender for Storage Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "On",
        "current_value_if_fail": "Off",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-storage-introduction",
    },
    "microsoft defender for containers should be enabled": {
        "cis_id": "2.1.5", "cis_title": "Ensure That Microsoft Defender for Containers Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "On",
        "current_value_if_fail": "Off",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction",
    },
    "azure defender for kubernetes should be enabled": {
        "cis_id": "2.1.5", "cis_title": "Ensure That Microsoft Defender for Containers Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "On",
        "current_value_if_fail": "Off",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction",
    },
    "azure defender for container registries should be enabled": {
        "cis_id": "2.1.5", "cis_title": "Ensure That Microsoft Defender for Containers Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "On",
        "current_value_if_fail": "Off",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction",
    },
    "azure defender for key vault should be enabled": {
        "cis_id": "2.1.6", "cis_title": "Ensure That Microsoft Defender for Azure Key Vault Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "On",
        "current_value_if_fail": "Off",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-key-vault-introduction",
    },
    "microsoft defender for key vault should be enabled": {
        "cis_id": "2.1.6", "cis_title": "Ensure That Microsoft Defender for Azure Key Vault Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "On",
        "current_value_if_fail": "Off",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-key-vault-introduction",
    },
    "azure defender for dns should be enabled": {
        "cis_id": "2.1.7", "cis_title": "Ensure That Microsoft Defender for DNS Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "On",
        "current_value_if_fail": "Off",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-dns-introduction",
    },
    "microsoft defender for dns should be enabled": {
        "cis_id": "2.1.7", "cis_title": "Ensure That Microsoft Defender for DNS Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "On",
        "current_value_if_fail": "Off",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-dns-introduction",
    },
    "azure defender for resource manager should be enabled": {
        "cis_id": "2.1.8", "cis_title": "Ensure That Microsoft Defender for Resource Manager Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "On",
        "current_value_if_fail": "Off",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-resource-manager-introduction",
    },
    "microsoft defender for resource manager should be enabled": {
        "cis_id": "2.1.8", "cis_title": "Ensure That Microsoft Defender for Resource Manager Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "On",
        "current_value_if_fail": "Off",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-resource-manager-introduction",
    },
    "microsoft defender for apis should be enabled": {
        "cis_id": "2.1.9", "cis_title": "Ensure That Microsoft Defender for APIs Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "On",
        "current_value_if_fail": "Off",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-apis-introduction",
    },

    # Section 2.1 - MDC Configuration
    "machines should be configured to periodically check for missing system updates": {
        "cis_id": "2.1.13", "cis_title": "Ensure That Microsoft Defender Recommendation for 'Apply system updates' Is 'Completed'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "Configured",
        "current_value_if_fail": "Not configured",
        "doc_url": "https://learn.microsoft.com/en-us/azure/update-manager/overview",
    },
    "auto provisioning of the log analytics agent should be enabled": {
        "cis_id": "2.1.17", "cis_title": "Ensure That Auto Provisioning of Monitoring Components Is Set To 'On'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "On",
        "current_value_if_fail": "Off",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/monitoring-components",
    },
    "subscriptions should have a contact email address for security issues": {
        "cis_id": "2.1.19", "cis_title": "Ensure 'Additional email addresses' Is Configured With a Security Contact Email",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "Security contact configured",
        "current_value_if_fail": "No security contact configured",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications",
    },
    "email notification for high severity alerts should be enabled": {
        "cis_id": "2.1.20", "cis_title": "Ensure That 'Notify about alerts with the following severity' Is Set to 'High'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "Enabled",
        "current_value_if_fail": "Disabled",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications",
    },
    "email notification to subscription owner for high severity alerts should be enabled": {
        "cis_id": "2.1.20", "cis_title": "Ensure That 'Notify about alerts with the following severity' Is Set to 'High'",
        "section": "2.1 — Microsoft Defender for Cloud", "level": "L1",
        "expected_value": "Enabled",
        "current_value_if_fail": "Disabled",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications",
    },

    # Section 3 - Storage Accounts
    "secure transfer to storage accounts should be enabled": {
        "cis_id": "3.1", "cis_title": "Ensure That 'Secure transfer required' Is Set to 'Enabled'",
        "section": "3 — Storage Accounts", "level": "L1",
        "expected_value": "Enabled",
        "current_value_if_fail": "Disabled",
        "doc_url": "https://learn.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer",
    },
    "storage account public access should be disallowed": {
        "cis_id": "3.7", "cis_title": "Ensure That 'Public access level' Is Set to Private for Blob Containers",
        "section": "3 — Storage Accounts", "level": "L1",
        "expected_value": "Public access disallowed",
        "current_value_if_fail": "Public access allowed",
        "doc_url": "https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure",
    },
    "storage accounts should restrict network access": {
        "cis_id": "3.7", "cis_title": "Ensure That 'Public access level' Is Set to Private for Blob Containers",
        "section": "3 — Storage Accounts", "level": "L1",
        "expected_value": "Network access restricted",
        "current_value_if_fail": "Network access unrestricted",
        "doc_url": "https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security",
    },
    "storage accounts should use customer-managed key for encryption": {
        "cis_id": "3.9", "cis_title": "Ensure Storage for Critical Data Are Encrypted With Customer Managed Keys",
        "section": "3 — Storage Accounts", "level": "L2",
        "expected_value": "Customer-managed key",
        "current_value_if_fail": "Microsoft-managed key",
        "doc_url": "https://learn.microsoft.com/en-us/azure/storage/common/customer-managed-keys-overview",
    },

    # Section 4 - Database Services
    "sql servers should have an azure active directory administrator provisioned": {
        "cis_id": "4.1.4", "cis_title": "Ensure That Azure Active Directory Admin Is Configured for SQL Servers",
        "section": "4 — Database Services", "level": "L1",
        "expected_value": "Entra ID admin configured",
        "current_value_if_fail": "No Entra ID admin configured",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-configure",
    },
    "transparent data encryption on sql databases should be enabled": {
        "cis_id": "4.1.1", "cis_title": "Ensure That 'Encryption at Rest' Is Set to On",
        "section": "4 — Database Services", "level": "L1",
        "expected_value": "Enabled",
        "current_value_if_fail": "Disabled",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-tde-overview",
    },
    "sql server audit retention should be set to at least 90 days": {
        "cis_id": "4.1.6", "cis_title": "Ensure that 'Auditing' Retention Is 'Greater than 90 days'",
        "section": "4 — Database Services", "level": "L1",
        "expected_value": "≥ 90 days",
        "current_value_if_fail": "< 90 days",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-sql/database/auditing-setup",
    },

    # Section 5 - Logging and Monitoring
    "activity log should be retained for at least one year": {
        "cis_id": "5.1.2", "cis_title": "Ensure That Activity Retention Log Is Set To 'At Least One Year'",
        "section": "5 — Logging and Monitoring", "level": "L1",
        "expected_value": "≥ 365 days",
        "current_value_if_fail": "< 365 days",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log",
    },
    "an activity log alert should exist for create or update network security group": {
        "cis_id": "5.2.2", "cis_title": "Ensure That Activity Alerts Exist For Create or Update Network Security Group",
        "section": "5 — Logging and Monitoring", "level": "L1",
        "expected_value": "Alert configured",
        "current_value_if_fail": "No alert configured",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-create-activity-log-alert-rule",
    },
    "an activity log alert should exist for delete network security group": {
        "cis_id": "5.2.3", "cis_title": "Ensure That Activity Alerts Exist For Delete Network Security Group",
        "section": "5 — Logging and Monitoring", "level": "L1",
        "expected_value": "Alert configured",
        "current_value_if_fail": "No alert configured",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-create-activity-log-alert-rule",
    },
    "an activity log alert should exist for create or update network security group rule": {
        "cis_id": "5.2.4", "cis_title": "Ensure That Activity Alerts Exist For Create or Update Network Security Group Rule",
        "section": "5 — Logging and Monitoring", "level": "L1",
        "expected_value": "Alert configured",
        "current_value_if_fail": "No alert configured",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-create-activity-log-alert-rule",
    },
    "an activity log alert should exist for create or update sql server firewall rule": {
        "cis_id": "5.2.7", "cis_title": "Ensure That Activity Alerts Exist For Create or Update SQL Server Firewall Rule",
        "section": "5 — Logging and Monitoring", "level": "L1",
        "expected_value": "Alert configured",
        "current_value_if_fail": "No alert configured",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-create-activity-log-alert-rule",
    },
    "an activity log alert should exist for delete sql server firewall rule": {
        "cis_id": "5.2.8", "cis_title": "Ensure That Activity Alerts Exist For Delete SQL Server Firewall Rule",
        "section": "5 — Logging and Monitoring", "level": "L1",
        "expected_value": "Alert configured",
        "current_value_if_fail": "No alert configured",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-create-activity-log-alert-rule",
    },
    "azure subscriptions should have a log profile for activity log": {
        "cis_id": "5.1.1", "cis_title": "Ensure That a Diagnostic Setting Exists for Subscription Activity Logs",
        "section": "5 — Logging and Monitoring", "level": "L1",
        "expected_value": "Activity log profile configured",
        "current_value_if_fail": "No activity log profile",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log",
    },
    "azure monitor log profile should collect logs for categories 'write,' 'delete,' and 'action'": {
        "cis_id": "5.1.3", "cis_title": "Ensure Audit Profile Captures All the Activities",
        "section": "5 — Logging and Monitoring", "level": "L1",
        "expected_value": "write, delete, and action categories captured",
        "current_value_if_fail": "Not all activity categories captured",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log",
    },
    "azure monitor should collect activity logs from all regions": {
        "cis_id": "5.1.4", "cis_title": "Ensure That Activity Logs Are Collected From All Regions",
        "section": "5 — Logging and Monitoring", "level": "L1",
        "expected_value": "All regions including global selected",
        "current_value_if_fail": "Not all regions selected",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log",
    },
    "azure monitor solution 'security and audit' must be deployed": {
        "cis_id": "5.3.1", "cis_title": "Ensure That Security and Audit Solution Is Deployed",
        "section": "5 — Logging and Monitoring", "level": "L1",
        "expected_value": "Security and Audit solution deployed",
        "current_value_if_fail": "Security and Audit solution not deployed",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log",
    },
    "an activity log alert should exist for specific policy operations": {
        "cis_id": "5.2.1", "cis_title": "Ensure That Activity Log Alert Exists For Create Policy Assignment",
        "section": "5 — Logging and Monitoring", "level": "L1",
        "expected_value": "Alert configured for policy operations",
        "current_value_if_fail": "No alert for policy operations",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-create-activity-log-alert-rule",
    },
    "an activity log alert should exist for specific administrative operations": {
        "cis_id": "5.2.9", "cis_title": "Ensure That Activity Log Alert Exists For Administrative Operations",
        "section": "5 — Logging and Monitoring", "level": "L1",
        "expected_value": "Alert configured for administrative operations",
        "current_value_if_fail": "No alert for administrative operations",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-create-activity-log-alert-rule",
    },
    "an activity log alert should exist for specific security operations": {
        "cis_id": "5.2.6", "cis_title": "Ensure That Activity Log Alert Exists For Create or Update Security Solution",
        "section": "5 — Logging and Monitoring", "level": "L1",
        "expected_value": "Alert configured for security operations",
        "current_value_if_fail": "No alert for security operations",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-create-activity-log-alert-rule",
    },
    "an activity log alert should exist for the delete network security group rule": {
        "cis_id": "5.2.5", "cis_title": "Ensure That Activity Log Alert Exists For Delete Network Security Group Rule",
        "section": "5 — Logging and Monitoring", "level": "L1",
        "expected_value": "Alert configured",
        "current_value_if_fail": "No alert configured",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-create-activity-log-alert-rule",
    },

    # Section 6 - Networking
    "rdp access from the internet should be blocked": {
        "cis_id": "6.1", "cis_title": "Ensure That RDP Access From the Internet Is Evaluated and Restricted",
        "section": "6 — Networking", "level": "L1",
        "expected_value": "Blocked",
        "current_value_if_fail": "Allowed from internet",
        "doc_url": "https://learn.microsoft.com/en-us/azure/virtual-network/manage-network-security-group",
    },
    "ssh access from the internet should be blocked": {
        "cis_id": "6.2", "cis_title": "Ensure That SSH Access From the Internet Is Evaluated and Restricted",
        "section": "6 — Networking", "level": "L1",
        "expected_value": "Blocked",
        "current_value_if_fail": "Allowed from internet",
        "doc_url": "https://learn.microsoft.com/en-us/azure/virtual-network/manage-network-security-group",
    },
    "network watcher should be enabled": {
        "cis_id": "6.5", "cis_title": "Ensure That Network Watcher Is 'Enabled'",
        "section": "6 — Networking", "level": "L1",
        "expected_value": "Enabled",
        "current_value_if_fail": "Disabled",
        "doc_url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-create",
    },

    # Section 7 - Virtual Machines
    "endpoint protection should be installed on machines": {
        "cis_id": "7.6", "cis_title": "Ensure That Endpoint Protection Is Installed On Virtual Machines",
        "section": "7 — Virtual Machines", "level": "L1",
        "expected_value": "Installed",
        "current_value_if_fail": "Not installed",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/endpoint-protection-recommendations-technical",
    },
    "system updates should be installed on your machines": {
        "cis_id": "7.7", "cis_title": "Ensure That System Updates Are Applied To Machines",
        "section": "7 — Virtual Machines", "level": "L1",
        "expected_value": "Up to date",
        "current_value_if_fail": "Missing updates",
        "doc_url": "https://learn.microsoft.com/en-us/azure/update-manager/overview",
    },
    "vulnerabilities in security configuration on your machines should be remediated": {
        "cis_id": "7.8", "cis_title": "Ensure That Security Configurations Are Remediated",
        "section": "7 — Virtual Machines", "level": "L1",
        "expected_value": "No vulnerabilities",
        "current_value_if_fail": "Vulnerabilities present",
        "doc_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/apply-security-baseline",
    },

    # Section 8 - Key Vault
    "key vault should have purge protection enabled": {
        "cis_id": "8.5", "cis_title": "Ensure That Azure Key Vault Enables Purge Protection",
        "section": "8 — Key Vault", "level": "L1",
        "expected_value": "Enabled",
        "current_value_if_fail": "Disabled",
        "doc_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/key-vault-recovery",
    },
    "key vault should have soft delete enabled": {
        "cis_id": "8.4", "cis_title": "Ensure That Azure Key Vault Enables Soft Delete",
        "section": "8 — Key Vault", "level": "L1",
        "expected_value": "Enabled",
        "current_value_if_fail": "Disabled",
        "doc_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview",
    },
    "resource logs in key vault should be enabled": {
        "cis_id": "8.7", "cis_title": "Ensure That Logging for Azure Key Vault Is 'Enabled'",
        "section": "8 — Key Vault", "level": "L1",
        "expected_value": "Enabled",
        "current_value_if_fail": "Disabled",
        "doc_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/howto-logging",
    },

    # Section 9 - AppService
    "web application should only be accessible over https": {
        "cis_id": "9.1", "cis_title": "Ensure App Service Authentication Is Set Up For Apps in Azure App Service",
        "section": "9 — AppService", "level": "L1",
        "expected_value": "HTTPS only",
        "current_value_if_fail": "HTTP allowed",
        "doc_url": "https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-bindings#enforce-https",
    },
    "function app should only be accessible over https": {
        "cis_id": "9.1", "cis_title": "Ensure App Service Authentication Is Set Up For Apps in Azure App Service",
        "section": "9 — AppService", "level": "L1",
        "expected_value": "HTTPS only",
        "current_value_if_fail": "HTTP allowed",
        "doc_url": "https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-bindings#enforce-https",
    },
    "latest tls version should be used in your web app": {
        "cis_id": "9.3", "cis_title": "Ensure Web App Is Using the Latest Version of TLS Encryption",
        "section": "9 — AppService", "level": "L1",
        "expected_value": "TLS 1.2+",
        "current_value_if_fail": "Older TLS version in use",
        "doc_url": "https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-bindings#enforce-tls-versions",
    },
    "latest tls version should be used in your function app": {
        "cis_id": "9.3", "cis_title": "Ensure Web App Is Using the Latest Version of TLS Encryption",
        "section": "9 — AppService", "level": "L1",
        "expected_value": "TLS 1.2+",
        "current_value_if_fail": "Older TLS version in use",
        "doc_url": "https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-bindings#enforce-tls-versions",
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
            entry["cis_id"]               = mapping["cis_id"]
            entry["cis_title"]            = mapping["cis_title"]
            entry["cis_section"]          = mapping["section"]
            entry["cis_level"]            = mapping["level"]
            entry["expected_value"]       = mapping.get("expected_value")
            entry["current_value_if_fail"] = mapping.get("current_value_if_fail")
            entry["cis_doc_url"]          = mapping.get("doc_url")
        else:
            entry["cis_id"]               = None
            entry["cis_title"]            = None
            entry["cis_section"]          = "Unmapped"
            entry["cis_level"]            = None
            entry["expected_value"]       = None
            entry["current_value_if_fail"] = None
            entry["cis_doc_url"]          = None
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