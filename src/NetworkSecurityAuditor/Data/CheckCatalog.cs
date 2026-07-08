using System.Collections.Frozen;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Data;

/// <summary>
/// Static catalog of all 69 security checks with metadata, severity, compliance mappings, and auditor hints.
/// </summary>
public static class CheckCatalog
{
    private static FrozenDictionary<string, CheckMetadata>? s_checks;

    public static FrozenDictionary<string, CheckMetadata> All => s_checks ??= BuildCatalog();

    private static FrozenDictionary<string, CheckMetadata> BuildCatalog()
    {
        var checks = new Dictionary<string, CheckMetadata>(69, StringComparer.OrdinalIgnoreCase);

        // ── Identity & Access (IA01-IA12) ───────────────────────────────────
        Add(checks, new CheckMetadata
        {
            Id = "IA01",
            Category = "Identity & Access",
            Label = "Domain Admin account audit",
            Hint = "Document every account with DA/EA/Schema Admin privileges and business justification. Check for daily-driver accounts, service accounts, and former employees in privileged groups.",
            Severity = Severity.Critical,
            Weight = 10,
            Type = CheckType.AD,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-1, PR.AC-4, PR.AC-6 | CIS Control 5.1, 5.4, 5.5, 6.8 | HIPAA 164.312(a)(1), 164.312(a)(2)(i)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory"
        });

        Add(checks, new CheckMetadata
        {
            Id = "IA02",
            Category = "Identity & Access",
            Label = "Service account audit",
            Hint = "Verify service account password age, rotation policy, least privilege, and SPN exposure. Flag accounts with passwords unchanged since creation or with Domain Admin membership.",
            Severity = Severity.Critical,
            Weight = 10,
            Type = CheckType.AD,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-1, PR.AC-4 | CIS Control 5.2, 5.4, 5.5 | HIPAA 164.312(a)(1), 164.312(d)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts"
        });

        Add(checks, new CheckMetadata
        {
            Id = "IA03",
            Category = "Identity & Access",
            Label = "Local MFA/Strong Auth signals",
            Hint = "Collect host-visible strong-auth indicators for remote access paths (VPN, RDP, WHfB, smart card). Tenant-wide MFA proof requires Graph-backed cloud checks.",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.AD,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-7 | CIS Control 6.3, 6.4, 6.5 | HIPAA 164.312(d)",
            EvidenceMode = EvidenceMode.Heuristic,
            RemediationUrl = "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mfa-howitworks"
        });

        Add(checks, new CheckMetadata
        {
            Id = "IA04",
            Category = "Identity & Access",
            Label = "Stale account review",
            Hint = "Cross-reference active AD accounts against HR separation records from the past 12-24 months. Check Entra ID, M365 licenses, VPN, and cloud service accounts.",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.AD,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-1, PR.AC-6 | CIS Control 5.1, 5.3 | HIPAA 164.312(a)(2)(ii), 164.308(a)(3)(ii)(C)",
            EvidenceMode = EvidenceMode.InterviewRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/entra/identity/users/clean-up-stale-accounts"
        });

        Add(checks, new CheckMetadata
        {
            Id = "IA05",
            Category = "Identity & Access",
            Label = "Password policy audit",
            Hint = "Review default domain and fine-grained password policies. Check minimum length (12+), complexity, history (24), lockout threshold, and NIST 800-63B alignment.",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.AD,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-1, PR.AC-7 | CIS Control 5.2 | HIPAA 164.312(d), 164.308(a)(5)(ii)(D)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy"
        });

        Add(checks, new CheckMetadata
        {
            Id = "IA06",
            Category = "Identity & Access",
            Label = "PAM/Privileged Access",
            Hint = "Evaluate PAM tooling (CyberArk, BeyondTrust, Delinea), JIT elevation, credential vaulting, session recording, and Entra PIM configuration.",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.AD,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-4, PR.AC-6 | CIS Control 5.4, 5.5, 6.8 | HIPAA 164.312(a)(1)",
            EvidenceMode = EvidenceMode.Checklist,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview"
        });

        Add(checks, new CheckMetadata
        {
            Id = "IA07",
            Category = "Identity & Access",
            Label = "Shared/Generic accounts",
            Hint = "Inventory accounts used by multiple people (reception, scanner, warehouse). Shared accounts destroy accountability and should be replaced with individual accounts.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.AD,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-1, PR.AC-6 | CIS Control 5.1, 5.4 | HIPAA 164.312(a)(2)(i)",
            EvidenceMode = EvidenceMode.Heuristic,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory"
        });

        Add(checks, new CheckMetadata
        {
            Id = "IA08",
            Category = "Identity & Access",
            Label = "Guest/Vendor accounts",
            Hint = "Audit vendor/contractor accounts for expiration dates, limited group membership, recent usage, and documented sponsor. Check when the last vendor access review was performed.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.AD,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-1, PR.AC-3 | CIS Control 5.1, 5.3, 6.1 | HIPAA 164.308(a)(4)(ii)(B), 164.312(a)(1)",
            EvidenceMode = EvidenceMode.Heuristic,
            RemediationUrl = "https://learn.microsoft.com/en-us/entra/identity/users/clean-up-stale-accounts"
        });

        Add(checks, new CheckMetadata
        {
            Id = "IA09",
            Category = "Identity & Access",
            Label = "Remote access audit",
            Hint = "Inventory RDP, VPN, split-tunnel settings, remote-access agents, RMM tools, and unsigned portable remote-control binaries to identify exposed or unmanaged paths.",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.AD,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-3, PR.AC-7 | CIS Control 6.3, 6.4, 6.5 | HIPAA 164.312(d), 164.312(e)(1)",
            EvidenceMode = EvidenceMode.Heuristic,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access"
        });

        Add(checks, new CheckMetadata
        {
            Id = "IA10",
            Category = "Identity & Access",
            Label = "Inactive accounts",
            Hint = "Find enabled accounts with no login in 90+ days. These are prime attack targets because nobody notices unauthorized use of a forgotten account.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.AD,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-1, PR.AC-6 | CIS Control 5.3 | HIPAA 164.312(a)(2)(ii)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/entra/identity/users/clean-up-stale-accounts"
        });

        Add(checks, new CheckMetadata
        {
            Id = "IA11",
            Category = "Identity & Access",
            Label = "Kerberos encryption readiness",
            Hint = "Detect legacy RC4/DES encryption dependencies across service accounts, computer accounts, and trusts. Review msDS-SupportedEncryptionTypes and KDC events 201-209.",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.AD,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-1, PR.AC-7, PR.DS-2 | CIS Control 5.2, 6.7, 8.11 | HIPAA 164.312(a)(2)(i), 164.312(d), 164.312(e)(2)(ii)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-encryption-types"
        });

        Add(checks, new CheckMetadata
        {
            Id = "IA12",
            Category = "Identity & Access",
            Label = "dMSA/BadSuccessor exposure",
            Hint = "Review Windows Server 2025 DCs for dMSA objects, msDS-ManagedAccountPrecededByLink, OU ACLs for non-tier-0 principals with CreateChild/GenericAll rights. Apply CVE-2025-53779 updates.",
            Severity = Severity.Critical,
            Weight = 10,
            Type = CheckType.AD,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-1, PR.AC-4, PR.AC-6 | CIS Control 5.4, 6.8 | HIPAA 164.312(a)(1), 164.312(a)(2)(i)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview"
        });

        // ── Endpoint Security (EP01-EP10) ───────────────────────────────────
        Add(checks, new CheckMetadata
        {
            Id = "EP01",
            Category = "Endpoint Security",
            Label = "AV/EDR status",
            Hint = "Verify EDR/AV deployment coverage is 100% by comparing agent count against AD computer objects. Check agent health, definition age, and identify gaps (Linux, Macs, IoT).",
            Severity = Severity.Critical,
            Weight = 10,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF DE.CM-4, PR.DS-5 | CIS Control 10.1, 10.2 | HIPAA 164.308(a)(5)(ii)(B)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/defender-endpoint/next-generation-protection"
        });

        Add(checks, new CheckMetadata
        {
            Id = "EP02",
            Category = "Endpoint Security",
            Label = "BitLocker/encryption",
            Hint = "Verify BitLocker with XTS-AES 256 on all endpoints. Check AD for recovery keys and compare against total computer count. Unencrypted lost laptops are reportable breaches.",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.DS-1, PR.DS-5 | CIS Control 3.6 | HIPAA 164.312(a)(2)(iv), 164.312(e)(2)(ii)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/"
        });

        Add(checks, new CheckMetadata
        {
            Id = "EP03",
            Category = "Endpoint Security",
            Label = "SMB/NTLM hardening",
            Hint = "Verify SMBv1 disabled, SMB signing required, SMB encryption enabled, NTLM level 5, LLMNR disabled, and NetBIOS over TCP/IP disabled to prevent relay and poisoning attacks.",
            Severity = Severity.Critical,
            Weight = 10,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-5, PR.DS-2 | CIS Control 4.1, 4.8 | HIPAA 164.312(e)(1), 164.312(a)(1)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening"
        });

        Add(checks, new CheckMetadata
        {
            Id = "EP04",
            Category = "Endpoint Security",
            Label = "Patch compliance + CISA KEV",
            Hint = "Check patch management tool compliance reports. Prioritize internet-facing systems, CISA KEV actively exploited vulns, and third-party patching (Adobe, Java, Chrome, 7-Zip).",
            Severity = Severity.Critical,
            Weight = 10,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.IP-12, ID.RA-1 | CIS Control 7.1, 7.2, 7.3, 7.4 | HIPAA 164.308(a)(5)(ii)(B)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-overview"
        });

        Add(checks, new CheckMetadata
        {
            Id = "EP05",
            Category = "Endpoint Security",
            Label = "Local admin + privesc scan",
            Hint = "Check local Administrators group on sample workstations. Flag Domain Users or large groups in local admins. Recommend removal and self-service elevation tools.",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-4, PR.AC-6 | CIS Control 5.4, 5.5 | HIPAA 164.312(a)(1)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/"
        });

        Add(checks, new CheckMetadata
        {
            Id = "EP06",
            Category = "Endpoint Security",
            Label = "Host firewall + attack surface",
            Hint = "Verify Windows Firewall is enabled on all three profiles (Domain, Private, Public) and enforced via GPO. Review overly permissive inbound allow rules.",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-5, PR.PT-4 | CIS Control 4.4, 4.5 | HIPAA 164.312(e)(1)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/"
        });

        Add(checks, new CheckMetadata
        {
            Id = "EP07",
            Category = "Endpoint Security",
            Label = "Application control + macros",
            Hint = "Check for AppLocker, WDAC, or SRP configuration. At minimum, block execution from user-writable locations. Verify Office macro policies restrict unsigned/internet-sourced macros.",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.DS-5, PR.IP-1 | CIS Control 2.5, 2.6, 2.7 | HIPAA 164.312(a)(1)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/"
        });

        Add(checks, new CheckMetadata
        {
            Id = "EP08",
            Category = "Endpoint Security",
            Label = "Credential Guard/LSA",
            Hint = "Validate VBS, Credential Guard, LSA Protection (RunAsPPL), WDigest caching disabled, TPM 2.0, and Secure Boot. These are the primary defense against credential theft.",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-2, PR.PT-1 | CIS Control 1.1, 4.1, 10.5 | HIPAA 164.310(a)(1) | CMMC L2 SC.L2-3.13.11",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/"
        });

        Add(checks, new CheckMetadata
        {
            Id = "EP09",
            Category = "Endpoint Security",
            Label = "AutoRun/AutoPlay",
            Hint = "Verify AutoPlay is disabled for all drives via GPO and registry (NoDriveTypeAutoRun=255). AutoRun was a massive malware vector and must be explicitly disabled.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.PT-2 | CIS Control 10.3 | HIPAA 164.308(a)(5)(ii)(B)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/turn-off-autoplay"
        });

        Add(checks, new CheckMetadata
        {
            Id = "EP10",
            Category = "Endpoint Security",
            Label = "EOL operating systems",
            Hint = "Identify end-of-life OS (Win7, Server 2012 R2, etc.) from AD computer objects. Document hostname, purpose, migration blockers, and compensating controls for each.",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.AD,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.IP-12, ID.AM-2 | CIS Control 2.1, 2.2 | HIPAA 164.308(a)(5)(ii)(B)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/lifecycle/products/"
        });

        // ── Logging & Monitoring (LM01-LM08) ────────────────────────────────
        Add(checks, new CheckMetadata
        {
            Id = "LM01",
            Category = "Logging & Monitoring",
            Label = "DNS logging",
            Hint = "Verify DNS query logging is enabled and retained for at least 90 days. DNS logs are critical for incident response to identify C2 communication and compromised hosts.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF DE.CM-1, DE.AE-3 | CIS Control 8.2, 8.9 | HIPAA 164.312(b), 164.308(a)(1)(ii)(D)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging"
        });

        Add(checks, new CheckMetadata
        {
            Id = "LM02",
            Category = "Logging & Monitoring",
            Label = "SIEM/centralized logging",
            Hint = "Verify centralized log collection from DCs, firewalls, VPN, DNS, file servers, and EDR. Without central logging, the org is blind to security events and cannot perform IR.",
            Severity = Severity.Critical,
            Weight = 10,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF DE.CM-1, DE.CM-3, DE.AE-3 | CIS Control 8.2, 8.5, 8.9 | HIPAA 164.312(b), 164.308(a)(1)(ii)(D)",
            EvidenceMode = EvidenceMode.Heuristic,
            RemediationUrl = "https://learn.microsoft.com/en-us/azure/sentinel/overview"
        });

        Add(checks, new CheckMetadata
        {
            Id = "LM03",
            Category = "Logging & Monitoring",
            Label = "Audit policy + PS logging",
            Hint = "Verify Advanced Audit Policy for logon events (4624/4625), privilege use (4672), account management (4720/4726), log clearing (1102), and PowerShell ScriptBlock/Module logging.",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF DE.CM-1, DE.CM-3, DE.AE-3 | CIS Control 8.2, 8.5, 8.8 | HIPAA 164.312(b)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing"
        });

        Add(checks, new CheckMetadata
        {
            Id = "LM04",
            Category = "Logging & Monitoring",
            Label = "Firewall logging",
            Hint = "Verify firewall logging for both allowed and denied traffic, remote syslog storage, and retention of at least 90 days. Local-only logs can fill up and cover only days.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF DE.CM-1 | CIS Control 8.2, 8.5, 8.9 | HIPAA 164.312(b)",
            EvidenceMode = EvidenceMode.ExternalRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/"
        });

        Add(checks, new CheckMetadata
        {
            Id = "LM05",
            Category = "Logging & Monitoring",
            Label = "Failed logon monitoring",
            Hint = "Verify account lockout policy and alerting for brute-force patterns. Check Event ID 4740 on PDC emulator and SIEM rules for failed login thresholds.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF DE.CM-1, DE.AE-2 | CIS Control 8.5 | HIPAA 164.312(b), 164.308(a)(1)(ii)(D)",
            EvidenceMode = EvidenceMode.Heuristic,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625"
        });

        Add(checks, new CheckMetadata
        {
            Id = "LM06",
            Category = "Logging & Monitoring",
            Label = "File integrity monitoring",
            Hint = "Check for FIM coverage (Tripwire, OSSEC/Wazuh, EDR FIM) on critical system files, registry keys, scheduled tasks, and web server directories.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF DE.CM-1, DE.CM-5 | CIS Control 3.14 | HIPAA 164.312(b), 164.312(c)(2)",
            EvidenceMode = EvidenceMode.Checklist,
            RemediationUrl = "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"
        });

        Add(checks, new CheckMetadata
        {
            Id = "LM07",
            Category = "Logging & Monitoring",
            Label = "Log retention + sizes",
            Hint = "Verify actual log retention meets compliance minimums (HIPAA 6yr, PCI 1yr, insurance 90d). Check event log max sizes and overwrite settings across SIEM, firewall, and DCs.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF DE.CM-1, PR.PT-1 | CIS Control 8.1, 8.9, 8.10 | HIPAA 164.312(b), 164.530(j)(2)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing"
        });

        Add(checks, new CheckMetadata
        {
            Id = "LM08",
            Category = "Logging & Monitoring",
            Label = "Alerting configuration",
            Hint = "Verify security alerting for 24/7 coverage: who receives alerts, escalation path, IR retainer, and MDR service. If a critical alert fires at 2am Saturday, what happens?",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF DE.DP-4, RS.CO-2, RS.CO-3 | CIS Control 17.1, 17.2, 17.4 | HIPAA 164.308(a)(6)(i), 164.308(a)(6)(ii)",
            EvidenceMode = EvidenceMode.InterviewRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/azure/sentinel/create-analytics-rules"
        });

        // ── Network Architecture (NA01-NA07) ────────────────────────────────
        Add(checks, new CheckMetadata
        {
            Id = "NA01",
            Category = "Network Architecture",
            Label = "Network segmentation",
            Hint = "Test if workstations and servers are on the same subnet. A flat network lets a single compromised workstation reach every server immediately.",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-5 | CIS Control 12.2, 12.8 | HIPAA 164.312(e)(1)",
            EvidenceMode = EvidenceMode.Heuristic,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/networking/technologies/network-segmentation"
        });

        Add(checks, new CheckMetadata
        {
            Id = "NA02",
            Category = "Network Architecture",
            Label = "VLAN configuration",
            Hint = "Review core switch VLAN configuration for proper separation of users, servers, IoT, VoIP, and guest. Verify inter-VLAN firewall rules exist and are not allow-all.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-5 | CIS Control 12.2 | HIPAA 164.312(e)(1)",
            EvidenceMode = EvidenceMode.ExternalRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/networking/technologies/vrss/vrss-top"
        });

        Add(checks, new CheckMetadata
        {
            Id = "NA03",
            Category = "Network Architecture",
            Label = "Wireless security",
            Hint = "Verify WPA2/WPA3-Enterprise with RADIUS for corporate WiFi, strong PSK rotation for guest, rogue AP detection, and true guest isolation from internal networks.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-3, PR.AC-5 | CIS Control 12.6 | HIPAA 164.312(e)(1)",
            EvidenceMode = EvidenceMode.ExternalRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/networking/technologies/nps/nps-top"
        });

        Add(checks, new CheckMetadata
        {
            Id = "NA04",
            Category = "Network Architecture",
            Label = "Network documentation",
            Hint = "Request the network diagram and verify it is current, shows all VLANs/subnets, firewall placement, WAN connections, and matches the physical setup.",
            Severity = Severity.Low,
            Weight = 3,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF ID.AM-1, ID.AM-2, ID.AM-4 | CIS Control 1.1, 1.2, 12.1 | HIPAA 164.310(d)(2)(iii)",
            EvidenceMode = EvidenceMode.Checklist,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/networking/"
        });

        Add(checks, new CheckMetadata
        {
            Id = "NA05",
            Category = "Network Architecture",
            Label = "802.1X/NAC",
            Hint = "Check if 802.1X is configured on switch ports with RADIUS authentication. Verify failed-auth devices go to quarantine VLAN and unused ports are administratively disabled.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-1, PR.AC-3 | CIS Control 1.4, 12.5 | HIPAA 164.312(a)(1)",
            EvidenceMode = EvidenceMode.ExternalRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/networking/technologies/nps/nps-top"
        });

        Add(checks, new CheckMetadata
        {
            Id = "NA06",
            Category = "Network Architecture",
            Label = "Management interface isolation",
            Hint = "Verify switch/AP/firewall/IPMI management interfaces are on a dedicated management VLAN, not accessible from user networks, and use SSH/HTTPS not Telnet/HTTP.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-5, PR.PT-3 | CIS Control 12.2, 12.7 | HIPAA 164.312(e)(1)",
            EvidenceMode = EvidenceMode.ExternalRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/administration/server-manager/"
        });

        Add(checks, new CheckMetadata
        {
            Id = "NA07",
            Category = "Network Architecture",
            Label = "Guest network isolation",
            Hint = "Verify unused switch ports are disabled, port security limits MAC flooding, DHCP snooping and Dynamic ARP Inspection are enabled, and public-area jacks are on guest VLAN.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-5, PR.PT-4 | CIS Control 1.4, 12.2, 12.5 | HIPAA 164.312(e)(1)",
            EvidenceMode = EvidenceMode.ExternalRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/networking/technologies/nps/nps-top"
        });

        // ── Network Perimeter (NP01-NP10) ───────────────────────────────────
        Add(checks, new CheckMetadata
        {
            Id = "NP01",
            Category = "Network Perimeter",
            Label = "Firewall rules review",
            Hint = "Export the full rule list and search for any/any rules, rules with zero hit count in 90+ days, and rules older than 2 years. Every rule needs an owner and justification.",
            Severity = Severity.Critical,
            Weight = 10,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-5, PR.PT-4 | CIS Control 4.4, 4.5, 9.2 | HIPAA 164.312(e)(1)",
            EvidenceMode = EvidenceMode.ExternalRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/"
        });

        Add(checks, new CheckMetadata
        {
            Id = "NP02",
            Category = "Network Perimeter",
            Label = "Open ports audit",
            Hint = "Run external port scan and compare against documented port justification. Flag RDP (3389), SMB (445), Telnet (23), FTP (21), and database ports open to the internet.",
            Severity = Severity.Critical,
            Weight = 10,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-5, DE.CM-7 | CIS Control 4.1, 4.4, 9.2 | HIPAA 164.312(e)(1)",
            EvidenceMode = EvidenceMode.ExternalRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/"
        });

        Add(checks, new CheckMetadata
        {
            Id = "NP03",
            Category = "Network Perimeter",
            Label = "VPN configuration",
            Hint = "Check split tunneling policy, MFA requirement on VPN authentication, and verify the VPN authenticates against RADIUS/LDAP with a second factor.",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-3, PR.AC-7 | CIS Control 6.3, 6.4 | HIPAA 164.312(d), 164.312(e)(1)",
            EvidenceMode = EvidenceMode.ExternalRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/remote/remote-access/vpn/always-on-vpn/"
        });

        Add(checks, new CheckMetadata
        {
            Id = "NP04",
            Category = "Network Perimeter",
            Label = "DNS filtering",
            Hint = "Verify DNS filtering is active (Umbrella, NextDNS, pfBlockerNG) blocking malware/phishing/C2 domains. Test with known block-test domains and check if outbound port 53 is forced.",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.Local,
            RiskTier = RiskTier.Probing,
            Compliance = "NIST CSF PR.DS-5, DE.CM-1 | CIS Control 9.2, 9.3 | HIPAA 164.312(e)(1)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-overview"
        });

        Add(checks, new CheckMetadata
        {
            Id = "NP05",
            Category = "Network Perimeter",
            Label = "Egress filtering",
            Hint = "Check firewall outbound/egress rules. If a default Allow All outbound rule exists with no restrictions, flag it. At minimum, restrict outbound to ports 80/443 plus documented needs.",
            Severity = Severity.High,
            Weight = 8,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-5, PR.DS-5, DE.CM-1 | CIS Control 4.4, 4.5, 9.3 | HIPAA 164.312(e)(1)",
            EvidenceMode = EvidenceMode.ExternalRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/"
        });

        Add(checks, new CheckMetadata
        {
            Id = "NP06",
            Category = "Network Perimeter",
            Label = "Temporary firewall rules",
            Hint = "Search for rules with temp/test/old/vendor/person-name descriptions. Temporary rules from vendor access or troubleshooting are the top source of forgotten attack surface.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-5 | CIS Control 4.5 | HIPAA 164.312(e)(1)",
            EvidenceMode = EvidenceMode.ExternalRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/"
        });

        Add(checks, new CheckMetadata
        {
            Id = "NP07",
            Category = "Network Perimeter",
            Label = "IDS/IPS signatures",
            Hint = "Verify IDS/IPS is enabled (not just licensed), signatures are updated daily/weekly, mode is PREVENT not just DETECT, and alerts are actively reviewed.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF DE.CM-1, DE.DP-2 | CIS Control 13.3, 13.6 | HIPAA 164.312(e)(1)",
            EvidenceMode = EvidenceMode.ExternalRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/"
        });

        Add(checks, new CheckMetadata
        {
            Id = "NP08",
            Category = "Network Perimeter",
            Label = "SSL/TLS inspection",
            Hint = "Check if the firewall decrypts and inspects HTTPS traffic. Document exclusions (banking, healthcare) and employee awareness. Many SMBs will not have this.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF DE.CM-1 | CIS Control 9.3, 13.3 | HIPAA 164.312(e)(1)",
            EvidenceMode = EvidenceMode.ExternalRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings"
        });

        Add(checks, new CheckMetadata
        {
            Id = "NP09",
            Category = "Network Perimeter",
            Label = "NAT/port forward audit",
            Hint = "Review all port forwarding rules. Document each forward: external port, internal IP, purpose. Flag RDP forwards, workstation forwards, and forwards to EOL systems.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-5 | CIS Control 4.1, 4.4 | HIPAA 164.312(e)(1)",
            EvidenceMode = EvidenceMode.ExternalRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh"
        });

        Add(checks, new CheckMetadata
        {
            Id = "NP10",
            Category = "Network Perimeter",
            Label = "Firmware currency",
            Hint = "Check firmware version of all perimeter devices against vendor current/recommended. Look for known CVEs affecting running versions and flag end-of-life firmware.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.IP-12, ID.RA-1 | CIS Control 2.1, 7.1 | HIPAA 164.312(a)(1)",
            EvidenceMode = EvidenceMode.ExternalRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-overview"
        });

        // ── Backup & Recovery (BR01-BR08) ───────────────────────────────────
        Add(checks, new CheckMetadata
        {
            Id = "BR01",
            Category = "Backup & Recovery",
            Label = "Backup solution",
            Hint = "Verify 3-2-1 rule: 3 copies, 2 media types, 1 offsite. Check backup software config (Veeam, Datto, Acronis) and confirm offsite is a different physical location or cloud target.",
            Severity = Severity.Critical,
            Weight = 10,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.IP-4 | CIS Control 11.1, 11.2, 11.3 | HIPAA 164.308(a)(7)(ii)(A), 164.310(d)(2)(iv)",
            EvidenceMode = EvidenceMode.Heuristic,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/administration/windows-server-backup/windows-server-backup-overview"
        });

        Add(checks, new CheckMetadata
        {
            Id = "BR02",
            Category = "Backup & Recovery",
            Label = "Offsite/immutable backups",
            Hint = "Verify air-gapped or immutable backup copies exist for ransomware protection. If a ransomware operator gets Domain Admin, can they destroy every backup? If yes, this is critical.",
            Severity = Severity.Critical,
            Weight = 10,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.IP-4 | CIS Control 11.3, 11.4 | HIPAA 164.308(a)(7)(ii)(A)",
            EvidenceMode = EvidenceMode.ExternalRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/azure/backup/backup-overview"
        });

        Add(checks, new CheckMetadata
        {
            Id = "BR03",
            Category = "Backup & Recovery",
            Label = "Restore testing",
            Hint = "Ask when the last actual restore test was performed (not backup verification). A backup that has never been tested is not a backup. Recommend quarterly restore tests.",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.IP-4, PR.IP-9 | CIS Control 11.4, 11.5 | HIPAA 164.308(a)(7)(ii)(D)",
            EvidenceMode = EvidenceMode.InterviewRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/azure/backup/backup-azure-restore-windows-server"
        });

        Add(checks, new CheckMetadata
        {
            Id = "BR04",
            Category = "Backup & Recovery",
            Label = "RTO/RPO documentation",
            Hint = "Verify RTO/RPO are defined and business stakeholders are aware. Check if backup frequency actually meets the stated RPO and restore time meets the stated RTO.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF ID.BE-5, PR.IP-9, RC.RP-1 | CIS Control 11.1 | HIPAA 164.308(a)(7)(ii)(B)",
            EvidenceMode = EvidenceMode.InterviewRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/azure/backup/backup-overview"
        });

        Add(checks, new CheckMetadata
        {
            Id = "BR05",
            Category = "Backup & Recovery",
            Label = "Backup encryption",
            Hint = "Verify backup data is encrypted at rest (AES-256) and in transit (TLS). Check where encryption keys are stored (not only on the backup server itself).",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.DS-1, PR.DS-2 | CIS Control 3.6, 3.10 | HIPAA 164.312(a)(2)(iv), 164.312(e)(2)(ii)",
            EvidenceMode = EvidenceMode.ExternalRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/azure/backup/backup-encryption"
        });

        Add(checks, new CheckMetadata
        {
            Id = "BR06",
            Category = "Backup & Recovery",
            Label = "Backup monitoring",
            Hint = "Check backup console for recent failures, verify automated alerting is configured, and confirm someone reviews alerts daily. Silent backup failures for months is a common finding.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF DE.CM-3, DE.DP-4 | CIS Control 11.2 | HIPAA 164.308(a)(7)(ii)(A)",
            EvidenceMode = EvidenceMode.ExternalRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/azure/backup/backup-azure-monitoring-built-in-monitor"
        });

        Add(checks, new CheckMetadata
        {
            Id = "BR07",
            Category = "Backup & Recovery",
            Label = "DR plan",
            Hint = "Request the DR plan document and verify it contains contact list, system priority, step-by-step procedures, RTO/RPO, alternate site plan, and has been tabletop-tested in 12 months.",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.IP-9, RC.RP-1, RC.IM-1 | CIS Control 11.5 | HIPAA 164.308(a)(7)(i), 164.308(a)(7)(ii)(B-D)",
            EvidenceMode = EvidenceMode.Checklist,
            RemediationUrl = "https://learn.microsoft.com/en-us/azure/site-recovery/site-recovery-overview"
        });

        Add(checks, new CheckMetadata
        {
            Id = "BR08",
            Category = "Backup & Recovery",
            Label = "SaaS backup",
            Hint = "Verify third-party backup of M365/Google Workspace data. Microsoft provides infrastructure resilience, not data backup. Check Exchange, OneDrive, SharePoint, Teams coverage.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.IP-4 | CIS Control 11.1, 11.2 | HIPAA 164.308(a)(7)(ii)(A), 164.310(d)(2)(iv)",
            EvidenceMode = EvidenceMode.ExternalRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-overview"
        });

        // ── Common Findings (CF01-CF08) ─────────────────────────────────────
        Add(checks, new CheckMetadata
        {
            Id = "CF01",
            Category = "Common Findings",
            Label = "DA service accounts + ADCS",
            Hint = "Finding #1 across SMB audits: service accounts with DA privileges and weak/old passwords. Check for Kerberoastable SPNs. Recommend gMSA and 25+ character random passwords.",
            Severity = Severity.Critical,
            Weight = 10,
            Type = CheckType.AD,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-1, PR.AC-4 | CIS Control 5.2, 5.4, 5.5 | HIPAA 164.312(a)(1), 164.312(d)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory"
        });

        Add(checks, new CheckMetadata
        {
            Id = "CF02",
            Category = "Common Findings",
            Label = "Egress filtering test",
            Hint = "Verify firewall blocks ALL outbound by default and only allows documented ports. A single Allow All outbound rule lets malware C2 use any port to call home.",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.Local,
            RiskTier = RiskTier.Probing,
            Compliance = "NIST CSF PR.AC-5, PR.DS-5 | CIS Control 4.4, 4.5, 9.3 | HIPAA 164.312(e)(1)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/"
        });

        Add(checks, new CheckMetadata
        {
            Id = "CF03",
            Category = "Common Findings",
            Label = "Security awareness training",
            Hint = "Ask when the last security awareness training was conducted, what it covered, and whether phishing simulations are run. If the answer is never, flag it.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AT-1, PR.AT-2 | CIS Control 14.1, 14.2 | HIPAA 164.308(a)(5)(i), 164.308(a)(5)(ii)(A)",
            EvidenceMode = EvidenceMode.InterviewRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/security/adoption/security-awareness-training"
        });

        Add(checks, new CheckMetadata
        {
            Id = "CF04",
            Category = "Common Findings",
            Label = "Former employee access",
            Hint = "Cross-reference HR termination list against AD, Entra ID, M365, VPN, and cloud services. 20-50% of former employees typically still have active accounts.",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.AD,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-1, PR.AC-6 | CIS Control 5.1, 5.3 | HIPAA 164.308(a)(3)(ii)(C), 164.312(a)(2)(ii)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/entra/identity/users/clean-up-stale-accounts"
        });

        Add(checks, new CheckMetadata
        {
            Id = "CF05",
            Category = "Common Findings",
            Label = "Open shares audit",
            Hint = "Scan for open file shares with excessive permissions (Everyone, Authenticated Users). Document each share, its permissions, and whether access is appropriate for the data classification.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-5, ID.AM-4 | CIS Control 4.5 | HIPAA 164.312(e)(1)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening"
        });

        Add(checks, new CheckMetadata
        {
            Id = "CF06",
            Category = "Common Findings",
            Label = "Network flatness",
            Hint = "Test if workstations can directly ping DCs, file servers, SQL servers, cameras, and printers. If all are on the same subnet with no firewall hops, the network is flat.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-5 | CIS Control 12.2, 12.8 | HIPAA 164.312(e)(1)",
            EvidenceMode = EvidenceMode.Heuristic,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/networking/technologies/network-segmentation"
        });

        Add(checks, new CheckMetadata
        {
            Id = "CF07",
            Category = "Common Findings",
            Label = "Local admin rights",
            Hint = "Check local Administrators group on sample workstations. If Domain Users or large groups are members, every user is a local admin enabling malware and credential theft.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AC-4, PR.AC-6 | CIS Control 5.4, 5.5 | HIPAA 164.312(a)(1)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/"
        });

        Add(checks, new CheckMetadata
        {
            Id = "CF08",
            Category = "Common Findings",
            Label = "DNS filtering test",
            Hint = "Test DNS resolution from a workstation. If ISP DNS or unfiltered public resolvers are used, there is no DNS filtering. Recommend Umbrella, NextDNS, or Cloudflare Gateway.",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.Local,
            RiskTier = RiskTier.Probing,
            Compliance = "NIST CSF DE.CM-1, PR.DS-5 | CIS Control 9.2, 9.3 | HIPAA 164.312(e)(1)",
            EvidenceMode = EvidenceMode.Automated,
            RemediationUrl = "https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-overview"
        });

        // ── Policies & Standards (PS01-PS06) ────────────────────────────────
        Add(checks, new CheckMetadata
        {
            Id = "PS01",
            Category = "Policies & Standards",
            Label = "Security policies",
            Hint = "Request the information security policy document. Verify it covers access control, data classification, acceptable use, incident response, and has been reviewed within 12 months.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF ID.GV-1, ID.GV-3 | CIS Control 1.1 | HIPAA 164.308(a)(1)(i), 164.308(a)(1)(ii)(A), 164.316(b)(1)",
            EvidenceMode = EvidenceMode.Checklist,
            RemediationUrl = "https://learn.microsoft.com/en-us/security/adoption/security-policy"
        });

        Add(checks, new CheckMetadata
        {
            Id = "PS02",
            Category = "Policies & Standards",
            Label = "Acceptable use policy",
            Hint = "Verify an AUP exists, is signed by all employees, covers personal device use, social media, and data handling. Check when it was last updated and if new hires sign it.",
            Severity = Severity.Low,
            Weight = 3,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF ID.GV-1, PR.AT-1 | CIS Control 1.1 | HIPAA 164.308(a)(5)(i), 164.316(b)(1)",
            EvidenceMode = EvidenceMode.Checklist,
            RemediationUrl = "https://learn.microsoft.com/en-us/security/adoption/security-policy"
        });

        Add(checks, new CheckMetadata
        {
            Id = "PS03",
            Category = "Policies & Standards",
            Label = "Incident response plan",
            Hint = "Request the IR plan. Verify it includes contact/call tree, escalation paths, containment procedures, evidence preservation, communication plan, and has been tabletop-tested.",
            Severity = Severity.High,
            Weight = 7,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF RS.RP-1, RS.CO-1, RC.RP-1 | CIS Control 17.1, 17.4 | HIPAA 164.308(a)(6)(i), 164.308(a)(6)(ii), 164.316(b)(1)",
            EvidenceMode = EvidenceMode.Checklist,
            RemediationUrl = "https://learn.microsoft.com/en-us/security/adoption/incident-response-overview"
        });

        Add(checks, new CheckMetadata
        {
            Id = "PS04",
            Category = "Policies & Standards",
            Label = "Compliance monitoring",
            Hint = "Verify ongoing compliance monitoring processes exist for applicable frameworks (HIPAA, PCI, SOC2). Check for regular internal audits, gap assessments, and remediation tracking.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF ID.GV-3, DE.CM-1, DE.DP-4 | CIS Control 5.2 | HIPAA 164.308(a)(1)(ii)(D), 164.316(b)(2)(iii)",
            EvidenceMode = EvidenceMode.Checklist,
            RemediationUrl = "https://learn.microsoft.com/en-us/security/adoption/security-policy"
        });

        Add(checks, new CheckMetadata
        {
            Id = "PS05",
            Category = "Policies & Standards",
            Label = "Risk assessment",
            Hint = "Verify a formal risk assessment has been completed within the past 12 months identifying threats, vulnerabilities, likelihood, and impact with documented risk treatment decisions.",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF ID.RA-1, ID.RA-4, ID.RM-1 | CIS Control 1.4, 12.5 | HIPAA 164.308(a)(1)(ii)(A), 164.308(a)(1)(ii)(B)",
            EvidenceMode = EvidenceMode.InterviewRequired,
            RemediationUrl = "https://learn.microsoft.com/en-us/security/adoption/risk-management"
        });

        Add(checks, new CheckMetadata
        {
            Id = "PS06",
            Category = "Policies & Standards",
            Label = "Security training",
            Hint = "Verify role-based security training is provided to all staff, with additional training for privileged users. Check completion records and training frequency (at least annual).",
            Severity = Severity.Medium,
            Weight = 5,
            Type = CheckType.Local,
            RiskTier = RiskTier.ReadOnly,
            Compliance = "NIST CSF PR.AT-1, PR.AT-2 | CIS Control 14.1, 14.2 | HIPAA 164.308(a)(5)(i), 164.308(a)(5)(ii)(A)",
            EvidenceMode = EvidenceMode.Checklist,
            RemediationUrl = "https://learn.microsoft.com/en-us/security/adoption/security-awareness-training"
        });

        return ApplyCisBenchmarks(checks).ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);
    }

    private static Dictionary<string, CheckMetadata> ApplyCisBenchmarks(Dictionary<string, CheckMetadata> checks)
    {
        var cisWindowsBenchmark = BenchmarkMetadata.CisWindowsCatalogLabel;
        var cisControlsBenchmark = BenchmarkMetadata.CisControlsCatalogLabel;

        foreach (var (id, meta) in checks.ToList())
        {
            if (meta.CisBenchmark is not null) continue;

            var benchmark = id switch
            {
                "EP01" or "EP02" or "EP03" or "EP04" or "EP05" or "EP06" or "EP07" or "EP08" or "EP09" or "EP10"
                    => cisWindowsBenchmark,
                "LM03" or "LM04" or "LM05" or "LM07"
                    => cisWindowsBenchmark,
                _ when meta.Compliance.Contains("CIS Control")
                    => cisControlsBenchmark,
                _ => null
            };

            if (benchmark is not null)
            {
                checks[id] = new CheckMetadata
                {
                    Id = meta.Id, Category = meta.Category, Label = meta.Label, Hint = meta.Hint,
                    Severity = meta.Severity, Weight = meta.Weight, Type = meta.Type, RiskTier = meta.RiskTier,
                    Compliance = meta.Compliance, EvidenceMode = meta.EvidenceMode, RemediationUrl = meta.RemediationUrl,
                    CisImplementationGroup = meta.CisImplementationGroup, CisBenchmark = benchmark
                };
            }
        }
        return checks;
    }

    private static void Add(Dictionary<string, CheckMetadata> dict, CheckMetadata meta)
    {
        dict.Add(meta.Id, meta);
    }

    /// <summary>Returns all check IDs for a given category name.</summary>
    public static IEnumerable<string> IdsByCategory(string category) =>
        All.Values.Where(m => m.Category.Equals(category, StringComparison.OrdinalIgnoreCase))
                  .Select(m => m.Id)
                  .Order();

    /// <summary>Returns the ordered list of distinct category names.</summary>
    public static IReadOnlyList<string> Categories { get; } = new[]
    {
        "Identity & Access",
        "Endpoint Security",
        "Logging & Monitoring",
        "Network Architecture",
        "Network Perimeter",
        "Backup & Recovery",
        "Common Findings",
        "Policies & Standards"
    };
}
