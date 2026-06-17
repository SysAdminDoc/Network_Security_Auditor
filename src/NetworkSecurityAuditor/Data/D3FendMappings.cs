using System.Collections.Frozen;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Data;

/// <summary>
/// MITRE D3FEND countermeasure mappings for all 69 security checks.
/// Maps each check ID to defensive stages, techniques, labels, and descriptions.
/// </summary>
public static class D3FendMappings
{
    private static FrozenDictionary<string, DefendMapping>? s_mappings;

    public static FrozenDictionary<string, DefendMapping> All => s_mappings ??= BuildMappings();

    private static FrozenDictionary<string, DefendMapping> BuildMappings()
    {
        var mappings = new Dictionary<string, DefendMapping>(StringComparer.OrdinalIgnoreCase)
        {
            // ── Identity & Access ──────────────────────────────────────────
            ["IA01"] = new DefendMapping
            {
                Stages = ["Model", "Isolate"],
                Techniques = ["D3-AM", "D3F-UGPH", "D3-UAP"],
                Labels = ["Access Modeling", "User Group Permissions", "User Account Permissions"],
                Description = "Models and restricts privileged identities"
            },
            ["IA02"] = new DefendMapping
            {
                Stages = ["Harden"],
                Techniques = ["D3-CH", "D3-CRO", "D3-PR"],
                Labels = ["Credential Hardening", "Credential Rotation", "Password Rotation"],
                Description = "Hardens service-account credentials"
            },
            ["IA03"] = new DefendMapping
            {
                Stages = ["Harden", "Isolate"],
                Techniques = ["D3-MFA", "D3-CTS"],
                Labels = ["Multi-factor Authentication", "Credential Transmission Scoping"],
                Description = "Requires stronger authentication"
            },
            ["IA04"] = new DefendMapping
            {
                Stages = ["Model", "Evict"],
                Techniques = ["D3-AM", "D3-AL", "D3-APTS"],
                Labels = ["Access Modeling", "Account Locking", "Account Provisioning/Termination"],
                Description = "Identifies and removes stale account risk"
            },
            ["IA05"] = new DefendMapping
            {
                Stages = ["Harden"],
                Techniques = ["D3-CH", "D3-SPP", "D3-PR"],
                Labels = ["Credential Hardening", "Strong Password Policy", "Password Rotation"],
                Description = "Enforces credential complexity requirements"
            },
            ["IA06"] = new DefendMapping
            {
                Stages = ["Harden", "Isolate"],
                Techniques = ["D3-CH", "D3-CTS", "D3-UAP"],
                Labels = ["Credential Hardening", "Credential Transmission Scoping", "User Account Permissions"],
                Description = "Implements just-in-time privilege and credential vaulting"
            },
            ["IA07"] = new DefendMapping
            {
                Stages = ["Model", "Harden"],
                Techniques = ["D3-AM", "D3-UAP"],
                Labels = ["Access Modeling", "User Account Permissions"],
                Description = "Ensures individual accountability through unique accounts"
            },
            ["IA08"] = new DefendMapping
            {
                Stages = ["Isolate", "Harden"],
                Techniques = ["D3-CTS", "D3-UAP", "D3-CRO"],
                Labels = ["Credential Transmission Scoping", "User Account Permissions", "Credential Rotation"],
                Description = "Scopes and rotates vendor access credentials"
            },
            ["IA09"] = new DefendMapping
            {
                Stages = ["Harden", "Isolate"],
                Techniques = ["D3-MFA", "D3-CTS", "D3-NTF"],
                Labels = ["Multi-factor Authentication", "Credential Transmission Scoping", "Network Traffic Filtering"],
                Description = "Restricts remote access to managed devices"
            },
            ["IA10"] = new DefendMapping
            {
                Stages = ["Model", "Evict"],
                Techniques = ["D3-AM", "D3-APTS"],
                Labels = ["Access Modeling", "Account Provisioning/Termination"],
                Description = "Discovers and deactivates inactive accounts"
            },
            ["IA11"] = new DefendMapping
            {
                Stages = ["Harden"],
                Techniques = ["D3-CH", "D3-MENCR"],
                Labels = ["Credential Hardening", "Message Encryption"],
                Description = "Enforces AES Kerberos encryption to prevent ticket cracking"
            },
            ["IA12"] = new DefendMapping
            {
                Stages = ["Harden", "Isolate"],
                Techniques = ["D3-CH", "D3-UAP", "D3-AM"],
                Labels = ["Credential Hardening", "User Account Permissions", "Access Modeling"],
                Description = "Prevents dMSA delegation abuse through access controls"
            },

            // ── Endpoint Security ──────────────────────────────────────────
            ["EP01"] = new DefendMapping
            {
                Stages = ["Detect", "Harden"],
                Techniques = ["D3-PM", "D3-OSM", "D3-PH"],
                Labels = ["Platform Monitoring", "Operating System Monitoring", "Platform Hardening"],
                Description = "Validates endpoint protection"
            },
            ["EP02"] = new DefendMapping
            {
                Stages = ["Harden"],
                Techniques = ["D3-DENCR", "D3-PH"],
                Labels = ["Disk Encryption", "Platform Hardening"],
                Description = "Enforces data-at-rest encryption"
            },
            ["EP03"] = new DefendMapping
            {
                Stages = ["Harden", "Isolate"],
                Techniques = ["D3-CH", "D3-NTF", "D3-MENCR"],
                Labels = ["Credential Hardening", "Network Traffic Filtering", "Message Encryption"],
                Description = "Hardens SMB/NTLM/LLMNR"
            },
            ["EP04"] = new DefendMapping
            {
                Stages = ["Harden"],
                Techniques = ["D3-SU", "D3-PH"],
                Labels = ["Software Update", "Platform Hardening"],
                Description = "Ensures timely patching of known vulnerabilities"
            },
            ["EP05"] = new DefendMapping
            {
                Stages = ["Harden", "Detect"],
                Techniques = ["D3-PH", "D3-FCR", "D3-SBV"],
                Labels = ["Platform Hardening", "File Creation Restriction", "Service Binary Verification"],
                Description = "Prevents local privilege escalation via service misconfigs"
            },
            ["EP06"] = new DefendMapping
            {
                Stages = ["Isolate", "Detect"],
                Techniques = ["D3-NTF", "D3-IOPR", "D3-NM"],
                Labels = ["Network Traffic Filtering", "Inbound/Outbound Port Restriction", "Network Monitoring"],
                Description = "Enforces host-based firewall policy"
            },
            ["EP07"] = new DefendMapping
            {
                Stages = ["Harden"],
                Techniques = ["D3-EAL", "D3-PH"],
                Labels = ["Executable Allowlisting", "Platform Hardening"],
                Description = "Restricts execution to approved applications"
            },
            ["EP08"] = new DefendMapping
            {
                Stages = ["Harden", "Detect"],
                Techniques = ["D3-CH", "D3-PM", "D3-PH"],
                Labels = ["Credential Hardening", "Platform Monitoring", "Platform Hardening"],
                Description = "Protects credentials in memory via Credential Guard"
            },
            ["EP09"] = new DefendMapping
            {
                Stages = ["Harden"],
                Techniques = ["D3-PH", "D3-FCR"],
                Labels = ["Platform Hardening", "File Creation Restriction"],
                Description = "Disables AutoRun to block autoplay malware"
            },
            ["EP10"] = new DefendMapping
            {
                Stages = ["Harden", "Isolate"],
                Techniques = ["D3-PH", "D3-IOPR"],
                Labels = ["Platform Hardening", "Inbound/Outbound Port Restriction"],
                Description = "Controls removable media access"
            },

            // ── Logging & Monitoring ───────────────────────────────────────
            ["LM01"] = new DefendMapping
            {
                Stages = ["Detect"],
                Techniques = ["D3-SFA", "D3-OSM"],
                Labels = ["System File Analysis", "Operating System Monitoring"],
                Description = "Configures comprehensive audit policy"
            },
            ["LM02"] = new DefendMapping
            {
                Stages = ["Detect"],
                Techniques = ["D3-NM", "D3-PM", "D3-SIEM"],
                Labels = ["Network Monitoring", "Platform Monitoring", "SIEM Event Correlation"],
                Description = "Centralizes log collection and correlation"
            },
            ["LM03"] = new DefendMapping
            {
                Stages = ["Detect"],
                Techniques = ["D3-PSA", "D3-PM"],
                Labels = ["Process Spawn Analysis", "Platform Monitoring"],
                Description = "Enables PowerShell script block and module logging"
            },
            ["LM04"] = new DefendMapping
            {
                Stages = ["Detect"],
                Techniques = ["D3-NM", "D3-NTF"],
                Labels = ["Network Monitoring", "Network Traffic Filtering"],
                Description = "Captures firewall traffic for analysis"
            },
            ["LM05"] = new DefendMapping
            {
                Stages = ["Harden", "Detect"],
                Techniques = ["D3-DENCR", "D3-FV"],
                Labels = ["Disk Encryption", "File Verification"],
                Description = "Protects log integrity against tampering"
            },
            ["LM06"] = new DefendMapping
            {
                Stages = ["Detect"],
                Techniques = ["D3-FV", "D3-PM"],
                Labels = ["File Verification", "Platform Monitoring"],
                Description = "Implements scheduled log review processes"
            },
            ["LM07"] = new DefendMapping
            {
                Stages = ["Detect"],
                Techniques = ["D3-PM", "D3-OSM"],
                Labels = ["Platform Monitoring", "Operating System Monitoring"],
                Description = "Ensures adequate log retention capacity"
            },
            ["LM08"] = new DefendMapping
            {
                Stages = ["Detect"],
                Techniques = ["D3-NM", "D3-PM"],
                Labels = ["Network Monitoring", "Platform Monitoring"],
                Description = "Configures automated alerting on security events"
            },

            // ── Network Architecture ───────────────────────────────────────
            ["NA01"] = new DefendMapping
            {
                Stages = ["Isolate"],
                Techniques = ["D3-NI", "D3-NTF"],
                Labels = ["Network Isolation", "Network Traffic Filtering"],
                Description = "Segments flat networks into security zones"
            },
            ["NA02"] = new DefendMapping
            {
                Stages = ["Isolate"],
                Techniques = ["D3-NI", "D3-NTF"],
                Labels = ["Network Isolation", "Network Traffic Filtering"],
                Description = "Isolates high-value assets from general network"
            },
            ["NA03"] = new DefendMapping
            {
                Stages = ["Isolate"],
                Techniques = ["D3-NI", "D3-NTF", "D3-IOPR"],
                Labels = ["Network Isolation", "Network Traffic Filtering", "Inbound/Outbound Port Restriction"],
                Description = "Establishes DMZ for public-facing services"
            },
            ["NA04"] = new DefendMapping
            {
                Stages = ["Isolate"],
                Techniques = ["D3-NI", "D3-WF"],
                Labels = ["Network Isolation", "Wireless Filtering"],
                Description = "Separates wireless traffic from internal networks"
            },
            ["NA05"] = new DefendMapping
            {
                Stages = ["Isolate", "Harden"],
                Techniques = ["D3-NI", "D3-NTF", "D3-MFA"],
                Labels = ["Network Isolation", "Network Traffic Filtering", "Multi-factor Authentication"],
                Description = "Segments VPN access to authorized resources only"
            },
            ["NA06"] = new DefendMapping
            {
                Stages = ["Detect"],
                Techniques = ["D3-NM", "D3-NTAD"],
                Labels = ["Network Monitoring", "Network Traffic Anomaly Detection"],
                Description = "Deploys IDS to detect lateral movement"
            },
            ["NA07"] = new DefendMapping
            {
                Stages = ["Isolate", "Detect"],
                Techniques = ["D3-DNSDL", "D3-NTF"],
                Labels = ["DNS Denylisting", "Network Traffic Filtering"],
                Description = "Filters DNS to block C2 and exfiltration channels"
            },

            // ── Network Perimeter ──────────────────────────────────────────
            ["NP01"] = new DefendMapping
            {
                Stages = ["Isolate"],
                Techniques = ["D3-NTF", "D3-IOPR"],
                Labels = ["Network Traffic Filtering", "Inbound/Outbound Port Restriction"],
                Description = "Tightens firewall rule sets"
            },
            ["NP02"] = new DefendMapping
            {
                Stages = ["Detect", "Isolate"],
                Techniques = ["D3-NM", "D3-IOPR"],
                Labels = ["Network Monitoring", "Inbound/Outbound Port Restriction"],
                Description = "Identifies and closes unnecessary open ports"
            },
            ["NP03"] = new DefendMapping
            {
                Stages = ["Isolate", "Harden"],
                Techniques = ["D3-IOPR", "D3-MFA", "D3-NTF"],
                Labels = ["Inbound/Outbound Port Restriction", "Multi-factor Authentication", "Network Traffic Filtering"],
                Description = "Restricts RDP exposure and requires strong authentication"
            },
            ["NP04"] = new DefendMapping
            {
                Stages = ["Isolate", "Detect"],
                Techniques = ["D3-NTF", "D3-HTSA"],
                Labels = ["Network Traffic Filtering", "HTTP Session Analysis"],
                Description = "Deploys WAF to protect web applications"
            },
            ["NP05"] = new DefendMapping
            {
                Stages = ["Isolate"],
                Techniques = ["D3-NTF", "D3-IOPR"],
                Labels = ["Network Traffic Filtering", "Inbound/Outbound Port Restriction"],
                Description = "Tightens ACLs to least-privilege access"
            },
            ["NP06"] = new DefendMapping
            {
                Stages = ["Detect", "Isolate"],
                Techniques = ["D3-MENCR", "D3-NTF"],
                Labels = ["Message Encryption", "Network Traffic Filtering"],
                Description = "Inspects encrypted traffic for C2 indicators"
            },
            ["NP07"] = new DefendMapping
            {
                Stages = ["Detect"],
                Techniques = ["D3-NM", "D3-NTAD"],
                Labels = ["Network Monitoring", "Network Traffic Anomaly Detection"],
                Description = "Deploys IDS/IPS for perimeter defense"
            },
            ["NP08"] = new DefendMapping
            {
                Stages = ["Harden"],
                Techniques = ["D3-MENCR", "D3-CH"],
                Labels = ["Message Encryption", "Credential Hardening"],
                Description = "Enforces strong TLS configuration"
            },
            ["NP09"] = new DefendMapping
            {
                Stages = ["Isolate"],
                Techniques = ["D3-NTF", "D3-IOPR"],
                Labels = ["Network Traffic Filtering", "Inbound/Outbound Port Restriction"],
                Description = "Removes unnecessary NAT and port forwarding rules"
            },
            ["NP10"] = new DefendMapping
            {
                Stages = ["Harden"],
                Techniques = ["D3-SU", "D3-PH"],
                Labels = ["Software Update", "Platform Hardening"],
                Description = "Keeps perimeter device firmware current"
            },

            // ── Backup & Recovery ──────────────────────────────────────────
            ["BR01"] = new DefendMapping
            {
                Stages = ["Harden"],
                Techniques = ["D3-BA", "D3-PH"],
                Labels = ["Backup", "Platform Hardening"],
                Description = "Establishes regular backup procedures"
            },
            ["BR02"] = new DefendMapping
            {
                Stages = ["Harden", "Isolate"],
                Techniques = ["D3-BA", "D3-NI"],
                Labels = ["Backup", "Network Isolation"],
                Description = "Stores backups offsite or air-gapped"
            },
            ["BR03"] = new DefendMapping
            {
                Stages = ["Model"],
                Techniques = ["D3-AM", "D3-BA"],
                Labels = ["Access Modeling", "Backup"],
                Description = "Documents and tests disaster recovery procedures"
            },
            ["BR04"] = new DefendMapping
            {
                Stages = ["Detect"],
                Techniques = ["D3-FV", "D3-BA"],
                Labels = ["File Verification", "Backup"],
                Description = "Validates backup integrity through restore tests"
            },
            ["BR05"] = new DefendMapping
            {
                Stages = ["Model"],
                Techniques = ["D3-AM"],
                Labels = ["Access Modeling"],
                Description = "Defines recovery time and point objectives"
            },
            ["BR06"] = new DefendMapping
            {
                Stages = ["Detect"],
                Techniques = ["D3-PM", "D3-BA"],
                Labels = ["Platform Monitoring", "Backup"],
                Description = "Monitors backup job health and alerts on failures"
            },
            ["BR07"] = new DefendMapping
            {
                Stages = ["Harden"],
                Techniques = ["D3-DENCR", "D3-BA"],
                Labels = ["Disk Encryption", "Backup"],
                Description = "Encrypts backup data at rest and in transit"
            },
            ["BR08"] = new DefendMapping
            {
                Stages = ["Harden"],
                Techniques = ["D3-BA", "D3-PH"],
                Labels = ["Backup", "Platform Hardening"],
                Description = "Ensures critical systems have dedicated backup coverage"
            },

            // ── Common Findings ────────────────────────────────────────────
            ["CF01"] = new DefendMapping
            {
                Stages = ["Harden", "Model"],
                Techniques = ["D3-CH", "D3-AM", "D3-UAP"],
                Labels = ["Credential Hardening", "Access Modeling", "User Account Permissions"],
                Description = "Remediates AD privilege and credential hygiene"
            },
            ["CF02"] = new DefendMapping
            {
                Stages = ["Harden"],
                Techniques = ["D3-PH", "D3-MENCR"],
                Labels = ["Platform Hardening", "Message Encryption"],
                Description = "Disables legacy protocols and enforces modern alternatives"
            },
            ["CF03"] = new DefendMapping
            {
                Stages = ["Harden"],
                Techniques = ["D3-SAT", "D3-PH"],
                Labels = ["Security Awareness Training", "Platform Hardening"],
                Description = "Trains users to recognize social engineering"
            },
            ["CF04"] = new DefendMapping
            {
                Stages = ["Model", "Isolate"],
                Techniques = ["D3-AM", "D3-UAP"],
                Labels = ["Access Modeling", "User Account Permissions"],
                Description = "Enforces least-privilege file and application access"
            },
            ["CF05"] = new DefendMapping
            {
                Stages = ["Isolate", "Detect"],
                Techniques = ["D3-UAP", "D3-NM"],
                Labels = ["User Account Permissions", "Network Monitoring"],
                Description = "Restricts and monitors file share access"
            },
            ["CF06"] = new DefendMapping
            {
                Stages = ["Isolate", "Harden"],
                Techniques = ["D3-NTF", "D3-MFA"],
                Labels = ["Network Traffic Filtering", "Multi-factor Authentication"],
                Description = "Controls and audits remote access paths"
            },
            ["CF07"] = new DefendMapping
            {
                Stages = ["Harden", "Model"],
                Techniques = ["D3-UAP", "D3-AM"],
                Labels = ["User Account Permissions", "Access Modeling"],
                Description = "Removes unnecessary local admin privileges"
            },
            ["CF08"] = new DefendMapping
            {
                Stages = ["Detect", "Harden"],
                Techniques = ["D3-SU", "D3-PM"],
                Labels = ["Software Update", "Platform Monitoring"],
                Description = "Implements continuous vulnerability scanning and remediation"
            },

            // ── Policies & Standards ───────────────────────────────────────
            ["PS01"] = new DefendMapping
            {
                Stages = ["Model"],
                Techniques = ["D3-AM"],
                Labels = ["Access Modeling"],
                Description = "Establishes formal security policy framework"
            },
            ["PS02"] = new DefendMapping
            {
                Stages = ["Model"],
                Techniques = ["D3-AM"],
                Labels = ["Access Modeling"],
                Description = "Defines acceptable use boundaries"
            },
            ["PS03"] = new DefendMapping
            {
                Stages = ["Model", "Detect"],
                Techniques = ["D3-AM", "D3-IRD"],
                Labels = ["Access Modeling", "Incident Response Documentation"],
                Description = "Documents and rehearses incident response procedures"
            },
            ["PS04"] = new DefendMapping
            {
                Stages = ["Detect"],
                Techniques = ["D3-PM"],
                Labels = ["Platform Monitoring"],
                Description = "Monitors compliance posture continuously"
            },
            ["PS05"] = new DefendMapping
            {
                Stages = ["Model"],
                Techniques = ["D3-AM"],
                Labels = ["Access Modeling"],
                Description = "Conducts regular risk assessments"
            },
            ["PS06"] = new DefendMapping
            {
                Stages = ["Harden"],
                Techniques = ["D3-SAT"],
                Labels = ["Security Awareness Training"],
                Description = "Delivers ongoing security awareness training"
            }
        };

        return mappings.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);
    }
}
