using System.Collections.Frozen;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Data;

/// <summary>
/// MITRE ATT&amp;CK Enterprise v19 mappings for all 69 security checks.
/// v19 split Defense Evasion into Stealth (TA0005) and Defense Impairment (TA0112).
/// Maps each check ID to its relevant tactics, techniques, and a threat description.
/// </summary>
public static class MitreMappings
{
    private static FrozenDictionary<string, AttackMapping>? s_mappings;

    public static FrozenDictionary<string, AttackMapping> All => s_mappings ??= BuildMappings();

    private static FrozenDictionary<string, AttackMapping> BuildMappings()
    {
        var mappings = new Dictionary<string, AttackMapping>(StringComparer.OrdinalIgnoreCase)
        {
            // ── Identity & Access ──────────────────────────────────────────
            ["IA01"] = new AttackMapping
            {
                Tactics = ["TA0004", "TA0003"],
                Techniques = ["T1078.002", "T1078.001", "T1098"],
                Description = "Compromised privileged accounts expand blast radius and privilege escalation"
            },
            ["IA02"] = new AttackMapping
            {
                Tactics = ["TA0006", "TA0004"],
                Techniques = ["T1558.003", "T1558.004", "T1078.002"],
                Description = "Service accounts with SPNs are Kerberoastable; stale passwords make cracking trivial"
            },
            ["IA03"] = new AttackMapping
            {
                Tactics = ["TA0001", "TA0006"],
                Techniques = ["T1078", "T1110.001", "T1110.003", "T1556"],
                Description = "Missing MFA allows credential stuffing and password spraying"
            },
            ["IA04"] = new AttackMapping
            {
                Tactics = ["TA0001", "TA0003"],
                Techniques = ["T1078.002", "T1078.001"],
                Description = "Stale accounts are prime targets for unauthorized access"
            },
            ["IA05"] = new AttackMapping
            {
                Tactics = ["TA0006", "TA0001"],
                Techniques = ["T1110.001", "T1110.002", "T1110.003"],
                Description = "Weak password policy enables brute force and credential spraying"
            },
            ["IA06"] = new AttackMapping
            {
                Tactics = ["TA0004", "TA0003", "TA0006"],
                Techniques = ["T1078.002", "T1550.002", "T1550.003"],
                Description = "Without PAM/LAPS, pass-the-hash and golden ticket attacks"
            },
            ["IA07"] = new AttackMapping
            {
                Tactics = ["TA0001", "TA0005"],
                Techniques = ["T1078", "T1078.001"],
                Description = "Shared accounts eliminate attribution"
            },
            ["IA08"] = new AttackMapping
            {
                Tactics = ["TA0001", "TA0003"],
                Techniques = ["T1078", "T1199"],
                Description = "Vendor accounts with persistent access enable trusted relationship attacks"
            },
            ["IA09"] = new AttackMapping
            {
                Tactics = ["TA0001", "TA0005"],
                Techniques = ["T1078.004", "T1556.006"],
                Description = "Unmanaged remote access allows credentialed access from untrusted devices"
            },
            ["IA10"] = new AttackMapping
            {
                Tactics = ["TA0001", "TA0003"],
                Techniques = ["T1078", "T1078.002"],
                Description = "Stale accounts expand attack surface"
            },
            ["IA11"] = new AttackMapping
            {
                Tactics = ["TA0006", "TA0008"],
                Techniques = ["T1558.003", "T1550.003"],
                Description = "RC4/DES Kerberos keeps service tickets crackable"
            },
            ["IA12"] = new AttackMapping
            {
                Tactics = ["TA0004", "TA0003", "TA0006"],
                Techniques = ["T1098", "T1078.002", "T1550.003"],
                Description = "BadSuccessor/dMSA abuse turns delegated OU rights into domain privilege escalation"
            },

            // ── Endpoint Security ──────────────────────────────────────────
            ["EP01"] = new AttackMapping
            {
                Tactics = ["TA0112", "TA0002"],
                Techniques = ["T1685.001", "T1686.003", "T1059"],
                Description = "Disabled AV allows malware execution"
            },
            ["EP02"] = new AttackMapping
            {
                Tactics = ["TA0005", "TA0002"],
                Techniques = ["T1486", "T1059"],
                Description = "Missing encryption exposes data at rest"
            },
            ["EP03"] = new AttackMapping
            {
                Tactics = ["TA0006", "TA0008", "TA0005"],
                Techniques = ["T1557.001", "T1040", "T1570", "T1187"],
                Description = "SMB/NTLM misconfig enables relay attacks and credential capture"
            },
            ["EP04"] = new AttackMapping
            {
                Tactics = ["TA0001", "TA0002"],
                Techniques = ["T1190", "T1203", "T1210"],
                Description = "Unpatched systems enable exploitation of public-facing apps"
            },
            ["EP05"] = new AttackMapping
            {
                Tactics = ["TA0004", "TA0003", "TA0002"],
                Techniques = ["T1574.009", "T1574.001", "T1547.001", "T1053"],
                Description = "Unquoted service paths and cached creds enable local privesc"
            },
            ["EP06"] = new AttackMapping
            {
                Tactics = ["TA0112", "TA0011"],
                Techniques = ["T1686.003", "T1071", "T1048"],
                Description = "Firewall gaps allow C2 and data exfiltration"
            },
            ["EP07"] = new AttackMapping
            {
                Tactics = ["TA0002", "TA0005"],
                Techniques = ["T1059", "T1204.002", "T1137", "T1221"],
                Description = "Missing AppLocker/WDAC enables arbitrary code execution"
            },
            ["EP08"] = new AttackMapping
            {
                Tactics = ["TA0006", "TA0005", "TA0004"],
                Techniques = ["T1003.001", "T1003.004", "T1003.005", "T1547.008"],
                Description = "Missing Credential Guard enables LSASS dumping"
            },
            ["EP09"] = new AttackMapping
            {
                Tactics = ["TA0005", "TA0003"],
                Techniques = ["T1685.001", "T1112"],
                Description = "Misconfigured AutoRun expands attack surface"
            },
            ["EP10"] = new AttackMapping
            {
                Tactics = ["TA0005", "TA0010"],
                Techniques = ["T1091", "T1052"],
                Description = "Uncontrolled removable media enables malware delivery"
            },

            // ── Logging & Monitoring ───────────────────────────────────────
            ["LM01"] = new AttackMapping
            {
                Tactics = ["TA0112"],
                Techniques = ["T1685.002", "T1070.001"],
                Description = "Inadequate audit policy creates blind spots"
            },
            ["LM02"] = new AttackMapping
            {
                Tactics = ["TA0112", "TA0040"],
                Techniques = ["T1685.002", "T1485"],
                Description = "No SIEM means no correlation or alerting"
            },
            ["LM03"] = new AttackMapping
            {
                Tactics = ["TA0002", "TA0112"],
                Techniques = ["T1059.001", "T1059.003", "T1685.002", "T1070"],
                Description = "Missing PS logging allows script-based attacks without trace"
            },
            ["LM04"] = new AttackMapping
            {
                Tactics = ["TA0112", "TA0011"],
                Techniques = ["T1685.002", "T1071"],
                Description = "No firewall logging means network attacks go undetected"
            },
            ["LM05"] = new AttackMapping
            {
                Tactics = ["TA0112"],
                Techniques = ["T1685.002", "T1070.001", "T1070.002"],
                Description = "Logs without integrity protection can be tampered with"
            },
            ["LM06"] = new AttackMapping
            {
                Tactics = ["TA0112"],
                Techniques = ["T1070.001", "T1685.002"],
                Description = "Missing log review means alerts never acted upon"
            },
            ["LM07"] = new AttackMapping
            {
                Tactics = ["TA0112"],
                Techniques = ["T1070.001", "T1685.002"],
                Description = "Small log sizes cause critical events to be overwritten"
            },
            ["LM08"] = new AttackMapping
            {
                Tactics = ["TA0112", "TA0011"],
                Techniques = ["T1685.002", "T1071"],
                Description = "Missing alerting means attacks proceed without response"
            },

            // ── Network Architecture ───────────────────────────────────────
            ["NA01"] = new AttackMapping
            {
                Tactics = ["TA0008"],
                Techniques = ["T1021", "T1570", "T1210"],
                Description = "Flat networks enable unrestricted lateral movement"
            },
            ["NA02"] = new AttackMapping
            {
                Tactics = ["TA0008", "TA0011"],
                Techniques = ["T1021", "T1071"],
                Description = "Missing segmentation enables lateral movement to high-value targets"
            },
            ["NA03"] = new AttackMapping
            {
                Tactics = ["TA0001", "TA0008"],
                Techniques = ["T1078", "T1557", "T1021"],
                Description = "Weak wireless controls allow unauthorized network access and lateral movement from WiFi"
            },
            ["NA04"] = new AttackMapping
            {
                Tactics = ["TA0007", "TA0043"],
                Techniques = ["T1016", "T1046"],
                Description = "Stale network diagrams and inventories hide exposed attack paths from defenders"
            },
            ["NA05"] = new AttackMapping
            {
                Tactics = ["TA0001", "TA0008"],
                Techniques = ["T1200", "T1078", "T1021"],
                Description = "Missing 802.1X or NAC allows rogue devices to join internal networks"
            },
            ["NA06"] = new AttackMapping
            {
                Tactics = ["TA0001", "TA0008"],
                Techniques = ["T1133", "T1021", "T1210"],
                Description = "Exposed management interfaces give attackers direct administrative paths"
            },
            ["NA07"] = new AttackMapping
            {
                Tactics = ["TA0001", "TA0008"],
                Techniques = ["T1200", "T1021", "T1210"],
                Description = "Poor guest network isolation lets untrusted devices reach internal systems"
            },

            // ── Network Perimeter ──────────────────────────────────────────
            ["NP01"] = new AttackMapping
            {
                Tactics = ["TA0112", "TA0011"],
                Techniques = ["T1686.003", "T1071"],
                Description = "Weak firewall rules expose attack surface"
            },
            ["NP02"] = new AttackMapping
            {
                Tactics = ["TA0001", "TA0043"],
                Techniques = ["T1190", "T1046"],
                Description = "Open ports expose services to exploitation"
            },
            ["NP03"] = new AttackMapping
            {
                Tactics = ["TA0001", "TA0008"],
                Techniques = ["T1133", "T1021.001"],
                Description = "Exposed RDP enables brute force and ransomware delivery"
            },
            ["NP04"] = new AttackMapping
            {
                Tactics = ["TA0001", "TA0005"],
                Techniques = ["T1190", "T1686.003"],
                Description = "WAF gaps allow web app exploitation"
            },
            ["NP05"] = new AttackMapping
            {
                Tactics = ["TA0001", "TA0008"],
                Techniques = ["T1190", "T1210"],
                Description = "Permissive ACLs expose internal services"
            },
            ["NP06"] = new AttackMapping
            {
                Tactics = ["TA0001", "TA0011"],
                Techniques = ["T1190", "T1071.001"],
                Description = "Missing SSL inspection allows encrypted C2"
            },
            ["NP07"] = new AttackMapping
            {
                Tactics = ["TA0005", "TA0011"],
                Techniques = ["T1071", "T1568", "T1686.003"],
                Description = "No IDS/IPS means network attacks bypass perimeter"
            },
            ["NP08"] = new AttackMapping
            {
                Tactics = ["TA0006", "TA0009"],
                Techniques = ["T1557", "T1040", "T1552.001"],
                Description = "Weak TLS enables credential interception and MitM"
            },
            ["NP09"] = new AttackMapping
            {
                Tactics = ["TA0001", "TA0008"],
                Techniques = ["T1190", "T1021"],
                Description = "Unnecessary NAT/port forwards expose internal hosts"
            },
            ["NP10"] = new AttackMapping
            {
                Tactics = ["TA0001", "TA0002"],
                Techniques = ["T1190", "T1210"],
                Description = "Unpatched perimeter firmware contains known exploitable vulnerabilities"
            },

            // ── Backup & Recovery ──────────────────────────────────────────
            ["BR01"] = new AttackMapping
            {
                Tactics = ["TA0040"],
                Techniques = ["T1486", "T1490", "T1485"],
                Description = "No backup means ransomware encryption is catastrophic"
            },
            ["BR02"] = new AttackMapping
            {
                Tactics = ["TA0040"],
                Techniques = ["T1486", "T1490"],
                Description = "Backups without offsite copies are destroyed alongside primary"
            },
            ["BR03"] = new AttackMapping
            {
                Tactics = ["TA0040"],
                Techniques = ["T1486", "T1490"],
                Description = "Untested backups may fail during actual restore and recovery"
            },
            ["BR04"] = new AttackMapping
            {
                Tactics = ["TA0040"],
                Techniques = ["T1486", "T1490", "T1489"],
                Description = "Undefined RTO/RPO leaves responders without recovery targets"
            },
            ["BR05"] = new AttackMapping
            {
                Tactics = ["TA0010", "TA0040"],
                Techniques = ["T1048", "T1486"],
                Description = "Unencrypted backups expose data if backup storage is compromised"
            },
            ["BR06"] = new AttackMapping
            {
                Tactics = ["TA0040"],
                Techniques = ["T1490", "T1486"],
                Description = "Unmonitored backup failures mean data loss discovered only during recovery"
            },
            ["BR07"] = new AttackMapping
            {
                Tactics = ["TA0040"],
                Techniques = ["T1486", "T1490", "T1485"],
                Description = "No DR plan means extended downtime during incidents"
            },
            ["BR08"] = new AttackMapping
            {
                Tactics = ["TA0040"],
                Techniques = ["T1486", "T1490", "T1561"],
                Description = "Missing backup for critical systems means targeted destruction is irrecoverable"
            },

            // ── Common Findings ────────────────────────────────────────────
            ["CF01"] = new AttackMapping
            {
                Tactics = ["TA0006", "TA0004", "TA0003"],
                Techniques = ["T1558.003", "T1078.002", "T1098"],
                Description = "DA service accounts, missing LAPS, GPP passwords enable domain compromise"
            },
            ["CF02"] = new AttackMapping
            {
                Tactics = ["TA0008", "TA0005"],
                Techniques = ["T1021.002", "T1570"],
                Description = "SMBv1 and legacy protocols enable EternalBlue-class exploits"
            },
            ["CF03"] = new AttackMapping
            {
                Tactics = ["TA0001", "TA0043"],
                Techniques = ["T1566.001", "T1566.002", "T1598"],
                Description = "Untrained users fall for phishing and social engineering"
            },
            ["CF04"] = new AttackMapping
            {
                Tactics = ["TA0009", "TA0010"],
                Techniques = ["T1005", "T1039", "T1048"],
                Description = "Excessive permissions enable data collection and exfiltration"
            },
            ["CF05"] = new AttackMapping
            {
                Tactics = ["TA0009", "TA0010"],
                Techniques = ["T1039", "T1005", "T1048"],
                Description = "Open shares expose sensitive data"
            },
            ["CF06"] = new AttackMapping
            {
                Tactics = ["TA0008", "TA0011"],
                Techniques = ["T1021.001", "T1071"],
                Description = "Unrestricted remote access enables lateral movement"
            },
            ["CF07"] = new AttackMapping
            {
                Tactics = ["TA0004", "TA0008"],
                Techniques = ["T1078.001", "T1021"],
                Description = "Excessive local admin rights enable privilege escalation"
            },
            ["CF08"] = new AttackMapping
            {
                Tactics = ["TA0001", "TA0005"],
                Techniques = ["T1190", "T1211", "T1685.001"],
                Description = "Missing vulnerability management leaves known CVEs exploitable"
            },

            // ── Policies & Standards ───────────────────────────────────────
            ["PS01"] = new AttackMapping
            {
                Tactics = ["TA0001", "TA0042"],
                Techniques = ["T1078", "T1595"],
                Description = "Missing security policies leave no defined security posture"
            },
            ["PS02"] = new AttackMapping
            {
                Tactics = ["TA0042"],
                Techniques = ["T1595", "T1589"],
                Description = "No AUP means no policy enforcement"
            },
            ["PS03"] = new AttackMapping
            {
                Tactics = ["TA0040", "TA0042"],
                Techniques = ["T1486", "T1489", "T1485"],
                Description = "Missing IR plan means uncoordinated response to breaches"
            },
            ["PS04"] = new AttackMapping
            {
                Tactics = ["TA0042"],
                Techniques = ["T1595"],
                Description = "No compliance monitoring means security drift goes undetected"
            },
            ["PS05"] = new AttackMapping
            {
                Tactics = ["TA0042", "TA0043"],
                Techniques = ["T1595", "T1592"],
                Description = "Missing risk assessment leaves unknown vulnerabilities unaddressed"
            },
            ["PS06"] = new AttackMapping
            {
                Tactics = ["TA0001", "TA0043"],
                Techniques = ["T1566", "T1598", "T1204"],
                Description = "Without ongoing training users remain the weakest link"
            }
        };

        return mappings.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);
    }
}
