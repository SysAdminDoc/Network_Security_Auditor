using System.Collections.Frozen;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Data;

/// <summary>
/// MITRE D3FEND 1.6.0 countermeasure mappings for all 70 security checks.
/// Maps each check ID to defensive stages, techniques, labels, and descriptions. Tests check every ID and
/// label against the pinned D3FEND release, derive the stages from the techniques, and keep the PowerShell
/// map identical.
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
                Techniques = ["D3-AM", "D3-UGPH", "D3-UAP"],
                Labels = ["Access Modeling", "User Group Permissions", "User Account Permissions"],
                Description = "Models and restricts privileged identities and administrative group membership"
            },
            ["IA02"] = new DefendMapping
            {
                Stages = ["Harden"],
                Techniques = ["D3-CH", "D3-CRO", "D3-PR"],
                Labels = ["Credential Hardening", "Credential Rotation", "Password Rotation"],
                Description = "Hardens service-account credentials and reduces Kerberoast exposure"
            },
            ["IA03"] = new DefendMapping
            {
                Stages = ["Harden", "Isolate"],
                Techniques = ["D3-MFA", "D3-CTS"],
                Labels = ["Multi-factor Authentication", "Credential Transmission Scoping"],
                Description = "Requires stronger authentication and scopes where credentials can be used"
            },
            ["IA04"] = new DefendMapping
            {
                Stages = ["Detect", "Isolate", "Evict"],
                Techniques = ["D3-DAM", "D3-UAP", "D3-AL"],
                Labels = ["Domain Account Monitoring", "User Account Permissions", "Account Locking"],
                Description = "Finds stale accounts so they can be locked before someone reuses them"
            },
            ["IA05"] = new DefendMapping
            {
                Stages = ["Harden"],
                Techniques = ["D3-SPP", "D3-PWA", "D3-PR"],
                Labels = ["Strong Password Policy", "Password Authentication", "Password Rotation"],
                Description = "Enforces password strength and rotation"
            },
            ["IA06"] = new DefendMapping
            {
                Stages = ["Harden", "Isolate"],
                Techniques = ["D3-AMED", "D3-CRO", "D3-UAP"],
                Labels = ["Access Mediation", "Credential Rotation", "User Account Permissions"],
                Description = "Mediates privileged access and rotates local administrator passwords"
            },
            ["IA07"] = new DefendMapping
            {
                Stages = ["Detect", "Isolate"],
                Techniques = ["D3-DAM", "D3-UAP"],
                Labels = ["Domain Account Monitoring", "User Account Permissions"],
                Description = "Finds shared accounts and restores per-user accountability"
            },
            ["IA08"] = new DefendMapping
            {
                Stages = ["Detect", "Isolate"],
                Techniques = ["D3-DAM", "D3-APA", "D3-UAP"],
                Labels = ["Domain Account Monitoring", "Access Policy Administration", "User Account Permissions"],
                Description = "Controls guest and vendor account lifecycle and permissions"
            },
            ["IA09"] = new DefendMapping
            {
                Stages = ["Harden", "Isolate"],
                Techniques = ["D3-MFA", "D3-DRA", "D3-CTS"],
                Labels = ["Multi-factor Authentication", "Disable Remote Access", "Credential Transmission Scoping"],
                Description = "Removes unmanaged remote access paths and requires strong authentication for the rest"
            },
            ["IA10"] = new DefendMapping
            {
                Stages = ["Detect", "Evict"],
                Techniques = ["D3-DAM", "D3-AL"],
                Labels = ["Domain Account Monitoring", "Account Locking"],
                Description = "Finds inactive accounts so they can be locked before abuse"
            },
            ["IA11"] = new DefendMapping
            {
                Stages = ["Harden", "Detect"],
                Techniques = ["D3-CH", "D3-CRO", "D3-MENCR", "D3-DAM"],
                Labels = ["Credential Hardening", "Credential Rotation", "Message Encryption", "Domain Account Monitoring"],
                Description = "Hardens Kerberos encryption by finding RC4 and DES dependencies"
            },
            ["IA12"] = new DefendMapping
            {
                Stages = ["Model", "Detect", "Isolate"],
                Techniques = ["D3-AM", "D3-UAP", "D3-APA", "D3-DAM"],
                Labels = ["Access Modeling", "User Account Permissions", "Access Policy Administration", "Domain Account Monitoring"],
                Description = "Models and restricts dMSA creation rights while watching for BadSuccessor abuse"
            },

            // ── Endpoint Security ──────────────────────────────────────────
            ["EP01"] = new DefendMapping
            {
                Stages = ["Harden", "Detect"],
                Techniques = ["D3-PM", "D3-OSM", "D3-PH"],
                Labels = ["Platform Monitoring", "Operating System Monitoring", "Platform Hardening"],
                Description = "Validates endpoint protection, ASR and anti-malware monitoring"
            },
            ["EP02"] = new DefendMapping
            {
                Stages = ["Harden"],
                Techniques = ["D3-DENCR", "D3-FE"],
                Labels = ["Disk Encryption", "File Encryption"],
                Description = "Protects data at rest with disk and file encryption"
            },
            ["EP03"] = new DefendMapping
            {
                Stages = ["Harden", "Isolate"],
                Techniques = ["D3-MAN", "D3-MENCR", "D3-CH", "D3-NTF"],
                Labels = ["Message Authentication", "Message Encryption", "Credential Hardening", "Network Traffic Filtering"],
                Description = "Signs and encrypts SMB, hardens NTLM and filters relay paths"
            },
            ["EP04"] = new DefendMapping
            {
                Stages = ["Model", "Harden"],
                Techniques = ["D3-SWI", "D3-AVE", "D3-SU"],
                Labels = ["Software Inventory", "Asset Vulnerability Enumeration", "Software Update"],
                Description = "Inventories software, enumerates known exploited vulnerabilities and keeps updates current"
            },
            ["EP05"] = new DefendMapping
            {
                Stages = ["Harden", "Detect", "Isolate"],
                Techniques = ["D3-SICA", "D3-SCP", "D3-UAP"],
                Labels = ["System Init Config Analysis", "System Configuration Permissions", "User Account Permissions"],
                Description = "Finds local privilege escalation paths and unsafe configuration permissions"
            },
            ["EP06"] = new DefendMapping
            {
                Stages = ["Isolate"],
                Techniques = ["D3-NTF", "D3-ITF", "D3-OTF"],
                Labels = ["Network Traffic Filtering", "Inbound Traffic Filtering", "Outbound Traffic Filtering"],
                Description = "Enforces host firewall filtering for inbound and outbound traffic"
            },
            ["EP07"] = new DefendMapping
            {
                Stages = ["Harden", "Isolate"],
                Techniques = ["D3-EAL", "D3-ACH"],
                Labels = ["Executable Allowlisting", "Application Configuration Hardening"],
                Description = "Allowlists executables and hardens Office macro settings"
            },
            ["EP08"] = new DefendMapping
            {
                Stages = ["Harden", "Isolate"],
                Techniques = ["D3-CH", "D3-HBPI", "D3-TBI"],
                Labels = ["Credential Hardening", "Hardware-based Process Isolation", "TPM Boot Integrity"],
                Description = "Uses hardware-backed isolation and boot integrity to protect credentials"
            },
            ["EP09"] = new DefendMapping
            {
                Stages = ["Harden", "Isolate"],
                Techniques = ["D3-IOPR", "D3-PH"],
                Labels = ["IO Port Restriction", "Platform Hardening"],
                Description = "Restricts removable media and turns off AutoRun and AutoPlay"
            },
            ["EP10"] = new DefendMapping
            {
                Stages = ["Model", "Harden"],
                Techniques = ["D3-AI", "D3-SWI", "D3-SU"],
                Labels = ["Asset Inventory", "Software Inventory", "Software Update"],
                Description = "Inventories end-of-life operating systems so they can be upgraded or covered by ESU"
            },
            ["EP11"] = new DefendMapping
            {
                Stages = ["Harden"],
                Techniques = ["D3-BA", "D3-SU"],
                Labels = ["Bootloader Authentication", "Software Update"],
                Description = "Moves Secure Boot trust to the 2023 certificates so boot manager revocations keep applying"
            },

            // ── Logging & Monitoring ───────────────────────────────────────
            ["LM01"] = new DefendMapping
            {
                Stages = ["Detect"],
                Techniques = ["D3-DNSTA", "D3-NTA"],
                Labels = ["DNS Traffic Analysis", "Network Traffic Analysis"],
                Description = "Analyzes DNS query logs to spot DNS-based command and control"
            },
            ["LM02"] = new DefendMapping
            {
                Stages = ["Detect"],
                Techniques = ["D3-OSM", "D3-PM"],
                Labels = ["Operating System Monitoring", "Platform Monitoring"],
                Description = "Centralizes operating system and platform telemetry for correlation"
            },
            ["LM03"] = new DefendMapping
            {
                Stages = ["Detect"],
                Techniques = ["D3-SEA", "D3-PLA", "D3-OSM"],
                Labels = ["Script Execution Analysis", "Process Lineage Analysis", "Operating System Monitoring"],
                Description = "Records script execution and process lineage through audit policy and PowerShell logging"
            },
            ["LM04"] = new DefendMapping
            {
                Stages = ["Detect"],
                Techniques = ["D3-NTA", "D3-CAA"],
                Labels = ["Network Traffic Analysis", "Connection Attempt Analysis"],
                Description = "Analyzes firewall logs for connection attempts and traffic patterns"
            },
            ["LM05"] = new DefendMapping
            {
                Stages = ["Detect"],
                Techniques = ["D3-ANET", "D3-LAM", "D3-DAM"],
                Labels = ["Authentication Event Thresholding", "Local Account Monitoring", "Domain Account Monitoring"],
                Description = "Thresholds failed logon events on local and domain accounts"
            },
            ["LM06"] = new DefendMapping
            {
                Stages = ["Detect"],
                Techniques = ["D3-FIM", "D3-SFA"],
                Labels = ["File Integrity Monitoring", "System File Analysis"],
                Description = "Detects unauthorized changes with file integrity monitoring and system file analysis"
            },
            ["LM07"] = new DefendMapping
            {
                Stages = ["Detect"],
                Techniques = ["D3-OSM", "D3-PM"],
                Labels = ["Operating System Monitoring", "Platform Monitoring"],
                Description = "Keeps enough operating system and platform event history for an investigation"
            },
            ["LM08"] = new DefendMapping
            {
                Stages = ["Detect"],
                Techniques = ["D3-ANET", "D3-NTSA", "D3-UBA"],
                Labels = ["Authentication Event Thresholding", "Network Traffic Signature Analysis", "User Behavior Analysis"],
                Description = "Raises alerts on authentication thresholds, network signatures and user behavior"
            },

            // ── Network Architecture ───────────────────────────────────────
            ["NA01"] = new DefendMapping
            {
                Stages = ["Model", "Isolate"],
                Techniques = ["D3-NM", "D3-NI", "D3-NRAM"],
                Labels = ["Network Mapping", "Network Isolation", "Network Resource Access Mediation"],
                Description = "Maps the network and isolates zones to limit lateral movement"
            },
            ["NA02"] = new DefendMapping
            {
                Stages = ["Isolate"],
                Techniques = ["D3-BDI", "D3-NI", "D3-RAM"],
                Labels = ["Broadcast Domain Isolation", "Network Isolation", "Routing Access Mediation"],
                Description = "Separates broadcast domains with VLANs and mediates routing between them"
            },
            ["NA03"] = new DefendMapping
            {
                Stages = ["Harden", "Isolate"],
                Techniques = ["D3-NAM", "D3-MENCR"],
                Labels = ["Network Access Mediation", "Message Encryption"],
                Description = "Mediates wireless network access and encrypts wireless traffic"
            },
            ["NA04"] = new DefendMapping
            {
                Stages = ["Model"],
                Techniques = ["D3-NM", "D3-NNI", "D3-AI"],
                Labels = ["Network Mapping", "Network Node Inventory", "Asset Inventory"],
                Description = "Keeps network diagrams, node inventories and asset records current"
            },
            ["NA05"] = new DefendMapping
            {
                Stages = ["Harden", "Isolate"],
                Techniques = ["D3-LAMED", "D3-NAM", "D3-CBAN"],
                Labels = ["LAN Access Mediation", "Network Access Mediation", "Certificate-based Authentication"],
                Description = "Mediates LAN access with 802.1X and certificate-based device authentication"
            },
            ["NA06"] = new DefendMapping
            {
                Stages = ["Isolate"],
                Techniques = ["D3-NI", "D3-NAM"],
                Labels = ["Network Isolation", "Network Access Mediation"],
                Description = "Isolates management interfaces on their own network with mediated access"
            },
            ["NA07"] = new DefendMapping
            {
                Stages = ["Isolate"],
                Techniques = ["D3-NI", "D3-BDI", "D3-NAM"],
                Labels = ["Network Isolation", "Broadcast Domain Isolation", "Network Access Mediation"],
                Description = "Keeps guest networks in their own broadcast domain, away from internal systems"
            },

            // ── Network Perimeter ──────────────────────────────────────────
            ["NP01"] = new DefendMapping
            {
                Stages = ["Isolate"],
                Techniques = ["D3-NTF", "D3-ITF", "D3-OTF"],
                Labels = ["Network Traffic Filtering", "Inbound Traffic Filtering", "Outbound Traffic Filtering"],
                Description = "Filters inbound and outbound traffic at the perimeter"
            },
            ["NP02"] = new DefendMapping
            {
                Stages = ["Model", "Isolate"],
                Techniques = ["D3-NVA", "D3-NTPM", "D3-ITF"],
                Labels = ["Network Vulnerability Assessment", "Network Traffic Policy Mapping", "Inbound Traffic Filtering"],
                Description = "Assesses listening services and maps them against inbound filtering"
            },
            ["NP03"] = new DefendMapping
            {
                Stages = ["Harden", "Isolate"],
                Techniques = ["D3-ET", "D3-NAM", "D3-MFA"],
                Labels = ["Encrypted Tunnels", "Network Access Mediation", "Multi-factor Authentication"],
                Description = "Scopes VPN access through encrypted tunnels with multi-factor authentication"
            },
            ["NP04"] = new DefendMapping
            {
                Stages = ["Detect", "Isolate"],
                Techniques = ["D3-DNSDL", "D3-DNRA"],
                Labels = ["DNS Denylisting", "Domain Name Reputation Analysis"],
                Description = "Blocks known-bad domains through DNS denylisting and reputation analysis"
            },
            ["NP05"] = new DefendMapping
            {
                Stages = ["Model", "Isolate"],
                Techniques = ["D3-OTF", "D3-NTPM"],
                Labels = ["Outbound Traffic Filtering", "Network Traffic Policy Mapping"],
                Description = "Maps egress policy and filters outbound traffic"
            },
            ["NP06"] = new DefendMapping
            {
                Stages = ["Model", "Isolate"],
                Techniques = ["D3-NTPM", "D3-NTF"],
                Labels = ["Network Traffic Policy Mapping", "Network Traffic Filtering"],
                Description = "Maps temporary firewall rules against policy so stale ones get removed"
            },
            ["NP07"] = new DefendMapping
            {
                Stages = ["Detect"],
                Techniques = ["D3-NTSA", "D3-NTA", "D3-NTCD"],
                Labels = ["Network Traffic Signature Analysis", "Network Traffic Analysis", "Network Traffic Community Deviation"],
                Description = "Validates intrusion detection and prevention coverage with signature and anomaly analysis"
            },
            ["NP08"] = new DefendMapping
            {
                Stages = ["Harden", "Detect"],
                Techniques = ["D3-MENCR", "D3-PCA", "D3-NTA"],
                Labels = ["Message Encryption", "Passive Certificate Analysis", "Network Traffic Analysis"],
                Description = "Checks TLS encryption and certificate visibility for inspection"
            },
            ["NP09"] = new DefendMapping
            {
                Stages = ["Model", "Isolate"],
                Techniques = ["D3-ITF", "D3-NTPM", "D3-NRAM"],
                Labels = ["Inbound Traffic Filtering", "Network Traffic Policy Mapping", "Network Resource Access Mediation"],
                Description = "Reviews NAT and port-forward exposure to internal hosts"
            },
            ["NP10"] = new DefendMapping
            {
                Stages = ["Model", "Harden", "Detect"],
                Techniques = ["D3-SU", "D3-FV", "D3-SYSVA"],
                Labels = ["Software Update", "Firmware Verification", "System Vulnerability Assessment"],
                Description = "Keeps perimeter firmware updated and verified against known vulnerabilities"
            },

            // ── Backup & Recovery ──────────────────────────────────────────
            ["BR01"] = new DefendMapping
            {
                Stages = ["Restore"],
                Techniques = ["D3-RF", "D3-RDI"],
                Labels = ["Restore File", "Restore Disk Image"],
                Description = "Establishes backups that can restore files and full disk images"
            },
            ["BR02"] = new DefendMapping
            {
                Stages = ["Restore"],
                Techniques = ["D3-RDI", "D3-RF", "D3-RO"],
                Labels = ["Restore Disk Image", "Restore File", "Restore Object"],
                Description = "Keeps offsite and immutable copies that can be restored after local destruction"
            },
            ["BR03"] = new DefendMapping
            {
                Stages = ["Restore"],
                Techniques = ["D3-RF", "D3-RDI", "D3-RO"],
                Labels = ["Restore File", "Restore Disk Image", "Restore Object"],
                Description = "Confirms that restore procedures actually bring back files, images and objects"
            },
            ["BR04"] = new DefendMapping
            {
                Stages = ["Model", "Restore"],
                Techniques = ["D3-ODM", "D3-ORA", "D3-RC"],
                Labels = ["Operational Dependency Mapping", "Operational Risk Assessment", "Restore Configuration"],
                Description = "Documents RTO/RPO targets and the dependencies that set recovery order"
            },
            ["BR05"] = new DefendMapping
            {
                Stages = ["Harden", "Restore"],
                Techniques = ["D3-FE", "D3-MENCR", "D3-RF"],
                Labels = ["File Encryption", "Message Encryption", "Restore File"],
                Description = "Protects backup data with encryption at rest and in transit"
            },
            ["BR06"] = new DefendMapping
            {
                Stages = ["Detect", "Restore"],
                Techniques = ["D3-PM", "D3-RF", "D3-RDI"],
                Labels = ["Platform Monitoring", "Restore File", "Restore Disk Image"],
                Description = "Monitors backup jobs so the file and image restores they promise are there when needed"
            },
            ["BR07"] = new DefendMapping
            {
                Stages = ["Model", "Restore"],
                Techniques = ["D3-RC", "D3-RA", "D3-ORA"],
                Labels = ["Restore Configuration", "Restore Access", "Operational Risk Assessment"],
                Description = "Keeps a DR plan with the configuration and access needed to recover"
            },
            ["BR08"] = new DefendMapping
            {
                Stages = ["Restore"],
                Techniques = ["D3-RE", "D3-RF", "D3-RO"],
                Labels = ["Restore Email", "Restore File", "Restore Object"],
                Description = "Gives SaaS mail, files and other workload data a restore path outside the provider"
            },

            // ── Common Findings ────────────────────────────────────────────
            ["CF01"] = new DefendMapping
            {
                Stages = ["Harden", "Isolate"],
                Techniques = ["D3-CH", "D3-CRO", "D3-UAP"],
                Labels = ["Credential Hardening", "Credential Rotation", "User Account Permissions"],
                Description = "Hardens privileged service-account credentials and certificate services exposure"
            },
            ["CF02"] = new DefendMapping
            {
                Stages = ["Isolate"],
                Techniques = ["D3-OTF", "D3-NTF"],
                Labels = ["Outbound Traffic Filtering", "Network Traffic Filtering"],
                Description = "Tests egress filtering so outbound traffic is limited to what the business needs"
            },
            ["CF03"] = new DefendMapping
            {
                Stages = ["Detect", "Isolate"],
                Techniques = ["D3-MA", "D3-URA", "D3-CF"],
                Labels = ["Message Analysis", "URL Reputation Analysis", "Content Filtering"],
                Description = "Backs up security awareness training with message, URL and content filtering"
            },
            ["CF04"] = new DefendMapping
            {
                Stages = ["Detect", "Evict"],
                Techniques = ["D3-DAM", "D3-AL", "D3-CR"],
                Labels = ["Domain Account Monitoring", "Account Locking", "Credential Revocation"],
                Description = "Finds former employee accounts, locks them and revokes their credentials"
            },
            ["CF05"] = new DefendMapping
            {
                Stages = ["Isolate"],
                Techniques = ["D3-LFP", "D3-RFAM", "D3-UAP"],
                Labels = ["Local File Permissions", "Remote File Access Mediation", "User Account Permissions"],
                Description = "Restricts open shares with local and remote file access controls"
            },
            ["CF06"] = new DefendMapping
            {
                Stages = ["Model", "Isolate"],
                Techniques = ["D3-NI", "D3-NRAM", "D3-NM"],
                Labels = ["Network Isolation", "Network Resource Access Mediation", "Network Mapping"],
                Description = "Breaks up a flat network with isolation and resource access mediation"
            },
            ["CF07"] = new DefendMapping
            {
                Stages = ["Detect", "Isolate"],
                Techniques = ["D3-LAM", "D3-UAP", "D3-APA"],
                Labels = ["Local Account Monitoring", "User Account Permissions", "Access Policy Administration"],
                Description = "Monitors local admin accounts and reduces local administrator rights"
            },
            ["CF08"] = new DefendMapping
            {
                Stages = ["Detect", "Isolate"],
                Techniques = ["D3-DNSDL", "D3-DNRA"],
                Labels = ["DNS Denylisting", "Domain Name Reputation Analysis"],
                Description = "Tests DNS denylisting and domain reputation filtering on the resolvers in use"
            },

            // ── Policies & Standards ───────────────────────────────────────
            ["PS01"] = new DefendMapping
            {
                Stages = ["Model", "Isolate"],
                Techniques = ["D3-APA", "D3-ORA", "D3-AM"],
                Labels = ["Access Policy Administration", "Operational Risk Assessment", "Access Modeling"],
                Description = "Defines security policy and control ownership"
            },
            ["PS02"] = new DefendMapping
            {
                Stages = ["Model", "Isolate"],
                Techniques = ["D3-APA", "D3-OM"],
                Labels = ["Access Policy Administration", "Organization Mapping"],
                Description = "Defines acceptable use responsibilities and organizational expectations"
            },
            ["PS03"] = new DefendMapping
            {
                Stages = ["Model", "Restore"],
                Techniques = ["D3-RA", "D3-ORA", "D3-ODM"],
                Labels = ["Restore Access", "Operational Risk Assessment", "Operational Dependency Mapping"],
                Description = "Structures incident response and recovery decisions"
            },
            ["PS04"] = new DefendMapping
            {
                Stages = ["Model", "Detect"],
                Techniques = ["D3-ORA", "D3-CI", "D3-PM"],
                Labels = ["Operational Risk Assessment", "Configuration Inventory", "Platform Monitoring"],
                Description = "Tracks compliance drift through periodic assessment and configuration inventory"
            },
            ["PS05"] = new DefendMapping
            {
                Stages = ["Model"],
                Techniques = ["D3-ORA", "D3-SYSVA", "D3-AI"],
                Labels = ["Operational Risk Assessment", "System Vulnerability Assessment", "Asset Inventory"],
                Description = "Identifies risks and vulnerable assets before exploitation"
            },
            ["PS06"] = new DefendMapping
            {
                Stages = ["Detect"],
                Techniques = ["D3-MA", "D3-UBA", "D3-WSAA"],
                Labels = ["Message Analysis", "User Behavior Analysis", "Web Session Activity Analysis"],
                Description = "Backs up user training with message, behavior and web session analysis"
            }
        };

        return mappings.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);
    }
}
