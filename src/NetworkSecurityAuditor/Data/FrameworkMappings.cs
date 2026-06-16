namespace NetworkSecurityAuditor.Data;

using System.Collections.Frozen;
using NetworkSecurityAuditor.Models;

public static class FrameworkMappings
{
    private static readonly Lazy<FrozenDictionary<string, ComplianceMapping>> _all = new(() =>
        new Dictionary<string, ComplianceMapping>(StringComparer.OrdinalIgnoreCase)
        {
            // ──────────────────────────────────────────────
            //  Identity & Access (IA01 – IA12)
            // ──────────────────────────────────────────────
            ["IA01"] = new()
            {
                NIST = "3.1.1, 3.1.2, 3.1.5",
                CMMC = "AC.L2-3.1.1, AC.L2-3.1.2, AC.L2-3.1.5",
                PCI = "7.2.1, 7.2.2, 8.6.1",
                SOC2 = "CC6.1, CC6.3",
                ISO27001 = "A.5.15, A.5.18, A.8.2",
                STIG = "V-254247, V-254248",
                FedRAMP = "AC-2, AC-3, AC-5, AC-6",
            },
            ["IA02"] = new()
            {
                NIST = "3.1.1, 3.1.5, 3.7.5",
                CMMC = "AC.L2-3.1.1, AC.L2-3.1.5",
                PCI = "7.2.2, 8.6.1, 8.6.2",
                SOC2 = "CC6.1, CC6.3",
                ISO27001 = "A.5.15, A.5.17, A.8.2",
                STIG = "V-254249, V-254250",
                FedRAMP = "AC-2, AC-6(5), AC-6(7)",
            },
            ["IA03"] = new()
            {
                NIST = "3.5.3, 3.7.5",
                CMMC = "IA.L2-3.5.3",
                PCI = "8.4.1, 8.4.2, 8.4.3",
                SOC2 = "CC6.1, CC6.6",
                ISO27001 = "A.5.17, A.8.5",
                STIG = "V-254251",
                E8 = "E8 Multi-factor Authentication ML1-ML3",
                CyberEssentials = "Cyber Essentials v3.3: User access control",
                FedRAMP = "IA-2(1), IA-2(2), IA-5",
            },
            ["IA04"] = new()
            {
                NIST = "3.1.1, 3.1.12",
                CMMC = "AC.L2-3.1.1, PS.L2-3.9.2",
                PCI = "8.1.4, 8.2.6",
                SOC2 = "CC6.1, CC6.2",
                ISO27001 = "A.5.18, A.6.5",
                STIG = "V-254252, V-254253",
                CyberEssentials = "Cyber Essentials v3.3: User access control",
                FedRAMP = "AC-2(3), PS-4",
            },
            ["IA05"] = new()
            {
                NIST = "3.5.7, 3.5.8, 3.5.9, 3.5.10",
                CMMC = "IA.L2-3.5.7, IA.L2-3.5.8",
                PCI = "8.3.6, 8.3.7, 8.3.9",
                SOC2 = "CC6.1",
                ISO27001 = "A.5.17, A.8.5",
                STIG = "V-254254, V-254255, V-254256",
                CyberEssentials = "Cyber Essentials v3.3: User access control",
                FedRAMP = "IA-5(1), IA-5(2), IA-5(6)",
            },
            ["IA06"] = new()
            {
                NIST = "3.1.5, 3.1.6, 3.1.7",
                CMMC = "AC.L2-3.1.5, AC.L2-3.1.6, AC.L2-3.1.7",
                PCI = "7.2.1, 8.2.4",
                SOC2 = "CC6.1, CC6.3",
                ISO27001 = "A.5.15, A.8.2, A.8.18",
                STIG = "V-254257, V-254258",
                E8 = "E8 Restrict Administrative Privileges ML2-ML3",
                CyberEssentials = "Cyber Essentials v3.3: User access control",
                FedRAMP = "AC-6(1), AC-6(2), AC-6(5)",
            },
            ["IA07"] = new()
            {
                NIST = "3.1.1, 3.5.1",
                CMMC = "AC.L2-3.1.1, IA.L2-3.5.1",
                PCI = "8.2.1, 8.2.2",
                SOC2 = "CC6.1",
                ISO27001 = "A.5.15, A.5.17",
                STIG = "V-254259",
                CyberEssentials = "Cyber Essentials v3.3: User access control",
                FedRAMP = "IA-2, IA-4, IA-8",
            },
            ["IA08"] = new()
            {
                NIST = "3.1.1, 3.1.12",
                CMMC = "AC.L2-3.1.1, PS.L2-3.9.2",
                PCI = "8.1.4, 8.6.1",
                SOC2 = "CC6.1, CC6.2",
                ISO27001 = "A.5.18, A.5.19, A.5.20",
                STIG = "V-254260",
                CyberEssentials = "Cyber Essentials v3.3: User access control",
                FedRAMP = "AC-2(3), PS-4, PS-5",
            },
            ["IA09"] = new()
            {
                NIST = "3.1.3, 3.5.3",
                CMMC = "AC.L2-3.1.3, IA.L2-3.5.3",
                PCI = "7.2.1, 8.4.1",
                SOC2 = "CC6.1, CC6.6",
                ISO27001 = "A.5.15, A.8.5",
                STIG = "V-254261, V-254262",
                E8 = "E8 Multi-factor Authentication ML2-ML3",
                CyberEssentials = "Cyber Essentials v3.3: User access control",
                FedRAMP = "AC-17, AC-20, IA-2(1)",
            },
            ["IA10"] = new()
            {
                NIST = "3.1.1, 3.1.12",
                CMMC = "AC.L2-3.1.1",
                PCI = "8.2.6",
                SOC2 = "CC6.1, CC6.2",
                ISO27001 = "A.5.18, A.6.5",
                STIG = "V-254263",
                E8 = "E8 Restrict Administrative Privileges ML1-ML3",
                CyberEssentials = "Cyber Essentials v3.3: User access control",
                FedRAMP = "AC-2(3), AC-2(12)",
            },
            ["IA11"] = new()
            {
                NIST = "3.5.2, 3.5.3, 3.13.8",
                CMMC = "IA.L2-3.5.2, IA.L2-3.5.3, SC.L2-3.13.8",
                PCI = "4.2.1, 8.3.6, 8.4.2",
                SOC2 = "CC6.1, CC6.6",
                ISO27001 = "A.5.17, A.8.5, A.8.24",
                STIG = "Kerberos encryption type policy / RC4 deprecation readiness",
                CyberEssentials = "Cyber Essentials v3.3: Secure configuration; User access control",
                FedRAMP = "SC-12, SC-13, SC-23",
            },
            ["IA12"] = new()
            {
                NIST = "3.1.5, 3.1.6, 3.1.7, 3.5.2",
                CMMC = "AC.L2-3.1.5, AC.L2-3.1.6, AC.L2-3.1.7, IA.L2-3.5.2",
                PCI = "7.2.1, 7.2.2, 8.2.4, 8.6.1",
                SOC2 = "CC6.1, CC6.3, CC6.6",
                ISO27001 = "A.5.15, A.5.17, A.8.2, A.8.18",
                STIG = "Windows Server 2025 dMSA / BadSuccessor delegated service account migration exposure",
                E8 = "E8 Restrict Administrative Privileges ML2-ML3",
                CyberEssentials = "Cyber Essentials v3.3: Secure configuration; User access control",
                FedRAMP = "AC-6(1), AC-6(2), IA-5",
            },

            // ──────────────────────────────────────────────
            //  Endpoint Security (EP01 – EP10)
            // ──────────────────────────────────────────────
            ["EP01"] = new()
            {
                NIST = "3.14.1, 3.14.2, 3.14.4, 3.14.5",
                CMMC = "SI.L2-3.14.1, SI.L2-3.14.2",
                PCI = "5.2.1, 5.2.2, 5.3.1, 5.3.2",
                SOC2 = "CC6.8, CC7.1",
                ISO27001 = "A.8.7",
                STIG = "V-254264, V-254265, V-254266",
                E8 = "E8 User Application Hardening ML1-ML3; E8 Configure Microsoft Office Macros ML2-ML3",
                CyberEssentials = "Cyber Essentials v3.3: Malware protection",
                FedRAMP = "SI-3, SI-4, SI-7",
            },
            ["EP02"] = new()
            {
                NIST = "3.8.6, 3.13.11",
                CMMC = "MP.L2-3.8.6, SC.L2-3.13.11",
                PCI = "3.5.1, 9.4.1",
                SOC2 = "CC6.1, CC6.7",
                ISO27001 = "A.8.24",
                STIG = "V-254267, V-254268",
                CyberEssentials = "Cyber Essentials v3.3: Secure configuration",
                FedRAMP = "SC-28, SC-28(1), MP-5",
            },
            ["EP03"] = new()
            {
                NIST = "3.1.13, 3.13.1, 3.13.8",
                CMMC = "AC.L2-3.1.13, SC.L2-3.13.1",
                PCI = "2.2.7, 4.2.1",
                SOC2 = "CC6.1, CC6.7",
                ISO27001 = "A.8.20, A.8.24",
                STIG = "V-254269, V-254270, V-254271",
                CyberEssentials = "Cyber Essentials v3.3: Secure configuration",
                FedRAMP = "AC-17(2), SC-8, SC-23",
            },
            ["EP04"] = new()
            {
                NIST = "3.14.1, 3.4.8, 3.4.9",
                CMMC = "SI.L2-3.14.1, CM.L2-3.4.8",
                PCI = "6.3.1, 6.3.3",
                SOC2 = "CC7.1, CC8.1",
                ISO27001 = "A.8.8, A.8.19",
                STIG = "V-254272, V-254273",
                E8 = "E8 Patch Applications ML1-ML3; E8 Patch Operating Systems ML1-ML3",
                CyberEssentials = "Cyber Essentials v3.3: Security update management",
                FedRAMP = "RA-5, SI-2, SI-5",
            },
            ["EP05"] = new()
            {
                NIST = "3.1.5, 3.1.6, 3.4.6",
                CMMC = "AC.L2-3.1.5, AC.L2-3.1.6",
                PCI = "7.2.1, 7.2.2",
                SOC2 = "CC6.1, CC6.3",
                ISO27001 = "A.5.15, A.8.2",
                STIG = "V-254274, V-254275",
                CyberEssentials = "Cyber Essentials v3.3: Firewalls; Secure configuration",
                FedRAMP = "AC-6, CM-5, CM-7",
            },
            ["EP06"] = new()
            {
                NIST = "3.13.1, 3.13.5",
                CMMC = "SC.L2-3.13.1, SC.L2-3.13.5",
                PCI = "1.2.1, 1.3.1, 1.4.1",
                SOC2 = "CC6.1, CC6.6",
                ISO27001 = "A.8.20, A.8.21",
                STIG = "V-254276, V-254277",
                CyberEssentials = "Cyber Essentials v3.3: Secure configuration",
                FedRAMP = "SC-7, SC-7(5), SC-7(8)",
            },
            ["EP07"] = new()
            {
                NIST = "3.4.6, 3.4.8",
                CMMC = "CM.L2-3.4.6, CM.L2-3.4.8",
                PCI = "2.2.4, 6.3.2",
                SOC2 = "CC6.8, CC7.1",
                ISO27001 = "A.8.7, A.8.19",
                STIG = "V-254278, V-254279",
                E8 = "E8 Application Control ML1-ML3; E8 Configure Microsoft Office Macros ML1-ML3",
                CyberEssentials = "Cyber Essentials v3.3: Malware protection; Secure configuration",
                FedRAMP = "CM-7, CM-7(2), CM-7(5)",
            },
            ["EP08"] = new()
            {
                NIST = "3.13.11, 3.14.1",
                CMMC = "SC.L2-3.13.11, SI.L2-3.14.1",
                PCI = "9.4.1, 2.2.1",
                SOC2 = "CC6.1, CC6.7",
                ISO27001 = "A.8.1, A.8.24",
                STIG = "V-254280, V-254281, V-254282",
                CyberEssentials = "Cyber Essentials v3.3: Secure configuration",
                FedRAMP = "SI-7, SI-7(1), SC-13",
            },
            ["EP09"] = new()
            {
                NIST = "3.4.1, 3.4.2",
                CMMC = "CM.L2-3.4.1, CM.L2-3.4.2",
                PCI = "2.2.1, 2.2.2",
                SOC2 = "CC6.1, CC8.1",
                ISO27001 = "A.8.9, A.8.19",
                STIG = "V-254283",
                E8 = "E8 User Application Hardening ML1",
                CyberEssentials = "Cyber Essentials v3.3: Secure configuration",
                FedRAMP = "CM-6, CM-7, SC-18",
            },
            ["EP10"] = new()
            {
                NIST = "3.8.9",
                CMMC = "MP.L2-3.8.9",
                PCI = "9.4.1, 9.4.5",
                SOC2 = "CC6.7",
                ISO27001 = "A.7.9, A.8.1",
                STIG = "V-254284",
                E8 = "E8 Patch Operating Systems ML1-ML3",
                CyberEssentials = "Cyber Essentials v3.3: Security update management",
                FedRAMP = "MA-3, MA-5, PE-16",
            },

            // ──────────────────────────────────────────────
            //  Logging & Monitoring (LM01 – LM08)
            // ──────────────────────────────────────────────
            ["LM01"] = new()
            {
                NIST = "3.3.1, 3.3.2",
                CMMC = "AU.L2-3.3.1, AU.L2-3.3.2",
                PCI = "10.2.1, 10.2.2",
                SOC2 = "CC7.2, CC7.3",
                ISO27001 = "A.8.15, A.8.16",
                STIG = "V-254285, V-254286",
                FedRAMP = "AU-2, AU-3, AU-12",
            },
            ["LM02"] = new()
            {
                NIST = "3.3.1, 3.3.4",
                CMMC = "AU.L2-3.3.1, AU.L2-3.3.4",
                PCI = "10.3.1, 10.3.3",
                SOC2 = "CC7.2, CC7.3",
                ISO27001 = "A.8.15, A.8.16",
                STIG = "V-254287",
                E8 = "E8 Application Control ML2-ML3; E8 User Application Hardening ML3",
                FedRAMP = "AU-2, AU-3(1), AU-12",
            },
            ["LM03"] = new()
            {
                NIST = "3.3.1, 3.3.2, 3.3.8",
                CMMC = "AU.L2-3.3.1, AU.L2-3.3.2",
                PCI = "10.2.1, 10.2.2, 10.6.3",
                SOC2 = "CC7.2, CC7.3",
                ISO27001 = "A.8.15, A.8.16",
                STIG = "V-254288, V-254289, V-254290",
                E8 = "E8 Application Control ML2-ML3; E8 User Application Hardening ML3",
                FedRAMP = "AU-2, AU-3, AU-6",
            },
            ["LM04"] = new()
            {
                NIST = "3.3.1, 3.13.1",
                CMMC = "AU.L2-3.3.1, SC.L2-3.13.1",
                PCI = "10.2.1, 1.2.1",
                SOC2 = "CC7.2",
                ISO27001 = "A.8.15, A.8.20",
                STIG = "V-254291",
                FedRAMP = "AU-2, SC-7(4)",
            },
            ["LM05"] = new()
            {
                NIST = "3.3.3, 3.3.4",
                CMMC = "AU.L2-3.3.3, AU.L2-3.3.4",
                PCI = "10.3.1, 10.3.2",
                SOC2 = "CC7.2, CC7.3",
                ISO27001 = "A.8.15, A.8.16",
                STIG = "V-254292",
                FedRAMP = "AU-6, AU-7, AU-9",
            },
            ["LM06"] = new()
            {
                NIST = "3.3.5",
                CMMC = "AU.L2-3.3.5",
                PCI = "10.3.4, 10.5.1",
                SOC2 = "CC7.2, CC7.4",
                ISO27001 = "A.8.15",
                STIG = "V-254293",
                FedRAMP = "AU-9, AU-9(4), AU-11",
            },
            ["LM07"] = new()
            {
                NIST = "3.3.4, 3.3.8",
                CMMC = "AU.L2-3.3.4, AU.L2-3.3.8",
                PCI = "10.5.1, 10.7.1",
                SOC2 = "CC7.2",
                ISO27001 = "A.8.15",
                STIG = "V-254294, V-254295",
                FedRAMP = "AU-4, AU-5, AU-11",
            },
            ["LM08"] = new()
            {
                NIST = "3.3.1, 3.6.1",
                CMMC = "AU.L2-3.3.1, IR.L2-3.6.1",
                PCI = "10.4.1, 10.7.2",
                SOC2 = "CC7.2, CC7.3",
                ISO27001 = "A.8.15, A.8.16",
                STIG = "V-254296",
                E8 = "E8 User Application Hardening ML3",
                FedRAMP = "AU-6(1), IR-4, SI-4",
            },

            // ──────────────────────────────────────────────
            //  Network Architecture (NA01 – NA07)
            // ──────────────────────────────────────────────
            ["NA01"] = new()
            {
                NIST = "3.13.1, 3.13.2",
                CMMC = "SC.L2-3.13.1, SC.L2-3.13.2",
                PCI = "1.2.1, 1.3.1, 1.3.2",
                SOC2 = "CC6.1, CC6.6",
                ISO27001 = "A.8.20, A.8.22",
                STIG = "V-254297",
                FedRAMP = "SC-7, SC-7(4), SC-7(5)",
            },
            ["NA02"] = new()
            {
                NIST = "3.13.1, 3.13.2",
                CMMC = "SC.L2-3.13.1, SC.L2-3.13.2",
                PCI = "1.2.1, 1.3.1",
                SOC2 = "CC6.1",
                ISO27001 = "A.8.20, A.8.22",
                STIG = "V-254298",
                FedRAMP = "SC-7, SC-7(4)",
            },
            ["NA03"] = new()
            {
                NIST = "3.13.2, 3.13.6",
                CMMC = "SC.L2-3.13.2, SC.L2-3.13.6",
                PCI = "1.2.1, 1.3.2",
                SOC2 = "CC6.6",
                ISO27001 = "A.8.20",
                STIG = "V-254299",
                E8 = "E8 Multi-factor Authentication ML1-ML3",
                FedRAMP = "SC-7(5), SC-7(18)",
            },
            ["NA04"] = new()
            {
                NIST = "3.13.1, 3.13.7",
                CMMC = "SC.L2-3.13.1",
                PCI = "11.3.1, 11.3.2",
                SOC2 = "CC7.1",
                ISO27001 = "A.8.20, A.8.21",
                STIG = "V-254300",
                FedRAMP = "SC-7, RA-5",
            },
            ["NA05"] = new()
            {
                NIST = "3.1.20",
                CMMC = "AC.L2-3.1.20",
                PCI = "1.4.1",
                SOC2 = "CC6.6",
                ISO27001 = "A.8.20",
                STIG = "V-254301",
                FedRAMP = "AC-20, SC-7(7)",
            },
            ["NA06"] = new()
            {
                NIST = "3.13.3",
                CMMC = "SC.L2-3.13.3",
                PCI = "11.4.1",
                SOC2 = "CC7.1, CC7.2",
                ISO27001 = "A.8.16, A.8.23",
                STIG = "V-254302",
                FedRAMP = "SC-7, SC-7(4), SC-7(8)",
            },
            ["NA07"] = new()
            {
                NIST = "3.13.1",
                CMMC = "SC.L2-3.13.1",
                PCI = "1.2.5",
                SOC2 = "CC6.6",
                ISO27001 = "A.8.20",
                STIG = "V-254303",
                FedRAMP = "SC-7(5), SC-7(12)",
            },

            // ──────────────────────────────────────────────
            //  Network Protocols (NP01 – NP10)
            // ──────────────────────────────────────────────
            ["NP01"] = new()
            {
                NIST = "3.13.1, 3.13.5",
                CMMC = "SC.L2-3.13.1, SC.L2-3.13.5",
                PCI = "1.2.1, 1.3.1, 1.4.1",
                SOC2 = "CC6.1, CC6.6",
                ISO27001 = "A.8.20, A.8.21",
                STIG = "V-254304, V-254305",
                CyberEssentials = "Cyber Essentials v3.3: Firewalls",
                FedRAMP = "SC-7, SC-7(4), SC-7(5)",
            },
            ["NP02"] = new()
            {
                NIST = "3.13.1, 3.13.5",
                CMMC = "SC.L2-3.13.1, SC.L2-3.13.5",
                PCI = "11.3.1, 11.3.2",
                SOC2 = "CC6.6, CC7.1",
                ISO27001 = "A.8.20, A.8.34",
                STIG = "V-254306",
                CyberEssentials = "Cyber Essentials v3.3: Firewalls",
                FedRAMP = "SC-7(4), SC-7(5)",
            },
            ["NP03"] = new()
            {
                NIST = "3.1.12, 3.1.20",
                CMMC = "AC.L2-3.1.12, AC.L2-3.1.20",
                PCI = "1.4.1, 8.2.1",
                SOC2 = "CC6.1, CC6.6",
                ISO27001 = "A.8.20",
                STIG = "V-254307",
                CyberEssentials = "Cyber Essentials v3.3: User access control; Firewalls",
                E8 = "E8 Multi-factor Authentication ML1-ML3",
                FedRAMP = "SC-7(5), SC-7(8), SC-7(18)",
            },
            ["NP04"] = new()
            {
                NIST = "3.13.1, 3.13.15",
                CMMC = "SC.L2-3.13.1",
                PCI = "1.2.5, 11.5.1",
                SOC2 = "CC6.6, CC6.8",
                ISO27001 = "A.8.20, A.8.23",
                STIG = "V-254308",
                CyberEssentials = "Cyber Essentials v3.3: Malware protection",
                FedRAMP = "SC-20, SC-21, SC-22",
            },
            ["NP05"] = new()
            {
                NIST = "3.13.1, 3.13.6",
                CMMC = "SC.L2-3.13.1, SC.L2-3.13.6",
                PCI = "1.2.1, 1.3.1",
                SOC2 = "CC6.6",
                ISO27001 = "A.8.20, A.8.21",
                STIG = "V-254309",
                CyberEssentials = "Cyber Essentials v3.3: Firewalls",
                FedRAMP = "SC-7(4)",
            },
            ["NP06"] = new()
            {
                NIST = "3.13.1, 3.13.8",
                CMMC = "SC.L2-3.13.1, SC.L2-3.13.8",
                PCI = "11.5.1",
                SOC2 = "CC6.6, CC7.1",
                ISO27001 = "A.8.20, A.8.21",
                STIG = "V-254310",
                CyberEssentials = "Cyber Essentials v3.3: Firewalls",
                FedRAMP = "SC-7(5), SC-7(8)",
            },
            ["NP07"] = new()
            {
                NIST = "3.13.1, 3.14.6",
                CMMC = "SC.L2-3.13.1, SI.L2-3.14.6",
                PCI = "11.5.1, 11.6.1",
                SOC2 = "CC6.8, CC7.1",
                ISO27001 = "A.8.16, A.8.23",
                STIG = "V-254311",
                FedRAMP = "SC-7(4), SC-7(5)",
            },
            ["NP08"] = new()
            {
                NIST = "3.13.8, 3.13.11",
                CMMC = "SC.L2-3.13.8, SC.L2-3.13.11",
                PCI = "4.2.1, 4.2.2",
                SOC2 = "CC6.1, CC6.7",
                ISO27001 = "A.8.24",
                STIG = "V-254312, V-254313",
                FedRAMP = "SC-7, SC-7(4)",
            },
            ["NP09"] = new()
            {
                NIST = "3.13.1, 3.13.5",
                CMMC = "SC.L2-3.13.1, SC.L2-3.13.5",
                PCI = "1.2.1, 1.3.1",
                SOC2 = "CC6.6",
                ISO27001 = "A.8.20",
                STIG = "V-254314",
                CyberEssentials = "Cyber Essentials v3.3: Firewalls",
                FedRAMP = "SC-7(5), SC-7(12)",
            },
            ["NP10"] = new()
            {
                NIST = "3.4.8, 3.14.1",
                CMMC = "CM.L2-3.4.8, SI.L2-3.14.1",
                PCI = "6.3.1, 6.3.3",
                SOC2 = "CC7.1, CC8.1",
                ISO27001 = "A.8.8, A.8.19",
                STIG = "V-254315",
                CyberEssentials = "Cyber Essentials v3.3: Security update management",
                E8 = "E8 Patch Applications ML1-ML3",
                FedRAMP = "SI-2, RA-5",
            },

            // ──────────────────────────────────────────────
            //  Backup & Recovery (BR01 – BR08)
            // ──────────────────────────────────────────────
            ["BR01"] = new()
            {
                NIST = "3.8.9",
                CMMC = "MP.L2-3.8.9",
                PCI = "12.10.1",
                SOC2 = "CC7.5, A1.2",
                ISO27001 = "A.8.13",
                STIG = "V-254316",
                E8 = "E8 Regular Backups ML1-ML3",
                FedRAMP = "CP-9, CP-10",
            },
            ["BR02"] = new()
            {
                NIST = "3.8.9",
                CMMC = "MP.L2-3.8.9",
                PCI = "12.10.1",
                SOC2 = "CC7.5, A1.2",
                ISO27001 = "A.8.13, A.8.14",
                STIG = "V-254317",
                E8 = "E8 Regular Backups ML1-ML3",
                FedRAMP = "CP-9(1), CP-10",
            },
            ["BR03"] = new()
            {
                NIST = "3.6.1, 3.6.2",
                CMMC = "IR.L2-3.6.1, IR.L2-3.6.2",
                PCI = "12.10.1, 12.10.2",
                SOC2 = "CC7.4, CC7.5, A1.2",
                ISO27001 = "A.5.29, A.5.30, A.8.14",
                STIG = "V-254318",
                E8 = "E8 Regular Backups ML2-ML3",
                FedRAMP = "CP-9, CP-9(1), CP-10",
            },
            ["BR04"] = new()
            {
                NIST = "3.8.9",
                CMMC = "MP.L2-3.8.9",
                PCI = "12.10.1",
                SOC2 = "A1.2",
                ISO27001 = "A.8.13",
                STIG = "V-254319",
                E8 = "E8 Regular Backups ML1-ML3",
                FedRAMP = "CP-9, CP-10, SC-28",
            },
            ["BR05"] = new()
            {
                NIST = "3.6.1, 3.6.3",
                CMMC = "IR.L2-3.6.1, IR.L2-3.6.3",
                PCI = "12.10.1, 12.10.2",
                SOC2 = "CC7.4, CC7.5, A1.2",
                ISO27001 = "A.5.29, A.5.30",
                STIG = "V-254320",
                E8 = "E8 Regular Backups ML2-ML3",
                FedRAMP = "CP-2, CP-4",
            },
            ["BR06"] = new()
            {
                NIST = "3.8.9",
                CMMC = "MP.L2-3.8.9",
                PCI = "12.10.1",
                SOC2 = "A1.2, A1.3",
                ISO27001 = "A.8.13",
                STIG = "V-254321",
                E8 = "E8 Regular Backups ML1-ML3",
                FedRAMP = "CP-9(1), CP-10",
            },
            ["BR07"] = new()
            {
                NIST = "3.13.11",
                CMMC = "SC.L2-3.13.11",
                PCI = "3.5.1, 9.4.1",
                SOC2 = "CC6.7, A1.2",
                ISO27001 = "A.8.13, A.8.24",
                STIG = "V-254322",
                E8 = "E8 Regular Backups ML2-ML3",
                FedRAMP = "CP-2, CP-4",
            },
            ["BR08"] = new()
            {
                NIST = "3.6.1",
                CMMC = "IR.L2-3.6.1",
                PCI = "12.10.1",
                SOC2 = "CC7.5, A1.2",
                ISO27001 = "A.5.29, A.8.13",
                STIG = "V-254323",
                E8 = "E8 Regular Backups ML1-ML3",
                FedRAMP = "CP-2, CP-4, CP-7",
            },

            // ──────────────────────────────────────────────
            //  Configuration (CF01 – CF08)
            // ──────────────────────────────────────────────
            ["CF01"] = new()
            {
                NIST = "3.1.5, 3.7.5, 3.13.8",
                CMMC = "AC.L2-3.1.5, SC.L2-3.13.8",
                PCI = "7.2.2, 8.6.1, 8.6.2",
                SOC2 = "CC6.1, CC6.3",
                ISO27001 = "A.5.15, A.5.17, A.8.5",
                STIG = "V-254324, V-254325",
                E8 = "E8 Restrict Administrative Privileges ML1-ML3",
                CyberEssentials = "Cyber Essentials v3.3: User access control",
                FedRAMP = "IA-5, SC-12, SC-17",
            },
            ["CF02"] = new()
            {
                NIST = "3.4.6, 3.4.7",
                CMMC = "CM.L2-3.4.6, CM.L2-3.4.7",
                PCI = "2.2.4, 2.2.7",
                SOC2 = "CC6.1, CC6.8",
                ISO27001 = "A.8.19, A.8.20",
                STIG = "V-254326",
                CyberEssentials = "Cyber Essentials v3.3: Secure configuration; Firewalls",
                FedRAMP = "AC-4, SC-7, SC-8",
            },
            ["CF03"] = new()
            {
                NIST = "3.2.1, 3.2.2",
                CMMC = "AT.L2-3.2.1, AT.L2-3.2.2",
                PCI = "12.6.1, 12.6.2",
                SOC2 = "CC1.4, CC2.2",
                ISO27001 = "A.6.3",
                STIG = "V-254327",
                E8 = "E8 Regular Backups ML1-ML3",
                FedRAMP = "CM-6, CM-7, AC-3",
            },
            ["CF04"] = new()
            {
                NIST = "3.1.1, 3.1.2",
                CMMC = "AC.L2-3.1.1, AC.L2-3.1.2",
                PCI = "7.2.1, 7.2.4",
                SOC2 = "CC6.1, CC6.3",
                ISO27001 = "A.5.15, A.8.3",
                STIG = "V-254328",
                CyberEssentials = "Cyber Essentials v3.3: Secure configuration",
                FedRAMP = "CM-6, SC-8",
            },
            ["CF05"] = new()
            {
                NIST = "3.1.1, 3.8.1",
                CMMC = "AC.L2-3.1.1, MP.L2-3.8.1",
                PCI = "7.2.4",
                SOC2 = "CC6.1, CC6.3",
                ISO27001 = "A.5.15, A.8.3",
                STIG = "V-254329",
                CyberEssentials = "Cyber Essentials v3.3: Secure configuration",
                FedRAMP = "CM-6, CM-7",
            },
            ["CF06"] = new()
            {
                NIST = "3.1.17",
                CMMC = "AC.L2-3.1.17",
                PCI = "7.2.5",
                SOC2 = "CC6.1",
                ISO27001 = "A.5.15, A.8.20",
                STIG = "V-254330",
                CyberEssentials = "Cyber Essentials v3.3: Secure configuration",
                FedRAMP = "CM-2, CM-6, CM-7",
            },
            ["CF07"] = new()
            {
                NIST = "3.1.5, 3.1.6",
                CMMC = "AC.L2-3.1.5, AC.L2-3.1.6",
                PCI = "7.2.1, 7.2.2",
                SOC2 = "CC6.1, CC6.3",
                ISO27001 = "A.5.15, A.8.2",
                STIG = "V-254331",
                E8 = "E8 Restrict Administrative Privileges ML1-ML3",
                CyberEssentials = "Cyber Essentials v3.3: User access control",
                FedRAMP = "AC-6, AU-9",
            },
            ["CF08"] = new()
            {
                NIST = "3.14.1, 3.14.6",
                CMMC = "SI.L2-3.14.1, SI.L2-3.14.6",
                PCI = "5.2.1, 11.5.1",
                SOC2 = "CC7.1, CC7.2",
                ISO27001 = "A.8.7, A.8.8",
                STIG = "V-254332",
                CyberEssentials = "Cyber Essentials v3.3: Malware protection",
                FedRAMP = "CM-7, SC-7(4)",
            },

            // ──────────────────────────────────────────────
            //  Physical Security (PS01 – PS06)
            // ──────────────────────────────────────────────
            ["PS01"] = new()
            {
                NIST = "3.12.1, 3.12.4",
                CMMC = "CA.L2-3.12.1, CA.L2-3.12.4",
                PCI = "12.1.1, 12.1.2",
                SOC2 = "CC1.1, CC1.2, CC5.2",
                ISO27001 = "A.5.1, A.5.2",
                STIG = "V-254333",
                FedRAMP = "PE-2, PE-3, PE-6",
            },
            ["PS02"] = new()
            {
                NIST = "3.12.1, 3.12.3",
                CMMC = "CA.L2-3.12.1, CA.L2-3.12.3",
                PCI = "12.1.1",
                SOC2 = "CC1.1, CC1.2",
                ISO27001 = "A.5.1",
                STIG = "V-254334",
                FedRAMP = "PE-1, PE-3, PE-6(1)",
            },
            ["PS03"] = new()
            {
                NIST = "3.6.1, 3.6.2, 3.6.3",
                CMMC = "IR.L2-3.6.1, IR.L2-3.6.2, IR.L2-3.6.3",
                PCI = "12.10.1, 12.10.2",
                SOC2 = "CC7.3, CC7.4, CC7.5",
                ISO27001 = "A.5.24, A.5.25, A.5.26",
                STIG = "V-254335",
                FedRAMP = "PE-4, PE-5, PE-9",
            },
            ["PS04"] = new()
            {
                NIST = "3.12.1",
                CMMC = "CA.L2-3.12.1",
                PCI = "12.4.1",
                SOC2 = "CC1.1, CC4.1, CC4.2",
                ISO27001 = "A.5.35, A.5.36",
                STIG = "V-254336",
                FedRAMP = "PE-14, PE-15, PE-18",
            },
            ["PS05"] = new()
            {
                NIST = "3.12.2",
                CMMC = "CA.L2-3.12.2",
                PCI = "12.1.2, 12.3.1",
                SOC2 = "CC3.1, CC3.2",
                ISO27001 = "A.5.7, A.5.8",
                STIG = "V-254337",
                FedRAMP = "PE-3(1), PE-6, PE-8",
            },
            ["PS06"] = new()
            {
                NIST = "3.2.1, 3.2.2",
                CMMC = "AT.L2-3.2.1, AT.L2-3.2.2",
                PCI = "12.6.1, 12.6.2, 12.6.3",
                SOC2 = "CC1.4, CC2.2",
                ISO27001 = "A.6.3",
                STIG = "V-254338",
                FedRAMP = "PE-17",
            },
        }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase));

    public static FrozenDictionary<string, ComplianceMapping> All => _all.Value;
}
