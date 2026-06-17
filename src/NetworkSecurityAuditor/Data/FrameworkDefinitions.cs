using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Data;

public static class FrameworkDefinitions
{
    public static readonly (string Name, Func<ComplianceMapping, string?> Selector)[] All =
    [
        ("CIS Controls v8.1", m => m.CIS),
        ("NIST 800-171", m => m.NIST),
        ("CMMC Level 2", m => m.CMMC),
        ("HIPAA Security Rule", m => m.HIPAA),
        ("PCI-DSS 4.0.1", m => m.PCI),
        ("SOC 2 Type II", m => m.SOC2),
        ("ISO 27001:2022", m => m.ISO27001),
        ("DISA STIG", m => m.STIG),
        ("FedRAMP Moderate", m => m.FedRAMP),
        ("Essential Eight", m => m.E8),
        ("Cyber Essentials", m => m.CyberEssentials),
    ];
}
