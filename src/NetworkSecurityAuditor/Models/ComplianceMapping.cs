namespace NetworkSecurityAuditor.Models;

public sealed class ComplianceMapping
{
    public string? NIST { get; init; }
    public string? NIST_R3 { get; init; }
    public string? CMMC { get; init; }
    public string? PCI { get; init; }
    public string? SOC2 { get; init; }
    public string? ISO27001 { get; init; }
    public string? STIG { get; init; }
    public string? E8 { get; init; }
    public string? CyberEssentials { get; init; }
    public string? FedRAMP { get; init; }

    public string FormatAll()
    {
        var parts = new List<string>();
        if (NIST is not null) parts.Add($"800-171r2: {NIST}");
        if (NIST_R3 is not null) parts.Add($"800-171r3: {NIST_R3}");
        if (CMMC is not null) parts.Add($"CMMC: {CMMC}");
        if (PCI is not null) parts.Add($"PCI: {PCI}");
        if (SOC2 is not null) parts.Add($"SOC2: {SOC2}");
        if (ISO27001 is not null) parts.Add($"ISO: {ISO27001}");
        if (STIG is not null) parts.Add($"STIG: {STIG}");
        if (E8 is not null) parts.Add($"E8: {E8}");
        if (CyberEssentials is not null) parts.Add($"CE: {CyberEssentials}");
        if (FedRAMP is not null) parts.Add($"FedRAMP: {FedRAMP}");
        return string.Join(" | ", parts);
    }
}
