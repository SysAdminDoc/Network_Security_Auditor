namespace NetworkSecurityAuditor.Checks;

using NetworkSecurityAuditor.Checks.CommonFindings;
using NetworkSecurityAuditor.Checks.EndpointSecurity;
using NetworkSecurityAuditor.Checks.LoggingMonitoring;
using NetworkSecurityAuditor.Checks.NetworkArchitecture;
using NetworkSecurityAuditor.Checks.NetworkPerimeter;
using NetworkSecurityAuditor.Data;

/// <summary>
/// Central registry of all security check implementations.
/// Implemented checks get their real class; unimplemented ones get <see cref="StubCheck"/>.
/// </summary>
public static class CheckRegistry
{
    public static Dictionary<string, ISecurityCheck> GetAllChecks()
    {
        var checks = new Dictionary<string, ISecurityCheck>(StringComparer.OrdinalIgnoreCase);

        // ── Implemented checks ──────────────────────────────────────────────

        // Endpoint Security
        Register(checks, new EP01_AvEdrCheck());
        Register(checks, new EP02_BitLockerCheck());
        Register(checks, new EP03_SmbNtlmCheck());
        Register(checks, new EP05_LocalAdminCheck());
        Register(checks, new EP06_HostFirewallCheck());

        // Logging & Monitoring
        Register(checks, new LM03_AuditPolicyCheck());
        Register(checks, new LM05_FailedLogonCheck());

        // Common Findings
        Register(checks, new CF07_LocalAdminRightsCheck());

        // Network Perimeter
        Register(checks, new NP01_FirewallRulesCheck());

        // Network Architecture
        Register(checks, new NA01_SegmentationCheck());

        // ── Stub all remaining checks from the catalog ──────────────────────
        foreach (var id in CheckCatalog.All.Keys)
        {
            if (!checks.ContainsKey(id))
                checks[id] = new StubCheck(id);
        }

        return checks;
    }

    private static void Register(Dictionary<string, ISecurityCheck> dict, ISecurityCheck check)
    {
        dict[check.Id] = check;
    }
}
