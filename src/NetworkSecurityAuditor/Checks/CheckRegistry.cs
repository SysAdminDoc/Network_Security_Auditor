namespace NetworkSecurityAuditor.Checks;

using NetworkSecurityAuditor.Checks.CommonFindings;
using NetworkSecurityAuditor.Checks.EndpointSecurity;
using NetworkSecurityAuditor.Checks.IdentityAccess;
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
        Register(checks, new EP04_PatchComplianceCheck());
        Register(checks, new EP05_LocalAdminCheck());
        Register(checks, new EP06_HostFirewallCheck());
        Register(checks, new EP07_AppControlCheck());
        Register(checks, new EP08_CredentialGuardCheck());
        Register(checks, new EP09_AutoRunCheck());
        Register(checks, new EP10_EolOsCheck());

        // Logging & Monitoring
        Register(checks, new LM01_DnsLoggingCheck());
        Register(checks, new LM02_SiemCheck());
        Register(checks, new LM03_AuditPolicyCheck());
        Register(checks, new LM04_FirewallLoggingCheck());
        Register(checks, new LM05_FailedLogonCheck());
        Register(checks, new LM06_FimCheck());
        Register(checks, new LM07_LogRetentionCheck());
        Register(checks, new LM08_AlertingCheck());

        // Common Findings
        Register(checks, new CF07_LocalAdminRightsCheck());

        // Network Perimeter
        Register(checks, new NP01_FirewallRulesCheck());

        // Network Architecture
        Register(checks, new NA01_SegmentationCheck());

        // Identity & Access
        Register(checks, new IA01_PrivilegedGroupsCheck());
        Register(checks, new IA02_ServiceAccountCheck());
        Register(checks, new IA03_MfaSignalsCheck());
        Register(checks, new IA04_StaleAccountCheck());
        Register(checks, new IA05_PasswordPolicyCheck());
        Register(checks, new IA06_PamCheck());
        Register(checks, new IA07_SharedAccountsCheck());
        Register(checks, new IA08_VendorAccountsCheck());
        Register(checks, new IA09_RemoteAccessCheck());
        Register(checks, new IA10_InactiveAccountsCheck());
        Register(checks, new IA11_KerberosEncryptionCheck());
        Register(checks, new IA12_DmsaCheck());

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
