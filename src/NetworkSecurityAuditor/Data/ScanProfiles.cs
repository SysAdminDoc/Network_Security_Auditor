using System.Collections.Frozen;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Data;

/// <summary>
/// Scan profile definitions mapping each <see cref="ScanProfileType"/> to its included check IDs.
/// Empty arrays indicate dynamic population: Full/CMMC/ISO27001/STIG/FedRAMP = all checks,
/// ADOnly/LocalOnly = filtered by <see cref="CheckType"/>.
/// </summary>
public static class ScanProfiles
{
    private static FrozenDictionary<ScanProfileType, string[]>? s_profiles;

    public static FrozenDictionary<ScanProfileType, string[]> All => s_profiles ??= BuildProfiles();

    private static FrozenDictionary<ScanProfileType, string[]> BuildProfiles()
    {
        var profiles = new Dictionary<ScanProfileType, string[]>
        {
            // ── Triage Profiles ─────────────────────────────────────────────
            [ScanProfileType.Quick] = new[]
            {
                "NP01", "NP02", "NP07", "NP08",
                "IA01", "IA02", "IA03", "IA04", "IA05", "IA11", "IA12",
                "EP01", "EP02", "EP04", "EP05",
                "LM01", "LM02",
                "BR01", "BR06",
                "CF01", "CF02", "CF05"
            },

            [ScanProfileType.Standard] = new[]
            {
                "NP01", "NP02", "NP03", "NP04", "NP05", "NP07", "NP08", "NP09", "NP10",
                "IA01", "IA02", "IA03", "IA04", "IA05", "IA06", "IA07", "IA08", "IA09", "IA10", "IA11", "IA12",
                "EP01", "EP02", "EP03", "EP04", "EP05", "EP06", "EP07", "EP08",
                "LM01", "LM02", "LM03", "LM04", "LM06", "LM08",
                "BR01", "BR02", "BR03", "BR05", "BR06", "BR08",
                "CF01", "CF02", "CF03", "CF04", "CF05",
                "NA01", "NA02", "NA03", "NA04",
                "PS01", "PS04"
            },

            // Empty = all checks
            [ScanProfileType.Full] = Array.Empty<string>(),

            // Empty = dynamically filtered by CheckType at runtime
            [ScanProfileType.ADOnly] = Array.Empty<string>(),
            [ScanProfileType.LocalOnly] = Array.Empty<string>(),

            // Cloud profile placeholder (Graph-backed checks)
            [ScanProfileType.Cloud] = Array.Empty<string>(),

            // ── Framework-Specific Profiles ─────────────────────────────────
            [ScanProfileType.HIPAA] = new[]
            {
                "IA01", "IA02", "IA03", "IA04", "IA05", "IA06", "IA07", "IA08", "IA09", "IA10", "IA11", "IA12",
                "EP01", "EP02", "EP03", "EP04", "EP05", "EP06", "EP07", "EP08", "EP09", "EP10",
                "LM01", "LM02", "LM03", "LM04", "LM05", "LM06", "LM07", "LM08",
                "BR01", "BR02", "BR03", "BR04", "BR05", "BR06", "BR07", "BR08",
                "CF01", "CF02", "CF03", "CF05", "CF07",
                "NP01", "NP02", "NP08",
                "PS01", "PS03", "PS04"
            },

            [ScanProfileType.PCI] = new[]
            {
                "NP01", "NP02", "NP03", "NP04", "NP05", "NP08", "NP09", "NP10",
                "IA01", "IA02", "IA03", "IA04", "IA05", "IA06", "IA07", "IA08", "IA09", "IA11", "IA12",
                "EP01", "EP02", "EP03", "EP04", "EP05", "EP06", "EP07", "EP08",
                "LM01", "LM02", "LM03", "LM04", "LM05", "LM06", "LM07", "LM08",
                "NA01", "NA02", "NA04",
                "BR01", "BR02", "BR03", "BR05",
                "CF01", "CF02", "CF04", "CF05",
                "PS01", "PS03", "PS04", "PS05", "PS06"
            },

            // All checks apply
            [ScanProfileType.CMMC] = Array.Empty<string>(),

            [ScanProfileType.E8] = new[]
            {
                "EP01", "EP04", "EP07", "EP09", "EP10",
                "IA01", "IA02", "IA03", "IA06", "IA09", "IA10", "IA12",
                "CF01", "CF03", "CF07",
                "BR01", "BR02", "BR03", "BR04", "BR05", "BR06", "BR07", "BR08",
                "LM02", "LM03", "LM08",
                "NP03", "NP10"
            },

            [ScanProfileType.CyberEssentials] = new[]
            {
                "NP01", "NP02", "NP03", "NP04", "NP05", "NP06", "NP09", "NP10",
                "IA01", "IA02", "IA03", "IA04", "IA05", "IA06", "IA07", "IA08", "IA09", "IA10", "IA11", "IA12",
                "EP01", "EP02", "EP03", "EP04", "EP05", "EP06", "EP07", "EP08", "EP09", "EP10",
                "CF01", "CF02", "CF04", "CF05", "CF06", "CF07", "CF08"
            },

            [ScanProfileType.SOC2] = new[]
            {
                "IA01", "IA02", "IA03", "IA04", "IA05", "IA06", "IA07", "IA08", "IA09", "IA10", "IA11", "IA12",
                "EP01", "EP02", "EP03", "EP04", "EP05", "EP06", "EP07", "EP08", "EP09",
                "LM01", "LM02", "LM03", "LM04", "LM05", "LM06", "LM07", "LM08",
                "NA01", "NA02", "NA03", "NA04", "NA05", "NA06",
                "NP01", "NP02", "NP03", "NP04", "NP05", "NP06", "NP07", "NP08", "NP09", "NP10",
                "BR01", "BR02", "BR03", "BR04", "BR05", "BR06", "BR07", "BR08",
                "CF01", "CF02", "CF03", "CF04", "CF05", "CF06", "CF07", "CF08",
                "PS01", "PS02", "PS03", "PS04", "PS05", "PS06"
            },

            // All checks apply
            [ScanProfileType.ISO27001] = Array.Empty<string>(),

            // All checks apply
            [ScanProfileType.STIG] = Array.Empty<string>(),

            // All checks apply
            [ScanProfileType.FedRAMP] = Array.Empty<string>()
        };

        return profiles.ToFrozenDictionary();
    }

    /// <summary>
    /// Resolves the effective check ID list for a profile, expanding empty arrays
    /// to all checks (Full/CMMC/ISO27001/STIG/FedRAMP) or filtering by <see cref="CheckType"/>
    /// (ADOnly/LocalOnly).
    /// </summary>
    public static string[] Resolve(ScanProfileType profile)
    {
        var ids = All[profile];

        // Non-empty = explicit list
        if (ids.Length > 0)
            return ids;

        // Dynamic type-filtered profiles
        if (profile == ScanProfileType.ADOnly)
            return CheckCatalog.All.Values
                .Where(m => m.Type == CheckType.AD)
                .Select(m => m.Id)
                .Order()
                .ToArray();

        if (profile == ScanProfileType.LocalOnly)
            return CheckCatalog.All.Values
                .Where(m => m.Type == CheckType.Local)
                .Select(m => m.Id)
                .Order()
                .ToArray();

        // Full / CMMC / ISO27001 / STIG / FedRAMP / Cloud = all checks
        return CheckCatalog.All.Keys.Order().ToArray();
    }
}
