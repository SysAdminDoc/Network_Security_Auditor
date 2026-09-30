namespace NetworkSecurityAuditor.Checks.NetworkPerimeter;

using System.Management;
using System.Text;
using System.Text.RegularExpressions;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// NP06 - Temporary Firewall Rules: Check firewall rules for stale/temporary indicators --
/// rules whose name or description has a word like "temp", "test" or "old", or a date. Only names and
/// descriptions are needed, so the rules are read from the active store without their filters,
/// which works without elevation and includes Group Policy and service-added rules.
/// </summary>
public sealed partial class NP06_TempRulesCheck : ISecurityCheck
{
    private readonly Func<CancellationToken, string?, IReadOnlyList<FirewallRuleSnapshot>> _readRules;
    private readonly Func<string, string, CancellationToken, string> _runCommand;

    public string Id => "NP06";

    public NP06_TempRulesCheck()
        : this(null, null)
    {
    }

    internal NP06_TempRulesCheck(
        Func<CancellationToken, string?, IReadOnlyList<FirewallRuleSnapshot>>? readRules,
        Func<string, string, CancellationToken, string>? runCommand = null)
    {
        _readRules = readRules ?? ((ct, store) => FirewallRuleReader.GetEnabledRules(ct, store, includeFilters: false));
        _runCommand = runCommand ?? ((file, args, ct) => CommandRunner.RunForOutput(file, args, TimeSpan.FromSeconds(30), ct));
    }

    // Whole words (or word sequences) only: a substring match flagged "Droplet Template", "Google Chrome for
    // Testing" and "Folder". "backup" and "vendor" aren't here because backup agents and vendor tools keep
    // permanent rules. The PS1 NP06 block carries the same list, and a test keeps them identical.
    internal static readonly string[] StaleIndicators =
    [
        "temp", "temporary", "tmp", "test", "old", "delete", "remove", "deprecated", "disable",
        "unused", "trial", "debug", "troubleshoot", "fixme", "todo", "copy of"
    ];

    // More enabled rules than this suggests nobody reviews them. Reported, never scored.
    internal const int HighRuleCount = 200;

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;
            var staleRules = new List<string>();
            int totalRules = 0;

            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("[Firewall Rule Staleness Analysis - active store (local, Group Policy and service rules)]");

            try
            {
                foreach (var rule in _readRules(ct, FirewallRuleReader.ActiveStore))
                {
                    ct.ThrowIfCancellationRequested();
                    totalRules++;

                    string name = rule.Name;
                    string desc = rule.Description;

                    ProcessRuleForStaleness(evidence, staleRules, name, desc);
                }
            }
            catch (ManagementException ex)
            {
                evidence.AppendLine($"  WMI error: {ex.Message}");
                evidence.AppendLine("  netsh reads the local store only; Group Policy and service-added rules aren't included.");
                QueryViaNetsh(evidence, staleRules, ref totalRules, ct);
            }

            evidence.AppendLine($"\n  Total enabled rules: {totalRules}");
            evidence.AppendLine($"  Rules with stale indicators: {staleRules.Count}");

            sb.AppendLine($"Scanned {totalRules} enabled firewall rules for staleness indicators.");
            if (totalRules > HighRuleCount)
                sb.AppendLine($"INFO: {totalRules} enabled rules is a lot to review. A long rule list is where stale rules hide.");

            if (staleRules.Count > 0)
            {
                hasIssue = true;
                sb.AppendLine($"\nWARNING: {staleRules.Count} firewall rule(s) have stale/temporary indicators:");
                foreach (string rule in staleRules.Take(20))
                    sb.AppendLine($"  - {rule}");
                if (staleRules.Count > 20)
                    sb.AppendLine($"  ... and {staleRules.Count - 20} more.");

                sb.AppendLine("\nRecommendation: Review and remove temporary/test firewall rules. " +
                    "Stale rules can create unintended access paths or policy drift.");
            }
            else
            {
                sb.AppendLine("PASS: No rules with obvious stale/temporary naming detected.");
            }

            var status = hasIssue ? CheckStatus.Partial : CheckStatus.Pass;

            return Task.FromResult(new CheckResult
            {
                Status = status,
                Findings = sb.ToString().TrimEnd(),
                Evidence = evidence.ToString().TrimEnd()
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.FromError(Id, ex));
        }
    }

    /// <summary>The indicator found as a whole word or word sequence in <paramref name="text"/>, or null.</summary>
    internal static string? MatchStaleIndicator(string? text)
    {
        if (string.IsNullOrEmpty(text)) return null;
        var words = WordSeparator().Split(text.ToLowerInvariant()).Where(w => w.Length > 0).ToArray();
        foreach (var indicator in StaleIndicators)
        {
            var parts = indicator.Split(' ');
            for (int i = 0; i + parts.Length <= words.Length; i++)
            {
                if (parts.Select((part, k) => words[i + k] == part).All(hit => hit))
                    return indicator;
            }
        }
        return null;
    }

    [GeneratedRegex(@"[^\p{L}\p{Nd}]+")]
    private static partial Regex WordSeparator();

    internal static bool HasDatePattern(string name)
    {
        // Check for common date patterns: YYYY-MM-DD, MM/DD/YYYY, YYYYMMDD
        if (string.IsNullOrEmpty(name)) return false;

        // Look for 4-digit years followed by separators and digits
        for (int i = 0; i <= name.Length - 10; i++)
        {
            if (char.IsAsciiDigit(name[i]) && char.IsAsciiDigit(name[i + 1]) &&
                char.IsAsciiDigit(name[i + 2]) && char.IsAsciiDigit(name[i + 3]))
            {
                int year = int.Parse(name.AsSpan(i, 4));
                if (year is >= 2015 and <= 2030)
                {
                    // Check if followed by separator and more digits
                    if (i + 4 < name.Length && (name[i + 4] is '-' or '/' or '.'))
                        return true;
                }
            }
        }

        return false;
    }

    private void QueryViaNetsh(
        StringBuilder evidence,
        List<string> staleRules,
        ref int totalRules,
        CancellationToken ct)
    {
        try
        {
            string output = _runCommand("netsh", "advfirewall firewall show rule name=all", ct);

            evidence.AppendLine("  [Parsed from netsh output]");

            string currentName = "";
            string currentDescription = "";
            bool currentEnabled = false;

            foreach (var rawLine in output.Split('\n'))
            {
                string line = rawLine.Trim();

                if (line.StartsWith("Rule Name:", StringComparison.OrdinalIgnoreCase))
                {
                    ProcessNetshRule(evidence, staleRules, ref totalRules, currentName, currentDescription, currentEnabled);

                    currentName = line[10..].Trim();
                    currentDescription = "";
                    currentEnabled = false;
                }
                else if (line.StartsWith("Enabled:", StringComparison.OrdinalIgnoreCase))
                {
                    currentEnabled = line.Contains("Yes", StringComparison.OrdinalIgnoreCase);
                }
                else if (line.StartsWith("Description:", StringComparison.OrdinalIgnoreCase))
                {
                    currentDescription = line[12..].Trim();
                }
            }

            ProcessNetshRule(evidence, staleRules, ref totalRules, currentName, currentDescription, currentEnabled);
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  netsh fallback error: {ex.Message}");
        }
    }

    private static void ProcessNetshRule(
        StringBuilder evidence,
        List<string> staleRules,
        ref int totalRules,
        string name,
        string description,
        bool enabled)
    {
        if (string.IsNullOrEmpty(name) || !enabled) return;

        totalRules++;
        ProcessRuleForStaleness(evidence, staleRules, name, description);
    }

    private static void ProcessRuleForStaleness(
        StringBuilder evidence,
        List<string> staleRules,
        string name,
        string desc)
    {
        if ((MatchStaleIndicator(name) ?? MatchStaleIndicator(desc)) is { } indicator)
        {
            staleRules.Add(name);
            evidence.AppendLine($"  STALE INDICATOR: \"{name}\" (matched: \"{indicator}\")");
            if (!string.IsNullOrEmpty(desc))
                evidence.AppendLine($"    Description: {desc}");
        }

        if (HasDatePattern(name) && !staleRules.Contains(name))
        {
            staleRules.Add(name);
            evidence.AppendLine($"  DATE IN NAME: \"{name}\" (may be a temporary rule)");
        }
    }
}
