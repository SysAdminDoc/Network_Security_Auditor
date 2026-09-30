namespace NetworkSecurityAuditor.Checks.EndpointSecurity;

using System.Globalization;
using System.Management;
using System.Text;
using NetworkSecurityAuditor.Checks.NetworkPerimeter;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// EP06 - Windows Firewall profile status, default actions, log sizes, high-risk listeners.
/// Listeners come from NP02's IP Helper read and classification, so default Windows role ports
/// (RPC, NetBIOS, SMB, WinRM) only count when a Public-profile network can reach them.
/// </summary>
public sealed class EP06_HostFirewallCheck : ISecurityCheck
{
    private readonly Func<IReadOnlyList<FirewallProfileSnapshot>> _profileProvider;
    private readonly Func<string, string, CancellationToken, string> _runCommand;
    private readonly Func<CancellationToken, NP02_OpenPortsCheck.PortSnapshot> _portSnapshotProvider;

    public string Id => "EP06";

    internal EP06_HostFirewallCheck(
        Func<IReadOnlyList<FirewallProfileSnapshot>>? profileProvider = null,
        Func<string, string, CancellationToken, string>? runCommand = null,
        Func<CancellationToken, NP02_OpenPortsCheck.PortSnapshot>? portSnapshotProvider = null)
    {
        _profileProvider = profileProvider ?? QueryFirewallProfilesViaWmi;
        _runCommand = runCommand ?? RunCommand;
        _portSnapshotProvider = portSnapshotProvider ?? NP02_OpenPortsCheck.CollectSnapshot;
    }

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasFailure = false;
            bool hasWarning = false;

            // -- Firewall profile status via structured provider first --
            ct.ThrowIfCancellationRequested();
            CheckFirewallProfiles(sb, evidence, ref hasFailure, ref hasWarning, ct);

            // -- High-risk listeners --
            ct.ThrowIfCancellationRequested();
            CheckListeners(sb, evidence, ref hasFailure, ref hasWarning, ct);

            if (!hasFailure && !hasWarning)
                sb.Insert(0, "All Windows Firewall profiles enabled with appropriate defaults.\n");

            var status = hasFailure ? CheckStatus.Fail
                : hasWarning ? CheckStatus.Partial
                : CheckStatus.Pass;

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

    private void CheckFirewallProfiles(
        StringBuilder sb,
        StringBuilder evidence,
        ref bool hasFailure,
        ref bool hasWarning,
        CancellationToken ct)
    {
        evidence.AppendLine("[Firewall Profile Status]");

        try
        {
            var profiles = _profileProvider();
            if (profiles.Count == 0)
                throw new InvalidOperationException("MSFT_NetFirewallProfile returned no profiles.");

            EvaluateFirewallProfiles(profiles, sb, evidence, ref hasFailure, ref hasWarning, ct);
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  WMI profile query failed: {ex.Message}");
            evidence.AppendLine("  Falling back to netsh profile parsing.");

            try
            {
                var netshOutput = _runCommand("netsh", "advfirewall show allprofiles", ct);
                evidence.AppendLine(netshOutput);

                var netshProfiles = ParseNetshProfiles(netshOutput);
                if (netshProfiles.Count == 0)
                    throw new InvalidOperationException("netsh output did not contain parseable firewall profiles.");

                EvaluateFirewallProfiles(netshProfiles, sb, evidence, ref hasFailure, ref hasWarning, ct);
            }
            catch (Exception fallbackEx)
            {
                hasFailure = true;
                evidence.AppendLine($"  netsh profile query failed: {fallbackEx.Message}");
                sb.AppendLine("FAIL: Could not verify Windows Firewall profile status via WMI or netsh.");
            }
        }
    }

    private static IReadOnlyList<FirewallProfileSnapshot> QueryFirewallProfilesViaWmi()
    {
        var profiles = new List<FirewallProfileSnapshot>();
        using var searcher = new ManagementObjectSearcher(
            @"root\StandardCimv2",
            "SELECT Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogBlocked, LogMaxSizeKilobytes FROM MSFT_NetFirewallProfile");
        using var results = searcher.Get();

        foreach (ManagementObject obj in results)
        {
            try
            {
                profiles.Add(new FirewallProfileSnapshot(
                    obj["Name"]?.ToString() ?? "Unknown",
                    ConvertWmiOptionalBool(obj["Enabled"]),
                    ConvertWmiAction(obj["DefaultInboundAction"]),
                    ConvertWmiAction(obj["DefaultOutboundAction"]),
                    ConvertWmiOptionalBool(obj["LogBlocked"]),
                    ConvertWmiOptionalUInt64(obj["LogMaxSizeKilobytes"]),
                    "WMI"));
            }
            finally
            {
                obj.Dispose();
            }
        }

        return profiles;
    }

    internal static IReadOnlyList<FirewallProfileSnapshot> ParseNetshProfiles(string output)
    {
        var profiles = new List<FirewallProfileSnapshot>();
        string? name = null;
        bool? enabled = null;
        FirewallDefaultAction inbound = FirewallDefaultAction.Unknown;
        FirewallDefaultAction outbound = FirewallDefaultAction.Unknown;
        bool? logDropped = null;
        ulong? logMaxSizeKb = null;

        void Flush()
        {
            if (name is null)
                return;

            profiles.Add(new FirewallProfileSnapshot(
                name,
                enabled,
                inbound,
                outbound,
                logDropped,
                logMaxSizeKb,
                "netsh"));
        }

        foreach (var rawLine in output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var line = rawLine.Trim();
            var profileName = TryGetNetshProfileName(line);
            if (profileName is not null)
            {
                Flush();
                name = profileName;
                enabled = null;
                inbound = FirewallDefaultAction.Unknown;
                outbound = FirewallDefaultAction.Unknown;
                logDropped = null;
                logMaxSizeKb = null;
                continue;
            }

            if (name is null)
                continue;

            if (TryGetNetshValue(line, "State", out var state))
            {
                enabled = ParseNetshEnabled(state);
            }
            else if (TryGetNetshValue(line, "Firewall Policy", out var policy))
            {
                inbound = ParseNetshInboundAction(policy);
                outbound = ParseNetshOutboundAction(policy);
            }
            else if (TryGetNetshValue(line, "LogDroppedConnections", out var logDroppedValue))
            {
                logDropped = ParseNetshEnabled(logDroppedValue);
            }
            else if (TryGetNetshValue(line, "LogMaxFileSize", out var logSizeValue) &&
                ulong.TryParse(logSizeValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedLogSize))
            {
                logMaxSizeKb = parsedLogSize;
            }
        }

        Flush();
        return profiles;
    }

    private static void EvaluateFirewallProfiles(
        IReadOnlyList<FirewallProfileSnapshot> profiles,
        StringBuilder sb,
        StringBuilder evidence,
        ref bool hasFailure,
        ref bool hasWarning,
        CancellationToken ct)
    {
        foreach (var profile in profiles)
        {
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine(
                $"  [{profile.Source}] {profile.Name}: Enabled={FormatNullableBool(profile.Enabled)}, " +
                $"InboundDefault={FormatAction(profile.DefaultInboundAction)}, " +
                $"OutboundDefault={FormatAction(profile.DefaultOutboundAction)}, " +
                $"LogDropped={FormatNullableBool(profile.LogDroppedConnections)}, " +
                $"LogMaxSizeKb={profile.LogMaxSizeKb?.ToString(CultureInfo.InvariantCulture) ?? "Unknown"}");

            if (profile.Enabled is not true)
            {
                hasFailure = true;
                sb.AppendLine(profile.Enabled is false
                    ? $"FAIL: Firewall profile '{profile.Name}' is DISABLED."
                    : $"FAIL: Firewall profile '{profile.Name}' enabled state could not be verified.");
            }

            if (profile.DefaultInboundAction != FirewallDefaultAction.Block)
            {
                hasFailure = true;
                sb.AppendLine(
                    $"FAIL: Firewall profile '{profile.Name}' default inbound action is {FormatAction(profile.DefaultInboundAction)}; expected Block.");
            }

            if (profile.LogDroppedConnections is false)
            {
                hasWarning = true;
                sb.AppendLine($"WARNING: Firewall profile '{profile.Name}' dropped-connection logging is disabled.");
            }
        }
    }

    private static string? TryGetNetshProfileName(string line)
    {
        foreach (var name in new[] { "Domain", "Private", "Public" })
        {
            if (line.StartsWith($"{name} Profile", StringComparison.OrdinalIgnoreCase))
                return name;
        }

        return null;
    }

    private static bool TryGetNetshValue(string line, string key, out string value)
    {
        if (!line.StartsWith(key, StringComparison.OrdinalIgnoreCase))
        {
            value = string.Empty;
            return false;
        }

        value = line[key.Length..].Trim();
        return value.Length > 0;
    }

    private static bool? ParseNetshEnabled(string value)
    {
        var normalized = value.Trim();
        if (normalized.StartsWith("ON", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith("Enable", StringComparison.OrdinalIgnoreCase))
            return true;

        if (normalized.StartsWith("OFF", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith("Disable", StringComparison.OrdinalIgnoreCase))
            return false;

        return null;
    }

    private static FirewallDefaultAction ParseNetshInboundAction(string value)
    {
        if (value.Contains("BlockInbound", StringComparison.OrdinalIgnoreCase))
            return FirewallDefaultAction.Block;

        if (value.Contains("AllowInbound", StringComparison.OrdinalIgnoreCase))
            return FirewallDefaultAction.Allow;

        return FirewallDefaultAction.Unknown;
    }

    private static FirewallDefaultAction ParseNetshOutboundAction(string value)
    {
        if (value.Contains("BlockOutbound", StringComparison.OrdinalIgnoreCase))
            return FirewallDefaultAction.Block;

        if (value.Contains("AllowOutbound", StringComparison.OrdinalIgnoreCase))
            return FirewallDefaultAction.Allow;

        return FirewallDefaultAction.Unknown;
    }

    private static FirewallDefaultAction ConvertWmiAction(object? value)
    {
        if (value is null)
            return FirewallDefaultAction.Unknown;

        if (value is string text)
        {
            if (text.Equals("Block", StringComparison.OrdinalIgnoreCase))
                return FirewallDefaultAction.Block;
            if (text.Equals("Allow", StringComparison.OrdinalIgnoreCase))
                return FirewallDefaultAction.Allow;
        }

        try
        {
            return Convert.ToUInt16(value, CultureInfo.InvariantCulture) switch
            {
                2 => FirewallDefaultAction.Allow,
                4 => FirewallDefaultAction.Block,
                _ => FirewallDefaultAction.Unknown
            };
        }
        catch
        {
            return FirewallDefaultAction.Unknown;
        }
    }

    private static bool? ConvertWmiOptionalBool(object? value)
    {
        if (value is null)
            return null;

        if (value is bool boolValue)
            return boolValue;

        if (value is string text)
        {
            if (bool.TryParse(text, out var parsedBool))
                return parsedBool;

            return ParseNetshEnabled(text);
        }

        try
        {
            return Convert.ToUInt64(value, CultureInfo.InvariantCulture) != 0;
        }
        catch
        {
            return null;
        }
    }

    private static ulong? ConvertWmiOptionalUInt64(object? value)
    {
        if (value is null)
            return null;

        try
        {
            return Convert.ToUInt64(value, CultureInfo.InvariantCulture);
        }
        catch
        {
            return null;
        }
    }

    private static string FormatNullableBool(bool? value) => value.HasValue
        ? value.Value.ToString(CultureInfo.InvariantCulture)
        : "Unknown";

    private static string FormatAction(FirewallDefaultAction action) => action switch
    {
        FirewallDefaultAction.Allow => "Allow",
        FirewallDefaultAction.Block => "Block",
        _ => "Unknown"
    };

    /// <summary>
    /// Insecure listeners and role ports a Public-profile network can reach fail; sensitive services
    /// beyond loopback are a warning. Default role ports on a private or domain network are evidence only.
    /// </summary>
    // Half the check didn't run, so it can't pass on the profiles alone.
    private static void ListenersNotChecked(StringBuilder sb, ref bool hasWarning)
    {
        hasWarning = true;
        sb.AppendLine("REVIEW: Listening ports couldn't be read, so high-risk listeners weren't checked.");
    }

    private void CheckListeners(StringBuilder sb, StringBuilder evidence, ref bool hasFailure, ref bool hasWarning, CancellationToken ct)
    {
        evidence.AppendLine("\n[High-Risk Listeners (IP Helper API)]");

        NP02_OpenPortsCheck.PortSnapshot snapshot;
        try
        {
            snapshot = _portSnapshotProvider(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            evidence.AppendLine($"  Listener read failed: {ex.Message}");
            ListenersNotChecked(sb, ref hasWarning);
            return;
        }
        if (snapshot.ListenerError is not null)
        {
            evidence.AppendLine($"  Listeners couldn't be read: {snapshot.ListenerError}");
            ListenersNotChecked(sb, ref hasWarning);
            return;
        }

        var (failures, reviews, informational) = NP02_OpenPortsCheck.Classify(snapshot);
        foreach (var item in failures) evidence.AppendLine($"  FAIL: {item}");
        foreach (var item in reviews) evidence.AppendLine($"  REVIEW: {item}");
        foreach (var item in informational) evidence.AppendLine($"  INFO: {item}");
        evidence.AppendLine($"  Total listening TCP ports: {snapshot.Listeners.Where(l => l.Protocol == "TCP").Select(l => l.Port).Distinct().Count()}");

        if (failures.Count > 0)
        {
            hasFailure = true;
            sb.AppendLine($"FAIL: {failures.Count} high-risk listener(s):");
            foreach (var item in failures)
                sb.AppendLine($"  - {item}");
        }
        if (reviews.Count > 0)
        {
            hasWarning = true;
            sb.AppendLine($"REVIEW: {reviews.Count} sensitive service(s) listening beyond loopback:");
            foreach (var item in reviews)
                sb.AppendLine($"  - {item}");
        }
        if (failures.Count == 0 && reviews.Count == 0)
            sb.AppendLine("PASS: No high-risk listeners, and no default role port is exposed to a Public-profile network.");
    }

    private static bool ContainsProfileDisabled(string output, string profileName)
    {
        // Rough heuristic: find profile section and check if State is OFF
        int idx = output.IndexOf($"{profileName} Profile", StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return false;

        int stateIdx = output.IndexOf("State", idx, StringComparison.OrdinalIgnoreCase);
        if (stateIdx < 0) return false;

        int lineEnd = output.IndexOf('\n', stateIdx);
        string stateLine = lineEnd > stateIdx ? output[stateIdx..lineEnd] : output[stateIdx..];

        return stateLine.Contains("OFF", StringComparison.OrdinalIgnoreCase);
    }

    private static string RunCommand(string fileName, string arguments, CancellationToken ct)
    {
        return CommandRunner.RunForOutput(fileName, arguments, TimeSpan.FromSeconds(30), ct);
    }
}

internal enum FirewallDefaultAction
{
    Unknown,
    Allow,
    Block
}

internal sealed record FirewallProfileSnapshot(
    string Name,
    bool? Enabled,
    FirewallDefaultAction DefaultInboundAction,
    FirewallDefaultAction DefaultOutboundAction,
    bool? LogDroppedConnections,
    ulong? LogMaxSizeKb,
    string Source);
