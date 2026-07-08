namespace NetworkSecurityAuditor.Checks.EndpointSecurity;

using System.Globalization;
using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// EP06 - Windows Firewall profile status, default actions, log sizes, high-risk inbound ports.
/// </summary>
public sealed class EP06_HostFirewallCheck : ISecurityCheck
{
    private readonly Func<IReadOnlyList<FirewallProfileSnapshot>> _profileProvider;
    private readonly Func<string, string, CancellationToken, string> _runCommand;

    public string Id => "EP06";

    private static readonly int[] HighRiskPorts =
        [21, 23, 69, 135, 139, 445, 1433, 3389, 5900, 5985, 5986];

    internal EP06_HostFirewallCheck(
        Func<IReadOnlyList<FirewallProfileSnapshot>>? profileProvider = null,
        Func<string, string, CancellationToken, string>? runCommand = null)
    {
        _profileProvider = profileProvider ?? QueryFirewallProfilesViaWmi;
        _runCommand = runCommand ?? RunCommand;
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

            // -- High-risk inbound ports --
            ct.ThrowIfCancellationRequested();
            CheckHighRiskPorts(sb, evidence, ref hasFailure, ct);

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

    private void CheckHighRiskPorts(StringBuilder sb, StringBuilder evidence, ref bool hasIssue, CancellationToken ct)
    {
        evidence.AppendLine("\n[High-Risk Inbound Ports - Listening]");

        try
        {
            // Use netstat to find listening TCP ports
            string output = _runCommand("netstat", "-an -p TCP", ct);
            var listeningPorts = new HashSet<int>();

            foreach (var line in output.Split('\n'))
            {
                if (!line.Contains("LISTENING", StringComparison.OrdinalIgnoreCase)) continue;

                // Parse: TCP    0.0.0.0:PORT    0.0.0.0:0    LISTENING
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 4) continue;

                string local = parts[1];
                int colonIdx = local.LastIndexOf(':');
                if (colonIdx > 0 && int.TryParse(local[(colonIdx + 1)..], out int port))
                {
                    listeningPorts.Add(port);
                }
            }

            var openHighRisk = new List<(int port, string desc)>();
            foreach (int port in HighRiskPorts)
            {
                if (listeningPorts.Contains(port))
                {
                    string desc = GetPortDescription(port);
                    openHighRisk.Add((port, desc));
                    evidence.AppendLine($"  OPEN: {port}/tcp ({desc})");
                }
            }

            if (openHighRisk.Count > 0)
            {
                hasIssue = true;
                sb.AppendLine($"WARNING: {openHighRisk.Count} high-risk port(s) are listening:");
                foreach (var (port, desc) in openHighRisk)
                    sb.AppendLine($"  - {port}/tcp ({desc})");
            }
            else
            {
                sb.AppendLine("PASS: No high-risk ports are actively listening.");
            }

            evidence.AppendLine($"  Total listening TCP ports: {listeningPorts.Count}");
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  netstat error: {ex.Message}");
        }
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

    private static string GetPortDescription(int port) => port switch
    {
        21 => "FTP",
        23 => "Telnet",
        69 => "TFTP",
        135 => "RPC/DCOM",
        139 => "NetBIOS Session",
        445 => "SMB",
        1433 => "SQL Server",
        3389 => "RDP",
        5900 => "VNC",
        5985 => "WinRM HTTP",
        5986 => "WinRM HTTPS",
        _ => "Unknown"
    };

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
