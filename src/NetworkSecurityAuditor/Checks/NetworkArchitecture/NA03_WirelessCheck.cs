namespace NetworkSecurityAuditor.Checks.NetworkArchitecture;

using System.Diagnostics;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// NA03 - Wireless Security: List wireless profiles via netsh, check for WPA2/WPA3,
/// flag open/WEP networks.
/// </summary>
public sealed class NA03_WirelessCheck : ISecurityCheck
{
    public string Id => "NA03";

    private static readonly HashSet<string> InsecureAuth = new(StringComparer.OrdinalIgnoreCase)
    {
        "Open", "WEP", "Shared", "WPA-Personal", "WPA-Enterprise"
    };

    private static readonly HashSet<string> SecureAuth = new(StringComparer.OrdinalIgnoreCase)
    {
        "WPA2-Personal", "WPA2-Enterprise", "WPA3-Personal", "WPA3-Enterprise",
        "WPA3SAE", "OWE"
    };

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasInsecure = false;
            int totalProfiles = 0;
            int secureProfiles = 0;
            int insecureProfiles = 0;

            // 1. Get list of wireless profiles
            ct.ThrowIfCancellationRequested();
            var profiles = GetWirelessProfiles(evidence, ct);

            if (profiles.Count == 0)
            {
                sb.AppendLine("No wireless profiles found. Wireless may not be available or configured on this system.");
                return Task.FromResult(new CheckResult
                {
                    Status = CheckStatus.NA,
                    Findings = sb.ToString().TrimEnd(),
                    Evidence = evidence.ToString().TrimEnd()
                });
            }

            // 2. Check each profile for security settings
            evidence.AppendLine("\n[Profile Security Details]");

            foreach (string profile in profiles)
            {
                ct.ThrowIfCancellationRequested();
                totalProfiles++;

                var details = GetProfileDetails(profile, evidence, ct);

                if (details.Authentication != null)
                {
                    if (InsecureAuth.Contains(details.Authentication) ||
                        details.Authentication.Contains("Open", StringComparison.OrdinalIgnoreCase) ||
                        details.Authentication.Contains("WEP", StringComparison.OrdinalIgnoreCase))
                    {
                        hasInsecure = true;
                        insecureProfiles++;
                        sb.AppendLine($"CRITICAL: Profile \"{profile}\" uses insecure authentication: {details.Authentication}" +
                            (details.Cipher != null ? $" / {details.Cipher}" : ""));
                    }
                    else if (SecureAuth.Any(s =>
                        details.Authentication.Contains(s, StringComparison.OrdinalIgnoreCase)))
                    {
                        secureProfiles++;
                    }
                    else
                    {
                        // Unknown auth type, report it
                        sb.AppendLine($"INFO: Profile \"{profile}\" uses authentication: {details.Authentication}");
                    }
                }
            }

            sb.Insert(0, $"Wireless profiles: {totalProfiles} total, {secureProfiles} secure, {insecureProfiles} insecure.\n");

            if (!hasInsecure && secureProfiles > 0)
                sb.AppendLine("PASS: All wireless profiles use WPA2 or WPA3 authentication.");

            var status = hasInsecure ? CheckStatus.Fail
                : secureProfiles > 0 ? CheckStatus.Pass
                : CheckStatus.Partial;

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

    private static List<string> GetWirelessProfiles(StringBuilder evidence, CancellationToken ct)
    {
        var profiles = new List<string>();
        evidence.AppendLine("[Wireless Profiles]");

        try
        {
            string output = RunCommand("netsh", "wlan show profiles", ct);
            evidence.AppendLine(output.Length > 2000 ? output[..2000] + "\n  ...(truncated)" : output);

            foreach (var line in output.Split('\n'))
            {
                string trimmed = line.Trim();
                // Format: "    All User Profile     : ProfileName"
                int colonIdx = trimmed.IndexOf(':');
                if (colonIdx >= 0 &&
                    trimmed.Contains("Profile", StringComparison.OrdinalIgnoreCase))
                {
                    string profileName = trimmed[(colonIdx + 1)..].Trim();
                    if (!string.IsNullOrWhiteSpace(profileName))
                        profiles.Add(profileName);
                }
            }
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  Error: {ex.Message}");
        }

        return profiles;
    }

    private static ProfileDetails GetProfileDetails(string profileName, StringBuilder evidence, CancellationToken ct)
    {
        var details = new ProfileDetails();

        try
        {
            string output = RunCommand("netsh", $"wlan show profile name=\"{profileName}\" key=clear", ct);

            foreach (var line in output.Split('\n'))
            {
                string trimmed = line.Trim();

                if (trimmed.StartsWith("Authentication", StringComparison.OrdinalIgnoreCase))
                {
                    int colonIdx = trimmed.IndexOf(':');
                    if (colonIdx >= 0)
                        details.Authentication = trimmed[(colonIdx + 1)..].Trim();
                }
                else if (trimmed.StartsWith("Cipher", StringComparison.OrdinalIgnoreCase))
                {
                    int colonIdx = trimmed.IndexOf(':');
                    if (colonIdx >= 0)
                        details.Cipher = trimmed[(colonIdx + 1)..].Trim();
                }
                else if (trimmed.StartsWith("Connection mode", StringComparison.OrdinalIgnoreCase))
                {
                    int colonIdx = trimmed.IndexOf(':');
                    if (colonIdx >= 0)
                        details.ConnectionMode = trimmed[(colonIdx + 1)..].Trim();
                }
            }

            evidence.AppendLine($"  \"{profileName}\": Auth={details.Authentication ?? "N/A"}, " +
                $"Cipher={details.Cipher ?? "N/A"}, Mode={details.ConnectionMode ?? "N/A"}");
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  \"{profileName}\": Error - {ex.Message}");
        }

        return details;
    }

    private static string RunCommand(string fileName, string arguments, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(fileName, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start {fileName}");

        ct.Register(() => { try { proc.Kill(); } catch { } });

        string output = proc.StandardOutput.ReadToEnd();
        proc.WaitForExit(15_000);
        return output;
    }

    private sealed class ProfileDetails
    {
        public string? Authentication { get; set; }
        public string? Cipher { get; set; }
        public string? ConnectionMode { get; set; }
    }
}
