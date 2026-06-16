namespace NetworkSecurityAuditor.Checks.NetworkArchitecture;

using System.Diagnostics;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// NA07 - Guest Network Isolation: Heuristic check examining wireless profiles for
/// guest/visitor SSIDs and their security settings.
/// </summary>
public sealed class NA07_GuestNetworkCheck : ISecurityCheck
{
    public string Id => "NA07";

    private static readonly string[] GuestIndicators =
    [
        "guest", "visitor", "public", "byod", "hotspot", "lobby", "conference"
    ];

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            var guestProfiles = new List<GuestProfileInfo>();
            int totalProfiles = 0;

            // 1. Get wireless profiles
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("[Wireless Profile Guest Network Scan]");

            var profiles = GetWirelessProfiles(evidence, ct);
            totalProfiles = profiles.Count;

            if (totalProfiles == 0)
            {
                sb.AppendLine("No wireless profiles found. Guest network isolation check requires wireless profiles.");
                sb.AppendLine("MANUAL VERIFICATION: Verify guest network isolation at the access point/controller level.");

                return Task.FromResult(new CheckResult
                {
                    Status = CheckStatus.Partial,
                    Findings = sb.ToString().TrimEnd(),
                    Evidence = evidence.ToString().TrimEnd()
                });
            }

            // 2. Check each profile for guest indicators
            evidence.AppendLine("\n[Guest SSID Analysis]");

            foreach (string profile in profiles)
            {
                ct.ThrowIfCancellationRequested();

                bool isGuest = GuestIndicators.Any(g =>
                    profile.Contains(g, StringComparison.OrdinalIgnoreCase));

                if (isGuest)
                {
                    var info = GetProfileSecurity(profile, evidence, ct);
                    info.Name = profile;
                    guestProfiles.Add(info);
                }
            }

            // 3. Report findings
            sb.AppendLine($"Scanned {totalProfiles} wireless profile(s); " +
                $"{guestProfiles.Count} match guest/visitor naming patterns.");

            if (guestProfiles.Count > 0)
            {
                foreach (var gp in guestProfiles)
                {
                    sb.AppendLine($"  Guest SSID: \"{gp.Name}\" - Auth: {gp.Authentication ?? "Unknown"}, " +
                        $"Cipher: {gp.Cipher ?? "Unknown"}");

                    if (gp.Authentication != null &&
                        (gp.Authentication.Contains("Open", StringComparison.OrdinalIgnoreCase) ||
                         gp.Authentication.Contains("WEP", StringComparison.OrdinalIgnoreCase)))
                    {
                        sb.AppendLine($"    WARNING: Guest network \"{gp.Name}\" uses weak/no encryption.");
                    }
                }

                sb.AppendLine();
                sb.AppendLine("MANUAL VERIFICATION REQUIRED:");
                sb.AppendLine("  [ ] Guest SSID is on a separate VLAN from corporate network");
                sb.AppendLine("  [ ] Guest network cannot reach internal resources");
                sb.AppendLine("  [ ] Guest network has bandwidth throttling");
                sb.AppendLine("  [ ] Guest network has client isolation enabled");
                sb.AppendLine("  [ ] Guest network has an acceptable use captive portal");
            }
            else
            {
                sb.AppendLine("No guest/visitor wireless profiles detected on this machine.");
                sb.AppendLine("MANUAL VERIFICATION: Check access point/controller configuration for guest SSID isolation.");
            }

            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.Partial,
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

        try
        {
            string output = RunCommand("netsh", "wlan show profiles", ct);

            foreach (var line in output.Split('\n'))
            {
                string trimmed = line.Trim();
                int colonIdx = trimmed.IndexOf(':');
                if (colonIdx >= 0 &&
                    trimmed.Contains("Profile", StringComparison.OrdinalIgnoreCase))
                {
                    string profileName = trimmed[(colonIdx + 1)..].Trim();
                    if (!string.IsNullOrWhiteSpace(profileName))
                    {
                        profiles.Add(profileName);
                        evidence.AppendLine($"  Profile: {profileName}");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  Error listing profiles: {ex.Message}");
        }

        return profiles;
    }

    private static GuestProfileInfo GetProfileSecurity(string profileName, StringBuilder evidence, CancellationToken ct)
    {
        var info = new GuestProfileInfo();

        try
        {
            string output = RunCommand("netsh", $"wlan show profile name=\"{profileName}\"", ct);

            foreach (var line in output.Split('\n'))
            {
                string trimmed = line.Trim();

                if (trimmed.StartsWith("Authentication", StringComparison.OrdinalIgnoreCase))
                {
                    int colonIdx = trimmed.IndexOf(':');
                    if (colonIdx >= 0)
                        info.Authentication = trimmed[(colonIdx + 1)..].Trim();
                }
                else if (trimmed.StartsWith("Cipher", StringComparison.OrdinalIgnoreCase))
                {
                    int colonIdx = trimmed.IndexOf(':');
                    if (colonIdx >= 0)
                        info.Cipher = trimmed[(colonIdx + 1)..].Trim();
                }
            }

            evidence.AppendLine($"    \"{profileName}\": Auth={info.Authentication ?? "N/A"}, Cipher={info.Cipher ?? "N/A"}");
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"    \"{profileName}\": Error - {ex.Message}");
        }

        return info;
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

    private sealed class GuestProfileInfo
    {
        public string Name { get; set; } = "";
        public string? Authentication { get; set; }
        public string? Cipher { get; set; }
    }
}
