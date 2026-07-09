namespace NetworkSecurityAuditor.Checks.NetworkArchitecture;

using System.IO;
using System.Text;
using System.Xml.Linq;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// NA03 - Wireless Security: List wireless profiles via netsh, check for WPA2/WPA3,
/// flag open/WEP networks.
/// </summary>
public sealed class NA03_WirelessCheck : ISecurityCheck
{
    public string Id => "NA03";

    private static readonly HashSet<string> InsecureAuth = new(StringComparer.OrdinalIgnoreCase)
    {
        "OPEN", "WEP", "SHARED", "WPA", "WPAPSK", "WPAPERSONAL", "WPAENTERPRISE"
    };

    private static readonly HashSet<string> SecureAuth = new(StringComparer.OrdinalIgnoreCase)
    {
        "WPA2", "WPA2PSK", "WPA3", "WPA3SAE", "WPA3ENT", "WPA3ENT192",
        "WPA2PERSONAL", "WPA2ENTERPRISE", "WPA3PERSONAL", "WPA3ENTERPRISE",
        "OWE", "ENHANCEDOPEN"
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

            foreach (var details in profiles)
            {
                ct.ThrowIfCancellationRequested();
                totalProfiles++;

                if (details.Authentication != null)
                {
                    var assessment = AssessAuthentication(details.Authentication);
                    if (assessment == WirelessAuthenticationAssessment.Insecure)
                    {
                        hasInsecure = true;
                        insecureProfiles++;
                        sb.AppendLine($"CRITICAL: Profile \"{details.Name}\" uses insecure authentication: {details.Authentication}" +
                            (details.Cipher != null ? $" / {details.Cipher}" : ""));
                    }
                    else if (assessment == WirelessAuthenticationAssessment.Secure)
                    {
                        secureProfiles++;
                    }
                    else
                    {
                        sb.AppendLine($"INFO: Profile \"{details.Name}\" uses authentication: {details.Authentication}");
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

    private static List<ProfileDetails> GetWirelessProfiles(StringBuilder evidence, CancellationToken ct)
    {
        evidence.AppendLine("[Wireless Profiles]");
        var exportedProfiles = GetWirelessProfilesFromExportedXml(evidence, ct);
        if (exportedProfiles.Count > 0)
            return exportedProfiles;

        return GetWirelessProfilesFromNetshText(evidence, ct);
    }

    private static List<ProfileDetails> GetWirelessProfilesFromExportedXml(StringBuilder evidence, CancellationToken ct)
    {
        var profiles = new List<ProfileDetails>();
        var tempDir = Path.Combine(Path.GetTempPath(), $"nsa-wlan-{Guid.NewGuid():N}");

        try
        {
            Directory.CreateDirectory(tempDir);
            var output = RunCommand("netsh", $"wlan export profile folder=\"{tempDir}\"", ct);
            evidence.AppendLine(output.Length > 2000 ? output[..2000] + "\n  ...(truncated)" : output);

            foreach (var file in Directory.EnumerateFiles(tempDir, "*.xml"))
            {
                var details = ParseExportedProfileXml(File.ReadAllText(file));
                if (details is null)
                    continue;

                profiles.Add(details);
                evidence.AppendLine($"  \"{details.Name}\": Auth={details.Authentication ?? "N/A"}, " +
                    $"Cipher={details.Cipher ?? "N/A"}, Mode={details.ConnectionMode ?? "N/A"}");
            }
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  XML export unavailable: {ex.Message}");
        }
        finally
        {
            try
            {
                if (Directory.Exists(tempDir))
                    Directory.Delete(tempDir, recursive: true);
            }
            catch { }
        }

        return profiles;
    }

    private static List<ProfileDetails> GetWirelessProfilesFromNetshText(StringBuilder evidence, CancellationToken ct)
    {
        var profiles = new List<ProfileDetails>();

        try
        {
            string output = RunCommand("netsh", "wlan show profiles", ct);
            evidence.AppendLine(output.Length > 2000 ? output[..2000] + "\n  ...(truncated)" : output);

            foreach (var profileName in ParseProfileNamesFromNetshOutput(output))
            {
                profiles.Add(GetProfileDetails(profileName, evidence, ct));
            }
        }
        catch (Exception ex)
        {
            evidence.AppendLine($"  Error: {ex.Message}");
        }

        return profiles;
    }

    internal static IReadOnlyList<string> ParseProfileNamesFromNetshOutput(string output)
    {
        var profiles = new List<string>();
        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.Trim();
            var colonIdx = trimmed.IndexOf(':');
            if (colonIdx < 0)
                continue;

            var label = trimmed[..colonIdx].Trim();
            if (!label.Contains("Profile", StringComparison.OrdinalIgnoreCase))
                continue;

            var profileName = trimmed[(colonIdx + 1)..].Trim();
            if (!string.IsNullOrWhiteSpace(profileName))
                profiles.Add(profileName);
        }

        return profiles;
    }

    private static ProfileDetails GetProfileDetails(string profileName, StringBuilder evidence, CancellationToken ct)
    {
        var details = new ProfileDetails { Name = profileName };

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
        return CommandRunner.RunForOutput(fileName, arguments, TimeSpan.FromSeconds(15), ct);
    }

    internal static ProfileDetails? ParseExportedProfileXml(string xml)
    {
        var doc = XDocument.Parse(xml);
        var root = doc.Root;
        if (root is null)
            return null;

        XNamespace ns = root.Name.Namespace;
        var name = root.Element(ns + "name")?.Value.Trim();
        if (string.IsNullOrWhiteSpace(name))
            return null;

        var authEncryption = root
            .Element(ns + "MSM")
            ?.Element(ns + "security")
            ?.Element(ns + "authEncryption");

        return new ProfileDetails
        {
            Name = name,
            Authentication = authEncryption?.Element(ns + "authentication")?.Value.Trim(),
            Cipher = authEncryption?.Element(ns + "encryption")?.Value.Trim(),
            ConnectionMode = root.Element(ns + "connectionMode")?.Value.Trim()
        };
    }

    internal static WirelessAuthenticationAssessment AssessAuthentication(string? authentication)
    {
        if (string.IsNullOrWhiteSpace(authentication))
            return WirelessAuthenticationAssessment.Unknown;

        var normalized = NormalizeAuthentication(authentication);
        if (InsecureAuth.Contains(normalized))
            return WirelessAuthenticationAssessment.Insecure;

        if (SecureAuth.Contains(normalized))
            return WirelessAuthenticationAssessment.Secure;

        return WirelessAuthenticationAssessment.Unknown;
    }

    private static string NormalizeAuthentication(string authentication)
    {
        var sb = new StringBuilder(authentication.Length);
        foreach (var ch in authentication)
        {
            if (char.IsLetterOrDigit(ch))
                sb.Append(char.ToUpperInvariant(ch));
        }

        return sb.ToString();
    }

    internal sealed class ProfileDetails
    {
        public string Name { get; set; } = "";
        public string? Authentication { get; set; }
        public string? Cipher { get; set; }
        public string? ConnectionMode { get; set; }
    }

    internal enum WirelessAuthenticationAssessment
    {
        Secure,
        Insecure,
        Unknown
    }
}
