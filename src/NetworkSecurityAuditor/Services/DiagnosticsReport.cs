using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkSecurityAuditor.Export;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Services;

public sealed class DiagnosticCheck
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required string Status { get; init; }
    public required string Detail { get; init; }
    public required string Remediation { get; init; }
}

public sealed class DiagnosticsReport
{
    public const string SchemaVersion = "1.0";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public required string Schema { get; init; }
    public required string ToolVersion { get; init; }
    public required string GeneratedAtUtc { get; init; }
    public required string Runtime { get; init; }
    public required string OSBuild { get; init; }
    public required bool IsAdmin { get; init; }
    public required bool IsDomainJoined { get; init; }
    public required bool AzureAdJoined { get; init; }
    public required bool IntuneManaged { get; init; }
    public required IReadOnlyList<DiagnosticCheck> Checks { get; init; }

    [JsonIgnore]
    public bool HasBlocked => Checks.Any(check => check.Status.Equals("Blocked", StringComparison.OrdinalIgnoreCase));

    [JsonIgnore]
    public bool HasDegraded => Checks.Any(check => check.Status.Equals("Degraded", StringComparison.OrdinalIgnoreCase));

    public static DiagnosticsReport Run(
        EnvironmentInfo environment,
        string outputPath,
        bool noInternet,
        Func<string?>? browserResolver = null)
    {
        var checks = new List<DiagnosticCheck>();

        checks.Add(new DiagnosticCheck
        {
            Id = "elevation",
            Name = "Administrator elevation",
            Status = environment.IsAdmin ? "Ready" : "Degraded",
            Detail = environment.IsAdmin
                ? "The process is elevated."
                : "The process is not elevated; administrator-only checks may return incomplete evidence.",
            Remediation = environment.IsAdmin ? "None." : "Run the headless command from an elevated PowerShell or use the documented elevation path."
        });

        checks.Add(new DiagnosticCheck
        {
            Id = "domain",
            Name = "Domain and Active Directory readiness",
            Status = environment.IsDomainJoined && environment.HasAD ? "Ready" : "Degraded",
            Detail = environment.IsDomainJoined
                ? environment.HasAD ? "The host is domain-joined and the Active Directory module is available." : "The host is domain-joined but the Active Directory module is unavailable."
                : "The host is not domain-joined; Active Directory checks are expected to be skipped.",
            Remediation = environment.IsDomainJoined && environment.HasAD
                ? "None."
                : "Install RSAT Active Directory tools when domain checks are required."
        });

        checks.Add(new DiagnosticCheck
        {
            Id = "rsat",
            Name = "RSAT and Windows capability modules",
            Status = environment.HasAD || environment.HasBitLocker || environment.HasSMB ? "Ready" : "Degraded",
            Detail = $"AD={environment.HasAD}; BitLocker={environment.HasBitLocker}; SMB={environment.HasSMB}.",
            Remediation = environment.HasAD || environment.HasBitLocker || environment.HasSMB
                ? "None."
                : "Install the Windows capabilities required by the selected check profile."
        });

        checks.Add(new DiagnosticCheck
        {
            Id = "winrm",
            Name = "WinRM readiness",
            Status = environment.WinRMRunning ? "Ready" : "Degraded",
            Detail = environment.WinRMRunning ? "WinRM is running." : "WinRM is not running; remote connectivity checks may be unavailable.",
            Remediation = environment.WinRMRunning ? "None." : "Enable and authorize WinRM only when remote checks are explicitly required."
        });

        checks.Add(new DiagnosticCheck
        {
            Id = "defender",
            Name = "Defender capability",
            Status = environment.HasDefender ? "Ready" : "Degraded",
            Detail = environment.HasDefender ? "Defender cmdlets are available." : "Defender cmdlets are unavailable; endpoint protection evidence may be limited.",
            Remediation = environment.HasDefender ? "None." : "Verify Defender or the supported endpoint protection integration on this host."
        });

        var outputStatus = GetOutputStatus(outputPath, out var outputDetail, out var outputRemediation);
        checks.Add(new DiagnosticCheck
        {
            Id = "output",
            Name = "Output path readiness",
            Status = outputStatus,
            Detail = outputDetail,
            Remediation = outputRemediation
        });

        var browserPath = browserResolver is null ? PdfExporter.FindBrowser() : browserResolver();
        checks.Add(new DiagnosticCheck
        {
            Id = "pdf",
            Name = "PDF browser discovery",
            Status = browserPath is not null ? "Ready" : "Degraded",
            Detail = browserPath is not null ? "A supported per-user or machine Edge/Chrome executable was found." : "No supported Edge or Chrome executable was found; PDF export will be unavailable.",
            Remediation = browserPath is not null ? "None." : "Install Microsoft Edge or Google Chrome, or use HTML/JSON exports."
        });

        checks.Add(new DiagnosticCheck
        {
            Id = "imports",
            Name = "Import safety limits",
            Status = "Ready",
            Detail = $"State={ImportFileGuard.MaxAuditStateBytes / 1_048_576} MiB; waivers={ImportFileGuard.MaxWaiverStoreBytes / 1_048_576} MiB; dashboard={ImportFileGuard.MaxDashboardFiles} files/{ImportFileGuard.MaxDashboardTotalBytes / 1_048_576} MiB total.",
            Remediation = "None. Limits are enforced before import parsing."
        });

        checks.Add(new DiagnosticCheck
        {
            Id = "internet",
            Name = "Internet and cache state",
            Status = noInternet ? "Degraded" : "Ready",
            Detail = noInternet
                ? "Internet access was explicitly disabled; cloud and external lookups are unavailable in this run."
                : "Internet access is permitted by command-line policy; this diagnostic does not make a network request.",
            Remediation = noInternet ? "Remove --no-internet only when external evidence is approved for the environment." : "None."
        });

        checks.Add(new DiagnosticCheck
        {
            Id = "graph",
            Name = "Microsoft Graph authentication readiness",
            Status = "Degraded",
            Detail = "The C# preview has no stored Graph token or tenant credential configuration; no token was inspected or persisted.",
            Remediation = "Use the PowerShell cloud assessment path with an approved delegated/app-only configuration, or configure the future C# cloud profile."
        });

        return new DiagnosticsReport
        {
            Schema = SchemaVersion,
            ToolVersion = VersionInfo.Version,
            GeneratedAtUtc = DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture),
            Runtime = RuntimeInformation.FrameworkDescription,
            OSBuild = environment.OSBuild > 0 ? $"{environment.OSVersion} ({environment.OSBuild})" : environment.OSVersion,
            IsAdmin = environment.IsAdmin,
            IsDomainJoined = environment.IsDomainJoined,
            AzureAdJoined = environment.AzureADJoined,
            IntuneManaged = environment.IntuneManaged,
            Checks = checks
        };
    }

    public string ToJson() => JsonSerializer.Serialize(this, JsonOptions);

    public string ToText()
    {
        var lines = new List<string>
        {
            $"Network Security Auditor diagnostics v{ToolVersion}",
            $"Generated (UTC): {GeneratedAtUtc}",
            $"Runtime: {Runtime}",
            $"OS build: {OSBuild}",
            $"Administrator: {IsAdmin}",
            $"Domain joined: {IsDomainJoined}",
            $"Azure AD joined: {AzureAdJoined}",
            $"Intune managed: {IntuneManaged}",
            ""
        };

        foreach (var check in Checks)
        {
            lines.Add($"[{check.Status}] {check.Name} ({check.Id})");
            lines.Add($"  {check.Detail}");
            lines.Add($"  Remediation: {check.Remediation}");
        }

        return string.Join(Environment.NewLine, lines) + Environment.NewLine;
    }

    private static string GetOutputStatus(string outputPath, out string detail, out string remediation)
    {
        try
        {
            var resolved = Path.GetFullPath(string.IsNullOrWhiteSpace(outputPath)
                ? Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
                : outputPath);
            var directory = Directory.Exists(resolved)
                ? resolved
                : Path.GetDirectoryName(resolved);

            if (!string.IsNullOrWhiteSpace(directory) && Directory.Exists(directory))
            {
                detail = "The configured output directory or its existing parent is available.";
                remediation = "None.";
                return "Ready";
            }

            detail = "The configured output directory and its parent do not exist.";
            remediation = "Create the output directory or select an existing writable location before running the scan.";
            return "Blocked";
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or NotSupportedException or UnauthorizedAccessException)
        {
            detail = "The configured output path could not be resolved safely.";
            remediation = "Use a fully qualified local output directory without invalid or provider-qualified path syntax.";
            return "Blocked";
        }
    }
}
