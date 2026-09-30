namespace NetworkSecurityAuditor.Checks.EndpointSecurity;

using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// EP01 - AV/EDR posture: Defender status via WMI, third-party AV from Security Center,
/// and EDR agents confirmed by their services rather than registry keys that ship with Windows.
/// </summary>
public sealed class EP01_AvEdrCheck : ISecurityCheck
{
    public string Id => "EP01";

    internal const string MdeStatusKey = @"HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status";
    internal const string MdeKey = @"HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection";
    internal const string PaloAltoKey = @"HKLM\SOFTWARE\Palo Alto Networks";

    // EDR agents with the services that prove they're installed and running. Registry keys
    // outlive uninstalls, so a key without a running service is only reported as a trace.
    // Defender for Endpoint and Cortex XDR are handled separately because their keys ship with
    // Windows or with GlobalProtect.
    private static readonly (string KeyPath, string Label, string[] ServiceNames)[] EdrRegistrySignatures =
    [
        (@"HKLM\SOFTWARE\CrowdStrike", "CrowdStrike Falcon", ["CSFalconService"]),
        (@"HKLM\SOFTWARE\SentinelOne", "SentinelOne", ["SentinelAgent"]),
        (@"HKLM\SOFTWARE\Carbon Black", "VMware Carbon Black", ["CbDefense", "CarbonBlack"]),
        (@"HKLM\SOFTWARE\Cylance", "BlackBerry Cylance", ["CylanceSvc"]),
        (@"HKLM\SOFTWARE\Sophos", "Sophos", ["SAVService", "Sophos Endpoint Defense Service"]),
        (@"HKLM\SOFTWARE\ESET", "ESET", ["ekrn"]),
    ];

    internal static IReadOnlyList<string> RegistryPathsToProbe =>
        EdrRegistrySignatures.Select(s => s.KeyPath).Append(MdeKey).Append(PaloAltoKey).ToArray();

    internal static IReadOnlyList<string> ServicesToProbe =>
        EdrRegistrySignatures.SelectMany(s => s.ServiceNames).Append("Sense").Append("cyserver").ToArray();

    internal sealed record DefenderStatus
    {
        public bool AmServiceEnabled { get; init; }
        public bool AntispywareEnabled { get; init; }
        public bool AntivirusEnabled { get; init; }
        public bool RealTimeProtectionEnabled { get; init; }
        public bool NisEnabled { get; init; }
        public int SignatureAgeDays { get; init; }
        /// <summary>MSFT_MpComputerStatus.AMRunningMode: Normal, Passive Mode, SxS Passive Mode, EDR Block Mode.</summary>
        public string? AmRunningMode { get; init; }
        public bool? IsTamperProtected { get; init; }
    }

    internal sealed record SecurityCenterProduct(string Name, uint ProductState);

    internal sealed record AsrRule(string Id, int Action);

    /// <summary>Everything EP01 reads from the host, so the decision can be tested with fixtures.</summary>
    internal sealed record AvEdrSnapshot
    {
        public DefenderStatus? Defender { get; init; }
        public string? DefenderError { get; init; }
        public bool SecurityCenterAvailable { get; init; }
        public IReadOnlyList<SecurityCenterProduct> SecurityCenterProducts { get; init; } = [];
        /// <summary>Service name to Win32_Service State for <see cref="ServicesToProbe"/>.</summary>
        public IReadOnlyDictionary<string, string> Services { get; init; } = new Dictionary<string, string>();
        public IReadOnlyList<string> RegistryKeysPresent { get; init; } = [];
        public int? MdeOnboardingState { get; init; }
        /// <summary>Configured ASR rules, or null when Defender preferences couldn't be read.</summary>
        public IReadOnlyList<AsrRule>? AsrRules { get; init; }
    }

    internal sealed record AvEdrAssessment(CheckStatus Status, string Findings, string Evidence, IReadOnlyList<string> EdrProducts);

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var assessment = Assess(CollectSnapshot(ct));
            return Task.FromResult(new CheckResult
            {
                Status = assessment.Status,
                Findings = assessment.Findings,
                Evidence = assessment.Evidence
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.FromError(Id, ex));
        }
    }

    internal static AvEdrAssessment Assess(AvEdrSnapshot snapshot)
    {
        var sb = new StringBuilder();
        var evidence = new StringBuilder();
        bool hasIssue = false;
        bool needsReview = false;

        // -- Third-party AV registered with Security Center (workstations) --
        var thirdParty = snapshot.SecurityCenterProducts
            .Where(p => !IsDefenderProduct(p.Name))
            .Select(p => (p.Name, p.ProductState, Decoded: DecodeSecurityCenterProductState(p.ProductState)))
            .ToList();
        var activeThirdParty = thirdParty.Where(p => p.Decoded.Enabled).ToList();

        // -- Defender --
        var defender = snapshot.Defender;
        bool defenderActive = false;
        if (defender is not null)
        {
            bool passive = defender.AmRunningMode?.Contains("Passive", StringComparison.OrdinalIgnoreCase) == true ||
                defender.AmRunningMode?.Contains("EDR Block", StringComparison.OrdinalIgnoreCase) == true;
            bool fullyOn = defender.AmServiceEnabled && defender.AntivirusEnabled && defender.RealTimeProtectionEnabled;
            defenderActive = fullyOn && !passive;

            evidence.AppendLine("[Defender Status]");
            evidence.AppendLine($"  AM Service Enabled:        {defender.AmServiceEnabled}");
            evidence.AppendLine($"  Running Mode:              {defender.AmRunningMode ?? "unknown"}");
            evidence.AppendLine($"  Antispyware Enabled:       {defender.AntispywareEnabled}");
            evidence.AppendLine($"  Antivirus Enabled:         {defender.AntivirusEnabled}");
            evidence.AppendLine($"  Real-Time Protection:      {defender.RealTimeProtectionEnabled}");
            evidence.AppendLine($"  Network Inspection (NIS):  {defender.NisEnabled}");
            evidence.AppendLine($"  Signature Age (days):      {defender.SignatureAgeDays}");
            evidence.AppendLine($"  Tamper Protection:         {FormatTamper(defender.IsTamperProtected)}");

            if (!defenderActive && activeThirdParty.Count > 0)
            {
                string mode = passive ? $"in {defender.AmRunningMode}" : "not the active engine";
                sb.AppendLine($"Microsoft Defender is {mode}; {string.Join(", ", activeThirdParty.Select(p => p.Name))} is the registered, active antivirus.");
            }
            else if (!defenderActive)
            {
                hasIssue = true;
                if (passive)
                {
                    sb.AppendLine($"CRITICAL: Microsoft Defender is in {defender.AmRunningMode} and no other active antivirus is registered.");
                }
                else
                {
                    sb.AppendLine("CRITICAL: Windows Defender is not fully enabled.");
                    if (!defender.AmServiceEnabled) sb.AppendLine("  - AM Service is disabled.");
                    if (!defender.AntivirusEnabled) sb.AppendLine("  - Antivirus engine is disabled.");
                    if (!defender.RealTimeProtectionEnabled) sb.AppendLine("  - Real-time protection is OFF.");
                }
            }

            if (defenderActive)
            {
                if (defender.SignatureAgeDays > 7)
                {
                    hasIssue = true;
                    sb.AppendLine($"WARNING: Antivirus signatures are {defender.SignatureAgeDays} days old (>7 days).");
                }
                else if (defender.SignatureAgeDays > 3)
                {
                    sb.AppendLine($"INFO: Signature age is {defender.SignatureAgeDays} days (monitor if trending upward).");
                }

                if (!defender.AntispywareEnabled)
                {
                    sb.AppendLine("WARNING: Antispyware component is disabled.");
                    hasIssue = true;
                }
            }
        }
        else
        {
            evidence.AppendLine("[Defender Status]");
            evidence.AppendLine($"  Not readable: {snapshot.DefenderError ?? "MSFT_MpComputerStatus returned nothing"}");
            sb.AppendLine("Defender WMI namespace not accessible (may be uninstalled or third-party AV is primary).");
        }

        evidence.AppendLine("\n[SecurityCenter2 AV Products]");
        if (!snapshot.SecurityCenterAvailable)
            evidence.AppendLine("  Not available (servers don't register AV with Security Center).");
        foreach (var product in snapshot.SecurityCenterProducts)
        {
            var decoded = DecodeSecurityCenterProductState(product.ProductState);
            evidence.AppendLine(
                $"  {product.Name}: enabled={decoded.Enabled}, upToDate={decoded.SignaturesUpToDate} " +
                $"(state=0x{product.ProductState:X6}, provider=0x{decoded.Provider:X2}, scanner=0x{decoded.ScannerState:X2}, signatures=0x{decoded.SignatureStatus:X2})");
        }

        if (thirdParty.Count > 0)
            sb.AppendLine($"Third-party AV detected: {string.Join(", ", thirdParty.Select(p => p.Name))}");

        if (!defenderActive)
        {
            if (activeThirdParty.Count > 0)
            {
                var stale = activeThirdParty.Where(p => !p.Decoded.SignaturesUpToDate).Select(p => p.Name).ToList();
                if (stale.Count > 0)
                {
                    needsReview = true;
                    sb.AppendLine($"WARNING: Security Center reports out-of-date signatures for {string.Join(", ", stale)}.");
                }
            }
            else if (thirdParty.Count > 0)
            {
                hasIssue = true;
                sb.AppendLine($"CRITICAL: {string.Join(", ", thirdParty.Select(p => p.Name))} is registered but not enabled, and Defender isn't active.");
            }
            else if (defender is null)
            {
                hasIssue = true;
                sb.AppendLine("CRITICAL: No AV/EDR product detected on this system.");
            }
        }

        // -- EDR/XDR agents --
        var edrProducts = DetectEdr(snapshot, evidence);
        if (edrProducts.Count > 0)
            sb.AppendLine($"EDR/XDR products detected: {string.Join(", ", edrProducts)}");

        // -- Attack surface reduction --
        evidence.AppendLine("\n[Attack Surface Reduction]");
        if (snapshot.AsrRules is null)
        {
            evidence.AppendLine("  Defender preferences not readable; ASR rules unknown.");
        }
        else
        {
            int block = snapshot.AsrRules.Count(r => r.Action == 1);
            int audit = snapshot.AsrRules.Count(r => r.Action == 2);
            int warn = snapshot.AsrRules.Count(r => r.Action == 6);
            int configured = block + audit + warn;
            evidence.AppendLine($"  ASR rules configured: {configured} (Block: {block}, Audit: {audit}, Warn: {warn}, Off: {snapshot.AsrRules.Count - configured})");
        }

        if (sb.Length == 0)
            sb.AppendLine("Windows Defender is fully enabled with current signatures.");

        var status = hasIssue ? CheckStatus.Fail
            : needsReview ? CheckStatus.Partial
            : defender is null && activeThirdParty.Count == 0 ? CheckStatus.Partial
            : CheckStatus.Pass;

        return new AvEdrAssessment(status, sb.ToString().TrimEnd(), evidence.ToString().TrimEnd(), edrProducts);
    }

    private static bool IsDefenderProduct(string name) =>
        name.Contains("Windows Defender", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("Microsoft Defender", StringComparison.OrdinalIgnoreCase);

    private static string FormatTamper(bool? value) => value switch
    {
        true => "On",
        false => "OFF",
        null => "unknown",
    };

    private static List<string> DetectEdr(AvEdrSnapshot snapshot, StringBuilder evidence)
    {
        var products = new List<string>();
        bool KeyPresent(string path) => snapshot.RegistryKeysPresent.Contains(path, StringComparer.OrdinalIgnoreCase);
        string? ServiceState(string name) => snapshot.Services.TryGetValue(name, out var state) ? state : null;
        static bool Running(string? state) => string.Equals(state, "Running", StringComparison.OrdinalIgnoreCase);

        evidence.AppendLine("\n[EDR/XDR Detection]");
        foreach (var (keyPath, label, serviceNames) in EdrRegistrySignatures)
        {
            var service = serviceNames.Select(n => (Name: n, State: ServiceState(n))).FirstOrDefault(s => s.State is not null);
            if (service.State is not null && Running(service.State))
            {
                products.Add(label);
                evidence.AppendLine($"  FOUND: {label} ({service.Name} service {service.State})");
            }
            else if (service.State is not null)
            {
                evidence.AppendLine($"  {label} installed but its {service.Name} service is {service.State}; not counted.");
            }
            else if (KeyPresent(keyPath))
            {
                evidence.AppendLine($"  {label} registry key present ({keyPath}) with no agent service; install trace only, not counted.");
            }
        }

        var sense = ServiceState("Sense");
        string onboarding = snapshot.MdeOnboardingState?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "absent";
        if (snapshot.MdeOnboardingState == 1 && Running(sense))
        {
            products.Add("Defender for Endpoint");
            evidence.AppendLine($"  FOUND: Defender for Endpoint (OnboardingState 1, Sense {sense})");
        }
        else if (snapshot.MdeOnboardingState == 1 || sense is not null || KeyPresent(MdeKey))
        {
            evidence.AppendLine($"  Defender for Endpoint not counted: OnboardingState {onboarding}, Sense service {sense ?? "not found"} (the key and service ship with Windows).");
        }

        var cyserver = ServiceState("cyserver");
        if (Running(cyserver))
        {
            products.Add("Cortex XDR");
            evidence.AppendLine($"  FOUND: Cortex XDR (cyserver service {cyserver})");
        }
        else if (cyserver is not null)
        {
            evidence.AppendLine($"  Cortex XDR installed but its cyserver service is {cyserver}; not counted.");
        }
        else if (KeyPresent(PaloAltoKey))
        {
            evidence.AppendLine($"  Palo Alto Networks key present without the Cortex XDR cyserver service; GlobalProtect VPN installs this key too. Not counted.");
        }

        if (products.Count == 0)
            evidence.AppendLine("  No EDR agents detected.");

        return products;
    }

    private static AvEdrSnapshot CollectSnapshot(CancellationToken ct)
    {
        DefenderStatus? defender = null;
        string? defenderError = null;
        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"root\Microsoft\Windows\Defender",
                "SELECT * FROM MSFT_MpComputerStatus");
            foreach (ManagementObject obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                using (obj)
                {
                    defender = new DefenderStatus
                    {
                        AmServiceEnabled = GetBool(obj, "AMServiceEnabled"),
                        AntispywareEnabled = GetBool(obj, "AntispywareEnabled"),
                        AntivirusEnabled = GetBool(obj, "AntivirusEnabled"),
                        RealTimeProtectionEnabled = GetBool(obj, "RealTimeProtectionEnabled"),
                        NisEnabled = GetBool(obj, "NISEnabled"),
                        SignatureAgeDays = GetInt(obj, "AntivirusSignatureAge"),
                        AmRunningMode = GetString(obj, "AMRunningMode"),
                        IsTamperProtected = GetNullableBool(obj, "IsTamperProtected"),
                    };
                }
            }
        }
        catch (ManagementException ex)
        {
            defenderError = ex.Message;
        }

        ct.ThrowIfCancellationRequested();
        var products = new List<SecurityCenterProduct>();
        bool securityCenter = false;
        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"root\SecurityCenter2",
                "SELECT displayName, productState FROM AntiVirusProduct");
            foreach (ManagementObject obj in searcher.Get())
            {
                using (obj)
                {
                    products.Add(new SecurityCenterProduct(
                        obj["displayName"]?.ToString() ?? "Unknown",
                        Convert.ToUInt32(obj["productState"] ?? 0, System.Globalization.CultureInfo.InvariantCulture)));
                }
            }
            securityCenter = true;
        }
        catch (ManagementException)
        {
            // SecurityCenter2 isn't present on servers.
        }

        ct.ThrowIfCancellationRequested();
        var services = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, State FROM Win32_Service WHERE " +
                string.Join(" OR ", ServicesToProbe.Distinct(StringComparer.OrdinalIgnoreCase).Select(s => $"Name = '{s}'")));
            foreach (ManagementObject obj in searcher.Get())
            {
                using (obj)
                {
                    var name = obj["Name"]?.ToString();
                    if (name is not null) services[name] = obj["State"]?.ToString() ?? "Unknown";
                }
            }
        }
        catch (ManagementException)
        {
            // Leave the map empty; EDR agents then go uncounted rather than assumed.
        }

        IReadOnlyList<AsrRule>? asr = null;
        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"root\Microsoft\Windows\Defender",
                "SELECT AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions FROM MSFT_MpPreference");
            foreach (ManagementObject obj in searcher.Get())
            {
                using (obj)
                {
                    var ids = obj["AttackSurfaceReductionRules_Ids"] as string[] ?? [];
                    var actions = (obj["AttackSurfaceReductionRules_Actions"] as Array)?.Cast<object?>()
                        .Select(a => a is null ? 0 : Convert.ToInt32(a, System.Globalization.CultureInfo.InvariantCulture)).ToArray() ?? [];
                    asr = ids.Select((id, i) => new AsrRule(id, i < actions.Length ? actions[i] : 0)).ToList();
                }
            }
        }
        catch (ManagementException)
        {
            asr = null;
        }

        int onboarding = RegistryHelper.GetValue(MdeStatusKey, "OnboardingState", -1);
        return new AvEdrSnapshot
        {
            Defender = defender,
            DefenderError = defenderError,
            SecurityCenterAvailable = securityCenter,
            SecurityCenterProducts = products,
            Services = services,
            RegistryKeysPresent = RegistryPathsToProbe.Where(RegistryHelper.KeyExists).ToList(),
            MdeOnboardingState = onboarding < 0 ? null : onboarding,
            AsrRules = asr,
        };
    }

    internal static SecurityCenterProductState DecodeSecurityCenterProductState(uint state)
    {
        var provider = (byte)((state >> 16) & 0xFF);
        var scannerState = (byte)((state >> 8) & 0xFF);
        var signatureStatus = (byte)(state & 0xFF);

        return new SecurityCenterProductState(
            provider,
            scannerState,
            signatureStatus,
            Enabled: scannerState is 0x10 or 0x11,
            SignaturesUpToDate: signatureStatus == 0x00);
    }

    internal readonly record struct SecurityCenterProductState(
        byte Provider,
        byte ScannerState,
        byte SignatureStatus,
        bool Enabled,
        bool SignaturesUpToDate);

    private static bool GetBool(ManagementObject obj, string prop)
    {
        try { return obj[prop] is true; } catch { return false; }
    }

    private static bool? GetNullableBool(ManagementObject obj, string prop)
    {
        try { return obj[prop] is bool value ? value : null; } catch { return null; }
    }

    private static string? GetString(ManagementObject obj, string prop)
    {
        try { return obj[prop]?.ToString(); } catch { return null; }
    }
    private static int GetInt(ManagementObject obj, string prop)
    {
        try { return Convert.ToInt32(obj[prop] ?? 0); } catch { return -1; }
    }
}
