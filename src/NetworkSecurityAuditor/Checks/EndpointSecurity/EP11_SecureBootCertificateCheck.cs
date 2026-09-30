namespace NetworkSecurityAuditor.Checks.EndpointSecurity;

using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// EP11 - Secure Boot 2023 certificate transition. The 2011 Microsoft Secure Boot certificates expire in 2026
/// (Windows Production PCA 2011 on 2026-10-19); a device that hasn't moved to the 2023 certificates stops getting
/// boot manager and DBX fixes. Everything here is readable without elevation: the Secure Boot servicing registry
/// values and the Microsoft-Windows-TPM-WMI events in the System log.
/// </summary>
public sealed class EP11_SecureBootCertificateCheck : ISecurityCheck
{
    public string Id => "EP11";

    internal const string SecureBootKey = @"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot";
    internal const string StateKey = SecureBootKey + @"\State";
    internal const string ServicingKey = SecureBootKey + @"\Servicing";
    internal const string TpmWmiProvider = "Microsoft-Windows-TPM-WMI";
    internal static readonly DateOnly Pca2011Expires = new(2026, 10, 19);

    /// <summary>
    /// AvailableUpdates bits documented in Microsoft's Secure Boot troubleshooting guide and the CVE-2023-24932
    /// boot manager revocation article. 0x5944 requests the full 2023 transition; it reads 0x4100 until the new
    /// boot manager is in place after a restart, then 0x4000.
    /// </summary>
    internal static readonly IReadOnlyList<(int Bit, string Meaning)> AvailableUpdateBits =
    [
        (0x0004, "apply a Key Exchange Key signed by the device's Platform Key (Microsoft Corporation KEK 2K CA 2023)"),
        (0x0040, "add Windows UEFI CA 2023 to the DB"),
        (0x0080, "add Windows Production PCA 2011 to the DBX"),
        (0x0100, "install the boot manager signed by Windows UEFI CA 2023"),
        (0x0200, "apply the Secure Version Number update to the firmware"),
        (0x0800, "add Microsoft Option ROM UEFI CA 2023 to the DB"),
        (0x1000, "add Microsoft UEFI CA 2023 to the DB"),
        (0x4000, "apply 0x0800 and 0x1000 only where Microsoft UEFI CA 2011 is already trusted"),
    ];

    /// <summary>TPM-WMI System log events with documented meanings.</summary>
    internal static readonly IReadOnlyDictionary<int, string> EventMeanings = new Dictionary<int, string>
    {
        [1795] = "the firmware rejected a Secure Boot variable update",
        [1799] = "the boot manager signed by Windows UEFI CA 2023 was installed",
        [1801] = "the updated Secure Boot certificates haven't been applied to the firmware",
        [1803] = "the KEK update can't be authorized because the OEM hasn't supplied a Platform Key-signed KEK",
        [1808] = "the device has the new Secure Boot certificates in its firmware",
    };

    internal enum FirmwareKind { Unknown, Bios, Uefi }

    internal sealed record SecureBootEvent(int Id, DateTime Time);

    internal sealed record SecureBootSnapshot
    {
        public FirmwareKind Firmware { get; init; }
        /// <summary>State\UEFISecureBootEnabled; null when the value is absent.</summary>
        public int? SecureBootEnabled { get; init; }
        public string? Status { get; init; }
        public int? Error { get; init; }
        public int? ErrorEvent { get; init; }
        public int? Capable { get; init; }
        public int? AvailableUpdates { get; init; }
        /// <summary>Newest first; null when the System log couldn't be read.</summary>
        public IReadOnlyList<SecureBootEvent>? Events { get; init; }
        public string? EventError { get; init; }
    }

    internal sealed record SecureBootCertAssessment(CheckStatus Status, string Findings, string Evidence);

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var assessment = Assess(CollectSnapshot(ct), DateOnly.FromDateTime(DateTime.Now));
            return Task.FromResult(new CheckResult
            {
                Status = assessment.Status,
                Findings = assessment.Findings,
                Evidence = assessment.Evidence
            });
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.FromError(Id, ex));
        }
    }

    internal static SecureBootCertAssessment Assess(SecureBootSnapshot s, DateOnly today)
    {
        var sb = new StringBuilder();
        var evidence = new StringBuilder();

        evidence.AppendLine("[Secure Boot State]");
        evidence.AppendLine($"  Firmware: {s.Firmware}");
        evidence.AppendLine($"  UEFISecureBootEnabled: {Show(s.SecureBootEnabled)}");
        evidence.AppendLine("\n[Secure Boot Servicing]");
        evidence.AppendLine($"  UEFICA2023Status: {s.Status ?? "(not set)"}");
        evidence.AppendLine($"  UEFICA2023Error: {(s.Error is { } e ? Hex(e) : "(not set)")}");
        if (s.ErrorEvent is { } ee) evidence.AppendLine($"  UEFICA2023ErrorEvent: {ee}");
        evidence.AppendLine($"  WindowsUEFICA2023Capable: {Show(s.Capable)}{(s.Capable is { } c ? $" ({DescribeCapable(c)})" : "")}");
        evidence.AppendLine($"  AvailableUpdates: {(s.AvailableUpdates is { } au ? Hex(au) : "(not set)")}");
        foreach (var line in DecodeAvailableUpdates(s.AvailableUpdates ?? 0))
            evidence.AppendLine($"    {line}");
        evidence.AppendLine($"\n[{TpmWmiProvider} events (System log)]");
        if (s.Events is null)
            evidence.AppendLine($"  Couldn't read: {s.EventError ?? "unavailable"}");
        else if (s.Events.Count == 0)
            evidence.AppendLine("  None of events 1795, 1799, 1801, 1803 or 1808 are in the log.");
        foreach (var ev in (s.Events ?? []).Take(10))
            evidence.AppendLine($"  {ev.Time.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)}  {ev.Id}: {EventMeanings.GetValueOrDefault(ev.Id, "unrecognized event")}");

        var latestResult = s.Events?.FirstOrDefault(e => e.Id is 1801 or 1808);
        if (latestResult is not null)
            sb.AppendLine($"Latest certificate event: {latestResult.Id} on {latestResult.Time.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)} ({EventMeanings[latestResult.Id]}).");

        if (s.Firmware == FirmwareKind.Bios)
        {
            sb.Insert(0, "N/A: This device boots in legacy BIOS mode, so Secure Boot certificates don't apply.\n");
            return Result(CheckStatus.NA);
        }
        if (s.SecureBootEnabled is null && s.Status is null && s.Capable is null)
        {
            sb.Insert(0, "N/A: This device doesn't report Secure Boot support, so the 2023 certificate transition doesn't apply.\n");
            return Result(CheckStatus.NA);
        }
        if (s.SecureBootEnabled == 0)
        {
            sb.Insert(0, $"N/A: Secure Boot is off, so the certificate transition protects nothing yet (EP08 reports Secure Boot being off). Transition status: {s.Status ?? "not reported"}.\n");
            return Result(CheckStatus.NA);
        }

        var daysLeft = Pca2011Expires.DayNumber - today.DayNumber;
        var deadline = daysLeft >= 0
            ? $"Windows Production PCA 2011 expires {Format(Pca2011Expires)} ({daysLeft} days)"
            : $"Windows Production PCA 2011 expired {Format(Pca2011Expires)}";
        var firmwareHint = s.Events?.FirstOrDefault(e => e.Id is 1795 or 1803) is { } fw
            ? $" Event {fw.Id} ({fw.Time.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}): {EventMeanings[fw.Id]}. Check the OEM for a firmware update."
            : "";

        if (s.Error is { } error and not 0)
        {
            sb.Insert(0, $"FAIL: The Secure Boot certificate update stopped with error {Hex(error)}{(s.ErrorEvent is { } errEvent ? $" (event {errEvent})" : "")}. {deadline}.{firmwareHint}\n");
            return Result(CheckStatus.Fail);
        }

        switch (s.Status?.Trim())
        {
            case { } st when st.Equals("Updated", StringComparison.OrdinalIgnoreCase):
                sb.Insert(0, $"Secure Boot 2023 certificates: Updated{(s.Capable == 2 ? ", booting from the boot manager signed by Windows UEFI CA 2023" : "")}.\n");
                return Result(CheckStatus.Pass);
            case { } st when st.Equals("InProgress", StringComparison.OrdinalIgnoreCase):
                sb.Insert(0, $"PARTIAL: The move to the 2023 Secure Boot certificates is in progress{PendingRestart(s.AvailableUpdates)}. {deadline}.{firmwareHint}\n");
                return Result(CheckStatus.Partial);
            case { } st when st.Equals("NotStarted", StringComparison.OrdinalIgnoreCase):
                sb.Insert(0, $"FAIL: The move to the 2023 Secure Boot certificates hasn't started. {deadline}. Install the current cumulative update, or set AvailableUpdates to 0x5944 on managed devices.{firmwareHint}\n");
                return Result(CheckStatus.Fail);
            case { } st:
                sb.Insert(0, $"PARTIAL: UEFICA2023Status reads \"{st}\", which isn't a documented state (NotStarted, InProgress, Updated). {deadline}.\n");
                return Result(CheckStatus.Partial);
        }

        // Older servicing builds don't write UEFICA2023Status; fall back to the certificate events and the DB flag.
        if (latestResult?.Id == 1808 || s.Capable == 2)
        {
            sb.Insert(0, $"Secure Boot 2023 certificates: applied ({(latestResult?.Id == 1808 ? "event 1808" : "WindowsUEFICA2023Capable = 2")}), although Windows doesn't report UEFICA2023Status.\n");
            return Result(CheckStatus.Pass);
        }
        if (s.Capable == 1)
        {
            sb.Insert(0, $"PARTIAL: Windows UEFI CA 2023 is in the DB, but the device still starts from the boot manager signed with the 2011 certificate. {deadline}.{firmwareHint}\n");
            return Result(CheckStatus.Partial);
        }
        sb.Insert(0, $"FAIL: Windows hasn't reported moving this device to the 2023 Secure Boot certificates{(latestResult?.Id == 1801 ? " and event 1801 says they aren't applied" : "")}. {deadline}. Install the current cumulative update.{firmwareHint}\n");
        return Result(CheckStatus.Fail);

        SecureBootCertAssessment Result(CheckStatus status) =>
            new(status, sb.ToString().TrimEnd(), evidence.ToString().TrimEnd());
    }

    /// <summary>Decodes AvailableUpdates into one line per set bit; undocumented bits are listed as such.</summary>
    internal static IReadOnlyList<string> DecodeAvailableUpdates(int value)
    {
        var lines = new List<string>();
        var known = 0;
        foreach (var (bit, meaning) in AvailableUpdateBits)
        {
            known |= bit;
            if ((value & bit) != 0)
                lines.Add($"{Hex(bit)}: {meaning}");
        }
        var unknown = value & ~known;
        if (unknown != 0)
            lines.Add($"{Hex(unknown)}: bits Microsoft doesn't document");
        if (value == 0x4000)
            lines.Add("Only the 0x4000 modifier is left, so every requested update has been applied.");
        return lines;
    }

    private static string PendingRestart(int? availableUpdates) =>
        availableUpdates is { } v && (v & 0x0100) != 0 && (v & ~0x4100) == 0
            ? " (the new boot manager is waiting for a restart)"
            : "";

    internal static string DescribeCapable(int value) => value switch
    {
        0 => "Windows UEFI CA 2023 isn't in the DB",
        1 => "Windows UEFI CA 2023 is in the DB",
        2 => "in the DB, and the device starts from the 2023-signed boot manager",
        _ => "undocumented value",
    };

    private static SecureBootSnapshot CollectSnapshot(CancellationToken ct)
    {
        var (events, eventError) = ReadEvents(ct);
        return new SecureBootSnapshot
        {
            Firmware = ReadFirmwareKind(),
            SecureBootEnabled = ReadInt(StateKey, "UEFISecureBootEnabled"),
            Status = RegistryHelper.GetValue<string>(ServicingKey, "UEFICA2023Status", null),
            Error = ReadInt(ServicingKey, "UEFICA2023Error"),
            ErrorEvent = ReadInt(ServicingKey, "UEFICA2023ErrorEvent"),
            Capable = ReadInt(ServicingKey, "WindowsUEFICA2023Capable"),
            AvailableUpdates = ReadInt(SecureBootKey, "AvailableUpdates"),
            Events = events,
            EventError = eventError,
        };
    }

    private static int? ReadInt(string key, string name)
    {
        var raw = RegistryHelper.GetValue<object>(key, name, null);
        return raw switch
        {
            int i => i,
            long l => unchecked((int)l),
            string str when int.TryParse(str, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) => parsed,
            _ => null,
        };
    }

    private static (IReadOnlyList<SecureBootEvent>? Events, string? Error) ReadEvents(CancellationToken ct)
    {
        try
        {
            var query = $"*[System[Provider[@Name='{TpmWmiProvider}'] and (EventID=1795 or EventID=1799 or EventID=1801 or EventID=1803 or EventID=1808)]]";
            var records = EventLogQueryHelper.Read("System", query, maxEvents: 50, ct);
            return (records.Select(r => new SecureBootEvent(r.Id, r.TimeCreated)).ToList(), null);
        }
        catch (EventLogException ex)
        {
            return (null, ex.Message.Trim());
        }
        catch (UnauthorizedAccessException ex)
        {
            return (null, ex.Message.Trim());
        }
    }

    private static FirmwareKind ReadFirmwareKind()
    {
        try
        {
            if (GetFirmwareType(out var type))
                return type switch { 1 => FirmwareKind.Bios, 2 => FirmwareKind.Uefi, _ => FirmwareKind.Unknown };
        }
        catch (EntryPointNotFoundException)
        {
        }

        return Environment.GetEnvironmentVariable("firmware_type") switch
        {
            "UEFI" => FirmwareKind.Uefi,
            "Legacy" => FirmwareKind.Bios,
            _ => FirmwareKind.Unknown,
        };
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFirmwareType(out int firmwareType);

    private static string Show(int? value) => value?.ToString(CultureInfo.InvariantCulture) ?? "(not set)";

    private static string Hex(int value) => "0x" + value.ToString("X4", CultureInfo.InvariantCulture);

    private static string Format(DateOnly date) => date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
}
