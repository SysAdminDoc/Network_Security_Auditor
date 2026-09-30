using NetworkSecurityAuditor.Checks.EndpointSecurity;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using Xunit.Abstractions;
using Event = NetworkSecurityAuditor.Checks.EndpointSecurity.EP11_SecureBootCertificateCheck.SecureBootEvent;
using Firmware = NetworkSecurityAuditor.Checks.EndpointSecurity.EP11_SecureBootCertificateCheck.FirmwareKind;
using Snapshot = NetworkSecurityAuditor.Checks.EndpointSecurity.EP11_SecureBootCertificateCheck.SecureBootSnapshot;

namespace NetworkSecurityAuditor.Tests;

public class EP11SecureBootCertificateTests(ITestOutputHelper output)
{
    private static readonly DateOnly Today = new(2026, 9, 30);

    private static Snapshot Uefi(string? status, int? capable = null, int? availableUpdates = 0, int? error = 0, params Event[] events) => new()
    {
        Firmware = Firmware.Uefi,
        SecureBootEnabled = 1,
        Status = status,
        Capable = capable,
        AvailableUpdates = availableUpdates,
        Error = error,
        Events = events,
    };

    [Fact]
    public void Updated_Passes()
    {
        var a = EP11_SecureBootCertificateCheck.Assess(Uefi("Updated", 2, 0, 0, new Event(1808, new DateTime(2026, 9, 27))), Today);

        Assert.Equal(CheckStatus.Pass, a.Status);
        Assert.Contains("Updated, booting from the boot manager signed by Windows UEFI CA 2023", a.Findings);
        Assert.Contains("Latest certificate event: 1808 on 2026-09-27", a.Findings);
        Assert.Contains("WindowsUEFICA2023Capable: 2 (in the DB, and the device starts from the 2023-signed boot manager)", a.Evidence);
    }

    [Fact]
    public void In_Progress_Is_Partial_And_Names_A_Pending_Restart()
    {
        var a = EP11_SecureBootCertificateCheck.Assess(Uefi("InProgress", 1, 0x4100), Today);

        Assert.Equal(CheckStatus.Partial, a.Status);
        Assert.Contains("the new boot manager is waiting for a restart", a.Findings);
        Assert.Contains("Windows Production PCA 2011 expires 2026-10-19 (19 days)", a.Findings);
    }

    [Fact]
    public void Not_Started_Fails()
    {
        var a = EP11_SecureBootCertificateCheck.Assess(Uefi("NotStarted", 0, 0, 0, new Event(1801, new DateTime(2026, 9, 29))), Today);

        Assert.Equal(CheckStatus.Fail, a.Status);
        Assert.Contains("FAIL: The move to the 2023 Secure Boot certificates hasn't started", a.Findings);
        Assert.Contains("Latest certificate event: 1801", a.Findings);
    }

    [Fact]
    public void An_Error_Fails_Even_While_In_Progress_And_Points_At_Firmware()
    {
        var snapshot = Uefi("InProgress", 1, 0x5944, unchecked((int)0x80070015), new Event(1795, new DateTime(2026, 9, 28))) with { ErrorEvent = 1795 };
        var a = EP11_SecureBootCertificateCheck.Assess(snapshot, Today);

        Assert.Equal(CheckStatus.Fail, a.Status);
        Assert.Contains("stopped with error 0x80070015 (event 1795)", a.Findings);
        Assert.Contains("the firmware rejected a Secure Boot variable update. Check the OEM for a firmware update.", a.Findings);
    }

    [Fact]
    public void Legacy_Bios_And_Secure_Boot_Off_Are_Not_Applicable()
    {
        var bios = EP11_SecureBootCertificateCheck.Assess(new Snapshot { Firmware = Firmware.Bios, Events = [] }, Today);
        var unsupported = EP11_SecureBootCertificateCheck.Assess(new Snapshot { Firmware = Firmware.Unknown, Events = [] }, Today);
        var off = EP11_SecureBootCertificateCheck.Assess(Uefi("NotStarted") with { SecureBootEnabled = 0 }, Today);

        Assert.Equal(CheckStatus.NA, bios.Status);
        Assert.Contains("legacy BIOS", bios.Findings);
        Assert.Equal(CheckStatus.NA, unsupported.Status);
        Assert.Equal(CheckStatus.NA, off.Status);
        Assert.Contains("Secure Boot is off", off.Findings);
    }

    [Fact]
    public void Without_A_Status_Value_The_Events_And_Db_Flag_Decide()
    {
        var byEvent = EP11_SecureBootCertificateCheck.Assess(Uefi(null, null, null, null, new Event(1808, new DateTime(2026, 9, 1))), Today);
        var inDbOnly = EP11_SecureBootCertificateCheck.Assess(Uefi(null, 1, null, null), Today);
        var nothing = EP11_SecureBootCertificateCheck.Assess(Uefi(null, 0, null, null, new Event(1801, new DateTime(2026, 9, 1))), Today);

        Assert.Equal(CheckStatus.Pass, byEvent.Status);
        Assert.Equal(CheckStatus.Partial, inDbOnly.Status);
        Assert.Equal(CheckStatus.Fail, nothing.Status);
        Assert.Contains("event 1801 says they aren't applied", nothing.Findings);
    }

    [Fact]
    public void Undocumented_Status_Is_Partial()
    {
        Assert.Equal(CheckStatus.Partial, EP11_SecureBootCertificateCheck.Assess(Uefi("Pending"), Today).Status);
    }

    [Fact]
    public void Decodes_The_AvailableUpdates_Bitmask()
    {
        var full = EP11_SecureBootCertificateCheck.DecodeAvailableUpdates(0x5944);
        Assert.Equal(6, full.Count);
        Assert.Contains("0x0040: add Windows UEFI CA 2023 to the DB", full);
        Assert.Contains("0x0100: install the boot manager signed by Windows UEFI CA 2023", full);

        Assert.Contains("Only the 0x4000 modifier is left, so every requested update has been applied.", EP11_SecureBootCertificateCheck.DecodeAvailableUpdates(0x4000));
        Assert.Contains("0x0002: bits Microsoft doesn't document", EP11_SecureBootCertificateCheck.DecodeAvailableUpdates(0x0042));
        Assert.Empty(EP11_SecureBootCertificateCheck.DecodeAvailableUpdates(0));
    }

    [Fact]
    public void Is_Catalogued_As_A_Local_Read_Only_Check()
    {
        var meta = CheckCatalog.All["EP11"];
        Assert.Equal(CheckType.Local, meta.Type);
        Assert.Equal(RiskTier.ReadOnly, meta.RiskTier);
        Assert.Contains("T1542.003", MitreMappings.All["EP11"].Techniques);
        Assert.Contains("Bootloader Authentication", D3FendMappings.All["EP11"].Labels);
    }

    [Fact]
    public async Task Live_Host_Collection_Completes_Without_A_Check_Error()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var env = NetworkSecurityAuditor.Services.EnvironmentDetector.Detect();
        var result = await new EP11_SecureBootCertificateCheck().ExecuteAsync(env, new AuditOptions(), CancellationToken.None);
        output.WriteLine($"{result.Status}\n{result.Findings}\n{result.Evidence}");

        Assert.Null(result.Error);
        Assert.Contains("[Secure Boot Servicing]", result.Evidence);
        Assert.DoesNotContain("Couldn't read:", result.Evidence);
    }
}
