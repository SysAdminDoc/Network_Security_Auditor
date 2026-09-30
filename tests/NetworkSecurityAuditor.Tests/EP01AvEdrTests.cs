namespace NetworkSecurityAuditor.Tests;

using NetworkSecurityAuditor.Checks.EndpointSecurity;
using NetworkSecurityAuditor.Models;
using Defender = NetworkSecurityAuditor.Checks.EndpointSecurity.EP01_AvEdrCheck.DefenderStatus;
using Product = NetworkSecurityAuditor.Checks.EndpointSecurity.EP01_AvEdrCheck.SecurityCenterProduct;
using Snapshot = NetworkSecurityAuditor.Checks.EndpointSecurity.EP01_AvEdrCheck.AvEdrSnapshot;

public sealed class EP01AvEdrTests(Xunit.Abstractions.ITestOutputHelper output)
{
    private const uint EnabledUpToDate = 0x041000u;
    private const uint EnabledOutOfDate = 0x041010u;
    private const uint Disabled = 0x040100u;

    private static Defender ActiveDefender() => new()
    {
        AmServiceEnabled = true,
        AntispywareEnabled = true,
        AntivirusEnabled = true,
        RealTimeProtectionEnabled = true,
        NisEnabled = true,
        SignatureAgeDays = 0,
        AmRunningMode = "Normal",
        IsTamperProtected = true,
    };

    private static Defender PassiveDefender() => ActiveDefender() with
    {
        RealTimeProtectionEnabled = false,
        AmRunningMode = "Passive Mode",
    };

    // Every Windows 10+ host carries the WATP key and the Sense service, onboarded or not.
    private static Snapshot StockWindows(Defender? defender = null) => new()
    {
        Defender = defender ?? ActiveDefender(),
        SecurityCenterAvailable = true,
        SecurityCenterProducts = [new Product("Windows Defender", 0x061100u)],
        Services = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["Sense"] = "Stopped" },
        RegistryKeysPresent = [EP01_AvEdrCheck.MdeKey],
        AsrRules = [],
    };

    [Fact]
    public void Stock_Windows_Does_Not_Report_Defender_For_Endpoint()
    {
        var assessment = EP01_AvEdrCheck.Assess(StockWindows());

        Assert.Equal(CheckStatus.Pass, assessment.Status);
        Assert.DoesNotContain("Defender for Endpoint", assessment.EdrProducts);
        Assert.Contains("Defender for Endpoint not counted", assessment.Evidence);
    }

    [Fact]
    public void Onboarded_Defender_For_Endpoint_Needs_OnboardingState_And_A_Running_Sense()
    {
        var onboardedStopped = StockWindows() with { MdeOnboardingState = 1 };
        var running = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["Sense"] = "Running" };
        var runningNotOnboarded = StockWindows() with { Services = running, MdeOnboardingState = 0 };
        var onboardedRunning = StockWindows() with { Services = running, MdeOnboardingState = 1 };

        Assert.DoesNotContain("Defender for Endpoint", EP01_AvEdrCheck.Assess(onboardedStopped).EdrProducts);
        Assert.DoesNotContain("Defender for Endpoint", EP01_AvEdrCheck.Assess(runningNotOnboarded).EdrProducts);
        Assert.Contains("Defender for Endpoint", EP01_AvEdrCheck.Assess(onboardedRunning).EdrProducts);
    }

    [Fact]
    public void Palo_Alto_Key_Alone_Is_Not_Cortex_Xdr()
    {
        var globalProtectOnly = StockWindows() with { RegistryKeysPresent = [EP01_AvEdrCheck.MdeKey, EP01_AvEdrCheck.PaloAltoKey] };
        var cortex = globalProtectOnly with
        {
            Services = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["Sense"] = "Stopped", ["cyserver"] = "Running" },
        };

        var vpnOnly = EP01_AvEdrCheck.Assess(globalProtectOnly);
        Assert.DoesNotContain("Cortex XDR", vpnOnly.EdrProducts);
        Assert.Contains("GlobalProtect", vpnOnly.Evidence);
        Assert.Contains("Cortex XDR", EP01_AvEdrCheck.Assess(cortex).EdrProducts);
    }

    [Fact]
    public void Leftover_Edr_Registry_Key_Without_A_Running_Agent_Is_Not_Counted()
    {
        var leftover = StockWindows() with { RegistryKeysPresent = [EP01_AvEdrCheck.MdeKey, @"HKLM\SOFTWARE\ESET"] };
        var stopped = leftover with
        {
            Services = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["Sense"] = "Stopped", ["ekrn"] = "Stopped" },
        };
        var running = leftover with
        {
            Services = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["Sense"] = "Stopped", ["ekrn"] = "Running" },
        };

        var trace = EP01_AvEdrCheck.Assess(leftover);
        Assert.Empty(trace.EdrProducts);
        Assert.Contains("install trace only", trace.Evidence);
        Assert.Empty(EP01_AvEdrCheck.Assess(stopped).EdrProducts);
        Assert.Equal(["ESET"], EP01_AvEdrCheck.Assess(running).EdrProducts);
    }

    [Fact]
    public void A_Running_Agent_Service_Counts_Even_When_Its_Sibling_Is_Stopped()
    {
        var sophos = StockWindows() with
        {
            RegistryKeysPresent = [EP01_AvEdrCheck.MdeKey, @"HKLM\SOFTWARE\Sophos"],
            Services = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Sense"] = "Stopped",
                ["SAVService"] = "Stopped",
                ["Sophos Endpoint Defense Service"] = "Running",
            },
        };

        var assessment = EP01_AvEdrCheck.Assess(sophos);
        Assert.Equal(["Sophos"], assessment.EdrProducts);
        Assert.Contains("FOUND: Sophos (Sophos Endpoint Defense Service service Running)", assessment.Evidence);
    }

    [Fact]
    public void Passive_Defender_Beside_An_Active_Third_Party_Av_Passes()
    {
        var snapshot = StockWindows(PassiveDefender()) with
        {
            SecurityCenterProducts = [new Product("Windows Defender", 0x060100u), new Product("Sophos Anti-Virus", EnabledUpToDate)],
        };

        var assessment = EP01_AvEdrCheck.Assess(snapshot);

        Assert.Equal(CheckStatus.Pass, assessment.Status);
        Assert.Contains("Passive Mode", assessment.Findings);
        Assert.Contains("Sophos Anti-Virus is the registered, active antivirus", assessment.Findings);
        Assert.DoesNotContain("CRITICAL", assessment.Findings);
    }

    [Fact]
    public void Defender_Turned_Off_By_A_Third_Party_Av_Is_Not_A_Failure()
    {
        var off = ActiveDefender() with { AntivirusEnabled = false, RealTimeProtectionEnabled = false, AmRunningMode = "Not running" };
        var snapshot = StockWindows(off) with
        {
            SecurityCenterProducts = [new Product("ESET Security", EnabledUpToDate)],
        };

        Assert.Equal(CheckStatus.Pass, EP01_AvEdrCheck.Assess(snapshot).Status);
    }

    [Fact]
    public void Passive_Defender_Without_Another_Active_Av_Fails()
    {
        var alone = EP01_AvEdrCheck.Assess(StockWindows(PassiveDefender()));
        var disabledThirdParty = EP01_AvEdrCheck.Assess(StockWindows(PassiveDefender()) with
        {
            SecurityCenterProducts = [new Product("Sophos Anti-Virus", Disabled)],
        });

        Assert.Equal(CheckStatus.Fail, alone.Status);
        Assert.Contains("no other active antivirus", alone.Findings);
        Assert.Equal(CheckStatus.Fail, disabledThirdParty.Status);
    }

    [Fact]
    public void Primary_Third_Party_Av_With_Stale_Signatures_Is_Partial()
    {
        var snapshot = StockWindows(PassiveDefender()) with
        {
            SecurityCenterProducts = [new Product("Sophos Anti-Virus", EnabledOutOfDate)],
        };

        var assessment = EP01_AvEdrCheck.Assess(snapshot);

        Assert.Equal(CheckStatus.Partial, assessment.Status);
        Assert.Contains("out-of-date signatures", assessment.Findings);
    }

    [Fact]
    public void Active_Defender_Still_Fails_On_Stale_Signatures_Or_Disabled_Real_Time()
    {
        Assert.Equal(CheckStatus.Fail, EP01_AvEdrCheck.Assess(StockWindows(ActiveDefender() with { SignatureAgeDays = 9 })).Status);
        Assert.Equal(CheckStatus.Fail, EP01_AvEdrCheck.Assess(StockWindows(ActiveDefender() with { RealTimeProtectionEnabled = false })).Status);
    }

    [Fact]
    public void Tamper_Protection_And_Asr_Rule_Count_Appear_In_Evidence()
    {
        var snapshot = StockWindows(ActiveDefender() with { IsTamperProtected = false }) with
        {
            AsrRules =
            [
                new EP01_AvEdrCheck.AsrRule("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", 1),
                new EP01_AvEdrCheck.AsrRule("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", 2),
                new EP01_AvEdrCheck.AsrRule("d4f940ab-401b-4efc-aadc-ad5f3c50688a", 6),
                new EP01_AvEdrCheck.AsrRule("01443614-cd74-433a-b99e-2ecdc07bfc25", 0),
            ],
        };

        var assessment = EP01_AvEdrCheck.Assess(snapshot);

        Assert.Contains("Tamper Protection:         OFF", assessment.Evidence);
        Assert.Contains("ASR rules configured: 3 (Block: 1, Audit: 1, Warn: 1, Off: 1)", assessment.Evidence);
    }

    [Fact]
    public void Unreadable_Defender_Preferences_Report_Asr_As_Unknown()
    {
        var assessment = EP01_AvEdrCheck.Assess(StockWindows() with { AsrRules = null });

        Assert.Contains("ASR rules unknown", assessment.Evidence);
    }

    [Fact]
    public void Server_Without_Defender_Or_Security_Center_Fails_As_No_Av()
    {
        var assessment = EP01_AvEdrCheck.Assess(new Snapshot { DefenderError = "Invalid namespace" });

        Assert.Equal(CheckStatus.Fail, assessment.Status);
        Assert.Contains("No AV/EDR product detected", assessment.Findings);
    }

    [Fact]
    public async Task Live_Host_Collection_Completes_Without_A_Check_Error()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var result = await new EP01_AvEdrCheck().ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);
        output.WriteLine($"{result.Status}\n{result.Findings}\n{result.Evidence}");

        Assert.NotEqual(CheckStatus.NA, result.Status);
        Assert.Contains("[EDR/XDR Detection]", result.Evidence);
        Assert.Contains("[Attack Surface Reduction]", result.Evidence);
    }

    [Theory]
    [InlineData(0x041000u)]
    [InlineData(0x061100u)]
    public void DecodeSecurityCenterProductState_Recognizes_Enabled_And_UpToDate_States(uint rawState)
    {
        var decoded = EP01_AvEdrCheck.DecodeSecurityCenterProductState(rawState);

        Assert.True(decoded.Enabled);
        Assert.True(decoded.SignaturesUpToDate);
    }

    [Fact]
    public void DecodeSecurityCenterProductState_Uses_Full_Signature_Status_Byte()
    {
        var decoded = EP01_AvEdrCheck.DecodeSecurityCenterProductState(0x041001u);

        Assert.True(decoded.Enabled);
        Assert.Equal(0x01, decoded.SignatureStatus);
        Assert.False(decoded.SignaturesUpToDate);
    }

    [Fact]
    public void DecodeSecurityCenterProductState_Does_Not_Treat_Unknown_Scanner_State_As_Enabled()
    {
        var decoded = EP01_AvEdrCheck.DecodeSecurityCenterProductState(0x040000u);

        Assert.False(decoded.Enabled);
        Assert.True(decoded.SignaturesUpToDate);
    }
}
