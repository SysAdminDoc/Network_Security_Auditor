using NetworkSecurityAuditor.Models;
using System.IO;

namespace NetworkSecurityAuditor.Tests;

public class CliArgsTests
{
    [Fact]
    public void Silent_Flag_Parsed()
    {
        var args = App.ParseArgs(["--silent"]);
        Assert.True(args.Silent);
    }

    [Fact]
    public void Dashboard_Flag_Parsed()
    {
        var args = App.ParseArgs(["--dashboard"]);
        Assert.True(args.Dashboard);
    }

    [Fact]
    public void NoElevate_Flag_Parsed()
    {
        var args = App.ParseArgs(["--no-elevate"]);
        Assert.True(args.NoElevate);
    }

    [Fact]
    public void NoInternet_Flag_Parsed()
    {
        var args = App.ParseArgs(["--no-internet"]);
        Assert.True(args.NoInternet);
    }

    [Fact]
    public void PrivacyMode_Flag_Parsed()
    {
        var args = App.ParseArgs(["--privacy"]);
        Assert.True(args.PrivacyMode);
    }

    [Fact]
    public void Profile_Parsed()
    {
        var args = App.ParseArgs(["--profile", "Quick"]);
        Assert.Equal(ScanProfileType.Quick, args.ScanProfile);
    }

    [Fact]
    public void Profile_CaseInsensitive()
    {
        var args = App.ParseArgs(["--profile", "hipaa"]);
        Assert.Equal(ScanProfileType.HIPAA, args.ScanProfile);
    }

    [Fact]
    public void Profile_Invalid_KeepsDefault()
    {
        var args = App.ParseArgs(["--profile", "invalid"]);
        Assert.Equal(ScanProfileType.Full, args.ScanProfile);
    }

    [Fact]
    public void ReportTier_Parsed()
    {
        var args = App.ParseArgs(["--report-tier", "Executive"]);
        Assert.Equal(ReportTier.Executive, args.ReportTier);
    }

    [Fact]
    public void OutputPath_Parsed()
    {
        var args = App.ParseArgs(["--output", @"C:\Reports"]);
        Assert.Equal(@"C:\Reports", args.OutputPath);
    }

    [Fact]
    public void Client_Parsed()
    {
        var args = App.ParseArgs(["--client", "Acme Corp"]);
        Assert.Equal("Acme Corp", args.Client);
    }

    [Fact]
    public void Auditor_Parsed()
    {
        var args = App.ParseArgs(["--auditor", "jsmith"]);
        Assert.Equal("jsmith", args.Auditor);
    }

    [Fact]
    public void Waivers_Parsed()
    {
        var args = App.ParseArgs(["--waivers", @"C:\waivers.json"]);
        Assert.Equal(@"C:\waivers.json", args.WaiversPath);
    }

    [Fact]
    public void Branding_Parsed()
    {
        var args = App.ParseArgs(["--branding", @"C:\brand.json"]);
        Assert.Equal(@"C:\brand.json", args.BrandingPath);
    }

    [Fact]
    public void InputDir_Parsed()
    {
        var args = App.ParseArgs(["--input-dir", @"C:\Scans"]);
        Assert.Equal(@"C:\Scans", args.InputDir);
    }

    [Fact]
    public void StaleDays_Parsed()
    {
        var args = App.ParseArgs(["--stale-days", "14"]);
        Assert.Equal(14, args.StaleDays);
    }

    [Fact]
    public void ExportAll_Sets_All_Formats()
    {
        var args = App.ParseArgs(["--export-all"]);
        Assert.True(args.ExportCsv);
        Assert.True(args.ExportJsonl);
        Assert.True(args.ExportDefectDojo);
        Assert.True(args.ExportSarif);
        Assert.True(args.ExportNavigator);
        Assert.True(args.ExportOcsf);
        Assert.True(args.ExportOscal);
        Assert.True(args.ExportIntune);
        Assert.True(args.ExportComplianceSummary);
        Assert.True(args.ExportSiem);
        Assert.True(args.ExportCmmc);
        Assert.True(args.ExportPdf);
    }

    [Fact]
    public void Individual_Export_Flags()
    {
        var args = App.ParseArgs(["--export-csv", "--export-sarif", "--export-pdf"]);
        Assert.True(args.ExportCsv);
        Assert.True(args.ExportSarif);
        Assert.True(args.ExportPdf);
        Assert.False(args.ExportJsonl);
        Assert.False(args.ExportOcsf);
    }

    [Fact]
    public void Unknown_Flags_Ignored()
    {
        var args = App.ParseArgs(["--unknown", "--silent", "--bogus"]);
        Assert.True(args.Silent);
    }

    [Fact]
    public void Empty_Args_Returns_Defaults()
    {
        var args = App.ParseArgs([]);
        Assert.False(args.Silent);
        Assert.False(args.Dashboard);
        Assert.Equal(ScanProfileType.Full, args.ScanProfile);
        Assert.Equal(ReportTier.All, args.ReportTier);
        Assert.Equal("", args.OutputPath);
        Assert.Equal(30, args.StaleDays);
    }

    [Fact]
    public void Multiple_Flags_Combined()
    {
        var args = App.ParseArgs(["--silent", "--no-internet", "--privacy", "--profile", "ADOnly", "--client", "TestCo", "--export-csv"]);
        Assert.True(args.Silent);
        Assert.True(args.NoInternet);
        Assert.True(args.PrivacyMode);
        Assert.Equal(ScanProfileType.ADOnly, args.ScanProfile);
        Assert.Equal("TestCo", args.Client);
        Assert.True(args.ExportCsv);
    }

    [Fact]
    public void PowerShell_Style_Flags_Accepted()
    {
        var args = App.ParseArgs(["-Silent", "-ScanProfile", "CMMC", "-ExportCSV"]);
        Assert.True(args.Silent);
        Assert.Equal(ScanProfileType.CMMC, args.ScanProfile);
        Assert.True(args.ExportCsv);
    }

    [Fact]
    public async Task Headless_Exception_Returns_Alert_ExitCode_And_Writes_Error()
    {
        using var errorWriter = new StringWriter();

        var exitCode = await App.RunHeadlessWithExitHandlingAsync(
            "Silent",
            () => throw new InvalidOperationException("locked export path"),
            errorWriter);

        var error = errorWriter.ToString();
        Assert.Equal((int)ExitCode.ImmediateAlert, exitCode);
        Assert.Contains("Silent mode failed", error);
        Assert.Contains("locked export path", error);
    }
}
