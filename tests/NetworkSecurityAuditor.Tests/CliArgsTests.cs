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
    public void NoElevate_PowerShell_Alias_Parsed()
    {
        var args = App.ParseArgs(["-NoElevate"]);
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
    public void IntuneStigImport_Parsed()
    {
        var args = App.ParseArgs(["--intune-stig-import", @"C:\Exports\stig.json"]);
        Assert.Equal(@"C:\Exports\stig.json", args.IntuneStigImportPath);
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
        Assert.True(args.ExportOscalPoam);
        Assert.True(args.ExportIntune);
        Assert.True(args.ExportComplianceSummary);
        Assert.True(args.ExportSiem);
        Assert.True(args.ExportCmmc);
        Assert.True(args.ExportPdf);
    }

    [Fact]
    public void Individual_Export_Flags()
    {
        var args = App.ParseArgs(["--export-csv", "--export-sarif", "--export-pdf", "--export-oscal-poam", "-ExportDefectDojo"]);
        Assert.True(args.ExportCsv);
        Assert.True(args.ExportDefectDojo);
        Assert.True(args.ExportSarif);
        Assert.True(args.ExportPdf);
        Assert.True(args.ExportOscalPoam);
        Assert.False(args.ExportJsonl);
        Assert.False(args.ExportOcsf);
    }

    [Fact]
    public void Unknown_Flags_Are_Warned_And_Known_Flags_Still_Parse()
    {
        var args = App.ParseArgs(["--unknown", "--silent", "--bogus"]);
        Assert.True(args.Silent);
        Assert.Contains("Unknown argument ignored: --unknown", args.ParseWarnings);
        Assert.Contains("Unknown argument ignored: --bogus", args.ParseWarnings);
    }

    [Fact]
    public void Value_Flag_Does_Not_Consume_Following_Flag()
    {
        var args = App.ParseArgs(["--client", "--export-csv"]);

        Assert.Equal("", args.Client);
        Assert.True(args.ExportCsv);
        Assert.Contains("--client requires a value.", args.ParseWarnings);
    }

    [Fact]
    public void Last_Position_Value_Flag_Adds_Warning()
    {
        var args = App.ParseArgs(["--output"]);

        Assert.Equal("", args.OutputPath);
        Assert.Contains("--output requires a value.", args.ParseWarnings);
    }

    [Fact]
    public void Invalid_Enum_Value_Adds_Warning_And_Keeps_Default()
    {
        var args = App.ParseArgs(["--profile", "UnknownProfile", "--report-tier", "UnknownTier"]);

        Assert.Equal(ScanProfileType.Full, args.ScanProfile);
        Assert.Equal(ReportTier.All, args.ReportTier);
        Assert.Contains("--profile must be a valid scan profile.", args.ParseWarnings);
        Assert.Contains("--report-tier must be a valid report tier.", args.ParseWarnings);
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
    public void Gui_Mode_Attempts_Self_Elevation_When_Not_Admin()
    {
        var args = App.ParseArgs([]);

        Assert.True(App.ShouldAttemptSelfElevation(args, isRunningAsAdmin: false));
        Assert.False(App.ShouldWarnHeadlessWithoutElevation(args, isRunningAsAdmin: false));
    }

    [Theory]
    [InlineData("--silent")]
    [InlineData("--dashboard")]
    public void Headless_Mode_Does_Not_Attempt_Self_Elevation_When_Not_Admin(string flag)
    {
        var args = App.ParseArgs([flag]);

        Assert.False(App.ShouldAttemptSelfElevation(args, isRunningAsAdmin: false));
        Assert.True(App.ShouldWarnHeadlessWithoutElevation(args, isRunningAsAdmin: false));
    }

    [Fact]
    public void NoElevate_Suppresses_Elevation_And_Headless_Warning()
    {
        var args = App.ParseArgs(["--silent", "--no-elevate"]);

        Assert.False(App.ShouldAttemptSelfElevation(args, isRunningAsAdmin: false));
        Assert.False(App.ShouldWarnHeadlessWithoutElevation(args, isRunningAsAdmin: false));
    }

    [Fact]
    public void Dashboard_Missing_Input_Uses_Distinct_Exit_Code()
    {
        Assert.Equal(64, (int)ExitCode.InputPathUnavailable);

        var source = ReadSourceFile("src", "NetworkSecurityAuditor", "App.xaml.cs");
        Assert.Contains("return (int)ExitCode.InputPathUnavailable;", source);
    }

    [Fact]
    public void Elevated_Relaunch_Preserves_Working_Directory()
    {
        var source = ReadSourceFile("src", "NetworkSecurityAuditor", "App.xaml.cs");

        Assert.Contains("WorkingDirectory = System.Environment.CurrentDirectory", source);
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

    [Fact]
    public void ResolveOutputDirectory_Treats_Output_As_Directory()
    {
        var outputDir = Path.Combine(Path.GetTempPath(), "nsa-output");
        var fallback = Path.Combine(Path.GetTempPath(), "fallback");

        var resolved = App.ResolveOutputDirectory(outputDir, fallback);

        Assert.Equal(Path.GetFullPath(outputDir), resolved);
    }

    [Fact]
    public void SafeFileNameSegment_Replaces_Invalid_Path_Characters()
    {
        var segment = App.SafeFileNameSegment(@"ACME:West/Prod", "Client");

        Assert.DoesNotContain(Path.DirectorySeparatorChar, segment);
        Assert.DoesNotContain(Path.AltDirectorySeparatorChar, segment);
        Assert.DoesNotContain(':', segment);
        Assert.StartsWith("ACME", segment);
    }

    private static string ReadSourceFile(params string[] segments)
    {
        var pathSegments = new string[segments.Length + 1];
        pathSegments[0] = FindRepoRoot();
        Array.Copy(segments, 0, pathSegments, 1, segments.Length);
        return File.ReadAllText(Path.Combine(pathSegments));
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "NetworkSecurityAuditor.slnx")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new DirectoryNotFoundException("Could not locate NetworkSecurityAuditor.slnx from test output directory.");
    }
}
