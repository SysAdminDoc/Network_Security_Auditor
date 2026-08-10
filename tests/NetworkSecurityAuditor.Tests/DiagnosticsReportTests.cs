using System.Text.Json;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

namespace NetworkSecurityAuditor.Tests;

public class DiagnosticsReportTests
{
    [Fact]
    public void Run_Produces_Bounded_Operator_Report_Without_Identity_Fields()
    {
        var outputDirectory = Path.Combine(Path.GetTempPath(), "nsa-diagnostics-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(outputDirectory);

        try
        {
            var report = DiagnosticsReport.Run(
                new EnvironmentInfo
                {
                    ComputerName = "SECRET-HOST",
                    DomainName = "secret.example",
                    OSVersion = "24H2",
                    OSBuild = 26100,
                    IsAdmin = true,
                    IsDomainJoined = true,
                    HasAD = true,
                    WinRMRunning = true,
                    HasDefender = true,
                    HasBitLocker = true,
                    HasSMB = true
                },
                outputDirectory,
                noInternet: true,
                browserResolver: () => null);

            var json = report.ToJson();
            using var document = JsonDocument.Parse(json);

            Assert.Equal(DiagnosticsReport.SchemaVersion, document.RootElement.GetProperty("schema").GetString());
            Assert.Contains(report.Checks, check => check.Id == "imports" && check.Status == "Ready");
            Assert.Contains(report.Checks, check => check.Id == "internet" && check.Status == "Degraded");
            Assert.Contains(report.Checks, check => check.Id == "pdf" && check.Status == "Degraded");
            Assert.DoesNotContain("SECRET-HOST", json, StringComparison.Ordinal);
            Assert.DoesNotContain("secret.example", json, StringComparison.Ordinal);
        }
        finally
        {
            if (Directory.Exists(outputDirectory))
                Directory.Delete(outputDirectory, recursive: true);
        }
    }

    [Fact]
    public void Run_Marks_Missing_Output_Parent_Blocked()
    {
        var missing = Path.Combine(Path.GetTempPath(), "nsa-diagnostics-missing-" + Guid.NewGuid().ToString("N"), "reports");
        var report = DiagnosticsReport.Run(new EnvironmentInfo(), missing, noInternet: false, browserResolver: () => "C:\\browser.exe");

        Assert.Contains(report.Checks, check => check.Id == "output" && check.Status == "Blocked");
        Assert.True(report.HasBlocked);
    }
}
