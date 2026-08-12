namespace NetworkSecurityAuditor.Tests;

using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;

public sealed class DependencyHealthToolingTests
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    [Fact]
    public void Dependency_Gate_Offline_Clean_Report_Passes_And_Reports_Direct_And_Transitive_Packages()
    {
        if (!OperatingSystem.IsWindows())
            return;

        using var fixture = DependencyFixture.Create();
        fixture.WriteInventory(
            topLevel: [Package("Direct.Package", "1.2.3")],
            transitive: [Package("Transitive.Package", "2.0.0")]);
        fixture.WriteCleanVulnerabilityReport();
        fixture.WriteCleanOutdatedReport();

        var result = fixture.Run(release: true);

        Assert.Equal(0, result.ExitCode);
        Assert.Equal("Pass", result.Report["decision"]!["status"]!.GetValue<string>());
        Assert.Equal("PrecomputedOffline", result.Report["execution"]!["mode"]!.GetValue<string>());
        Assert.Contains("No network access", result.Report["execution"]!["network_behavior"]!.GetValue<string>());
        Assert.Equal(2, result.Report["summary"]!["package_occurrences"]!.GetValue<int>());
        Assert.Equal(1, result.Report["summary"]!["direct_occurrences"]!.GetValue<int>());
        Assert.Equal(1, result.Report["summary"]!["transitive_occurrences"]!.GetValue<int>());
    }

    [Fact]
    public void Dependency_Gate_Fails_Any_Vulnerability_In_Local_And_Release_Policy()
    {
        if (!OperatingSystem.IsWindows())
            return;

        using var fixture = DependencyFixture.Create();
        fixture.WriteInventory(topLevel: [Package("Risk.Package", "3.1.0")]);
        fixture.WriteVulnerabilityReport(
            Package(
                "Risk.Package",
                "3.1.0",
                vulnerabilities:
                [
                    new JsonObject
                    {
                        ["severity"] = "High",
                        ["advisoryurl"] = "https://example.test/advisories/RISK-1",
                    },
                ]));
        fixture.WriteCleanOutdatedReport();

        var local = fixture.Run(release: false);
        var release = fixture.Run(release: true);

        Assert.Equal(2, local.ExitCode);
        Assert.Equal(2, release.ExitCode);
        Assert.Equal("Fail", release.Report["decision"]!["status"]!.GetValue<string>());
        Assert.Equal(1, release.Report["summary"]!["vulnerable_package_occurrences"]!.GetValue<int>());
        Assert.Equal(1, release.Report["summary"]!["vulnerability_advisories"]!.GetValue<int>());
    }

    [Fact]
    public void Dependency_Gate_Warns_Locally_And_Requires_Exact_Dated_Release_Exception()
    {
        if (!OperatingSystem.IsWindows())
            return;

        using var fixture = DependencyFixture.Create();
        fixture.WriteInventory(topLevel: [Package("Drift.Package", "4.2.1")]);
        fixture.WriteCleanVulnerabilityReport();
        fixture.WriteOutdatedReport(Package("Drift.Package", "4.2.1", latest: "4.2.2"));

        var local = fixture.Run(release: false);
        var unapprovedRelease = fixture.Run(release: true);

        Assert.Equal(0, local.ExitCode);
        Assert.Equal("Warning", local.Report["decision"]!["status"]!.GetValue<string>());
        Assert.Equal(3, unapprovedRelease.ExitCode);
        Assert.Equal("Fail", unapprovedRelease.Report["decision"]!["status"]!.GetValue<string>());

        fixture.WriteException(
            name: "approved-drift-package-patch",
            packageId: "Drift.Package",
            resolvedVersion: "4.2.1",
            latestVersion: "4.2.2",
            expiresOn: "2026-09-01");
        var approvedRelease = fixture.Run(release: true);

        Assert.Equal(0, approvedRelease.ExitCode);
        Assert.Equal("PassWithExceptions", approvedRelease.Report["decision"]!["status"]!.GetValue<string>());
        Assert.Equal(1, approvedRelease.Report["summary"]!["approved_exception_occurrences"]!.GetValue<int>());
        Assert.Equal(
            "approved-drift-package-patch",
            approvedRelease.Report["summary"]!["used_exception_names"]![0]!.GetValue<string>());
    }

    [Fact]
    public void Release_Publisher_Invokes_Dependency_Gate_And_Archives_Its_Report()
    {
        var script = File.ReadAllText(Path.Combine(FindRepoRoot(), "tools", "Publish-CSharpRelease.ps1"));

        Assert.Contains("Test-DependencyHealth.ps1", script);
        Assert.Contains("'-Release'", script);
        Assert.Contains("'-NoRestore'", script);
        Assert.Contains("dependency-health.json", script);
        Assert.Contains("dependency_health =", script);
        Assert.Contains("$dependencyHealthPath, $manifestPath", script);
    }

    private static JsonObject Package(
        string id,
        string resolved,
        string? latest = null,
        JsonArray? vulnerabilities = null)
    {
        var package = new JsonObject
        {
            ["id"] = id,
            ["requestedVersion"] = resolved,
            ["resolvedVersion"] = resolved,
        };
        if (latest is not null)
            package["latestVersion"] = latest;
        if (vulnerabilities is not null)
            package["vulnerabilities"] = vulnerabilities;
        return package;
    }

    private static string FindRepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "NetworkSecurityAuditor.slnx")))
            directory = directory.Parent;

        return directory?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }

    private sealed class DependencyFixture : IDisposable
    {
        private readonly string root;
        private readonly string reportsDirectory;
        private readonly string exceptionsPath;
        private int reportSequence;

        private DependencyFixture(string root)
        {
            this.root = root;
            reportsDirectory = Path.Combine(root, "reports");
            exceptionsPath = Path.Combine(root, "exceptions.json");
            Directory.CreateDirectory(reportsDirectory);
            WriteExceptions([]);
        }

        public static DependencyFixture Create() =>
            new(Path.Combine(Path.GetTempPath(), "nsa-dependency-health-" + Guid.NewGuid().ToString("N")));

        public void WriteInventory(JsonObject[] topLevel, JsonObject[]? transitive = null) =>
            WriteReport("inventory.json", Report(topLevel, transitive ?? []));

        public void WriteCleanVulnerabilityReport() => WriteReport("vulnerable.json", EmptyReport());

        public void WriteVulnerabilityReport(JsonObject package) =>
            WriteReport("vulnerable.json", Report([package], []));

        public void WriteCleanOutdatedReport() => WriteReport("outdated.json", EmptyReport());

        public void WriteOutdatedReport(JsonObject package) =>
            WriteReport("outdated.json", Report([package], []));

        public void WriteException(
            string name,
            string packageId,
            string resolvedVersion,
            string latestVersion,
            string expiresOn) =>
            WriteExceptions(
            [
                new JsonObject
                {
                    ["name"] = name,
                    ["package_id"] = packageId,
                    ["resolved_version"] = resolvedVersion,
                    ["latest_version"] = latestVersion,
                    ["owner"] = "Dependency owner",
                    ["reason"] = "Scheduled for the next validated dependency refresh.",
                    ["expires_on"] = expiresOn,
                },
            ]);

        public GateResult Run(bool release)
        {
            var outputPath = Path.Combine(root, $"result-{++reportSequence}.json");
            var repoRoot = FindRepoRoot();
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo("powershell.exe")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    WorkingDirectory = repoRoot,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                },
            };
            process.StartInfo.ArgumentList.Add("-NoProfile");
            process.StartInfo.ArgumentList.Add("-NonInteractive");
            process.StartInfo.ArgumentList.Add("-ExecutionPolicy");
            process.StartInfo.ArgumentList.Add("Bypass");
            process.StartInfo.ArgumentList.Add("-File");
            process.StartInfo.ArgumentList.Add(Path.Combine(repoRoot, "tools", "Test-DependencyHealth.ps1"));
            process.StartInfo.ArgumentList.Add("-OfflineReportsDirectory");
            process.StartInfo.ArgumentList.Add(reportsDirectory);
            process.StartInfo.ArgumentList.Add("-ExceptionsPath");
            process.StartInfo.ArgumentList.Add(exceptionsPath);
            process.StartInfo.ArgumentList.Add("-OutputPath");
            process.StartInfo.ArgumentList.Add(outputPath);
            process.StartInfo.ArgumentList.Add("-AsOfDate");
            process.StartInfo.ArgumentList.Add("2026-08-12");
            if (release)
                process.StartInfo.ArgumentList.Add("-Release");

            Assert.True(process.Start(), "Failed to launch dependency health gate.");
            Assert.True(process.WaitForExit(20_000), "Dependency health gate timed out.");
            var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
            Assert.True(File.Exists(outputPath), $"Dependency health gate did not write a report. Output: {output}");
            var report = JsonNode.Parse(File.ReadAllText(outputPath))?.AsObject()
                ?? throw new InvalidOperationException("Dependency health result was not a JSON object.");
            return new GateResult(process.ExitCode, report, output);
        }

        public void Dispose()
        {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }

        private void WriteExceptions(JsonObject[] exceptions)
        {
            var document = new JsonObject
            {
                ["schema_version"] = "1.0",
                ["exceptions"] = new JsonArray(exceptions),
            };
            File.WriteAllText(exceptionsPath, document.ToJsonString(JsonOptions));
        }

        private void WriteReport(string fileName, JsonObject report) =>
            File.WriteAllText(Path.Combine(reportsDirectory, fileName), report.ToJsonString(JsonOptions));

        private static JsonObject EmptyReport() =>
            new()
            {
                ["version"] = 1,
                ["projects"] = new JsonArray(new JsonObject { ["path"] = "src/Fixture.csproj" }),
            };

        private static JsonObject Report(JsonObject[] topLevel, JsonObject[] transitive) =>
            new()
            {
                ["version"] = 1,
                ["sources"] = new JsonArray("https://api.nuget.org/v3/index.json"),
                ["projects"] = new JsonArray(
                    new JsonObject
                    {
                        ["path"] = "src/Fixture.csproj",
                        ["frameworks"] = new JsonArray(
                            new JsonObject
                            {
                                ["framework"] = "net10.0-windows",
                                ["topLevelPackages"] = new JsonArray(topLevel),
                                ["transitivePackages"] = new JsonArray(transitive),
                            }),
                    }),
            };
    }

    private sealed record GateResult(int ExitCode, JsonObject Report, string Output);
}
