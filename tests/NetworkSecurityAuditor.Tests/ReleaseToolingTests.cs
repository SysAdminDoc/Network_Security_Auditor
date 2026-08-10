namespace NetworkSecurityAuditor.Tests;

using System.Diagnostics;

public class ReleaseToolingTests
{
    [Fact]
    public void Csharp_Release_Tool_Cleans_Tests_Publishes_Signs_And_Checksums()
    {
        var script = ReadSourceFile("tools", "Publish-CSharpRelease.ps1");

        Assert.Contains("Remove-Item -LiteralPath $resolvedArtifactsDir -Recurse -Force", script);
        Assert.Contains("Assert-ReleaseArtifactsPath", script);
        Assert.Contains("$artifactsRootWithSeparator", script);
        Assert.Contains("FileAttributes]::ReparsePoint", script);
        Assert.Contains("'test', $solutionPath", script);
        Assert.Contains("'publish'", script);
        Assert.Contains("Set-AuthenticodeSignature", script);
        Assert.Contains("Get-CodeSigningCertificate", script);
        Assert.Contains("Compress-Archive", script);
        Assert.Contains("Get-Sha256Hex -Path $zipPath", script);
        Assert.Contains("Write-CycloneDxSbom", script);
        Assert.Contains("dotnet list $projectPath package --include-transitive --format json", script);
        Assert.Contains("runtime_support", script);
        Assert.Contains("package_inventory", script);
        Assert.Contains(".cdx.json", script);
        Assert.Contains("SHA256SUMS.txt", script);
        Assert.Contains("release-manifest.json", script);
        Assert.Contains("windows-net10", script);
        Assert.DoesNotContain("windows-net9", script);
        Assert.Contains("NetworkSecurityAuditor.exe", script);
    }

    [Theory]
    [InlineData(".")]
    [InlineData("artifacts")]
    [InlineData("src")]
    [InlineData("tests")]
    [InlineData("tools")]
    [InlineData("..")]
    public void Csharp_Release_Tool_Rejects_Dangerous_Artifact_Directories(string relativePath)
    {
        if (!OperatingSystem.IsWindows())
            return;

        var repoRoot = FindRepoRoot();
        var scriptPath = Path.Combine(repoRoot, "tools", "Publish-CSharpRelease.ps1");
        var markerPath = Path.Combine(repoRoot, "src", "NetworkSecurityAuditor", "NetworkSecurityAuditor.csproj");
        var markerBefore = File.ReadAllBytes(markerPath);
        var targetPath = Path.GetFullPath(Path.Combine(repoRoot, relativePath));

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
        process.StartInfo.ArgumentList.Add(scriptPath);
        process.StartInfo.ArgumentList.Add("-ArtifactsDir");
        process.StartInfo.ArgumentList.Add(targetPath);
        process.StartInfo.ArgumentList.Add("-SkipTests");
        process.StartInfo.ArgumentList.Add("-SkipSigning");

        Assert.True(process.Start(), "Failed to launch the release script.");
        Assert.True(process.WaitForExit(30_000), $"Release validation did not stop for '{relativePath}'.");

        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        Assert.NotEqual(0, process.ExitCode);
        Assert.Contains("Refusing", output, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(markerBefore, File.ReadAllBytes(markerPath));
    }

    [Fact]
    public void Readme_Documents_Local_Csharp_Installable_Artifact()
    {
        var readme = ReadSourceFile("README.md");

        Assert.Contains(".\\tools\\Publish-CSharpRelease.ps1", readme);
        Assert.Contains("NetworkSecurityAuditor-csharp-v", readme);
        Assert.Contains("windows-net10", readme);
        Assert.Contains("CycloneDX SBOM", readme);
        Assert.Contains("SHA256SUMS.txt", readme);
        Assert.Contains(".NET 10 Desktop Runtime", readme);
    }

    [Fact]
    public void VersionInfo_Derives_From_InformationalVersion_Without_Stale_Literal()
    {
        var source = ReadSourceFile("src", "NetworkSecurityAuditor", "VersionInfo.cs");

        Assert.Contains("AssemblyInformationalVersionAttribute", source);
        Assert.DoesNotContain("?? \"5.", source);
        Assert.Equal("5.3.3", VersionInfo.Version);
    }

    [Fact]
    public void App_Checks_AttachConsole_Return_And_Documents_Waited_Exit_Codes()
    {
        var app = ReadSourceFile("src", "NetworkSecurityAuditor", "App.xaml.cs");
        var readme = ReadSourceFile("README.md");

        Assert.Contains("if (!AttachConsole(-1))", app);
        Assert.DoesNotContain("AttachConsole(-1);", app);
        Assert.Contains("Start-Process -Wait -PassThru", readme);
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
