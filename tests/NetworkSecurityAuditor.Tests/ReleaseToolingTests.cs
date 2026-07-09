namespace NetworkSecurityAuditor.Tests;

public class ReleaseToolingTests
{
    [Fact]
    public void Csharp_Release_Tool_Cleans_Tests_Publishes_Signs_And_Checksums()
    {
        var script = ReadSourceFile("tools", "Publish-CSharpRelease.ps1");

        Assert.Contains("Remove-Item -LiteralPath $resolvedArtifactsDir -Recurse -Force", script);
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
        Assert.Equal("5.3.0", VersionInfo.Version);
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
