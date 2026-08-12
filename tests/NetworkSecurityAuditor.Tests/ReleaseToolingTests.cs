namespace NetworkSecurityAuditor.Tests;

using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

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
        Assert.Contains("[System.IO.Path]::GetDirectoryName($existingPath)", script);
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
        Assert.Contains("schema_version = '1.0'", script);
        Assert.Contains("Verify-CSharpRelease.ps1", script);
        Assert.Contains("covered_files = $coveredFiles", script);
        Assert.Contains("Get-ZipMetadata", script);
        Assert.Contains("'-File', $verifierPath, '-ReleaseDir', $releaseDir", script);
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
        Assert.Contains("Verify-CSharpRelease.ps1", readme);
    }

    [Fact]
    public void Csharp_Release_Verifier_Validates_Complete_Local_Bundle()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var dir = CreateReleaseFixture();
        try
        {
            var result = RunVerifier(dir);

            Assert.Equal(0, result.ExitCode);
            Assert.Contains("VERIFIED:", result.Output);
            Assert.Contains("Authenticode: not signed (SkippedByParameter); signature was not claimed.", result.Output);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Theory]
    [InlineData("missing-zip", "missing its file")]
    [InlineData("tampered-sbom", "Checksum mismatch")]
    [InlineData("missing-manifest", "Missing release-manifest.json")]
    [InlineData("missing-checksum-entry", "missing required entry")]
    public void Csharp_Release_Verifier_Rejects_Missing_Or_Tampered_Contract_Files(string mutation, string expected)
    {
        if (!OperatingSystem.IsWindows())
            return;

        var dir = CreateReleaseFixture();
        try
        {
            switch (mutation)
            {
                case "missing-zip":
                    File.Delete(Path.Combine(dir, FixturePackageName));
                    break;
                case "tampered-sbom":
                    File.AppendAllText(Path.Combine(dir, FixtureSbomName), "tampered", Encoding.UTF8);
                    break;
                case "missing-manifest":
                    File.Delete(Path.Combine(dir, "release-manifest.json"));
                    break;
                case "missing-checksum-entry":
                    File.WriteAllLines(
                        Path.Combine(dir, "SHA256SUMS.txt"),
                        File.ReadAllLines(Path.Combine(dir, "SHA256SUMS.txt"))
                            .Where(line => !line.EndsWith(FixtureSbomName, StringComparison.Ordinal)));
                    break;
            }

            var result = RunVerifier(dir);

            Assert.NotEqual(0, result.ExitCode);
            Assert.Contains(expected, result.Output, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Csharp_Release_Verifier_Rejects_Invalid_Sbom_After_Hashes_Are_Updated()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var dir = CreateReleaseFixture();
        try
        {
            var sbomPath = Path.Combine(dir, FixtureSbomName);
            var sbom = JsonNode.Parse(File.ReadAllText(sbomPath))!.AsObject();
            sbom["$schema"] = "https://cyclonedx.org/schema/bom-1.4.schema.json";
            File.WriteAllText(sbomPath, sbom.ToJsonString(JsonOptions));
            RefreshManifestAndChecksums(dir);

            var result = RunVerifier(dir);

            Assert.NotEqual(0, result.ExitCode);
            Assert.Contains("does not declare the CycloneDX 1.5 JSON schema", result.Output);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Csharp_Release_Verifier_Rejects_Zip_Without_Entrypoint_After_Hashes_Are_Updated()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var dir = CreateReleaseFixture();
        try
        {
            var zipPath = Path.Combine(dir, FixturePackageName);
            var replacement = Path.Combine(dir, "replacement.zip");
            using (var source = ZipFile.OpenRead(zipPath))
            using (var target = ZipFile.Open(replacement, ZipArchiveMode.Create))
            {
                foreach (var entry in source.Entries.Where(entry => entry.FullName != "NetworkSecurityAuditor.exe"))
                {
                    var copy = target.CreateEntry(entry.FullName);
                    using var input = entry.Open();
                    using var output = copy.Open();
                    input.CopyTo(output);
                }
            }
            File.Move(replacement, zipPath, overwrite: true);
            RefreshManifestAndChecksums(dir);

            var result = RunVerifier(dir);

            Assert.NotEqual(0, result.ExitCode);
            Assert.Contains("ZIP entrypoint is missing", result.Output);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Csharp_Release_Verifier_Requires_Manifest_And_Valid_Authenticode_When_Requested()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var dir = CreateReleaseFixture();
        try
        {
            var result = RunVerifier(dir, requireSignature: true);

            Assert.NotEqual(0, result.ExitCode);
            Assert.Contains("signature is required", result.Output, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("SkippedByParameter", result.Output);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
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

    private const string FixturePackageName = "NetworkSecurityAuditor-csharp-v1.2.3-windows-net10.zip";
    private const string FixtureSbomName = "NetworkSecurityAuditor-csharp-v1.2.3-windows-net10.cdx.json";
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private static string CreateReleaseFixture()
    {
        var repoRoot = FindRepoRoot();
        var dir = Path.Combine(Path.GetTempPath(), "nsa-release-verifier-" + Guid.NewGuid().ToString("N"));
        var payload = Path.Combine(dir, "payload");
        Directory.CreateDirectory(payload);
        File.WriteAllBytes(Path.Combine(payload, "NetworkSecurityAuditor.exe"), [0x4d, 0x5a, 0x00, 0x00]);
        File.WriteAllBytes(Path.Combine(payload, "NetworkSecurityAuditor.dll"), [0x4d, 0x5a, 0x00, 0x00]);
        File.WriteAllText(Path.Combine(payload, "NetworkSecurityAuditor.deps.json"), "{}");
        File.WriteAllText(Path.Combine(payload, "NetworkSecurityAuditor.runtimeconfig.json"), """
            {
              "runtimeOptions": {
                "tfm": "net10.0",
                "framework": { "name": "Microsoft.WindowsDesktop.App", "version": "10.0.0" }
              }
            }
            """);
        var zipPath = Path.Combine(dir, FixturePackageName);
        ZipFile.CreateFromDirectory(payload, zipPath);
        Directory.Delete(payload, recursive: true);

        var sbom = new JsonObject
        {
            ["$schema"] = "https://cyclonedx.org/schema/bom-1.5.schema.json",
            ["bomFormat"] = "CycloneDX",
            ["specVersion"] = "1.5",
            ["version"] = 1,
            ["metadata"] = new JsonObject
            {
                ["component"] = new JsonObject
                {
                    ["type"] = "application",
                    ["name"] = "NetworkSecurityAuditor",
                    ["version"] = "1.2.3"
                }
            },
            ["components"] = new JsonArray()
        };
        File.WriteAllText(Path.Combine(dir, FixtureSbomName), sbom.ToJsonString(JsonOptions));
        File.Copy(Path.Combine(repoRoot, "tools", "Verify-CSharpRelease.ps1"), Path.Combine(dir, "Verify-CSharpRelease.ps1"));

        using var archive = ZipFile.OpenRead(zipPath);
        var uncompressedBytes = archive.Entries.Sum(entry => entry.Length);
        var manifest = new JsonObject
        {
            ["schema_version"] = "1.0",
            ["project"] = "NetworkSecurityAuditor",
            ["artifact"] = "CSharpRewrite",
            ["version"] = "1.2.3",
            ["configuration"] = "Release",
            ["target_framework"] = "net10.0-windows",
            ["install"] = new JsonObject
            {
                ["package"] = FixturePackageName,
                ["entrypoint"] = "NetworkSecurityAuditor.exe",
                ["framework"] = ".NET 10 Desktop Runtime"
            },
            ["archive"] = new JsonObject
            {
                ["format"] = "zip",
                ["file"] = FixturePackageName,
                ["entrypoint"] = "NetworkSecurityAuditor.exe",
                ["runtime_config"] = "NetworkSecurityAuditor.runtimeconfig.json",
                ["deps_file"] = "NetworkSecurityAuditor.deps.json",
                ["entry_count"] = archive.Entries.Count,
                ["uncompressed_bytes"] = uncompressedBytes
            },
            ["runtime_support"] = new JsonObject
            {
                ["framework"] = ".NET 10 Desktop Runtime",
                ["target_framework"] = "net10.0-windows"
            },
            ["signing"] = new JsonObject
            {
                ["status"] = "SkippedByParameter",
                ["signed_files"] = new JsonArray(),
                ["certificate_thumbprint"] = ""
            },
            ["sbom"] = new JsonObject
            {
                ["format"] = "CycloneDX",
                ["spec_version"] = "1.5",
                ["file"] = FixtureSbomName,
                ["sha256"] = Hash(Path.Combine(dir, FixtureSbomName)),
                ["component_count"] = 0
            },
            ["verification"] = new JsonObject
            {
                ["tool"] = "Verify-CSharpRelease.ps1",
                ["sha256"] = Hash(Path.Combine(dir, "Verify-CSharpRelease.ps1"))
            },
            ["checksums"] = new JsonObject
            {
                ["file"] = "SHA256SUMS.txt",
                ["algorithm"] = "SHA256",
                ["covered_files"] = new JsonArray(FixturePackageName, FixtureSbomName, "Verify-CSharpRelease.ps1", "release-manifest.json")
            },
            ["artifacts"] = new JsonArray(
                Artifact(FixturePackageName, dir),
                Artifact(FixtureSbomName, dir),
                Artifact("Verify-CSharpRelease.ps1", dir))
        };
        File.WriteAllText(Path.Combine(dir, "release-manifest.json"), manifest.ToJsonString(JsonOptions));
        WriteChecksums(dir, manifest);
        return dir;
    }

    private static void RefreshManifestAndChecksums(string dir)
    {
        var manifestPath = Path.Combine(dir, "release-manifest.json");
        var manifest = JsonNode.Parse(File.ReadAllText(manifestPath))!.AsObject();
        foreach (var artifact in manifest["artifacts"]!.AsArray().Select(node => node!.AsObject()))
        {
            var name = artifact["file"]!.GetValue<string>();
            artifact["sha256"] = Hash(Path.Combine(dir, name));
        }
        manifest["sbom"]!["sha256"] = Hash(Path.Combine(dir, FixtureSbomName));
        manifest["verification"]!["sha256"] = Hash(Path.Combine(dir, "Verify-CSharpRelease.ps1"));
        using (var archive = ZipFile.OpenRead(Path.Combine(dir, FixturePackageName)))
        {
            manifest["archive"]!["entry_count"] = archive.Entries.Count;
            manifest["archive"]!["uncompressed_bytes"] = archive.Entries.Sum(entry => entry.Length);
        }
        File.WriteAllText(manifestPath, manifest.ToJsonString(JsonOptions));
        WriteChecksums(dir, manifest);
    }

    private static JsonObject Artifact(string fileName, string dir) => new()
    {
        ["file"] = fileName,
        ["sha256"] = Hash(Path.Combine(dir, fileName))
    };

    private static void WriteChecksums(string dir, JsonObject manifest)
    {
        var lines = manifest["checksums"]!["covered_files"]!.AsArray()
            .Select(node => node!.GetValue<string>())
            .Select(name => $"{Hash(Path.Combine(dir, name))}  {name}");
        File.WriteAllLines(Path.Combine(dir, "SHA256SUMS.txt"), lines, Encoding.ASCII);
    }

    private static string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();

    private static VerifierResult RunVerifier(string releaseDir, bool requireSignature = false)
    {
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
                RedirectStandardError = true
            }
        };
        process.StartInfo.ArgumentList.Add("-NoProfile");
        process.StartInfo.ArgumentList.Add("-NonInteractive");
        process.StartInfo.ArgumentList.Add("-ExecutionPolicy");
        process.StartInfo.ArgumentList.Add("Bypass");
        process.StartInfo.ArgumentList.Add("-File");
        process.StartInfo.ArgumentList.Add(Path.Combine(repoRoot, "tools", "Verify-CSharpRelease.ps1"));
        process.StartInfo.ArgumentList.Add("-ReleaseDir");
        process.StartInfo.ArgumentList.Add(releaseDir);
        if (requireSignature)
            process.StartInfo.ArgumentList.Add("-RequireSignature");

        Assert.True(process.Start(), "Failed to launch the release verifier.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(20_000), "Release verifier did not finish within 20 seconds.");
        Task.WaitAll(stdout, stderr);
        return new VerifierResult(process.ExitCode, stdout.Result + stderr.Result);
    }

    private sealed record VerifierResult(int ExitCode, string Output);

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
