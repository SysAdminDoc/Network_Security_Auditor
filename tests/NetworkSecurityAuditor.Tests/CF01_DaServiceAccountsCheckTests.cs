using System.Runtime.InteropServices;
using NetworkSecurityAuditor.Checks.CommonFindings;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class CF01_DaServiceAccountsCheckTests
{
    private static Task<CheckResult> Run(FixtureDirectoryReader reader, string sysvolPoliciesPath) =>
        new CF01_DaServiceAccountsCheck(_ => reader, _ => sysvolPoliciesPath)
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

    [Fact]
    public async Task Clean_Domain_Admins_With_Gmsa_And_Clean_Sysvol_Passes()
    {
        var root = CreatePolicyRoot();
        try
        {
            var reader = FixtureDirectoryReader.Load("CF01-pass.json");
            var result = await Run(reader, root);

            Assert.Equal(CheckStatus.Pass, result.Status);
            Assert.StartsWith("No critical service account issues detected in Domain Admins.", result.Findings);
            Assert.Contains("gMSA adoption: 2 group managed service account(s) found (good).", result.Findings);
            Assert.Contains("ADCS: 1 Certificate Authority(ies) found.", result.Findings);
            Assert.DoesNotContain("CRITICAL", result.Findings);
            Assert.Contains("Service accounts in DA: 0", result.Evidence);
            Assert.Contains("CA: CORP-CA01-CA (ca01.corp.example)", result.Evidence);
            Assert.Contains("No GPP passwords found.", result.Evidence);
            Assert.Equal(1, reader.Queries.Single(q => q.Filter.Contains("Domain Admins", StringComparison.Ordinal)).SizeLimit);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Service_Accounts_In_Domain_Admins_Fail()
    {
        var root = CreatePolicyRoot();
        try
        {
            var result = await Run(FixtureDirectoryReader.Load("CF01-fail.json"), root);

            Assert.Equal(CheckStatus.Fail, result.Status);
            Assert.StartsWith("Service account security issues detected.", result.Findings);
            Assert.Contains("CRITICAL: Likely service account \"svc_sql\" is in Domain Admins. [HasSPN] [PwdNeverExpires]", result.Findings);
            Assert.Contains("CRITICAL: Likely service account \"veeam.backup\" is in Domain Admins.\n", result.Findings.ReplaceLineEndings("\n"));
            Assert.DoesNotContain("\"Administrator\"", result.Findings);
            Assert.Contains("Recommendation: Remove service accounts from Domain Admins.", result.Findings);
            Assert.Contains("INFO: No gMSA accounts found.", result.Findings);
            Assert.Contains("Could not read: CN=Ops Admin,CN=Users,DC=emea,DC=corp,DC=example", result.Evidence);
            Assert.Contains("Service accounts in DA: 2", result.Evidence);
            Assert.Contains("No ADCS enrollment services found.", result.Evidence);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Gpp_Cpassword_In_Sysvol_Fails_Even_With_Clean_Domain_Admins()
    {
        var root = CreatePolicyRoot();
        try
        {
            var machineGroups = Path.Combine(root, "{31B2F340-016D-11D2-945F-00C04FB984F9}", "Machine", "Preferences", "Groups");
            Directory.CreateDirectory(machineGroups);
            File.WriteAllText(Path.Combine(machineGroups, "Groups.xml"),
                """<Groups><User name="LocalAdmin"><Properties cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" /></User></Groups>""");

            var result = await Run(FixtureDirectoryReader.Load("CF01-pass.json"), root);

            Assert.Equal(CheckStatus.Fail, result.Status);
            Assert.Contains("CRITICAL: 1 GPP file(s) with cpassword found in SYSVOL.", result.Findings);
            Assert.Contains("GPP PASSWORD FOUND:", result.Evidence);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Directory_Failure_Is_An_Error()
    {
        var result = await new CF01_DaServiceAccountsCheck(_ => throw new COMException("The server is not operational.", unchecked((int)0x8007203A)))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Error, result.Status);
    }

    [Fact]
    public void GppPasswordScan_Counts_NonEmpty_Cpassword_Files()
    {
        var root = CreatePolicyRoot();
        try
        {
            var machineGroups = Path.Combine(root, "policy-1", "Machine", "Preferences", "Groups");
            var userDrives = Path.Combine(root, "policy-1", "User", "Preferences", "Drives");
            Directory.CreateDirectory(machineGroups);
            Directory.CreateDirectory(userDrives);
            File.WriteAllText(Path.Combine(machineGroups, "Groups.xml"), """<User cpassword="not-empty" />""");
            File.WriteAllText(Path.Combine(userDrives, "Drives.xml"), """<Drive cpassword="" />""");

            var result = CF01_DaServiceAccountsCheck.ScanGppPasswordFiles(root, CancellationToken.None);

            Assert.Equal(1, result.FoundCount);
            Assert.Equal(2, result.InspectedCount);
            Assert.Contains(result.EvidenceLines, line => line.Contains("GPP PASSWORD FOUND", StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void GppPasswordScan_Skips_Oversized_Files()
    {
        var root = CreatePolicyRoot();
        try
        {
            var machineGroups = Path.Combine(root, "policy-1", "Machine", "Preferences", "Groups");
            Directory.CreateDirectory(machineGroups);
            var content = new string('x', (int)CF01_DaServiceAccountsCheck.MaxGppFileBytes + 1) + """ cpassword="not-empty" """;
            File.WriteAllText(Path.Combine(machineGroups, "Groups.xml"), content);

            var result = CF01_DaServiceAccountsCheck.ScanGppPasswordFiles(root, CancellationToken.None);

            Assert.Equal(0, result.FoundCount);
            Assert.Equal(0, result.InspectedCount);
            Assert.Equal(1, result.SkippedOversizedCount);
            Assert.Contains(result.EvidenceLines, line => line.Contains("Skipped oversized GPP file", StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void GppPasswordScan_Honors_Cancellation()
    {
        var root = CreatePolicyRoot();
        try
        {
            using var cts = new CancellationTokenSource();
            cts.Cancel();

            Assert.Throws<OperationCanceledException>(() =>
                CF01_DaServiceAccountsCheck.ScanGppPasswordFiles(root, cts.Token));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static string CreatePolicyRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "nsa-cf01-gpp-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }
}
