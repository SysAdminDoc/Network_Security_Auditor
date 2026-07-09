using NetworkSecurityAuditor.Checks.CommonFindings;

namespace NetworkSecurityAuditor.Tests;

public class CF01_DaServiceAccountsCheckTests
{
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
