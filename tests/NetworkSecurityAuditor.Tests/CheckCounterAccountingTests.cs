namespace NetworkSecurityAuditor.Tests;

public class CheckCounterAccountingTests
{
    [Theory]
    [InlineData("src/NetworkSecurityAuditor/Checks/EndpointSecurity/EP07_AppControlCheck.cs")]
    [InlineData("src/NetworkSecurityAuditor/Checks/LoggingMonitoring/LM07_LogRetentionCheck.cs")]
    [InlineData("src/NetworkSecurityAuditor/Checks/LoggingMonitoring/LM01_DnsLoggingCheck.cs")]
    public void Applicable_Check_Counters_Are_Not_Adjusted_By_Decrementing_Failures(string relativePath)
    {
        var source = File.ReadAllText(Path.Combine(FindRepoRoot(), relativePath));

        Assert.DoesNotContain("failCount--", source);
    }

    [Theory]
    [InlineData("src/NetworkSecurityAuditor/Checks/EndpointSecurity/EP07_AppControlCheck.cs")]
    [InlineData("src/NetworkSecurityAuditor/Checks/LoggingMonitoring/LM01_DnsLoggingCheck.cs")]
    public void Optional_Checks_Are_Not_Removed_By_Decrementing_Totals_After_Precounting(string relativePath)
    {
        var source = File.ReadAllText(Path.Combine(FindRepoRoot(), relativePath));

        Assert.DoesNotContain("totalChecks--", source);
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
