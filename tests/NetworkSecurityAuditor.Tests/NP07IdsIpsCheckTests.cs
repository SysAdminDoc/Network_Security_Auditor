namespace NetworkSecurityAuditor.Tests;

using System.Text.RegularExpressions;
using NetworkSecurityAuditor.Checks.NetworkPerimeter;
using NetworkSecurityAuditor.Models;
using Agent = NetworkSecurityAuditor.Checks.NetworkPerimeter.NP07_IdsIpsCheck.AgentService;
using Snapshot = NetworkSecurityAuditor.Checks.NetworkPerimeter.NP07_IdsIpsCheck.IdsSnapshot;

public sealed class NP07IdsIpsCheckTests
{
    private static readonly Agent StockSense = new("Sense", "Windows Defender Advanced Threat Protection Service", "Stopped", "Defender for Endpoint");

    [Theory]
    [InlineData("BrokerInfrastructure")]
    [InlineData("TimeBrokerSvc")]
    [InlineData("SystemEventsBroker")]
    [InlineData("cbdhsvc_8c0c6")]
    [InlineData("SQLBrowser")]
    [InlineData("SensorService")]
    public void Built_In_Services_Match_No_Agent_Pattern(string serviceName)
    {
        Assert.DoesNotContain(NP07_IdsIpsCheck.AgentServices, a => NP07_IdsIpsCheck.NameMatches(a.Pattern, serviceName));
    }

    [Fact]
    public void Stock_Windows_11_Host_Does_Not_Pass()
    {
        var result = NP07_IdsIpsCheck.Assess(new Snapshot { Services = [StockSense], NisEnabled = true });

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("No running IDS/IPS or EDR agent on this host.", result.Findings);
        Assert.Contains("Defender for Endpoint (not running)", result.Findings);
        Assert.Contains("isn't a network IDS/IPS", result.Findings);
    }

    [Fact]
    public void A_Running_Ids_Passes_And_A_Stopped_One_Does_Not()
    {
        var running = NP07_IdsIpsCheck.Assess(new Snapshot { Services = [new Agent("Suricata", "Suricata IDS", "Running", "Suricata IDS")] });
        var stopped = NP07_IdsIpsCheck.Assess(new Snapshot { Services = [new Agent("Suricata", "Suricata IDS", "Stopped", "Suricata IDS")] });

        Assert.Equal(CheckStatus.Pass, running.Status);
        Assert.Contains("Suricata IDS: Suricata IDS", running.Findings);
        Assert.Equal(CheckStatus.Partial, stopped.Status);
        Assert.Contains("Suricata IDS (not running)", stopped.Findings);
    }

    [Fact]
    public void Defender_For_Endpoint_Counts_Only_When_Onboarded_And_Running()
    {
        var sense = StockSense with { State = "Running" };

        Assert.Equal(CheckStatus.Pass, NP07_IdsIpsCheck.Assess(new Snapshot { Services = [sense], MdeOnboardingState = 1 }).Status);
        var notOnboarded = NP07_IdsIpsCheck.Assess(new Snapshot { Services = [sense], MdeOnboardingState = 0 });
        Assert.Equal(CheckStatus.Partial, notOnboarded.Status);
        Assert.Contains("not onboarded (OnboardingState 0)", notOnboarded.Findings);
        Assert.Equal(CheckStatus.Partial, NP07_IdsIpsCheck.Assess(new Snapshot { Services = [StockSense], MdeOnboardingState = 1 }).Status);
    }

    [Fact]
    public void Install_Traces_Alone_Do_Not_Pass()
    {
        var result = NP07_IdsIpsCheck.Assess(new Snapshot { TraceLabels = ["Wazuh"] });

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("Install traces without a running agent: Wazuh.", result.Findings);
    }

    [Fact]
    public void Prefix_Patterns_Match_Only_At_The_Start()
    {
        Assert.True(NP07_IdsIpsCheck.NameMatches("Snort*", "SnortSvc"));
        Assert.False(NP07_IdsIpsCheck.NameMatches("Snort*", "MySnortSvc"));
        Assert.True(NP07_IdsIpsCheck.NameMatches("Sense", "sense"));
        Assert.False(NP07_IdsIpsCheck.NameMatches("Sense", "SenseNdr"));
    }

    // The PowerShell NP07 block carries its own copy of the list; this keeps the two in step.
    [Fact]
    public void PowerShell_Service_List_Matches_The_App_List()
    {
        var script = File.ReadAllText(Path.Combine(FindRepoRoot(), "NetworkSecurityAudit.ps1"));
        var start = script.IndexOf("'NP07' = @{ Type='Local'", StringComparison.Ordinal);
        var end = script.IndexOf("'NP08' = @{", start, StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start);
        var rows = Regex.Matches(script[start..end], @"@\{Name='(?<name>[^']+)';Desc='(?<desc>[^']+)'\}");

        Assert.Equal(NP07_IdsIpsCheck.AgentServices.Select(a => (a.Pattern, a.Label)), rows.Select(r => (r.Groups["name"].Value, r.Groups["desc"].Value)));
        Assert.Contains("$status = if ($found) {'Pass'} else {'Partial'}", script[start..end]);
    }

    [Fact]
    public async Task Live_Host_Collection_Completes_Without_A_Check_Error()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var env = NetworkSecurityAuditor.Services.EnvironmentDetector.Detect();
        var result = await new NP07_IdsIpsCheck().ExecuteAsync(env, new AuditOptions(), CancellationToken.None);

        Assert.Null(result.Error);
        Assert.DoesNotContain("BrokerInfrastructure", result.Evidence);
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "NetworkSecurityAuditor.slnx")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new DirectoryNotFoundException("Could not locate NetworkSecurityAuditor.slnx from test output directory.");
    }
}
