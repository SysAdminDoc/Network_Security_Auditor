namespace NetworkSecurityAuditor.Tests;

using NetworkSecurityAuditor.Checks.LoggingMonitoring;
using NetworkSecurityAuditor.Models;
using Snapshot = NetworkSecurityAuditor.Checks.LoggingMonitoring.LM02_SiemCheck.SiemSnapshot;

public sealed class LM02SiemCheckTests(Xunit.Abstractions.ITestOutputHelper output)
{
    // Services present on a stock Windows 11 or Server host with nothing extra installed.
    private static Dictionary<string, string> CleanHostServices() =>
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["EventLog"] = "Running",
            ["Wecsvc"] = "Stopped",
            ["Sense"] = "Stopped",
            ["WinDefend"] = "Running",
        };

    [Fact]
    public void Clean_Windows_Host_Fails_Even_Though_EventLog_Wecsvc_And_Sense_Exist()
    {
        var assessment = LM02_SiemCheck.Assess(new Snapshot { Services = CleanHostServices() });

        Assert.Equal(CheckStatus.Fail, assessment.Status);
        Assert.Empty(assessment.CountedSources);
        Assert.Contains("local logging only", assessment.Evidence);
    }

    [Fact]
    public void EventLog_Alone_Never_Passes_Even_When_Every_Inbox_Service_Runs()
    {
        var services = CleanHostServices();
        services["Wecsvc"] = "Running";
        services["Sense"] = "Running";

        var assessment = LM02_SiemCheck.Assess(new Snapshot { Services = services, MdeOnboardingState = 0 });

        Assert.Equal(CheckStatus.Fail, assessment.Status);
        Assert.Contains("no subscriptions", assessment.Evidence);
        Assert.Contains("without OnboardingState = 1", assessment.Evidence);
    }

    [Fact]
    public void Running_Splunk_Universal_Forwarder_Passes()
    {
        var services = CleanHostServices();
        services["SplunkForwarder"] = "Running";

        var assessment = LM02_SiemCheck.Assess(new Snapshot
        {
            Services = services,
            RegistryKeysPresent = [@"HKLM\SOFTWARE\Splunk"],
        });

        Assert.Equal(CheckStatus.Pass, assessment.Status);
        Assert.Equal(["Splunk Universal Forwarder"], assessment.CountedSources);
        Assert.Contains("matches a detected service", assessment.Evidence);
    }

    [Fact]
    public void Onboarded_Running_Defender_For_Endpoint_Passes()
    {
        var services = CleanHostServices();
        services["Sense"] = "Running";

        var assessment = LM02_SiemCheck.Assess(new Snapshot { Services = services, MdeOnboardingState = 1 });

        Assert.Equal(CheckStatus.Pass, assessment.Status);
        Assert.Equal(["Microsoft Defender for Endpoint (onboarded)"], assessment.CountedSources);
    }

    [Fact]
    public void Onboarded_Defender_With_Stopped_Sense_Is_Reported_Not_Counted()
    {
        var assessment = LM02_SiemCheck.Assess(new Snapshot { Services = CleanHostServices(), MdeOnboardingState = 1 });

        Assert.Equal(CheckStatus.Fail, assessment.Status);
        Assert.Contains("Microsoft Defender for Endpoint (Stopped)", assessment.Findings);
    }

    [Fact]
    public void Stopped_Agent_Service_Is_Reported_But_Not_Counted()
    {
        var services = CleanHostServices();
        services["SplunkForwarder"] = "Stopped";

        var assessment = LM02_SiemCheck.Assess(new Snapshot
        {
            Services = services,
            RegistryKeysPresent = [@"HKLM\SOFTWARE\Splunk"],
        });

        Assert.Equal(CheckStatus.Fail, assessment.Status);
        Assert.Empty(assessment.CountedSources);
        Assert.Contains("INSTALLED, NOT RUNNING: Splunk Universal Forwarder", assessment.Evidence);
        Assert.Contains("Splunk Universal Forwarder (Stopped)", assessment.Findings);
    }

    [Fact]
    public void Event_Collector_Counts_Only_With_Subscriptions_And_A_Running_Service()
    {
        var services = CleanHostServices();
        services["Wecsvc"] = "Running";

        var idle = LM02_SiemCheck.Assess(new Snapshot { Services = services });
        var collecting = LM02_SiemCheck.Assess(new Snapshot { Services = services, CollectorSubscriptions = ["DC-Security"] });
        var stoppedWithSubscriptions = LM02_SiemCheck.Assess(new Snapshot
        {
            Services = CleanHostServices(),
            CollectorSubscriptions = ["DC-Security"],
        });

        Assert.Equal(CheckStatus.Fail, idle.Status);
        Assert.Equal(CheckStatus.Pass, collecting.Status);
        Assert.Equal(["Windows Event Collector (WEF)"], collecting.CountedSources);
        Assert.Equal(CheckStatus.Fail, stoppedWithSubscriptions.Status);
        Assert.Contains("collector service isn't running", stoppedWithSubscriptions.Evidence);
    }

    [Fact]
    public void Source_Initiated_Forwarding_Policy_Passes()
    {
        var assessment = LM02_SiemCheck.Assess(new Snapshot
        {
            Services = CleanHostServices(),
            ForwardingTargets = ["1 = Server=http://wec01.contoso.local:5985/wsman/SubscriptionManager/WEC,Refresh=60"],
        });

        Assert.Equal(CheckStatus.Pass, assessment.Status);
        Assert.Equal(["Windows Event Forwarding (WEF)"], assessment.CountedSources);
    }

    [Fact]
    public void Registry_Trace_Without_Any_Matching_Service_Is_Partial()
    {
        var assessment = LM02_SiemCheck.Assess(new Snapshot
        {
            Services = CleanHostServices(),
            RegistryKeysPresent = [@"HKLM\SOFTWARE\ossec-agent"],
        });

        Assert.Equal(CheckStatus.Partial, assessment.Status);
        Assert.Contains("install trace only", assessment.Evidence);
    }

    [Fact]
    public void Wazuh_Registry_Key_Is_Corroborated_By_The_Wazuh_Service()
    {
        var services = CleanHostServices();
        services["WazuhSvc"] = "Running";

        var assessment = LM02_SiemCheck.Assess(new Snapshot
        {
            Services = services,
            RegistryKeysPresent = [@"HKLM\SOFTWARE\ossec-agent"],
        });

        Assert.Equal(CheckStatus.Pass, assessment.Status);
        Assert.DoesNotContain("install trace only", assessment.Evidence);
    }

    [Fact]
    public void Service_Enumeration_Failure_Is_Not_Assessed_Instead_Of_Fail()
    {
        var assessment = LM02_SiemCheck.Assess(new Snapshot { Services = null, ServiceEnumerationError = "Access denied" });

        Assert.Equal(CheckStatus.NotAssessed, assessment.Status);
        Assert.Equal("Access denied", assessment.Error);
    }

    [Fact]
    public async Task Live_Host_Collection_Completes_Without_A_Check_Error()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var result = await new LM02_SiemCheck().ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);
        output.WriteLine($"{result.Status}\n{result.Findings}\n{result.Evidence}");

        Assert.NotEqual(CheckStatus.NA, result.Status);
        Assert.Contains("[Microsoft Defender for Endpoint]", result.Evidence);
        Assert.Contains("[Windows Event Forwarding (WEF)]", result.Evidence);
    }

    [Fact]
    public void Registry_Indicator_Paths_Are_Exposed_For_Collection()
    {
        Assert.Contains(@"HKLM\SOFTWARE\Splunk", LM02_SiemCheck.RegistryIndicatorPaths);
        Assert.Equal(6, LM02_SiemCheck.RegistryIndicatorPaths.Count);
    }
}
