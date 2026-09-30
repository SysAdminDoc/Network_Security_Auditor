namespace NetworkSecurityAuditor.Tests;

using NetworkSecurityAuditor.Checks.NetworkPerimeter;
using System.Text.RegularExpressions;
using NetworkSecurityAuditor.Models;

public sealed class NP06TempRulesCheckTests
{
    private static FirewallRuleSnapshot Rule(string name, string description = "") =>
        new($"{{{name}}}", name, description, Direction: 1, Action: 2, Protocol: null, LocalPorts: [], RemotePorts: [], RemoteAddresses: []);

    [Fact]
    public async Task Reads_The_Active_Store_So_A_Group_Policy_Temp_Rule_Is_Seen()
    {
        var check = new NP06_TempRulesCheck((_, store) => store == FirewallRuleReader.ActiveStore
            ? [Rule("Core Networking - DNS (UDP-Out)"), Rule("Vendor access - TEMP until go-live")]
            : [Rule("Core Networking - DNS (UDP-Out)")]);

        var result = await check.ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("Scanned 2 enabled firewall rules", result.Findings);
        Assert.Contains("Vendor access - TEMP until go-live", result.Findings);
        Assert.Contains("active store", result.Evidence);
    }

    // Names are all NP06 needs, and the rules (unlike their filters) are readable without elevation,
    // so a standard user reads the active store directly instead of falling back to netsh.
    [Fact]
    public async Task Live_Host_Reads_The_Active_Store_Without_Elevation()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var result = await new NP06_TempRulesCheck().ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Null(result.Error);
        Assert.Contains("[Firewall Rule Staleness Analysis - active store", result.Evidence);
        Assert.DoesNotContain("WMI error", result.Evidence);
        Assert.DoesNotContain("Parsed from netsh", result.Evidence);
    }

    [Theory]
    [InlineData("Droplet Template")]
    [InlineData("Google Chrome for Testing")]
    [InlineData("Folder Sync")]
    [InlineData("Hold Music Server")]
    [InlineData("Contoso Backup Agent")]
    [InlineData("Vendor Portal")]
    public async Task Indicator_Inside_Another_Word_Is_Not_Stale(string name)
    {
        var result = await new NP06_TempRulesCheck((_, _) => [Rule(name)]).ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.DoesNotContain("STALE INDICATOR", result.Evidence);
    }

    [Theory]
    [InlineData("TEMP vendor access", "", "temp")]
    [InlineData("tmp_rdp_rule", "", "tmp")]
    [InlineData("Copy of Remote Desktop", "", "copy of")]
    [InlineData("SQL 1433", "Old port, remove after migration", "old")]
    public async Task Whole_Word_Indicator_Is_Stale_And_Partial(string name, string description, string indicator)
    {
        var result = await new NP06_TempRulesCheck((_, _) => [Rule(name, description)]).ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains($"(matched: \"{indicator}\")", result.Evidence);
    }

    [Fact]
    public async Task Many_Stale_Rules_Stay_Partial_And_A_Long_Rule_List_Is_Only_Noted()
    {
        var rules = Enumerable.Range(0, 210).Select(i => Rule(i < 6 ? $"Temp rule {i}" : $"App rule {i}")).ToList();

        var result = await new NP06_TempRulesCheck((_, _) => rules).ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("INFO: 210 enabled rules", result.Findings);
        Assert.Equal(CheckStatus.Pass, (await new NP06_TempRulesCheck((_, _) => rules.Skip(6).ToList())
            .ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None)).Status);
    }

    [Fact]
    public void Dated_Rule_Names_Match_The_Script_Rule()
    {
        Assert.True(NP06_TempRulesCheck.HasDatePattern("Allow vendor 2024-03-01"));
        Assert.False(NP06_TempRulesCheck.HasDatePattern("Build 20240301"));
        Assert.False(NP06_TempRulesCheck.HasDatePattern("Port 1999-2000 range"));
    }

    [Fact]
    public void Script_Uses_The_Same_Indicator_List()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "NetworkSecurityAuditor.slnx")))
            dir = dir.Parent;
        var script = File.ReadAllText(Path.Combine(dir!.FullName, "NetworkSecurityAudit.ps1"));
        var list = Regex.Match(script, @"function Get-Np06StaleIndicator \{\s+param\(\[string\]\$Text\)\s+\$indicators = @\((?<list>[^)]*)\)");

        Assert.True(list.Success, "Get-Np06StaleIndicator's indicator list not found in NetworkSecurityAudit.ps1");
        Assert.Equal(NP06_TempRulesCheck.StaleIndicators, Regex.Matches(list.Groups["list"].Value, "'([^']*)'").Select(m => m.Groups[1].Value));
    }
}
