namespace NetworkSecurityAuditor.Tests;

using System.Text;
using NetworkSecurityAuditor.Checks.NetworkPerimeter;

public sealed class NP03VpnCheckTests
{
    [Fact]
    public void AssessSplitTunnelRoutes_Does_Not_Treat_Multiple_Default_Routes_As_Split_Tunnel()
    {
        const string routeOutput = """
            Network Destination        Netmask          Gateway       Interface  Metric
                      0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     25
                      0.0.0.0          0.0.0.0      10.10.10.1     10.10.10.20     35
            """;

        var assessment = NP03_VpnCheck.AssessSplitTunnelRoutes(routeOutput);

        Assert.Equal(2, assessment.DefaultRouteCount);
        Assert.True(assessment.HasMultipleDefaultRoutes);
        Assert.False(assessment.IsConfirmedSplitTunnel);
    }

    [Fact]
    public void AssessSplitTunnelRoutes_Counts_Single_Default_Route()
    {
        const string routeOutput = """
            Network Destination        Netmask          Gateway       Interface  Metric
                      0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     25
            """;

        var assessment = NP03_VpnCheck.AssessSplitTunnelRoutes(routeOutput);

        Assert.Equal(1, assessment.DefaultRouteCount);
        Assert.False(assessment.HasMultipleDefaultRoutes);
        Assert.False(assessment.IsConfirmedSplitTunnel);
    }

    private const string Phonebook = """
        [Contoso VPN]
        Encoding=1
        PBVersion=8
        Type=2
        AutoLogon=0
        IpPrioritizeRemote=0
        VpnStrategy=7

        MEDIA=rastapi
        Port=VPN2-0
        Device=WAN Miniport (IKEv2)

        DEVICE=vpn
        PhoneNumber=vpn.contoso.example
        AreaCode=
        PhoneNumber=ignored.example

        [Home DSL]
        Type=5
        IpPrioritizeRemote=1

        DEVICE=PPPoE
        PhoneNumber=

        [Full Tunnel VPN]
        Type=2
        IpPrioritizeRemote=1
        DEVICE=vpn
        PhoneNumber=203.0.113.10
        """;

    [Fact]
    public void ParsePhonebook_Reads_Entries_And_Keeps_First_Value_Of_Repeated_Keys()
    {
        var entries = NP03_VpnCheck.ParsePhonebook(Phonebook.Replace("\n", "\r\n"));

        Assert.Equal(new[] { "Contoso VPN", "Home DSL", "Full Tunnel VPN" }, entries.Select(e => e.Name));
        var contoso = entries[0];
        Assert.True(contoso.IsVpn);
        Assert.Equal("vpn.contoso.example", contoso.Server);
        Assert.True(contoso.SplitTunnel);
        Assert.False(entries[1].IsVpn);
        Assert.False(entries[2].SplitTunnel);
        Assert.Equal("Contoso VPN | Server: vpn.contoso.example | split tunnel (IpPrioritizeRemote=0)", NP03_VpnCheck.DescribePhonebookEntry(contoso));
    }

    [Fact]
    public void ParsePhonebook_Tolerates_Empty_And_Headerless_Text()
    {
        Assert.Empty(NP03_VpnCheck.ParsePhonebook(""));
        Assert.Empty(NP03_VpnCheck.ParsePhonebook("Type=2\nPhoneNumber=orphan.example\n"));
        var bare = Assert.Single(NP03_VpnCheck.ParsePhonebook("[Bare]\n"));
        Assert.False(bare.IsVpn);
        Assert.Null(bare.SplitTunnel);
    }

    [Fact]
    public void ReadPhonebooks_Finds_Vpn_Entries_Without_Naming_The_Path()
    {
        string directory = Path.Combine(Path.GetTempPath(), "nsa-pbk-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            string userBook = Path.Combine(directory, "user.pbk");
            string machineBook = Path.Combine(directory, "machine.pbk");
            File.WriteAllText(userBook, Phonebook);
            var sb = new StringBuilder();
            var evidence = new StringBuilder();

            bool found = NP03_VpnCheck.ReadPhonebooks(
                [("current user", userBook), ("all users", machineBook)], sb, evidence, CancellationToken.None);

            Assert.True(found);
            string text = evidence.ToString();
            Assert.Contains("RAS phonebook (current user): 2 VPN entries", text);
            Assert.Contains("Contoso VPN | Server: vpn.contoso.example | split tunnel", text);
            Assert.Contains("Full Tunnel VPN | Server: 203.0.113.10 | full tunnel", text);
            Assert.Contains("RAS phonebook (all users): none", text);
            Assert.DoesNotContain("Home DSL", text);
            Assert.DoesNotContain(directory, text);
            Assert.Contains("Built-in VPN connection configured: Contoso VPN", sb.ToString());
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void ReadPhonebooks_Reports_No_Vpn_For_A_Dial_Up_Only_Phonebook()
    {
        string path = Path.Combine(Path.GetTempPath(), "nsa-pbk-" + Guid.NewGuid().ToString("N") + ".pbk");
        File.WriteAllText(path, "[Home DSL]\nType=5\n");
        try
        {
            var evidence = new StringBuilder();

            bool found = NP03_VpnCheck.ReadPhonebooks([("all users", path)], new StringBuilder(), evidence, CancellationToken.None);

            Assert.False(found);
            Assert.Contains("RAS phonebook (all users): 0 VPN entries", evidence.ToString());
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Phonebook_Paths_Cover_The_User_And_All_Users_Books()
    {
        var paths = NP03_VpnCheck.PhonebookPaths();

        Assert.Equal(new[] { "current user", "all users" }, paths.Select(p => p.Scope));
        Assert.All(paths, p => Assert.EndsWith(Path.Combine("Microsoft", "Network", "Connections", "Pbk", "rasphone.pbk"), p.Path));
        Assert.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), paths[0].Path);
        Assert.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), paths[1].Path);
    }
}
