namespace NetworkSecurityAuditor.Tests;

using NetworkSecurityAuditor.Checks.NetworkPerimeter;
using NetworkSecurityAuditor.Models;
using Listener = NetworkSecurityAuditor.Checks.NetworkPerimeter.NP02_OpenPortsCheck.ListenerEndpoint;
using Snapshot = NetworkSecurityAuditor.Checks.NetworkPerimeter.NP02_OpenPortsCheck.PortSnapshot;

public sealed class NP02OpenPortsCheckTests(Xunit.Abstractions.ITestOutputHelper output)
{
    // What a stock Windows 11 workstation with WinRM enabled listens on.
    private static List<Listener> DefaultWorkstationListeners() =>
    [
        new("TCP", "0.0.0.0", 135),
        new("TCP", "::", 135),
        new("TCP", "192.168.1.20", 139),
        new("TCP", "0.0.0.0", 445),
        new("TCP", "::", 445),
        new("TCP", "0.0.0.0", 5985),
        new("TCP", "0.0.0.0", 49664),
        new("TCP", "127.0.0.1", 5939),
    ];

    private static FirewallRuleSnapshot InboundAllow(string name, string localPort, int profiles, string? program = null) =>
        new($"{{{name}}}", name, string.Empty, Direction: 1, Action: 2, Protocol: "TCP",
            LocalPorts: [localPort], RemotePorts: [], RemoteAddresses: [], Profiles: profiles, Program: program);

    [Fact]
    public void Default_Workstation_On_A_Private_Network_Is_Never_Fail()
    {
        var assessment = NP02_OpenPortsCheck.Assess(new Snapshot { Listeners = DefaultWorkstationListeners() });

        Assert.NotEqual(CheckStatus.Fail, assessment.Status);
        Assert.Equal(CheckStatus.Pass, assessment.Status);
        Assert.Contains("TCP 445 (SMB)", assessment.Findings);
        Assert.Contains("default Windows role port", assessment.Findings);
    }

    [Fact]
    public void Default_Workstation_On_A_Public_Network_With_Default_Firewall_Rules_Is_Never_Fail()
    {
        var assessment = NP02_OpenPortsCheck.Assess(new Snapshot
        {
            Listeners = DefaultWorkstationListeners(),
            PublicInterfaceAddresses = ["192.168.1.20"],
            PublicFirewallEnabled = true,
            // Stock rules: SMB-In is Private/Domain only, WinRM HTTP-In is Domain/Private, Teams allows any port for its
            // own program, a Store app rule is scoped to its AppContainer package, and a service rule to its service.
            FirewallRules =
            [
                InboundAllow("File and Printer Sharing (SMB-In)", "445", profiles: 3, program: "System"),
                InboundAllow("Windows Remote Management (HTTP-In)", "5985", profiles: 3, program: "System"),
                new("{teams}", "Microsoft Teams", string.Empty, 1, 2, "TCP", [], [], [], Profiles: 4, Program: @"C:\Program Files\Teams\ms-teams.exe"),
                new("{store}", "Xbox Game Bar", string.Empty, 1, 2, "Any", [], [], [], Profiles: 0, Program: "Any",
                    Package: "S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742"),
                new("{svc}", "Delivery Optimization (TCP-In)", string.Empty, 1, 2, "TCP", [], [], [], Profiles: 0, Program: @"%SystemRoot%\system32\svchost.exe", Service: "DoSvc"),
            ],
        });

        Assert.NotEqual(CheckStatus.Fail, assessment.Status);
        Assert.Equal(CheckStatus.Pass, assessment.Status);
    }

    [Fact]
    public void Unscoped_Any_Port_Allow_Rule_On_Public_Exposes_Role_Ports()
    {
        var assessment = NP02_OpenPortsCheck.Assess(new Snapshot
        {
            Listeners = DefaultWorkstationListeners(),
            PublicInterfaceAddresses = ["192.168.1.20"],
            PublicFirewallEnabled = true,
            FirewallRules = [new("{open}", "Allow everything", string.Empty, 1, 2, "Any", [], [], [], Profiles: 4)],
        });

        Assert.Equal(CheckStatus.Fail, assessment.Status);
        Assert.Contains("via inbound rule 'Allow everything'", assessment.Findings);
    }

    [Fact]
    public void Block_Rule_Overrides_Allow_Rule_And_Default_Allow()
    {
        var block = new FirewallRuleSnapshot("{block}", "Block SMB on Public", string.Empty, 1, 4, "TCP", ["445"], [], [], Profiles: 4);
        var withAllow = NP02_OpenPortsCheck.Assess(new Snapshot
        {
            Listeners = [new("TCP", "0.0.0.0", 445)],
            PublicInterfaceAddresses = ["192.168.1.20"],
            PublicFirewallEnabled = true,
            FirewallRules = [InboundAllow("File and Printer Sharing (SMB-In)", "445", profiles: 4, program: "System"), block],
        });
        var withDefaultAllow = NP02_OpenPortsCheck.Assess(new Snapshot
        {
            Listeners = [new("TCP", "0.0.0.0", 445)],
            PublicInterfaceAddresses = ["192.168.1.20"],
            PublicFirewallEnabled = true,
            PublicDefaultInboundAllow = true,
            FirewallRules = [block],
        });

        Assert.Equal(CheckStatus.Pass, withAllow.Status);
        Assert.Equal(CheckStatus.Pass, withDefaultAllow.Status);
    }

    [Fact]
    public void Scoped_Block_Rule_Does_Not_Hide_An_Open_Port()
    {
        var allow = InboundAllow("File and Printer Sharing (SMB-In)", "445", profiles: 4, program: "System");
        FirewallRuleSnapshot Block(string? program = null, string[]? remote = null) =>
            new("{block}", "Partial block", string.Empty, 1, 4, "TCP", ["445"], [], remote ?? [], Profiles: 4, Program: program);

        foreach (var block in new[] { Block(program: @"C:\Tools\agent.exe"), Block(remote: ["10.0.0.0/8"]) })
        {
            var assessment = NP02_OpenPortsCheck.Assess(new Snapshot
            {
                Listeners = [new("TCP", "0.0.0.0", 445)],
                PublicInterfaceAddresses = ["192.168.1.20"],
                PublicFirewallEnabled = true,
                FirewallRules = [allow, block],
            });

            Assert.Equal(CheckStatus.Fail, assessment.Status);
        }
    }

    [Fact]
    public void Public_Firewall_Off_Is_Known_Even_When_Rules_Are_Unreadable()
    {
        // The non-elevated case: profiles read fine, port filters return access denied.
        var assessment = NP02_OpenPortsCheck.Assess(new Snapshot
        {
            Listeners = DefaultWorkstationListeners(),
            PublicInterfaceAddresses = ["192.168.1.20"],
            PublicFirewallEnabled = false,
            FirewallError = "Access denied",
        });

        Assert.Equal(CheckStatus.Fail, assessment.Status);
        Assert.Contains("the Public firewall profile being off", assessment.Findings);
    }

    [Fact]
    public void Default_Inbound_Allow_With_Unreadable_Rules_Is_Exposed()
    {
        var assessment = NP02_OpenPortsCheck.Assess(new Snapshot
        {
            Listeners = [new("TCP", "0.0.0.0", 445)],
            PublicInterfaceAddresses = ["192.168.1.20"],
            PublicFirewallEnabled = true,
            PublicDefaultInboundAllow = true,
            FirewallError = "Access denied",
        });

        Assert.Equal(CheckStatus.Fail, assessment.Status);
    }

    [Fact]
    public void Unreadable_Network_Categories_Are_Partial_Not_Pass()
    {
        var assessment = NP02_OpenPortsCheck.Assess(new Snapshot
        {
            Listeners = DefaultWorkstationListeners(),
            NetworkProfileError = "Invalid class",
        });

        Assert.Equal(CheckStatus.Partial, assessment.Status);
        Assert.Contains("network categories couldn't be read", assessment.Findings);
    }

    [Fact]
    public void Telnet_Listener_Fails()
    {
        var listeners = DefaultWorkstationListeners();
        listeners.Add(new Listener("TCP", "0.0.0.0", 23));

        var assessment = NP02_OpenPortsCheck.Assess(new Snapshot { Listeners = listeners });

        Assert.Equal(CheckStatus.Fail, assessment.Status);
        Assert.Contains("TCP 23 (Telnet) listening on 0.0.0.0 (all interfaces)", assessment.Findings);
    }

    [Theory]
    [InlineData("TCP", 21)]
    [InlineData("UDP", 69)]
    [InlineData("TCP", 5900)]
    [InlineData("TCP", 6379)]
    [InlineData("TCP", 27017)]
    public void Cleartext_And_No_Auth_Database_Listeners_Fail(string protocol, int port)
    {
        var assessment = NP02_OpenPortsCheck.Assess(new Snapshot { Listeners = [new(protocol, "10.0.0.5", port)] });

        Assert.Equal(CheckStatus.Fail, assessment.Status);
    }

    [Fact]
    public void Loopback_Only_Insecure_Listener_Is_Informational()
    {
        var assessment = NP02_OpenPortsCheck.Assess(new Snapshot { Listeners = [new("TCP", "127.0.0.1", 6379), new("TCP", "::1", 6379)] });

        Assert.Equal(CheckStatus.Pass, assessment.Status);
        Assert.Contains("loopback only", assessment.Findings);
    }

    [Fact]
    public void Smb_Allowed_Inbound_On_The_Public_Profile_Fails()
    {
        var assessment = NP02_OpenPortsCheck.Assess(new Snapshot
        {
            Listeners = DefaultWorkstationListeners(),
            PublicInterfaceAddresses = ["192.168.1.20"],
            PublicFirewallEnabled = true,
            FirewallRules = [InboundAllow("File and Printer Sharing (SMB-In)", "445", profiles: 4, program: "System")],
        });

        Assert.Equal(CheckStatus.Fail, assessment.Status);
        Assert.Contains("TCP 445 (SMB) reachable from a Public-profile network via inbound rule 'File and Printer Sharing (SMB-In)'", assessment.Findings);
        Assert.DoesNotContain("TCP 135 (RPC/DCOM) reachable", assessment.Findings);
    }

    [Fact]
    public void Rpc_Endpoint_Mapper_Keyword_Rule_Maps_To_Port_135()
    {
        Assert.True(NP02_OpenPortsCheck.LocalPortsInclude(["RPC-EPMap"], 135));
        Assert.True(NP02_OpenPortsCheck.LocalPortsInclude(["5000-5990"], 5985));
        Assert.False(NP02_OpenPortsCheck.LocalPortsInclude(["RPC"], 135));
        Assert.False(NP02_OpenPortsCheck.LocalPortsInclude(["4450"], 445));
    }

    [Fact]
    public void Public_Firewall_Profile_Off_Exposes_Default_Role_Ports()
    {
        var assessment = NP02_OpenPortsCheck.Assess(new Snapshot
        {
            Listeners = DefaultWorkstationListeners(),
            PublicInterfaceAddresses = ["192.168.1.20"],
            PublicFirewallEnabled = false,
        });

        Assert.Equal(CheckStatus.Fail, assessment.Status);
        Assert.Contains("the Public firewall profile being off", assessment.Findings);
    }

    [Fact]
    public void Role_Port_Bound_Only_To_A_Private_Interface_Is_Not_Exposed()
    {
        var assessment = NP02_OpenPortsCheck.Assess(new Snapshot
        {
            Listeners = [new("TCP", "10.10.0.4", 445)],
            PublicInterfaceAddresses = ["192.168.1.20"],
            PublicFirewallEnabled = false,
        });

        Assert.Equal(CheckStatus.Pass, assessment.Status);
    }

    [Fact]
    public void Rdp_Listener_Is_Review_Not_Fail_Until_Publicly_Exposed()
    {
        var listeners = DefaultWorkstationListeners();
        listeners.Add(new Listener("TCP", "0.0.0.0", 3389));

        var privateOnly = NP02_OpenPortsCheck.Assess(new Snapshot { Listeners = listeners });
        var exposed = NP02_OpenPortsCheck.Assess(new Snapshot
        {
            Listeners = listeners,
            PublicInterfaceAddresses = ["203.0.113.8"],
            PublicFirewallEnabled = true,
            FirewallRules = [InboundAllow("Remote Desktop - User Mode (TCP-In)", "3389", profiles: 0)],
        });

        Assert.Equal(CheckStatus.Partial, privateOnly.Status);
        Assert.Equal(CheckStatus.Fail, exposed.Status);
    }

    [Fact]
    public void Unreadable_Firewall_On_A_Public_Network_Is_Partial_Not_Pass_Or_Fail()
    {
        var profileUnknown = NP02_OpenPortsCheck.Assess(new Snapshot
        {
            Listeners = DefaultWorkstationListeners(),
            PublicInterfaceAddresses = ["192.168.1.20"],
            FirewallProfileError = "Access denied",
            FirewallError = "Access denied",
        });
        var assessment = NP02_OpenPortsCheck.Assess(new Snapshot
        {
            Listeners = DefaultWorkstationListeners(),
            PublicInterfaceAddresses = ["192.168.1.20"],
            PublicFirewallEnabled = true,
            FirewallError = "Access denied",
        });

        Assert.Equal(CheckStatus.Partial, profileUnknown.Status);
        Assert.Equal(CheckStatus.Partial, assessment.Status);
        Assert.Contains("couldn't be read to confirm it's blocked", assessment.Findings);
        Assert.DoesNotContain("not exposed to a Public-profile network", assessment.Findings.Split('\n').First(l => l.Contains("TCP 445")));
    }

    [Fact]
    public void Unreadable_Listener_Table_Is_Not_Assessed()
    {
        var assessment = NP02_OpenPortsCheck.Assess(new Snapshot { ListenerError = "The parameter is incorrect" });

        Assert.Equal(CheckStatus.NotAssessed, assessment.Status);
        Assert.Equal("The parameter is incorrect", assessment.Error);
    }

    [Fact]
    public void Firewall_Profile_Mask_Applies_To_Public_Only_When_Bit_Four_Or_Any()
    {
        Assert.True(InboundAllow("any", "445", profiles: 0).AppliesToPublicProfile);
        Assert.True(InboundAllow("public", "445", profiles: 4).AppliesToPublicProfile);
        Assert.False(InboundAllow("private-domain", "445", profiles: 3).AppliesToPublicProfile);
    }

    [Fact]
    public async Task Live_Host_Collection_Completes_Without_A_Check_Error()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var result = await new NP02_OpenPortsCheck().ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);
        output.WriteLine($"{result.Status}\n{result.Findings}\n{result.Evidence}");

        Assert.NotEqual(CheckStatus.NA, result.Status);
        Assert.Contains("[Listening Endpoints (IP Helper API)]", result.Evidence);
    }
}
