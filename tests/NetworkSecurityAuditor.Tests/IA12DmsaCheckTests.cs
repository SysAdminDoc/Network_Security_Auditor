using System.Runtime.InteropServices;
using NetworkSecurityAuditor.Checks.IdentityAccess;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class IA12DmsaCheckTests
{
    private static Task<CheckResult> Run(string fixture) =>
        new IA12_DmsaCheck(_ => FixtureDirectoryReader.Load(fixture))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

    [Fact]
    public async Task No_Dmsa_And_Standard_Container_Acl_Passes()
    {
        var result = await Run("IA12-pass.json");

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("Delegated Managed Service Accounts found: 0", result.Findings);
        Assert.Contains("PASS: No dMSA objects or suspicious delegations detected.", result.Findings);
        Assert.Contains("INFO: Domain functional level < 10.", result.Findings);
        Assert.Contains("Container DN: CN=Managed Service Accounts,DC=corp,DC=example", result.Evidence);
        Assert.Contains("Total CreateChild ACEs: 4", result.Evidence);
        Assert.Contains("Domain Functional Level: 7", result.Evidence);
    }

    [Fact]
    public async Task Dmsa_Object_Helpdesk_Delegation_And_2025_Level_Fail()
    {
        var result = await Run("IA12-fail.json");

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("Delegated Managed Service Accounts found: 1", result.Findings);
        Assert.Contains("WARNING: dMSA objects exist.", result.Findings);
        Assert.Contains(@"CRITICAL: Non-standard CreateChild delegation on MSA container: CORP\Helpdesk", result.Findings);
        Assert.DoesNotContain("Contractors", result.Findings);
        Assert.Contains("WARNING: Domain functional level >= 10 (WS2025).", result.Findings);
        Assert.DoesNotContain("PASS:", result.Findings);
        Assert.Contains("dmsa_web$ | DN=CN=dmsa_web,OU=Service Accounts,DC=corp,DC=example", result.Evidence);
        Assert.Contains("Successor: None", result.Evidence);
        Assert.Contains(@"CreateChild ACE: CORP\Contractors | Type=Deny", result.Evidence);
        Assert.Contains("Total CreateChild ACEs: 6", result.Evidence);
    }

    [Fact]
    public async Task Unreadable_Container_Acl_Is_Reported_Separately_From_A_Missing_Container()
    {
        var result = await Run("IA12-acl-unreadable.json");

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("INFO: Could not read MSA container ACLs", result.Findings);
        Assert.Contains("Container exists and is accessible.", result.Evidence);
        Assert.Contains("Could not read ACLs: Access is denied.", result.Evidence);
        Assert.DoesNotContain("container not found", result.Evidence);
    }

    [Fact]
    public async Task Missing_Container_Is_Noted_In_Evidence()
    {
        var result = await Run("IA12-no-container.json");

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("Managed Service Accounts container not found or inaccessible.", result.Evidence);
        Assert.DoesNotContain("Container exists", result.Evidence);
        Assert.DoesNotContain("Could not read MSA container ACLs", result.Findings);
    }

    [Fact]
    public async Task Unreachable_Domain_Root_Is_An_Error()
    {
        var result = await Run("IA12-domain-unreachable.json");

        Assert.Equal(CheckStatus.Error, result.Status);
        Assert.Contains("The server is not operational.", result.Findings);
    }

    [Fact]
    public async Task Directory_Failure_Is_An_Error()
    {
        var result = await new IA12_DmsaCheck(_ => throw new COMException("The server is not operational.", unchecked((int)0x8007203A)))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Error, result.Status);
    }
}
