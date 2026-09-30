namespace NetworkSecurityAuditor.Tests;

using System.DirectoryServices;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

public sealed class LdapDirectoryReaderTests
{
    [Fact]
    public void Searches_Carry_Server_And_Client_Time_Limits_Below_The_Check_Timeout()
    {
        // Neither the entry nor the searcher contacts a DC until a search runs.
        using var root = new DirectoryEntry("LDAP://dc.example.invalid");
        var query = new DirectoryQuery("(objectClass=user)", ["sAMAccountName"]);

        using var searcher = LdapDirectoryReader.CreateSearcher(root, query);

        var checkTimeout = TimeSpan.FromSeconds(new AuditOptions().CheckTimeoutSeconds);
        Assert.Equal(LdapDirectoryReader.SearchServerTimeLimit, searcher.ServerTimeLimit);
        Assert.Equal(LdapDirectoryReader.SearchClientTimeout, searcher.ClientTimeout);
        Assert.True(searcher.ServerTimeLimit > TimeSpan.Zero);
        Assert.True(searcher.ServerTimeLimit < searcher.ClientTimeout);
        Assert.True(searcher.ClientTimeout < checkTimeout,
            "A stalled DC should end the search before the runner abandons the check.");
    }

    [Fact]
    public void Searcher_Keeps_The_Query_Shape()
    {
        using var root = new DirectoryEntry("LDAP://dc.example.invalid");
        var paged = new DirectoryQuery("(objectClass=group)", ["member", "cn"]) { PageSize = 500, Scope = SearchScope.OneLevel };
        var findOne = new DirectoryQuery("(objectClass=domain)", ["name"]) { SizeLimit = 1 };

        using var pagedSearcher = LdapDirectoryReader.CreateSearcher(root, paged);
        using var findOneSearcher = LdapDirectoryReader.CreateSearcher(root, findOne);

        Assert.Equal("(objectClass=group)", pagedSearcher.Filter);
        Assert.Equal(SearchScope.OneLevel, pagedSearcher.SearchScope);
        Assert.Equal(500, pagedSearcher.PageSize);
        Assert.Equal(new[] { "member", "cn" }, pagedSearcher.PropertiesToLoad.Cast<string>());
        Assert.Equal(0, findOneSearcher.PageSize);
        Assert.Equal(1, findOneSearcher.SizeLimit);
        Assert.Equal(LdapDirectoryReader.SearchServerTimeLimit, findOneSearcher.ServerTimeLimit);
    }

    [Theory]
    [InlineData(null, false, "LDAP://corp.example")]
    [InlineData(DirectoryReader.RootDse, false, "LDAP://corp.example/RootDSE")]
    [InlineData(DirectoryReader.RootDseServerless, false, "LDAP://RootDSE")]
    [InlineData("CN=Users,DC=corp,DC=example", false, "LDAP://CN=Users,DC=corp,DC=example")]
    [InlineData("CN=Schema,CN=Configuration,DC=corp,DC=example", true, "LDAP://corp.example/CN=Schema,CN=Configuration,DC=corp,DC=example")]
    [InlineData("OU=A/B,DC=corp,DC=example", true, "LDAP://corp.example/OU=A\\/B,DC=corp,DC=example")]
    public void Binds_Match_What_The_Checks_Used_Before_The_Reader_Seam(string? dn, bool onDomainServer, string expected)
    {
        Assert.Equal(expected, new LdapDirectoryReader("corp.example").Bind(dn, onDomainServer));
    }

    [Fact]
    public void Domain_Server_Bind_Without_A_Domain_Stays_Serverless()
    {
        Assert.Equal("LDAP://CN=Schema,DC=x", new LdapDirectoryReader("").Bind("CN=Schema,DC=x", onDomainServer: true));
    }

    [Fact]
    public void A_Sid_That_Wont_Translate_Falls_Back_To_The_Sid_String()
    {
        var sid = new System.Security.Principal.SecurityIdentifier("S-1-5-21-1-2-3-1110");

        foreach (var failure in new Exception[]
        {
            new System.Security.Principal.IdentityNotMappedException(),
            new System.ComponentModel.Win32Exception(1789),
            new UnauthorizedAccessException(),
            new SystemException("lookup failed"),
        })
        {
            Assert.Equal(sid.Value, LdapDirectoryReader.AccountName(sid, _ => throw failure));
        }
        Assert.Equal(@"CORP\Helpdesk", LdapDirectoryReader.AccountName(sid, _ => @"CORP\Helpdesk"));
        Assert.Throws<InvalidOperationException>(() => LdapDirectoryReader.AccountName(sid, _ => throw new InvalidOperationException()));
    }
}
