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
}
