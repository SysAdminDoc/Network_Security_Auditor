using NetworkSecurityAuditor.Services;

namespace NetworkSecurityAuditor.Tests;

public class Tier0PrincipalsTests
{
    private const string Domain = "S-1-5-21-1004336348-1177238915-682003330";
    private const string Child = "S-1-5-21-2222222222-3333333333-4444444444";

    [Theory]
    [InlineData(Domain + "-512", true)]   // Domain Admins
    [InlineData(Domain + "-519", true)]   // Enterprise Admins, single-domain forest
    [InlineData(Domain + "-502", true)]   // krbtgt
    [InlineData(Domain + "-500", true)]   // built-in Administrator
    [InlineData("S-1-5-32-544", true)]    // Administrators
    [InlineData("S-1-5-32-548", true)]    // Account Operators
    [InlineData("S-1-5-18", true)]        // SYSTEM
    [InlineData("S-1-5-9", true)]         // Enterprise Domain Controllers
    [InlineData(Domain + "-513", false)]  // Domain Users
    [InlineData(Domain + "-1105", false)] // an ordinary group
    [InlineData(Domain + "5-512", false)] // a different domain whose SID merely starts the same
    [InlineData("S-1-1-0", false)]        // Everyone
    [InlineData(null, false)]
    public void IsTier0_Matches_By_Sid(string? sid, bool expected) =>
        Assert.Equal(expected, Tier0Principals.IsTier0(sid, Domain));

    [Fact]
    public void Enterprise_Admins_Come_From_The_Forest_Root()
    {
        Assert.True(Tier0Principals.IsTier0(Domain + "-519", Child, forestRootSid: Domain));
        Assert.True(Tier0Principals.IsTier0(Child + "-512", Child, forestRootSid: Domain));
        // The forest root's Domain Admins and built-in Administrator control the whole forest.
        Assert.True(Tier0Principals.IsTier0(Domain + "-512", Child, forestRootSid: Domain));
        Assert.True(Tier0Principals.IsTier0(Domain + "-500", Child, forestRootSid: Domain));
        // The root's ordinary principals stay outside a child domain's Tier 0.
        Assert.False(Tier0Principals.IsTier0(Domain + "-513", Child, forestRootSid: Domain));
    }

    [Fact]
    public void Of_And_Rid_Round_Trip()
    {
        Assert.Equal(Domain + "-512", Tier0Principals.Of(Domain, Tier0Principals.DomainAdminsRid));
        Assert.Equal(1105, Tier0Principals.Rid(Domain + "-1105", Domain));
        Assert.Null(Tier0Principals.Rid("S-1-5-32-544", Domain));
    }

    [Fact]
    public void Domain_Sid_And_Rule_Sids_Come_Through_The_Fixture_Reader()
    {
        var reader = FixtureDirectoryReader.FromJson($$"""
            {
              "entries": { "(domain)": { "objectSid": [ { "$sid": "{{Domain}}" } ] } },
              "acls": { "OU=Staff,DC=corp,DC=example": [ { "identity": "CORP\\Domänen-Admins", "sid": "{{Domain}}-512", "rights": "CreateChild" } ] }
            }
            """);

        Assert.Equal(Domain, Tier0Principals.ReadDomainSid(reader, CancellationToken.None));
        var rule = Assert.Single(reader.ReadAccessRules("OU=Staff,DC=corp,DC=example", CancellationToken.None));
        Assert.True(Tier0Principals.IsTier0(rule.Sid, Domain));
    }
}
