using NetworkSecurityAuditor.Services;

namespace NetworkSecurityAuditor.Tests;

public class PrivilegedGroupResolverTests
{
    private const string Root = "S-1-5-21-1004336348-1177238915-682003330";
    private const string Child = "S-1-5-21-2222222222-3333333333-1444444444";
    private const string Chain = PrivilegedGroupResolver.InChainRule;

    private static PrivilegedGroupResolver Resolver(FixtureDirectoryReader reader) =>
        PrivilegedGroupResolver.Create(reader, CancellationToken.None);

    private const string SingleDomain = $$"""
        "(domain)": { "objectSid": { "$sid": "{{Root}}" }, "distinguishedName": "DC=corp,DC=example" },
        "RootDSE": { "rootDomainNamingContext": "DC=corp,DC=example" }
        """;

    [Fact]
    public void Single_Domain_Forest_Finds_Every_Group_By_Sid_Under_The_Domain_Root()
    {
        var identity = Resolver(FixtureDirectoryReader.FromJson($$"""{ "entries": { {{SingleDomain}} } }""")).Identity;

        Assert.True(identity.IsForestRoot);
        Assert.Equal(Root + "-512", identity.SidOf(WellKnownGroup.DomainAdmins));
        Assert.Equal(Root + "-519", identity.SidOf(WellKnownGroup.EnterpriseAdmins));
        Assert.Equal("S-1-5-32-544", identity.SidOf(WellKnownGroup.Administrators));
        Assert.Equal("S-1-5-32-555", identity.SidOf(WellKnownGroup.RemoteDesktopUsers));
        Assert.Null(identity.SearchBaseOf(WellKnownGroup.EnterpriseAdmins));
    }

    [Fact]
    public void Child_Domain_Looks_Up_Enterprise_And_Schema_Admins_In_The_Forest_Root()
    {
        var reader = FixtureDirectoryReader.FromJson($$"""
            {
              "entries": {
                "(domain)": { "objectSid": { "$sid": "{{Child}}" }, "distinguishedName": "DC=emea,DC=corp,DC=example" },
                "RootDSE": { "rootDomainNamingContext": "DC=corp,DC=example" },
                "DC=corp,DC=example": { "objectSid": { "$sid": "{{Root}}" } }
              },
              "searches": [
                { "base": "DC=corp,DC=example", "filter": "(objectSid={{Root}}-519)", "results": [
                  { "distinguishedName": "CN=Organisations-Admins,CN=Users,DC=corp,DC=example", "sAMAccountName": "Organisations-Admins" } ] },
                { "base": null, "filter": "(objectSid={{Child}}-512)", "results": [
                  { "distinguishedName": "CN=Domänen-Admins,CN=Users,DC=emea,DC=corp,DC=example", "sAMAccountName": "Domänen-Admins" } ] }
              ]
            }
            """);
        var resolver = Resolver(reader);

        Assert.False(resolver.Identity.IsForestRoot);
        Assert.Equal("DC=corp,DC=example", resolver.Identity.SearchBaseOf(WellKnownGroup.SchemaAdmins));
        Assert.Null(resolver.Identity.SearchBaseOf(WellKnownGroup.DomainAdmins));

        var ea = resolver.Resolve(WellKnownGroup.EnterpriseAdmins, CancellationToken.None);
        Assert.True(ea.Found);
        Assert.Equal("Organisations-Admins", ea.Name);
        Assert.Equal("DC=corp,DC=example", ea.SearchBase);
        Assert.Equal("Domänen-Admins", resolver.Resolve(WellKnownGroup.DomainAdmins, CancellationToken.None).Name);
        Assert.Equal(1, reader.Queries[0].SizeLimit);
    }

    [Fact]
    public void Unreadable_RootDse_Treats_The_Domain_As_Its_Own_Forest_Root()
    {
        var identity = Resolver(FixtureDirectoryReader.FromJson($$"""
            { "entries": {
                "(domain)": { "objectSid": { "$sid": "{{Child}}" } },
                "RootDSE": { "$error": { "hresult": "0x80070005", "message": "Access is denied." } } } }
            """)).Identity;

        Assert.True(identity.IsForestRoot);
        Assert.Equal(Child + "-519", identity.SidOf(WellKnownGroup.EnterpriseAdmins));
    }

    [Fact]
    public void Domain_Root_Without_A_Sid_Is_An_Error()
    {
        var reader = FixtureDirectoryReader.FromJson("""{ "entries": { "(domain)": { "distinguishedName": "DC=corp,DC=example" } } }""");

        Assert.Throws<InvalidOperationException>(() => Resolver(reader));
    }

    [Fact]
    public void Missing_Group_Is_Not_Found_And_Has_No_Members()
    {
        var reader = FixtureDirectoryReader.FromJson($$"""
            { "entries": { {{SingleDomain}} },
              "searches": [ { "base": null, "filter": "(objectSid={{Root}}-518)", "results": [] } ] }
            """);
        var resolver = Resolver(reader);

        var group = resolver.Resolve(WellKnownGroup.SchemaAdmins, CancellationToken.None);
        Assert.False(group.Found);
        Assert.Equal("Schema Admins", group.Name);
        Assert.Empty(resolver.Members(group, [], CancellationToken.None));
    }

    [Fact]
    public void Members_Carry_Their_Path_Through_Nested_Groups_And_Cycles_End()
    {
        var da = "CN=Domain Admins,CN=Users,DC=corp,DC=example";
        var reader = FixtureDirectoryReader.FromJson($$"""
            {
              "entries": {
                {{SingleDomain}},
                "CN=Partner,OU=Admins,DC=emea,DC=corp,DC=example": { "sAMAccountName": "partner", "objectClass": [ "user" ] },
                "CN=Gone,OU=Admins,DC=emea,DC=corp,DC=example": { "$error": { "hresult": "0x8007203A", "message": "The server is not operational." } }
              },
              "searches": [
                { "base": null, "filter": "(objectSid={{Root}}-512)", "results": [ { "distinguishedName": "{{da}}", "sAMAccountName": "Domain Admins",
                  "member": [ "CN=Tier0,OU=Groups,DC=corp,DC=example", "CN=Partner,OU=Admins,DC=emea,DC=corp,DC=example", "CN=Gone,OU=Admins,DC=emea,DC=corp,DC=example" ] } ] },
                { "base": null, "filter": "(|(memberOf:{{Chain}}:={{da}})(primaryGroupID=512))", "results": [
                  { "distinguishedName": "CN=Tier0,OU=Groups,DC=corp,DC=example", "sAMAccountName": "Tier0", "objectClass": [ "top", "group" ],
                    "memberOf": [ "{{da}}", "CN=Ops,OU=Groups,DC=corp,DC=example" ] },
                  { "distinguishedName": "CN=Ops,OU=Groups,DC=corp,DC=example", "sAMAccountName": "Ops", "objectClass": [ "top", "group" ],
                    "memberOf": [ "CN=Tier0,OU=Groups,DC=corp,DC=example" ] },
                  { "distinguishedName": "CN=Alice,OU=Admins,DC=corp,DC=example", "sAMAccountName": "alice", "objectClass": [ "user" ],
                    "memberOf": [ "CN=Ops,OU=Groups,DC=corp,DC=example" ] },
                  { "distinguishedName": "CN=Pat,OU=Admins,DC=corp,DC=example", "sAMAccountName": "pat", "objectClass": [ "user" ], "primaryGroupID": 512 },
                  { "distinguishedName": "CN=Far,OU=Admins,DC=corp,DC=example", "sAMAccountName": "far", "objectClass": [ "user" ],
                    "memberOf": [ "CN=Elsewhere,DC=emea,DC=corp,DC=example" ], "primaryGroupID": 513 }
                ] }
              ]
            }
            """);
        var resolver = Resolver(reader);
        var members = resolver.Members(resolver.Resolve(WellKnownGroup.DomainAdmins, CancellationToken.None), ["lastLogonTimestamp"], CancellationToken.None)
            .ToDictionary(m => m.Name);

        Assert.Equal("Domain Admins > Tier0", members["Tier0"].Path);
        Assert.False(members["Tier0"].IsNested);
        Assert.True(members["Ops"].IsGroup);
        Assert.Equal("Domain Admins > Tier0 > Ops > alice", members["alice"].Path);
        Assert.True(members["alice"].IsNested);
        Assert.Equal("Domain Admins > pat", members["pat"].Path);
        Assert.True(members["pat"].ViaPrimaryGroup);
        Assert.Equal("Domain Admins > ... > far", members["far"].Path);
        Assert.Equal("Domain Admins > partner", members["partner"].Path);
        Assert.NotNull(members["partner"].Record);
        var gone = members["CN=Gone,OU=Admins,DC=emea,DC=corp,DC=example"];
        Assert.Null(gone.Record);
        Assert.Contains("not operational", gone.ReadError);
        Assert.Equal(7, members.Count);

        var membership = reader.Queries[1];
        Assert.Contains("lastLogonTimestamp", membership.Properties);
        Assert.Contains("memberOf", membership.Properties);
        Assert.Equal(0, membership.SizeLimit);
    }

    [Fact]
    public void Builtin_Groups_Skip_The_Primary_Group_Clause()
    {
        var admins = "CN=Administratoren,CN=Builtin,DC=corp,DC=example";
        var reader = FixtureDirectoryReader.FromJson($$"""
            { "entries": { {{SingleDomain}} },
              "searches": [
                { "base": null, "filter": "(objectSid=S-1-5-32-544)", "results": [ { "distinguishedName": "{{admins}}", "sAMAccountName": "Administratoren" } ] },
                { "base": null, "filter": "(memberOf:{{Chain}}:={{admins}})", "results": [] } ] }
            """);
        var resolver = Resolver(reader);

        Assert.Empty(resolver.Members(resolver.Resolve(WellKnownGroup.Administrators, CancellationToken.None), [], CancellationToken.None));
    }

    [Fact]
    public void Tier0GroupOf_Finds_A_Protected_Group_By_Sid_In_The_Domain_And_The_Forest_Root()
    {
        var reader = FixtureDirectoryReader.FromJson($$"""
            {
              "entries": {
                "(domain)": { "objectSid": { "$sid": "{{Child}}" }, "distinguishedName": "DC=emea,DC=corp,DC=example" },
                "RootDSE": { "rootDomainNamingContext": "DC=corp,DC=example" },
                "DC=corp,DC=example": { "objectSid": { "$sid": "{{Root}}" } }
              },
              "searches": [
                { "base": null, "filter": "(&(objectClass=group)(member:{{Chain}}:=CN=Bea,OU=Staff,DC=emea,DC=corp,DC=example))", "results": [
                  { "sAMAccountName": "Backup-Team", "objectSid": { "$sid": "{{Child}}-1200" } },
                  { "sAMAccountName": "Sicherungs-Operatoren", "objectSid": { "$sid": "S-1-5-32-551" } } ] },
                { "base": null, "filter": "(&(objectClass=group)(member:{{Chain}}:=CN=Eve,OU=Staff,DC=emea,DC=corp,DC=example))", "results": [] },
                { "base": "DC=corp,DC=example", "filter": "(&(objectClass=group)(member:{{Chain}}:=CN=Eve,OU=Staff,DC=emea,DC=corp,DC=example))", "results": [
                  { "sAMAccountName": "Organisations-Admins", "objectSid": { "$sid": "{{Root}}-519" } } ] },
                { "base": null, "filter": "(&(objectClass=group)(member:{{Chain}}:=CN=Doe\\5c, Sam \\28old\\29,OU=Staff,DC=emea,DC=corp,DC=example))", "results": [
                  { "sAMAccountName": "VPN Users", "objectSid": { "$sid": "{{Child}}-1201" } } ] },
                { "base": "DC=corp,DC=example", "filter": "(&(objectClass=group)(member:{{Chain}}:=CN=Doe\\5c, Sam \\28old\\29,OU=Staff,DC=emea,DC=corp,DC=example))", "results": [] }
              ]
            }
            """);
        var resolver = Resolver(reader);

        Assert.Equal("Sicherungs-Operatoren", resolver.Tier0GroupOf("CN=Bea,OU=Staff,DC=emea,DC=corp,DC=example", CancellationToken.None));
        Assert.Equal("Organisations-Admins", resolver.Tier0GroupOf("CN=Eve,OU=Staff,DC=emea,DC=corp,DC=example", CancellationToken.None));
        Assert.Null(resolver.Tier0GroupOf(@"CN=Doe\, Sam (old),OU=Staff,DC=emea,DC=corp,DC=example", CancellationToken.None));
    }

    [Theory]
    [InlineData("CN=Domain Admins,CN=Users,DC=corp,DC=example", "CN=Domain Admins,CN=Users,DC=corp,DC=example")]
    [InlineData(@"CN=Doe\, Jane (IT),OU=*Staff,DC=corp,DC=example", @"CN=Doe\5c, Jane \28IT\29,OU=\2aStaff,DC=corp,DC=example")]
    [InlineData("CN=Domänen-Admins,CN=Users,DC=corp,DC=example", "CN=Domänen-Admins,CN=Users,DC=corp,DC=example")]
    public void Filter_Values_Are_Escaped(string value, string expected) =>
        Assert.Equal(expected, PrivilegedGroupResolver.EscapeFilterValue(value));
}
