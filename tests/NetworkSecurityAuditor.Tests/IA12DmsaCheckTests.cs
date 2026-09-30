using System.Diagnostics;
using System.DirectoryServices;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text.Json.Nodes;
using NetworkSecurityAuditor.Checks.IdentityAccess;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

namespace NetworkSecurityAuditor.Tests;

public class IA12DmsaCheckTests
{
    private const string Domain = "S-1-5-21-1004336348-1177238915-682003330";

    private static Task<CheckResult> Run(string fixture) =>
        Run(FixtureDirectoryReader.Load(fixture), FixtureRemoteRegistryReader.Load(fixture));

    private static Task<CheckResult> Run(FixtureDirectoryReader reader, FixtureRemoteRegistryReader registry) =>
        new IA12_DmsaCheck(_ => reader, registry)
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

    /// <summary>A clock that only moves when a remote registry read advances it.</summary>
    private sealed class SteppingClock : TimeProvider
    {
        private long _ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _ticks;
        public void Advance(TimeSpan by) => _ticks += by.Ticks;
    }

    /// <summary>Answers from the fixture and makes each read take <paramref name="perRead"/> on the clock.</summary>
    private sealed class SlowRegistry(FixtureRemoteRegistryReader inner, SteppingClock clock, TimeSpan perRead) : IRemoteRegistryReader
    {
        public object? ReadMachineValue(string host, string subKey, string valueName, CancellationToken ct)
        {
            clock.Advance(perRead);
            return inner.ReadMachineValue(host, subKey, valueName, ct);
        }
    }

    private static string FixtureText(string fileName)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "NetworkSecurityAuditor.slnx")))
            dir = dir.Parent;
        return File.ReadAllText(Path.Combine(dir!.FullName, "tests", "NetworkSecurityAuditor.Tests", "Fixtures", "Directory", fileName));
    }

    [Fact]
    public async Task No_Dmsa_And_Standard_Container_Acl_Passes()
    {
        var result = await Run("IA12-pass.json");

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("Delegated Managed Service Accounts found: 0", result.Findings);
        Assert.Contains("PASS: No dMSA objects or suspicious delegations detected.", result.Findings);
        // A 2025 DC exposes the domain at functional level 7 too, so the sweep ran.
        Assert.Contains("Windows Server 2025 domain controllers: 1 of 2", result.Findings);
        Assert.Contains("dc01.corp.example | Windows Server 2025 Datacenter | 10.0 (26100) | Server 2025: yes | build 26100.6584 (remote registry UBR) | August 2025 fix: installed", result.Evidence);
        Assert.Contains("OUs, containers and domain root inspected: 4 of 4", result.Evidence);
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
        Assert.Contains("INFO: 1 dMSA object(s) exist.", result.Findings);
        Assert.Contains("CRITICAL: dc01.corp.example runs Windows Server 2025 build 26100.4652, below the August 2025 update (KB5063878, build 26100.4946) that fixes CVE-2025-53779.", result.Findings);
        Assert.Contains("CRITICAL: 1 non-Tier-0 principal(s) can create or take over dMSA objects while a Windows Server 2025 DC isn't confirmed patched.", result.Findings);
        Assert.Contains($@"  CORP\Helpdesk ({Domain}-1110): CreateChild (msDS-DelegatedManagedServiceAccount) on CN=Managed Service Accounts,DC=corp,DC=example", result.Findings);
        Assert.DoesNotContain("Contractors", result.Findings);
        Assert.DoesNotContain("PASS:", result.Findings);
        Assert.Contains("dmsa_web$ | DN=CN=dmsa_web,OU=Service Accounts,DC=corp,DC=example", result.Evidence);
        Assert.Contains("Linked account (msDS-ManagedAccountPrecededByLink): none", result.Evidence);
        Assert.Contains(@"CreateChild ACE: CORP\Contractors | Type=Deny", result.Evidence);
        Assert.Contains("Total CreateChild ACEs: 6", result.Evidence);
    }

    [Fact]
    public async Task Unreadable_Container_Acl_Is_Reported_Separately_From_A_Missing_Container()
    {
        var result = await Run("IA12-acl-unreadable.json");

        // An exposed domain whose default dMSA container can't be read isn't a clean pass.
        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("INFO: Could not read MSA container ACLs", result.Findings);
        Assert.Contains("REVIEW: 1 ACL(s) couldn't be read", result.Findings);
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
        var result = await new IA12_DmsaCheck(_ => throw new COMException("The server is not operational.", unchecked((int)0x8007203A)),
                FixtureRemoteRegistryReader.FromJson("{}"))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Error, result.Status);
    }

    [Fact]
    public async Task Exposed_Domain_Lists_Every_NonTier0_Principal_By_Sid()
    {
        var registry = FixtureRemoteRegistryReader.Load("IA12-exposed.json");
        var result = await Run(FixtureDirectoryReader.Load("IA12-exposed.json"), registry);

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("Windows Server 2025 domain controllers: 2 of 3", result.Findings);
        Assert.Contains("REVIEW: dc01.corp.example runs Windows Server 2025 but its patch level couldn't be read over remote registry (Access is denied.).", result.Findings);
        Assert.Contains("dc02.corp.example | Windows Server 2025 Datacenter | 10.0 (26100) | Server 2025: yes | build 26100.4946 (remote registry UBR) | August 2025 fix: installed", result.Evidence);
        Assert.Equal(new[] { "dc01.corp.example", "dc02.corp.example" }, registry.Hosts);

        Assert.Contains("CRITICAL: 6 non-Tier-0 principal(s) can create or take over dMSA objects", result.Findings);
        Assert.Contains($@"  CORP\Helpdesk ({Domain}-1110): CreateChild (msDS-DelegatedManagedServiceAccount) on OU=Workstations,OU=Corp,DC=corp,DC=example", result.Findings);
        Assert.Contains($@"  CORP\ServiceDesk ({Domain}-1112): WriteDacl on OU=Servers,OU=Corp,DC=corp,DC=example", result.Findings);
        Assert.Contains(@"  NT AUTHORITY\Authenticated Users (S-1-5-11): CreateChild (all classes) on OU=Lab,DC=corp,DC=example", result.Findings);
        Assert.Contains($@"  CORP\jdoe ({Domain}-1105): owner (implicit WriteDacl) on OU=Corp,DC=corp,DC=example", result.Findings);
        Assert.Contains("  Everyone (S-1-1-0): WriteProperty (msDS-ManagedAccountPrecededByLink) on CN=dmsa_app,OU=Servers,OU=Corp,DC=corp,DC=example", result.Findings);
        // SELF counts on a dMSA (anyone allowed to use it can act as it), not on a container.
        Assert.Contains(@"  NT AUTHORITY\SELF (S-1-5-10): WriteProperty (msDS-DelegatedMSAState) on CN=dmsa_app,OU=Servers,OU=Corp,DC=corp,DC=example" + Environment.NewLine, result.Findings);
        Assert.DoesNotContain("Desktop Support", result.Findings);
        Assert.DoesNotContain("CREATOR OWNER", result.Findings);
        Assert.DoesNotContain("Domain Admins", result.Findings);

        Assert.Contains("OUs, containers and domain root inspected: 7 of 7", result.Evidence);
        Assert.Contains("dMSA objects inspected: 1 of 1", result.Evidence);
        Assert.Contains($@"[RISK] CORP\Helpdesk | {Domain}-1110 | CreateChild (msDS-DelegatedManagedServiceAccount) | OU=Workstations,OU=Corp,DC=corp,DC=example", result.Evidence);
        Assert.Contains("State (msDS-DelegatedMSAState): 1 (migration started)", result.Evidence);
    }

    [Fact]
    public async Task Exposed_Domain_With_Every_2025_Dc_Patched_Is_A_Warning()
    {
        var registry = FixtureRemoteRegistryReader.FromJson("""
            { "remoteRegistry": {
                "dc01.corp.example": { "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion": { "UBR": 4851 } },
                "dc02.corp.example": { "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion": { "UBR": 6584 } } } }
            """);
        var result = await Run(FixtureDirectoryReader.Load("IA12-exposed.json"), registry);

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("WARNING: 6 non-Tier-0 principal(s) can create or take over dMSA objects. Every Windows Server 2025 DC has the August 2025 fix", result.Findings);
        Assert.DoesNotContain("CRITICAL", result.Findings);
        Assert.Contains("build 26100.4851 (remote registry UBR) | August 2025 fix: installed", result.Evidence);
    }

    [Fact]
    public async Task Clean_Domain_Passes_With_Scoped_Delegations_And_A_Benign_Migration()
    {
        var result = await Run("IA12-clean.json");

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("INFO: 1 dMSA object(s) exist.", result.Findings);
        Assert.Contains("PASS: No suspicious dMSA links or delegations detected.", result.Findings);
        Assert.DoesNotContain("Helpdesk", result.Findings);
        Assert.DoesNotContain("Contractors", result.Findings);
        Assert.Contains("Linked account (msDS-ManagedAccountPrecededByLink): CN=svc_sql,OU=Apps,DC=corp,DC=example", result.Evidence);
        Assert.Contains($"Linked account: svc_sql | SID={Domain}-1120 | links back (msDS-SupersededManagedAccountLink): yes | not Tier 0", result.Evidence);
        Assert.Contains("No non-Tier-0 principal can create or take over dMSA objects on the inspected objects.", result.Evidence);
    }

    [Fact]
    public async Task No_2025_Dc_Means_Not_Exposed()
    {
        var reader = FixtureDirectoryReader.Load("IA12-no-2025-dc.json");
        var registry = FixtureRemoteRegistryReader.Load("IA12-no-2025-dc.json");
        var result = await Run(reader, registry);

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("Windows Server 2025 domain controllers: 0 of 2", result.Findings);
        Assert.Contains("INFO: No domain controller runs Windows Server 2025, so no KDC can issue dMSA tickets and BadSuccessor doesn't apply here.", result.Findings);
        Assert.DoesNotContain("Everyone", result.Findings);
        Assert.Contains("Skipped: no Windows Server 2025 DC", result.Evidence);
        Assert.Empty(registry.Hosts);
        Assert.DoesNotContain(reader.Queries, q => q.Filter == IA12_DmsaCheck.OuFilter);
    }

    [Fact]
    public async Task Dmsa_Linked_To_A_Domain_Admin_Is_Flagged()
    {
        var reader = FixtureDirectoryReader.Load("IA12-dmsa-linked-da.json");
        var result = await Run(reader, FixtureRemoteRegistryReader.Load("IA12-dmsa-linked-da.json"));

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains($"CRITICAL: dMSA dmsa_backup$ is linked to jadmin (member of Tier 0 group {Domain}-512), and that account links back, so even patched DCs give the dMSA its privileges.", result.Findings);
        Assert.Contains($"CRITICAL: dMSA dmsa_krb$ is linked to Administrator (Tier 0 account {Domain}-500) with a one-way link.", result.Findings);
        Assert.Contains("CVE-2025-53779", result.Findings);
        Assert.Contains("Linked account (msDS-ManagedAccountPrecededByLink): CN=Jane Admin,OU=Admins,DC=corp,DC=example", result.Evidence);
        Assert.Contains("State (msDS-DelegatedMSAState): 2 (migration completed)", result.Evidence);

        // The link is read from the schema attribute, not the nonexistent "...Successor" name.
        var dmsaQuery = Assert.Single(reader.Queries, q => q.Filter == IA12_DmsaCheck.DmsaFilter);
        Assert.Contains("msDS-ManagedAccountPrecededByLink", dmsaQuery.Properties);
        Assert.DoesNotContain(dmsaQuery.Properties, p => p.Contains("Successor", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Root_Dse_Is_Read_On_The_Machine_Domain_Server()
    {
        var reader = FixtureDirectoryReader.Load("IA12-pass.json");
        await Run(reader, FixtureRemoteRegistryReader.Load("IA12-pass.json"));

        // A serverless bind follows the signed-in user's domain, so an auditor from a trusted forest would get that
        // forest's root and count this forest's Enterprise Admins as an outsider.
        Assert.Contains(DirectoryReader.RootDse, reader.EntryReads);
        Assert.DoesNotContain(DirectoryReader.RootDseServerless, reader.EntryReads);
    }

    [Fact]
    public async Task Dc_Patch_Reads_Stop_At_The_Time_Budget_And_Flag_The_Rest()
    {
        var clock = new SteppingClock();
        var inner = FixtureRemoteRegistryReader.FromJson("""
            { "remoteRegistry": {
                "dc01.corp.example": { "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion": { "UBR": 4946 } },
                "dc02.corp.example": { "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion": { "UBR": 4946 } } } }
            """);
        var registry = new SlowRegistry(inner, clock, IA12_DmsaCheck.DcReadBudget + TimeSpan.FromSeconds(1));

        var result = await new IA12_DmsaCheck(_ => FixtureDirectoryReader.Load("IA12-exposed.json"), registry) { Clock = clock }
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

        Assert.Equal(new[] { "dc01.corp.example" }, inner.Hosts);
        Assert.Contains("dc02.corp.example | Windows Server 2025 Datacenter | 10.0 (26100) | Server 2025: yes | patch level not read (the 45-second budget for DC reads ran out)", result.Evidence);
        Assert.Contains("REVIEW: The patch level of 1 Windows Server 2025 DC(s) wasn't read, so they aren't counted as patched.", result.Findings);
        // An unread DC is never taken as patched, so open delegations stay critical.
        Assert.Contains("CRITICAL: 6 non-Tier-0 principal(s)", result.Findings);
        Assert.Equal(CheckStatus.Fail, result.Status);
    }

    [Fact]
    public async Task Dc_Patch_Reads_Within_The_Budget_Read_Every_Dc()
    {
        var clock = new SteppingClock();
        var inner = FixtureRemoteRegistryReader.FromJson("""
            { "remoteRegistry": {
                "dc01.corp.example": { "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion": { "UBR": 4946 } },
                "dc02.corp.example": { "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion": { "UBR": 4946 } } } }
            """);
        var registry = new SlowRegistry(inner, clock, TimeSpan.FromSeconds(15));

        var result = await new IA12_DmsaCheck(_ => FixtureDirectoryReader.Load("IA12-exposed.json"), registry) { Clock = clock }
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

        Assert.Equal(new[] { "dc01.corp.example", "dc02.corp.example" }, inner.Hosts);
        Assert.DoesNotContain("wasn't read", result.Findings);
        Assert.Contains("WARNING: 6 non-Tier-0 principal(s)", result.Findings);
    }

    [Fact]
    public async Task Localized_Group_Names_Are_Matched_By_Sid()
    {
        var result = await Run("IA12-localized.json");

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("WARNING: 1 non-Tier-0 principal(s) can create or take over dMSA objects.", result.Findings);
        Assert.Contains($@"  CORP\Helpdesk-Mitarbeiter ({Domain}-1110): CreateChild (msDS-DelegatedManagedServiceAccount) on CN=Managed Service Accounts,DC=corp,DC=example", result.Findings);
        foreach (var tier0 in new[] { "Domänen-Admins", "Organisations-Admins", "Administratoren", "Konten-Operatoren", "Schema-Admins", "SYSTEM" })
            Assert.DoesNotContain(tier0, result.Findings);
    }

    [Fact]
    public async Task Localized_And_English_Names_Give_The_Same_Answer()
    {
        var german = FixtureText("IA12-localized.json");
        var english = german
            .Replace("NT-AUTORITÄT", "NT AUTHORITY")
            .Replace("Authentifizierte Benutzer", "Authenticated Users")
            .Replace("VORDEFINIERT\\\\Administratoren", "BUILTIN\\\\Administrators")
            .Replace("Konten-Operatoren", "Account Operators")
            .Replace("Domänen-Admins", "Domain Admins")
            .Replace("Organisations-Admins", "Enterprise Admins")
            .Replace("Schema-Admins", "Schema Admins");
        Assert.NotEqual(german, english);

        var inGerman = await Run(FixtureDirectoryReader.FromJson(german), FixtureRemoteRegistryReader.FromJson(german));
        var inEnglish = await Run(FixtureDirectoryReader.FromJson(english), FixtureRemoteRegistryReader.FromJson(english));

        Assert.Equal(inEnglish.Status, inGerman.Status);
        Assert.Equal(inEnglish.Findings, inGerman.Findings);
    }

    [Fact]
    public async Task Unlisted_Domain_Controllers_Are_Treated_As_Possibly_Exposed()
    {
        var node = JsonNode.Parse(FixtureText("IA12-pass.json"))!;
        var dcSearch = node["searches"]!.AsArray().First(s => (string?)s!["filter"] == IA12_DmsaCheck.DcFilter)!.AsObject();
        dcSearch.Remove("results");
        dcSearch["$error"] = new JsonObject { ["hresult"] = "0x80070005", ["message"] = "Access is denied." };
        var json = node.ToJsonString();

        var result = await Run(FixtureDirectoryReader.FromJson(json), FixtureRemoteRegistryReader.FromJson(json));

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("REVIEW: Couldn't list domain controllers (Access is denied.), so the check assumes a Windows Server 2025 DC may exist.", result.Findings);
        Assert.Contains("OUs, containers and domain root inspected: 4 of 4", result.Evidence);
    }

    [Fact]
    public async Task Acl_Sweep_Stops_At_Its_Cap_And_Says_So()
    {
        var ous = Enumerable.Range(0, IA12_DmsaCheck.MaxAclObjects + 5)
            .Select(i => new JsonObject { ["distinguishedName"] = $"OU=Branch{i:0000},DC=corp,DC=example" });
        var node = JsonNode.Parse(FixtureText("IA12-pass.json"))!;
        var ouSearch = node["searches"]!.AsArray().First(s => (string?)s!["filter"] == IA12_DmsaCheck.OuFilter)!;
        ouSearch["results"] = new JsonArray([.. ous]);
        var json = node.ToJsonString();

        var result = await Run(FixtureDirectoryReader.FromJson(json), FixtureRemoteRegistryReader.FromJson(json));

        // The branch OUs have no recorded ACL, so every one read fails and the sweep keeps going to the cap.
        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains($"REVIEW: The ACL sweep stopped at its limit ({IA12_DmsaCheck.MaxAclObjects} of {IA12_DmsaCheck.MaxAclObjects + 8} OUs and containers", result.Findings);
        Assert.Contains($"REVIEW: {IA12_DmsaCheck.MaxAclObjects - 2} ACL(s) couldn't be read", result.Findings);
    }

    [Theory]
    [InlineData(null, "Unknown")]
    [InlineData(4652, "Unpatched")]   // July 2025 cumulative update
    [InlineData(4850, "Unpatched")]
    [InlineData(4851, "Patched")]     // August 2025 hotpatch KB5064010
    [InlineData(4945, "Unpatched")]
    [InlineData(4946, "Patched")]     // August 2025 cumulative update KB5063878
    [InlineData(6508, "Patched")]     // September 2025 hotpatch
    [InlineData(33438, "Patched")]
    public void Patch_State_Follows_The_August_2025_Builds(int? ubr, string expected) =>
        Assert.Equal(expected, IA12_DmsaCheck.PatchStateOf(ubr).ToString());

    [Theory]
    [InlineData("Windows Server 2025 Datacenter", "10.0 (26100)", true)]
    [InlineData("Windows Server 2025 Standard Evaluation", null, true)]
    [InlineData(null, "10.0 (26100)", true)]
    [InlineData("Windows Server 2022 Standard", "10.0 (20348)", false)]
    [InlineData("Windows Server 2019 Datacenter", "10.0 (17763)", false)]
    [InlineData(null, null, false)]
    public void Server_2025_Is_Read_From_Os_Name_Or_Build(string? os, string? version, bool expected) =>
        Assert.Equal(expected, IA12_DmsaCheck.IsServer2025(os, version));

    [Theory]
    [InlineData("CreateChild", "00000000-0000-0000-0000-000000000000", false, "Allow", "CreateChild (all classes)")]
    [InlineData("CreateChild", "0feb936f-47b3-49f2-9386-1dedc2c23765", false, "Allow", "CreateChild (msDS-DelegatedManagedServiceAccount)")]
    [InlineData("CreateChild", "bf967a86-0de6-11d0-a285-00aa003049e2", false, "Allow", null)]  // computer class isn't the dMSA class
    [InlineData("GenericAll", "00000000-0000-0000-0000-000000000000", false, "Allow", "GenericAll")]
    [InlineData("GenericAll", "0feb936f-47b3-49f2-9386-1dedc2c23765", false, "Allow", "CreateChild (msDS-DelegatedManagedServiceAccount)")]
    [InlineData("GenericAll", "00000000-0000-0000-0000-000000000000", true, "Allow", null)]    // inherit-only: not on this object
    [InlineData("CreateChild", "00000000-0000-0000-0000-000000000000", false, "Deny", null)]
    [InlineData("WriteDacl", "00000000-0000-0000-0000-000000000000", false, "Allow", "WriteDacl")]
    [InlineData("WriteOwner", "00000000-0000-0000-0000-000000000000", false, "Allow", "WriteOwner")]
    [InlineData("GenericWrite", "00000000-0000-0000-0000-000000000000", false, "Allow", null)]  // no CreateChild bit
    [InlineData("WriteProperty", "a0945b2b-57a2-43bd-b327-4d112a4e8bd1", false, "Allow", null)] // not an OU right
    public void Container_Rights_That_Allow_Creating_A_Dmsa(string rights, string objectType, bool inheritOnly, string type, string? expected) =>
        Assert.Equal(expected, IA12_DmsaCheck.RelevantRights(Rule(rights, objectType, inheritOnly, type), IA12_DmsaCheck.AclScope.Container));

    [Theory]
    [InlineData("WriteProperty", "a0945b2b-57a2-43bd-b327-4d112a4e8bd1", "WriteProperty (msDS-ManagedAccountPrecededByLink)")]
    [InlineData("WriteProperty", "2f5c138a-bd38-4016-88b4-0ec87cbb4919", "WriteProperty (msDS-DelegatedMSAState)")]
    [InlineData("WriteProperty", "00000000-0000-0000-0000-000000000000", "WriteProperty (all attributes)")]
    [InlineData("GenericWrite", "00000000-0000-0000-0000-000000000000", "GenericWrite")]
    [InlineData("WriteProperty", "bf967950-0de6-11d0-a285-00aa003049e2", null)]  // description: harmless
    [InlineData("GenericRead", "00000000-0000-0000-0000-000000000000", null)]
    [InlineData("CreateChild", "00000000-0000-0000-0000-000000000000", null)]    // nothing to create under a dMSA
    public void Dmsa_Rights_That_Allow_Rewriting_The_Link(string rights, string objectType, string? expected) =>
        Assert.Equal(expected, IA12_DmsaCheck.RelevantRights(Rule(rights, objectType, false, "Allow"), IA12_DmsaCheck.AclScope.Dmsa));

    [Fact]
    public void Creator_Owner_Is_Skipped_And_Self_Counts_Only_On_A_Dmsa()
    {
        static bool NotTier0(string? sid) => false;
        Assert.False(IA12_DmsaCheck.IsReportable("S-1-3-0", IA12_DmsaCheck.AclScope.Container, NotTier0));
        Assert.False(IA12_DmsaCheck.IsReportable("S-1-3-0", IA12_DmsaCheck.AclScope.Dmsa, NotTier0));
        Assert.False(IA12_DmsaCheck.IsReportable("S-1-3-1", IA12_DmsaCheck.AclScope.Dmsa, NotTier0));
        Assert.False(IA12_DmsaCheck.IsReportable("S-1-5-10", IA12_DmsaCheck.AclScope.Container, NotTier0));
        Assert.True(IA12_DmsaCheck.IsReportable("S-1-5-10", IA12_DmsaCheck.AclScope.Dmsa, NotTier0));
        Assert.False(IA12_DmsaCheck.IsReportable(Domain + "-512", IA12_DmsaCheck.AclScope.Container, sid => Tier0Principals.IsTier0(sid, Domain)));
        Assert.True(IA12_DmsaCheck.IsReportable(Domain + "-1110", IA12_DmsaCheck.AclScope.Container, sid => Tier0Principals.IsTier0(sid, Domain)));
    }

    [Fact]
    public void Owner_Rights_Entry_Replaces_The_Owners_Implicit_Rights()
    {
        var plain = new DirectoryAcl(Domain + "-1105", @"CORP\jdoe", []);
        Assert.Equal("owner (implicit WriteDacl)", IA12_DmsaCheck.OwnerReason(plain, IA12_DmsaCheck.AclScope.Container));

        var narrowed = new DirectoryAcl(Domain + "-1105", @"CORP\jdoe",
            [new DirectoryAccessRule("OWNER RIGHTS", ActiveDirectoryRights.ReadControl, AccessControlType.Allow, Guid.Empty, false, IA12_DmsaCheck.OwnerRights)]);
        Assert.Null(IA12_DmsaCheck.OwnerReason(narrowed, IA12_DmsaCheck.AclScope.Container));

        var granting = new DirectoryAcl(Domain + "-1105", @"CORP\jdoe",
            [new DirectoryAccessRule("OWNER RIGHTS", ActiveDirectoryRights.CreateChild, AccessControlType.Allow, Guid.Empty, false, IA12_DmsaCheck.OwnerRights)]);
        Assert.Equal("owner via OWNER RIGHTS: CreateChild (all classes)", IA12_DmsaCheck.OwnerReason(granting, IA12_DmsaCheck.AclScope.Container));
        Assert.Contains(IA12_DmsaCheck.RiskyGrants(granting, IA12_DmsaCheck.AclScope.Container, _ => false),
            g => g.Sid == Domain + "-1105" && g.Reason.StartsWith("owner via OWNER RIGHTS", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("CN=dmsa_web,OU=Service Accounts,DC=corp,DC=example", "OU=Service Accounts,DC=corp,DC=example")]
    [InlineData(@"CN=Smith\, John,OU=Apps,DC=corp,DC=example", "OU=Apps,DC=corp,DC=example")]
    [InlineData("DC=example", null)]
    public void Parent_Dn_Honors_Escaped_Commas(string dn, string? expected) =>
        Assert.Equal(expected, IA12_DmsaCheck.ParentDn(dn));

    [Fact]
    public void Remote_Registry_Honors_Cancellation_And_Its_Timeout()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        var reader = new RemoteRegistryReader(TimeSpan.FromSeconds(1));
        Assert.ThrowsAny<OperationCanceledException>(() =>
            reader.ReadMachineValue("dc01.corp.example", IA12_DmsaCheck.CurrentVersionKey, "UBR", cancelled.Token));

        // 192.0.2.1 is TEST-NET-1: it never answers, so the read fails or times out instead of hanging a scan.
        var watch = Stopwatch.StartNew();
        Assert.ThrowsAny<Exception>(() => reader.ReadMachineValue("192.0.2.1", IA12_DmsaCheck.CurrentVersionKey, "UBR", CancellationToken.None));
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(10), $"Remote read took {watch.Elapsed}.");
    }

    private static DirectoryAccessRule Rule(string rights, string objectType, bool inheritOnly, string type) =>
        new("CORP\\Someone", Enum.Parse<ActiveDirectoryRights>(rights), Enum.Parse<AccessControlType>(type),
            Guid.Parse(objectType), false, Domain + "-1200", inheritOnly);
}
