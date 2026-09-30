using NetworkSecurityAuditor.Checks.IdentityAccess;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

namespace NetworkSecurityAuditor.Tests;

public class IA11KerberosEncryptionCheckTests
{
    // Written out rather than taken from the check, so a wrong path in the check fails here.
    private const string KdcKey = @"HKLM\SYSTEM\CurrentControlSet\Services\Kdc";
    private const string PolicyKey = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters";
    private const string Dc01 = "dc01.corp.example";
    private const string Dc02 = "dc02.corp.example";

    private static FixtureRegistryReader Dc(int? defaultEncTypes = null, int? phase = null)
    {
        var registry = new FixtureRegistryReader();
        if (defaultEncTypes is { } value)
            registry.Set(KdcKey, "DefaultDomainSupportedEncTypes", value);
        if (phase is { } p)
            registry.Set(PolicyKey, "RC4DefaultDisablementPhase", p);
        return registry;
    }

    private static Task<CheckResult> Run(
        string fixture,
        Dictionary<string, FixtureRegistryReader> dcs,
        Dictionary<string, IReadOnlyList<KdcEvent>>? events = null) =>
        Run(FixtureDirectoryReader.Load(fixture), dcs, events);

    // A DC missing from dcs (or events) behaves like one that can't be reached.
    private static Task<CheckResult> Run(
        FixtureDirectoryReader directory,
        Dictionary<string, FixtureRegistryReader> dcs,
        Dictionary<string, IReadOnlyList<KdcEvent>>? events = null) =>
        new IA11_KerberosEncryptionCheck(
                _ => directory,
                host => dcs.TryGetValue(host, out var registry) ? registry : throw new IOException("The network path was not found."),
                (host, _) => events is null
                    ? []
                    : events.TryGetValue(host, out var list) ? list : throw new UnauthorizedAccessException("Attempted to perform an unauthorized operation."))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

    [Fact]
    public async Task Fresh_Krbtgt_And_Aes_Service_Accounts_Pass()
    {
        var result = await Run("IA11-pass.json", new() { [Dc01] = Dc(phase: 2) });

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("PASS: krbtgt password age is 30 days.", result.Findings);
        Assert.Contains("Service accounts with SPNs: 2", result.Findings);
        Assert.Contains("  AES-capable: 2", result.Findings);
        Assert.Contains("  RC4-only (no AES): 0", result.Findings);
        Assert.Contains("Computer accounts with SPNs: 2", result.Findings);
        Assert.Contains("Managed service accounts (gMSA/sMSA) with SPNs: 1", result.Findings);
        Assert.Contains("dc01.corp.example: 0x18 (AES128+AES256). RC4DefaultDisablementPhase=2 (enforcement).", result.Findings);
        Assert.Contains("INFO: 2 AES account(s) also allow RC4", result.Findings);
        Assert.Contains("  dc01.corp.example: none.", result.Findings);
        Assert.Contains("svc_web | EncTypes=0x1C (RC4-HMAC+AES128+AES256)", result.Evidence);
        Assert.Contains("gmsa-web$ | EncTypes=0x18 (AES128+AES256)", result.Evidence);
        Assert.Contains("dc01.corp.example | DefaultDomainSupportedEncTypes=not set, RC4DefaultDisablementPhase=2 | effective 0x18", result.Evidence);
        // The domain object's msDS-SupportedEncryptionTypes isn't a KDC setting, so it's no longer read.
        Assert.DoesNotContain("Domain msDS-SupportedEncryptionTypes", result.Evidence);
    }

    [Fact]
    public async Task Old_Krbtgt_Rc4_Only_And_Des_Accounts_Fail()
    {
        var result = await Run("IA11-fail.json", new() { [Dc01] = Dc() });

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("CRITICAL: krbtgt password is 400 days old (Golden Ticket risk). Reset immediately.", result.Findings);
        Assert.Contains("Service accounts with SPNs: 4", result.Findings);
        Assert.Contains("  No encryption type set: 1", result.Findings);
        Assert.Contains("CRITICAL: 1 account(s) support DES encryption (broken, must be disabled).", result.Findings);
        Assert.Contains("  svc_legacy [user] 0x0 (DES(UAC))", result.Findings);
        Assert.Contains("FAIL: 1 account(s) support only RC4 (vulnerable to Kerberoasting). Enable AES.", result.Findings);
        Assert.Contains("  svc_backup [user] 0x4 (RC4-HMAC)", result.Findings);
        Assert.Contains("WARNING: 1 account(s) have no msDS-SupportedEncryptionTypes, and a DC default still allows RC4 (0x27 on dc01.corp.example, assumed).", result.Findings);
        Assert.Contains("  svc_print [user] 0x0 (None/Default)", result.Findings);
        Assert.Contains("svc_legacy | EncTypes=0x0 (DES(UAC))", result.Evidence);
        Assert.Contains("svc_print | EncTypes=0x0 (None/Default) | DC default 0x27", result.Evidence);
        Assert.DoesNotContain("Domain msDS-SupportedEncryptionTypes", result.Evidence);
    }

    [Fact]
    public async Task Every_Search_Runs_From_The_Domain_Root_And_Krbtgt_Is_A_Single_Result()
    {
        var directory = FixtureDirectoryReader.Load("IA11-pass.json");

        await Run(directory, new() { [Dc01] = Dc(phase: 2) });

        Assert.Equal(5, directory.Queries.Count);
        Assert.Equal(1, directory.Queries[0].SizeLimit);
        Assert.All(directory.Queries.Skip(1), q => Assert.Equal(0, q.SizeLimit));
        Assert.All(directory.Queries, q => Assert.Null(q.SearchBase));
        Assert.Equal("(&(objectCategory=computer)(|(userAccountControl:1.2.840.113556.1.4.803:=8192)(primaryGroupID=521)))", directory.Queries[1].Filter);
        Assert.Contains("dNSHostName", directory.Queries[1].Properties);
    }

    [Fact]
    public async Task Unset_Accounts_Pass_When_Every_Dc_Enforces_Aes()
    {
        var result = await Run("IA11-unset.json", new() { [Dc01] = Dc(phase: 2), [Dc02] = Dc(phase: 2) });

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("PASS: 3 account(s) without msDS-SupportedEncryptionTypes get the DC default 0x18 (AES128+AES256).", result.Findings);
        Assert.Contains("NAS01$ | EncTypes=0x0 (None/Default) | DC default 0x18 (AES128+AES256)", result.Evidence);
        Assert.Contains("svc_sql | EncTypes=0x18 (AES128+AES256)", result.Evidence);
    }

    [Fact]
    public async Task Unset_Accounts_Are_Partial_When_A_Dc_Still_Allows_Rc4_By_Default()
    {
        var result = await Run("IA11-unset.json", new() { [Dc01] = Dc(phase: 1), [Dc02] = Dc(phase: 2) });

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("dc01.corp.example: 0x27 (DES-CBC-CRC+DES-CBC-MD5+RC4-HMAC+AES-SK). RC4DefaultDisablementPhase=1 keeps RC4 in the default", result.Findings);
        Assert.Contains("WARNING: 3 account(s) have no msDS-SupportedEncryptionTypes, and a DC default still allows RC4 (0x27 on dc01.corp.example).", result.Findings);
        Assert.Contains("  svc_app [user] 0x0 (None/Default)", result.Findings);
        Assert.Contains("  NAS01$ [computer] 0x0 (None/Default)", result.Findings);
        Assert.Contains("  gmsa-web$ [gMSA] 0x0 (None/Default)", result.Findings);
        Assert.Contains("DC default 0x27 on dc01.corp.example, 0x18 on dc02.corp.example", result.Evidence);
    }

    [Fact]
    public async Task Unset_Accounts_Are_Partial_And_Say_What_Was_Assumed_When_Neither_Value_Is_Set()
    {
        var result = await Run("IA11-unset.json", new() { [Dc01] = Dc(), [Dc02] = Dc() });

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("Neither value is set: 0x18 with the April 2026 or later update, 0x27 before it; assumed 0x27", result.Findings);
        Assert.Contains("(0x27 on dc01.corp.example, assumed, 0x27 on dc02.corp.example, assumed)", result.Findings);
    }

    [Fact]
    public async Task An_Unreachable_Dc_Is_Named_And_Assumed_Rather_Than_Fatal()
    {
        var result = await Run("IA11-unset.json", new() { [Dc01] = Dc(phase: 2) });

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("dc02.corp.example: 0x27 (DES-CBC-CRC+DES-CBC-MD5+RC4-HMAC+AES-SK). Registry not readable (The network path was not found.); assumed 0x27.", result.Findings);
        Assert.Contains("(0x27 on dc02.corp.example, assumed)", result.Findings);
        Assert.Contains("dc02.corp.example | not readable | effective 0x27 (assumed)", result.Evidence);
        Assert.DoesNotContain("No domain controller's Kerberos settings could be read", result.Findings);
    }

    [Fact]
    public async Task No_Readable_Dc_Says_Which_Default_Was_Assumed()
    {
        var result = await Run("IA11-unset.json", new());

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("No domain controller's Kerberos settings could be read, so accounts without msDS-SupportedEncryptionTypes were evaluated against the pre-enforcement default 0x27, which allows RC4.", result.Findings);
    }

    [Fact]
    public async Task No_Dc_In_The_Directory_Says_Which_Default_Was_Assumed()
    {
        var directory = FixtureDirectoryReader.FromJson("""
            {
              "searches": [
                { "base": null, "filter": "(&(objectClass=user)(sAMAccountName=krbtgt))", "results": [] },
                { "base": null, "filter": "(&(objectCategory=computer)(|(userAccountControl:1.2.840.113556.1.4.803:=8192)(primaryGroupID=521)))", "results": [] },
                { "base": null, "filter": "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                  "results": [ { "sAMAccountName": "svc_app", "userAccountControl": 512 } ] },
                { "base": null, "filter": "(&(objectCategory=computer)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "results": [] },
                { "base": null, "filter": "(&(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "results": [] }
              ]
            }
            """);

        var result = await Run(directory, new());

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("No domain controller was found in the directory. Assumed the pre-enforcement default 0x27 (DES-CBC-CRC+DES-CBC-MD5+RC4-HMAC+AES-SK), which allows RC4.", result.Findings);
        Assert.Contains("(0x27 assumed, no DC found)", result.Findings);
        Assert.Contains("svc_app | EncTypes=0x0 (None/Default) | DC default 0x27 (assumed, no DC found)", result.Evidence);
        Assert.Contains("Not read: no domain controller was found.", result.Findings);
    }

    [Fact]
    public async Task An_Explicit_Aes_Default_Wins_Over_The_Phase()
    {
        var result = await Run("IA11-unset.json", new() { [Dc01] = Dc(0x18, phase: 1), [Dc02] = Dc(0x18) });

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("dc01.corp.example: 0x18 (AES128+AES256). DefaultDomainSupportedEncTypes is set explicitly and always applies.", result.Findings);
    }

    [Fact]
    public async Task An_Explicit_Default_With_Rc4_And_Aes_Leaves_Unset_Accounts_Partial()
    {
        var result = await Run("IA11-unset.json", new() { [Dc01] = Dc(0x3C), [Dc02] = Dc(0x18) });

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("(0x3C on dc01.corp.example)", result.Findings);
        Assert.DoesNotContain("FAIL:", result.Findings);
    }

    [Fact]
    public async Task An_Explicit_Default_Without_Aes_Fails()
    {
        var result = await Run("IA11-unset.json", new() { [Dc01] = Dc(0x24), [Dc02] = Dc(phase: 2) });

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("FAIL: dc01.corp.example DefaultDomainSupportedEncTypes=0x24 has no AES, so accounts without msDS-SupportedEncryptionTypes get RC4 tickets.", result.Findings);
    }

    [Fact]
    public async Task An_Explicit_Default_With_Des_Fails()
    {
        var result = await Run("IA11-unset.json", new() { [Dc01] = Dc(0x27), [Dc02] = Dc(phase: 2) });

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("CRITICAL: dc01.corp.example DefaultDomainSupportedEncTypes=0x27 enables DES for every account without msDS-SupportedEncryptionTypes.", result.Findings);
    }

    [Fact]
    public async Task Rc4_Only_Computers_And_Managed_Accounts_And_Des_Fail_By_Name()
    {
        var result = await Run("IA11-rc4.json", new() { [Dc01] = Dc(phase: 2) });

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("FAIL: 2 account(s) support only RC4 (vulnerable to Kerberoasting). Enable AES.", result.Findings);
        Assert.Contains("  NAS02$ [computer] 0x4 (RC4-HMAC)", result.Findings);
        Assert.Contains("  gmsa-legacy$ [gMSA] 0x24 (RC4-HMAC+AES-SK)", result.Findings);
        Assert.Contains("The 0x20 flag gives AES session keys only; the service ticket is still RC4-encrypted.", result.Findings);
        Assert.Contains("CRITICAL: 1 account(s) support DES encryption (broken, must be disabled).", result.Findings);
        Assert.Contains("  msa-old$ [sMSA] 0x1B (DES-CBC-CRC+DES-CBC-MD5+AES128+AES256)", result.Findings);
        Assert.Contains("INFO: 1 AES account(s) also allow RC4", result.Findings);
    }

    [Fact]
    public async Task Kdc_Events_Are_Summarized_Per_Dc_And_Leave_The_Check_Partial()
    {
        var now = DateTime.Now;
        var events = new Dictionary<string, IReadOnlyList<KdcEvent>>
        {
            [Dc01] =
            [
                new KdcEvent(201, now.AddDays(-1), "The Key Distribution Center detected RC4 usage that will be unsupported in enforcement phase."),
                new KdcEvent(201, now.AddDays(-2), ""),
                new KdcEvent(205, now.AddDays(-3), "")
            ]
        };

        var result = await Run("IA11-pass.json", new() { [Dc01] = Dc(phase: 2) }, events);

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Contains("WARNING: dc01.corp.example: 3 event(s): 201 x2, 205 x1.", result.Findings);
        Assert.Contains("    201: RC4 issued for a service without msDS-SupportedEncryptionTypes because the client offers only legacy ciphers; blocked at enforcement.", result.Findings);
        Assert.Contains("    205: DefaultDomainSupportedEncTypes explicitly enables insecure ciphers.", result.Findings);
        Assert.Contains("dc01.corp.example | Event 201 x2 | latest", result.Evidence);
        Assert.Contains("    The Key Distribution Center detected RC4 usage", result.Evidence);
    }

    [Fact]
    public async Task Unreadable_Kdc_Events_Are_Named_Without_Changing_The_Result()
    {
        var result = await Run("IA11-pass.json", new() { [Dc01] = Dc(phase: 2) }, new Dictionary<string, IReadOnlyList<KdcEvent>>());

        Assert.Equal(CheckStatus.Pass, result.Status);
        Assert.Contains("  dc01.corp.example: not readable (Attempted to perform an unauthorized operation.).", result.Findings);
    }

    [Theory]
    [InlineData(0, false, "Unset")]
    [InlineData(0x20, false, "Unset")]
    [InlineData(0x4, false, "Rc4Only")]
    [InlineData(0x24, false, "Rc4Only")]
    [InlineData(0x18, false, "Aes")]
    [InlineData(0x1C, false, "Aes")]
    [InlineData(0x3C, false, "Aes")]
    [InlineData(0x3, false, "Des")]
    [InlineData(0x1F, false, "Des")]
    [InlineData(0x18, true, "Des")]
    public void Classify_Reads_The_Ticket_Cipher_Bits(int encTypes, bool useDesKeyOnly, string expected)
    {
        Assert.Equal(expected, IA11_KerberosEncryptionCheck.Classify(encTypes, useDesKeyOnly).ToString());
    }

    [Theory]
    [InlineData(null, null, 0x27, true)]
    [InlineData(null, 0, 0x27, false)]
    [InlineData(null, 1, 0x27, false)]
    [InlineData(null, 2, 0x18, false)]
    [InlineData(null, 7, 0x27, true)]
    [InlineData(0x18, 1, 0x18, false)]
    [InlineData(0x24, 2, 0x24, false)]
    [InlineData(0, 2, 0x18, false)]
    public void ResolveDcDefault_Follows_The_Explicit_Value_Then_The_Phase(int? defaultEncTypes, int? phase, int effective, bool assumed)
    {
        var resolved = IA11_KerberosEncryptionCheck.ResolveDcDefault("dc01", defaultEncTypes, phase);

        Assert.Equal(effective, resolved.Effective);
        Assert.Equal(assumed, resolved.Assumed);
    }

    [Theory]
    [InlineData(201)]
    [InlineData(202)]
    [InlineData(203)]
    [InlineData(204)]
    [InlineData(205)]
    [InlineData(206)]
    [InlineData(207)]
    [InlineData(208)]
    [InlineData(209)]
    public void Every_Kdc_Event_From_201_To_209_Has_A_Meaning(int id)
    {
        Assert.DoesNotContain("not a CVE-2026-20833", IA11_KerberosEncryptionCheck.KdcEventMeaning(id));
    }

    [Fact]
    public void Kdc_Event_Query_Is_Valid_Xpath_For_The_System_Log()
    {
        // The local log answers the same query a DC gets; an invalid XPath would throw here.
        var events = IA11_KerberosEncryptionCheck.ReadKdcEvents(Environment.MachineName, CancellationToken.None);

        Assert.True(events.Count <= IA11_KerberosEncryptionCheck.MaxKdcEventsPerDc);
        Assert.All(events, e => Assert.InRange(e.Id, 201, 209));
    }

    [Fact]
    public async Task Directory_Failure_Is_An_Error()
    {
        var result = await new IA11_KerberosEncryptionCheck(
                _ => throw new System.Runtime.InteropServices.COMException("The server is not operational.", unchecked((int)0x8007203A)),
                _ => throw new InvalidOperationException("The registry must not be read."),
                (_, _) => throw new InvalidOperationException("Events must not be read."))
            .ExecuteAsync(FixtureDirectoryReader.DomainMember, new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Error, result.Status);
    }
}
