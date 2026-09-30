namespace NetworkSecurityAuditor.Checks.IdentityAccess;

using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// IA11 - Kerberos Encryption Readiness: krbtgt password age, and the ticket encryption types of every enabled user,
/// computer and managed service account (gMSA, sMSA) with an SPN. An account without msDS-SupportedEncryptionTypes
/// gets its KDC's default, which the April 2026 update for CVE-2026-20833 changed from 0x27 (RC4 allowed) to 0x18
/// (AES only), so each domain controller's DefaultDomainSupportedEncTypes and RC4DefaultDisablementPhase are read
/// and KDC events 201-209 are summarized.
/// </summary>
public sealed class IA11_KerberosEncryptionCheck : ISecurityCheck
{
    public string Id => "IA11";

    /// <summary>Where a KDC keeps DefaultDomainSupportedEncTypes (KB5021131, Microsoft Learn KDC registry keys).</summary>
    internal const string KdcKey = @"HKLM\SYSTEM\CurrentControlSet\Services\Kdc";

    /// <summary>Where the January 2026 and later updates read RC4DefaultDisablementPhase (CVE-2026-20833).</summary>
    internal const string KerberosPolicyKey = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters";

    /// <summary>The KDC default before the April 2026 update: DES, RC4 and AES session keys (KB5021131).</summary>
    internal const int PreEnforcementDefault = 0x27;

    /// <summary>The KDC default once RC4DefaultDisablementPhase is 2, the default from the April 2026 update on: AES-SHA1 only.</summary>
    internal const int EnforcementDefault = 0x18;

    internal const int KdcEventLookbackDays = 30;
    internal const int MaxKdcEventsPerDc = 200;
    private const int MaxListed = 20;
    private const int MaxEvidenceLines = 200;
    private const int SampleMessagesPerEventId = 2;
    // How long to wait for one DC's remote registry before naming it unreadable, so an unreachable DC can't stall the scan.
    internal static readonly TimeSpan RemoteRegistryTimeout = TimeSpan.FromSeconds(15);

    internal const string DomainControllerFilter =
        "(&(objectCategory=computer)(|(userAccountControl:1.2.840.113556.1.4.803:=8192)(primaryGroupID=521)))";

    // krbtgt has an SPN (kadmin/changepw) but is reviewed on its own; disabled accounts can't be used for tickets.
    internal const string UserSpnFilter =
        "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";

    // Domain controllers are included: their LDAP, CIFS and GC SPNs take tickets like any other service.
    internal const string ComputerSpnFilter =
        "(&(objectCategory=computer)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";

    internal const string ManagedServiceAccountSpnFilter =
        "(&(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";

    // msDS-SupportedEncryptionTypes bit flags ([MS-KILE] 2.2.7)
    private const int DES_CBC_CRC = 0x1;
    private const int DES_CBC_MD5 = 0x2;
    private const int RC4_HMAC = 0x4;
    private const int AES128_CTS = 0x8;
    private const int AES256_CTS = 0x10;
    private const int AES_SESSION_KEYS = 0x20;   // AES256-CTS-HMAC-SHA1-96-SK: AES session keys, the ticket keeps its cipher
    private const int AES128_SHA256 = 0x40;
    private const int AES256_SHA384 = 0x80;
    private const int DesMask = DES_CBC_CRC | DES_CBC_MD5;
    private const int AesMask = AES128_CTS | AES256_CTS;
    private const int TicketCipherMask = DesMask | RC4_HMAC | AesMask;
    private const int UF_USE_DES_KEY_ONLY = 0x200000;

    private readonly Func<EnvironmentInfo, IDirectoryReader> _directory;
    private readonly Func<string, IRegistryReader> _dcRegistry;
    private readonly Func<string, CancellationToken, IReadOnlyList<KdcEvent>> _kdcEvents;

    public IA11_KerberosEncryptionCheck() : this(
        env => new LdapDirectoryReader(env.DomainName),
        OpenDcRegistry,
        ReadKdcEvents)
    { }

    /// <param name="dcRegistry">Opens one DC's registry by host name; throws when the DC can't be read.</param>
    /// <param name="kdcEvents">Reads one DC's KDC events 201-209; throws when its System log can't be read.</param>
    internal IA11_KerberosEncryptionCheck(
        Func<EnvironmentInfo, IDirectoryReader> directory,
        Func<string, IRegistryReader> dcRegistry,
        Func<string, CancellationToken, IReadOnlyList<KdcEvent>> kdcEvents)
    {
        _directory = directory;
        _dcRegistry = dcRegistry;
        _kdcEvents = kdcEvents;
    }

    internal enum EncClass { Aes, Rc4Only, Des, Unset }

    internal sealed record SpnAccount(string Name, string Kind, int EncTypes, bool UseDesKeyOnly)
    {
        public EncClass Class => Classify(EncTypes, UseDesKeyOnly);
    }

    /// <summary>What a DC issues for an account without msDS-SupportedEncryptionTypes, and how that was decided.</summary>
    internal sealed record DcDefault(string Host, bool Readable, int? DefaultEncTypes, int? Phase, int Effective, bool Assumed, string Basis)
    {
        public bool AllowsRc4 => (Effective & RC4_HMAC) != 0;
        public bool ExplicitDes => DefaultEncTypes is > 0 && (Effective & DesMask) != 0;
        public bool ExplicitNoAes => DefaultEncTypes is > 0 && (Effective & AesMask) == 0;
    }

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        if (!env.IsDomainJoined)
        {
            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.NA,
                Findings = "Machine is not domain-joined. Kerberos encryption review requires Active Directory.",
                Evidence = $"IsDomainJoined=false @ {DateTime.Now:yyyy-MM-dd HH:mm}"
            });
        }

        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;
            bool hasWarning = false;

            var directory = _directory(env);

            // 1. Check krbtgt password age
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("[krbtgt Account]");

            var krbtgtQuery = new DirectoryQuery("(&(objectClass=user)(sAMAccountName=krbtgt))", ["pwdLastSet", "sAMAccountName"])
            {
                SizeLimit = 1
            };

            var krbtgtResult = directory.Search(krbtgtQuery, ct).FirstOrDefault();
            if (krbtgtResult != null)
            {
                long pwdTs = krbtgtResult.Long("pwdLastSet");

                if (pwdTs > 0)
                {
                    DateTime pwdDate = DateTime.FromFileTimeUtc(pwdTs);
                    int pwdAgeDays = (int)(DateTime.UtcNow - pwdDate).TotalDays;
                    evidence.AppendLine($"  krbtgt pwdLastSet = {pwdDate:yyyy-MM-dd} ({pwdAgeDays} days ago)");

                    if (pwdAgeDays > 180)
                    {
                        hasIssue = true;
                        sb.AppendLine($"CRITICAL: krbtgt password is {pwdAgeDays} days old (Golden Ticket risk). Reset immediately.");
                    }
                    else if (pwdAgeDays > 90)
                    {
                        sb.AppendLine($"WARNING: krbtgt password is {pwdAgeDays} days old. Schedule rotation.");
                    }
                    else
                    {
                        sb.AppendLine($"PASS: krbtgt password age is {pwdAgeDays} days.");
                    }
                }
                else
                {
                    evidence.AppendLine("  krbtgt pwdLastSet = 0 (never set)");
                    hasIssue = true;
                    sb.AppendLine("CRITICAL: krbtgt password has never been set.");
                }
            }
            else
            {
                evidence.AppendLine("  krbtgt account not found.");
                sb.AppendLine("WARNING: Could not find krbtgt account.");
            }

            // 2. What each DC issues for accounts without msDS-SupportedEncryptionTypes
            ct.ThrowIfCancellationRequested();
            var defaults = ReadDcDefaults(directory, ct);
            AppendDcDefaults(sb, evidence, defaults, ref hasIssue);

            // 3. Encryption types on accounts with SPNs
            ct.ThrowIfCancellationRequested();
            var users = ReadAccounts(directory, UserSpnFilter, ["sAMAccountName", "msDS-SupportedEncryptionTypes", "userAccountControl"], _ => "user", ct);
            var computers = ReadAccounts(directory, ComputerSpnFilter, ["sAMAccountName", "msDS-SupportedEncryptionTypes", "userAccountControl"], _ => "computer", ct);
            var managed = ReadAccounts(directory, ManagedServiceAccountSpnFilter,
                ["sAMAccountName", "msDS-SupportedEncryptionTypes", "userAccountControl", "objectClass"], ManagedKind, ct);

            string unsetNote = DescribeDefaultForUnset(defaults);
            evidence.AppendLine("\n[Kerberos Encryption Types on SPN Accounts]");
            AppendAccountEvidence(evidence, users, unsetNote);
            evidence.AppendLine("\n[Kerberos Encryption Types on Computer Accounts]");
            AppendAccountEvidence(evidence, computers, unsetNote);
            evidence.AppendLine("\n[Kerberos Encryption Types on Managed Service Accounts]");
            AppendAccountEvidence(evidence, managed, unsetNote);

            sb.AppendLine();
            AppendTally(sb, "Service accounts with SPNs", users);
            AppendTally(sb, "Computer accounts with SPNs", computers);
            AppendTally(sb, "Managed service accounts (gMSA/sMSA) with SPNs", managed);

            var all = users.Concat(computers).Concat(managed).ToList();
            var des = all.Where(a => a.Class == EncClass.Des).ToList();
            var rc4Only = all.Where(a => a.Class == EncClass.Rc4Only).ToList();
            var unset = all.Where(a => a.Class == EncClass.Unset).ToList();
            var aesWithRc4 = all.Where(a => a.Class == EncClass.Aes && (a.EncTypes & RC4_HMAC) != 0).ToList();

            if (des.Count > 0)
            {
                hasIssue = true;
                sb.AppendLine($"CRITICAL: {des.Count} account(s) support DES encryption (broken, must be disabled).");
                AppendNames(sb, des);
            }
            if (rc4Only.Count > 0)
            {
                hasIssue = true;
                sb.AppendLine($"FAIL: {rc4Only.Count} account(s) support only RC4 (vulnerable to Kerberoasting). Enable AES.");
                AppendNames(sb, rc4Only);
                if (rc4Only.Any(a => (a.EncTypes & AES_SESSION_KEYS) != 0))
                    sb.AppendLine("  The 0x20 flag gives AES session keys only; the service ticket is still RC4-encrypted.");
            }
            if (unset.Count > 0)
            {
                // With no DC found, the pre-enforcement default stands in for all of them.
                List<DcDefault> rc4Dcs = defaults.Count == 0
                    ? [new DcDefault("", false, null, null, PreEnforcementDefault, true, "no domain controller found")]
                    : defaults.Where(d => d.AllowsRc4).ToList();
                if (rc4Dcs.Count > 0)
                {
                    hasWarning = true;
                    sb.AppendLine($"WARNING: {unset.Count} account(s) have no msDS-SupportedEncryptionTypes, and a DC default still allows RC4 " +
                        $"({string.Join(", ", rc4Dcs.Select(DescribeRc4Default))}). " +
                        "Set AES (0x18) on these accounts, or set DefaultDomainSupportedEncTypes to 0x18 on every DC.");
                    AppendNames(sb, unset);
                }
                else
                {
                    sb.AppendLine($"PASS: {unset.Count} account(s) without msDS-SupportedEncryptionTypes get the DC default {unsetNote}.");
                }
            }
            if (aesWithRc4.Count > 0)
            {
                sb.AppendLine($"INFO: {aesWithRc4.Count} AES account(s) also allow RC4, so a client can still ask for an RC4 ticket. " +
                    "Remove RC4 once nothing needs it.");
            }

            // 4. KDC events 201-209 on each DC
            ct.ThrowIfCancellationRequested();
            if (AppendKdcEvents(sb, evidence, defaults, ct))
                hasWarning = true;

            return Task.FromResult(new CheckResult
            {
                Status = hasIssue ? CheckStatus.Fail : hasWarning ? CheckStatus.Partial : CheckStatus.Pass,
                Findings = sb.ToString().TrimEnd(),
                Evidence = evidence.ToString().TrimEnd()
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.FromError(Id, ex));
        }
    }

    internal static EncClass Classify(int encTypes, bool useDesKeyOnly)
    {
        if (useDesKeyOnly || (encTypes & DesMask) != 0)
            return EncClass.Des;
        // 0, or only flag bits such as 0x20: no ticket cipher is chosen, so the account is treated like unset.
        if ((encTypes & TicketCipherMask) == 0)
            return EncClass.Unset;
        return (encTypes & AesMask) != 0 ? EncClass.Aes : EncClass.Rc4Only;
    }

    /// <summary>
    /// The default a DC applies to accounts without msDS-SupportedEncryptionTypes. An explicit
    /// DefaultDomainSupportedEncTypes is always honored; otherwise RC4DefaultDisablementPhase 2 means 0x18, and
    /// 0 or 1 keeps 0x27 until the July 2026 update ignores it. With neither set the answer depends on the update level,
    /// which isn't read, so 0x27 is assumed.
    /// </summary>
    internal static DcDefault ResolveDcDefault(string host, int? defaultEncTypes, int? phase)
    {
        if (defaultEncTypes is int value && value > 0)
            return new(host, true, defaultEncTypes, phase, value, false, "DefaultDomainSupportedEncTypes is set explicitly and always applies");
        if (phase == 2)
            return new(host, true, defaultEncTypes, phase, EnforcementDefault, false, "RC4DefaultDisablementPhase=2 (enforcement)");
        if (phase is 0 or 1)
            return new(host, true, defaultEncTypes, phase, PreEnforcementDefault, false,
                $"RC4DefaultDisablementPhase={phase} keeps RC4 in the default until the July 2026 update, which ignores the value");
        return new(host, true, defaultEncTypes, phase, PreEnforcementDefault, true,
            "Neither value is set: 0x18 with the April 2026 or later update, 0x27 before it; assumed 0x27 because the update level isn't read");
    }

    internal static string FormatEncTypes(int enc, bool useDes)
    {
        var parts = new List<string>();
        if (useDes) parts.Add("DES(UAC)");
        if ((enc & DES_CBC_CRC) != 0) parts.Add("DES-CBC-CRC");
        if ((enc & DES_CBC_MD5) != 0) parts.Add("DES-CBC-MD5");
        if ((enc & RC4_HMAC) != 0) parts.Add("RC4-HMAC");
        if ((enc & AES128_CTS) != 0) parts.Add("AES128");
        if ((enc & AES256_CTS) != 0) parts.Add("AES256");
        if ((enc & AES_SESSION_KEYS) != 0) parts.Add("AES-SK");
        if ((enc & AES128_SHA256) != 0) parts.Add("AES128-SHA256");
        if ((enc & AES256_SHA384) != 0) parts.Add("AES256-SHA384");
        return parts.Count > 0 ? string.Join("+", parts) : "None/Default";
    }

    /// <summary>What a KDC event 201-209 means (CVE-2026-20833 support article).</summary>
    internal static string KdcEventMeaning(int id) => id switch
    {
        201 => "RC4 issued for a service without msDS-SupportedEncryptionTypes because the client offers only legacy ciphers; blocked at enforcement",
        202 => "RC4 issued for a service without msDS-SupportedEncryptionTypes because the service account has only legacy keys (reset its password); blocked at enforcement",
        203 => "blocked: service without msDS-SupportedEncryptionTypes and a client that offers only legacy ciphers",
        204 => "blocked: service without msDS-SupportedEncryptionTypes whose account has only legacy keys (reset its password)",
        205 => "DefaultDomainSupportedEncTypes explicitly enables insecure ciphers",
        206 => "service set to AES-SHA1 only but the client doesn't offer AES-SHA1; blocked at enforcement",
        207 => "service set to AES-SHA1 only but its account has no AES-SHA1 keys (reset its password); blocked at enforcement",
        208 => "denied: service set to AES-SHA1 only and the client doesn't offer AES-SHA1",
        209 => "denied: service set to AES-SHA1 only and its account has no AES-SHA1 keys (reset its password)",
        _ => "not a CVE-2026-20833 KDC event"
    };

    private List<DcDefault> ReadDcDefaults(IDirectoryReader directory, CancellationToken ct)
    {
        var hosts = directory.Search(new DirectoryQuery(DomainControllerFilter, ["dNSHostName", "cn"]), ct)
            .Select(dc => dc.String("dNSHostName") is { Length: > 0 } dns ? dns : dc.String("cn") ?? "")
            .Where(host => host.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var defaults = new List<DcDefault>(hosts.Count);
        foreach (var host in hosts)
        {
            ct.ThrowIfCancellationRequested();
            defaults.Add(ReadDcDefault(host));
        }
        return defaults;
    }

    private DcDefault ReadDcDefault(string host)
    {
        IRegistryReader? registry = null;
        try
        {
            registry = _dcRegistry(host);
            return ResolveDcDefault(
                host,
                registry.GetValue<int?>(KdcKey, "DefaultDomainSupportedEncTypes"),
                registry.GetValue<int?>(KerberosPolicyKey, "RC4DefaultDisablementPhase"));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new DcDefault(host, false, null, null, PreEnforcementDefault, true,
                $"Registry not readable ({ex.Message}); assumed 0x27");
        }
        finally
        {
            (registry as IDisposable)?.Dispose();
        }
    }

    private static void AppendDcDefaults(StringBuilder sb, StringBuilder evidence, List<DcDefault> defaults, ref bool hasIssue)
    {
        evidence.AppendLine("\n[Domain Controller Kerberos Defaults]");
        evidence.AppendLine("  Flags: DES=0x1/0x2, RC4=0x4, AES128=0x8, AES256=0x10, AES session keys=0x20");
        evidence.AppendLine($"  {KdcKey} DefaultDomainSupportedEncTypes; {KerberosPolicyKey} RC4DefaultDisablementPhase");

        sb.AppendLine("\nDomain controller default for accounts without msDS-SupportedEncryptionTypes:");
        if (defaults.Count == 0)
        {
            sb.AppendLine($"  No domain controller was found in the directory. Assumed the pre-enforcement default 0x{PreEnforcementDefault:X} " +
                $"({FormatEncTypes(PreEnforcementDefault, false)}), which allows RC4.");
            evidence.AppendLine("  No domain controllers found.");
            return;
        }

        foreach (var dc in defaults)
        {
            string settings = dc.Readable
                ? $"DefaultDomainSupportedEncTypes={Hex(dc.DefaultEncTypes)}, RC4DefaultDisablementPhase={Plain(dc.Phase)}"
                : "not readable";
            sb.AppendLine($"  {dc.Host}: 0x{dc.Effective:X} ({FormatEncTypes(dc.Effective, false)}). {dc.Basis}.");
            evidence.AppendLine($"  {dc.Host} | {settings} | effective 0x{dc.Effective:X}{(dc.Assumed ? " (assumed)" : "")}");

            if (dc.ExplicitDes)
            {
                hasIssue = true;
                sb.AppendLine($"CRITICAL: {dc.Host} DefaultDomainSupportedEncTypes=0x{dc.Effective:X} enables DES for every account without msDS-SupportedEncryptionTypes.");
            }
            else if (dc.ExplicitNoAes)
            {
                hasIssue = true;
                sb.AppendLine($"FAIL: {dc.Host} DefaultDomainSupportedEncTypes=0x{dc.Effective:X} has no AES, so accounts without msDS-SupportedEncryptionTypes get RC4 tickets.");
            }
        }

        if (defaults.All(d => !d.Readable))
        {
            sb.AppendLine($"  No domain controller's Kerberos settings could be read, so accounts without msDS-SupportedEncryptionTypes " +
                $"were evaluated against the pre-enforcement default 0x{PreEnforcementDefault:X}, which allows RC4.");
        }
    }

    private static string DescribeRc4Default(DcDefault dc) =>
        dc.Host.Length == 0
            ? $"0x{dc.Effective:X} assumed, no DC found"
            : $"0x{dc.Effective:X} on {dc.Host}{(dc.Assumed ? ", assumed" : "")}";

    private static string DescribeDefaultForUnset(List<DcDefault> defaults)
    {
        if (defaults.Count == 0)
            return $"0x{PreEnforcementDefault:X} (assumed, no DC found)";
        var values = defaults.Select(d => d.Effective).Distinct().ToList();
        return values.Count == 1
            ? $"0x{values[0]:X} ({FormatEncTypes(values[0], false)})"
            : string.Join(", ", defaults.Select(d => $"0x{d.Effective:X} on {d.Host}"));
    }

    private static List<SpnAccount> ReadAccounts(IDirectoryReader directory, string filter, IReadOnlyList<string> properties,
        Func<DirectoryRecord, string> kind, CancellationToken ct)
    {
        var accounts = new List<SpnAccount>();
        foreach (var sr in directory.Search(new DirectoryQuery(filter, properties), ct))
        {
            ct.ThrowIfCancellationRequested();
            accounts.Add(new SpnAccount(
                sr.String("sAMAccountName") ?? "",
                kind(sr),
                sr.Int("msDS-SupportedEncryptionTypes"),
                (sr.Int("userAccountControl") & UF_USE_DES_KEY_ONLY) != 0));
        }
        return accounts;
    }

    private static string ManagedKind(DirectoryRecord record) =>
        record.Strings("objectClass").Contains("msDS-GroupManagedServiceAccount", StringComparer.OrdinalIgnoreCase) ? "gMSA" : "sMSA";

    private static void AppendAccountEvidence(StringBuilder evidence, List<SpnAccount> accounts, string unsetNote)
    {
        foreach (var account in accounts.Take(MaxEvidenceLines))
        {
            string line = $"  {account.Name} | EncTypes=0x{account.EncTypes:X} ({FormatEncTypes(account.EncTypes, account.UseDesKeyOnly)})";
            if (account.Class == EncClass.Unset)
                line += $" | DC default {unsetNote}";
            evidence.AppendLine(line);
        }
        if (accounts.Count > MaxEvidenceLines)
            evidence.AppendLine($"  ... and {accounts.Count - MaxEvidenceLines} more.");
        if (accounts.Count == 0)
            evidence.AppendLine("  None.");
    }

    private static void AppendTally(StringBuilder sb, string heading, List<SpnAccount> accounts)
    {
        sb.AppendLine($"{heading}: {accounts.Count}");
        if (accounts.Count == 0)
            return;
        sb.AppendLine($"  AES-capable: {accounts.Count(a => a.Class == EncClass.Aes)}");
        sb.AppendLine($"  RC4-only (no AES): {accounts.Count(a => a.Class == EncClass.Rc4Only)}");
        sb.AppendLine($"  DES enabled: {accounts.Count(a => a.Class == EncClass.Des)}");
        sb.AppendLine($"  No encryption type set: {accounts.Count(a => a.Class == EncClass.Unset)}");
    }

    private static void AppendNames(StringBuilder sb, List<SpnAccount> accounts)
    {
        foreach (var account in accounts.Take(MaxListed))
            sb.AppendLine($"  {account.Name} [{account.Kind}] 0x{account.EncTypes:X} ({FormatEncTypes(account.EncTypes, account.UseDesKeyOnly)})");
        if (accounts.Count > MaxListed)
            sb.AppendLine($"  ... and {accounts.Count - MaxListed} more.");
    }

    /// <summary>Summarizes each DC's KDC events 201-209. Returns true when any were found.</summary>
    private bool AppendKdcEvents(StringBuilder sb, StringBuilder evidence, List<DcDefault> defaults, CancellationToken ct)
    {
        evidence.AppendLine($"\n[KDC Events 201-209, System log, Kdcsvc, last {KdcEventLookbackDays} days]");
        sb.AppendLine($"\nKDC events 201-209 (System log, Kdcsvc, last {KdcEventLookbackDays} days):");
        if (defaults.Count == 0)
        {
            sb.AppendLine("  Not read: no domain controller was found.");
            evidence.AppendLine("  No domain controllers found.");
            return false;
        }

        bool found = false;
        foreach (var dc in defaults)
        {
            ct.ThrowIfCancellationRequested();
            IReadOnlyList<KdcEvent> events;
            try
            {
                events = _kdcEvents(dc.Host, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                sb.AppendLine($"  {dc.Host}: not readable ({ex.Message}).");
                evidence.AppendLine($"  {dc.Host} | not readable: {ex.Message}");
                continue;
            }

            if (events.Count == 0)
            {
                sb.AppendLine($"  {dc.Host}: none.");
                evidence.AppendLine($"  {dc.Host} | none");
                continue;
            }

            found = true;
            string atLeast = events.Count >= MaxKdcEventsPerDc ? "at least " : "";
            var groups = events.GroupBy(e => e.Id).OrderBy(g => g.Key).ToList();
            sb.AppendLine($"WARNING: {dc.Host}: {atLeast}{events.Count} event(s): {string.Join(", ", groups.Select(g => $"{g.Key} x{g.Count()}"))}.");
            foreach (var group in groups)
            {
                sb.AppendLine($"    {group.Key}: {KdcEventMeaning(group.Key)}.");
                var latest = group.Max(e => e.TimeCreated);
                evidence.AppendLine($"  {dc.Host} | Event {group.Key} x{group.Count()} | latest {latest:yyyy-MM-dd HH:mm}");
                foreach (var sample in group.Where(e => e.Message.Length > 0).Take(SampleMessagesPerEventId))
                    evidence.AppendLine($"    {sample.Message}");
            }
        }
        return found;
    }

    private static string Hex(int? value) => value is { } v ? $"0x{v:X}" : "not set";

    private static string Plain(int? value) => value is { } v ? v.ToString(CultureInfo.InvariantCulture) : "not set";

    private static bool IsLocalHost(string host) =>
        string.Equals(host.Split('.')[0], Environment.MachineName, StringComparison.OrdinalIgnoreCase);

    private static IRegistryReader OpenDcRegistry(string host) =>
        IsLocalHost(host) ? SystemRegistryReader.Instance : RemoteHostRegistryReader.Connect(host, RemoteRegistryTimeout);

    internal static IReadOnlyList<KdcEvent> ReadKdcEvents(string host, CancellationToken ct)
    {
        using var session = IsLocalHost(host) ? new EventLogSession() : new EventLogSession(host);
        string xpath = EventLogQueryHelper.RecentEventsQuery(
            TimeSpan.FromDays(KdcEventLookbackDays),
            "Provider[@Name='Kdcsvc'] and (EventID >= 201 and EventID <= 209)");
        var query = new EventLogQuery("System", PathType.LogName, xpath) { Session = session, ReverseDirection = true };

        using var reader = new EventLogReader(query);
        var events = new List<KdcEvent>();
        var sampled = new Dictionary<int, int>();
        while (events.Count < MaxKdcEventsPerDc)
        {
            ct.ThrowIfCancellationRequested();
            using EventRecord? record = reader.ReadEvent();
            if (record is null)
                break;

            // Formatting a remote message is slow, so only the first couple per event ID are kept.
            string message = "";
            sampled.TryGetValue(record.Id, out int taken);
            if (taken < SampleMessagesPerEventId)
            {
                sampled[record.Id] = taken + 1;
                message = FirstLine(TryFormat(record));
            }
            events.Add(new KdcEvent(record.Id, record.TimeCreated ?? DateTime.MinValue, message));
        }
        return events;
    }

    private static string TryFormat(EventRecord record)
    {
        try
        {
            return record.FormatDescription() ?? "";
        }
        catch (EventLogException)
        {
            return "";
        }
    }

    private static string FirstLine(string text)
    {
        var line = text.Split('\n', 2)[0].Trim();
        return line.Length > 300 ? line[..300] + "..." : line;
    }
}

/// <summary>One KDC event 201-209 from a domain controller's System log.</summary>
internal sealed record KdcEvent(int Id, DateTime TimeCreated, string Message);
