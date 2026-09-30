namespace NetworkSecurityAuditor.Checks.IdentityAccess;

using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// IA08 - Guest/Vendor Accounts: Search AD for vendor/contractor/consultant/guest
/// accounts. Check AccountExpirationDate. Flag enabled accounts without expiration.
/// </summary>
public sealed class IA08_VendorAccountsCheck : ISecurityCheck
{
    public string Id => "IA08";

    private readonly Func<EnvironmentInfo, IDirectoryReader> _directory;

    public IA08_VendorAccountsCheck() : this(env => new LdapDirectoryReader(env.DomainName)) { }

    internal IA08_VendorAccountsCheck(Func<EnvironmentInfo, IDirectoryReader> directory) => _directory = directory;

    private const int MaxInvalidListed = 20;

    private static readonly string[] VendorPatterns =
    [
        "vendor", "contractor", "consultant", "extern", "guest",
        "partner", "3rdparty", "thirdparty", "outsource"
    ];

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        if (!env.IsDomainJoined)
        {
            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.NA,
                Findings = "Machine is not domain-joined. Vendor account review requires Active Directory.",
                Evidence = $"IsDomainJoined=false @ {DateTime.Now:yyyy-MM-dd HH:mm}"
            });
        }

        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;

            var directory = _directory(env);

            evidence.AppendLine("[Vendor/Guest Account Scan]");

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var accounts = new List<(string Sam, bool Enabled, string Expiration, string LastLogon, string Pattern, long ExpiresRaw)>();

            foreach (var pattern in VendorPatterns)
            {
                ct.ThrowIfCancellationRequested();
                var query = new DirectoryQuery(
                    $"(&(objectCategory=person)(objectClass=user)(sAMAccountName=*{pattern}*))",
                    ["sAMAccountName", "distinguishedName", "userAccountControl", "accountExpires", "lastLogonTimestamp"]);

                foreach (var sr in directory.Search(query, ct))
                {
                    string dn = sr.String("distinguishedName") ?? "";
                    if (!seen.Add(dn)) continue;

                    string sam = sr.String("sAMAccountName") ?? "";

                    int uac = sr.Int("userAccountControl");
                    bool enabled = (uac & 0x2) == 0;

                    // accountExpires: 0 or 0x7FFFFFFFFFFFFFFF = never expires
                    long expiresTicks = sr.Long("accountExpires");

                    string expirationStr;
                    bool hasExpiration;
                    if (expiresTicks == 0 || expiresTicks == long.MaxValue || expiresTicks == 0x7FFFFFFFFFFFFFFF)
                    {
                        expirationStr = "Never";
                        hasExpiration = false;
                    }
                    else
                    {
                        try
                        {
                            DateTime expDate = DateTime.FromFileTimeUtc(expiresTicks);
                            expirationStr = expDate.ToString("yyyy-MM-dd");
                            hasExpiration = true;
                        }
                        catch (ArgumentOutOfRangeException)
                        {
                            // Negative, or past the last date a FILETIME can hold: not a real expiration.
                            expirationStr = "Invalid";
                            hasExpiration = false;
                        }
                    }

                    long logonTs = sr.Long("lastLogonTimestamp");
                    string lastLogon = logonTs > 0
                        ? DateTime.FromFileTimeUtc(logonTs).ToString("yyyy-MM-dd")
                        : "Never";

                    accounts.Add((sam, enabled, expirationStr, lastLogon, pattern, expiresTicks));

                    // Flag enabled accounts without expiration
                    if (enabled && !hasExpiration)
                        hasIssue = true;
                }
            }

            int total = accounts.Count;
            int enabledNoExpiry = accounts.Count(a => a.Enabled && a.Expiration == "Never");
            var invalidExpiry = accounts.Where(a => a.Enabled && a.Expiration == "Invalid").ToList();

            sb.AppendLine($"Vendor/guest accounts found: {total}");

            if (enabledNoExpiry > 0)
            {
                sb.AppendLine($"CRITICAL: {enabledNoExpiry} enabled vendor/guest account(s) have NO expiration date set.");
                sb.AppendLine("  All vendor/contractor accounts should have an AccountExpirationDate.");
            }

            if (invalidExpiry.Count > 0)
            {
                sb.AppendLine($"CRITICAL: {invalidExpiry.Count} enabled vendor/guest account(s) have an accountExpires value that isn't a valid date, " +
                    "so they have no real expiration:");
                foreach (var account in invalidExpiry.Take(MaxInvalidListed))
                    sb.AppendLine($"  {account.Sam} (accountExpires={account.ExpiresRaw})");
                if (invalidExpiry.Count > MaxInvalidListed)
                    sb.AppendLine($"  ... and {invalidExpiry.Count - MaxInvalidListed} more.");
                sb.AppendLine("  Set a real AccountExpirationDate on each.");
            }

            foreach (var (sam, enabled, expiration, lastLogon, pattern, _) in accounts.Take(30))
            {
                string flag = !enabled ? "" : expiration switch
                {
                    "Never" => " [NO EXPIRY]",
                    "Invalid" => " [INVALID EXPIRY]",
                    _ => ""
                };
                string line = $"  {sam} | Enabled={enabled} | Expires={expiration} | LastLogon={lastLogon}{flag}";
                sb.AppendLine(line);
                evidence.AppendLine(line);
            }

            if (total > 30)
                evidence.AppendLine($"  ... and {total - 30} more.");

            if (total == 0)
                sb.AppendLine("No vendor/guest accounts detected matching common naming patterns.");

            return Task.FromResult(new CheckResult
            {
                Status = hasIssue ? CheckStatus.Fail : (total > 0 ? CheckStatus.Partial : CheckStatus.Pass),
                Findings = sb.ToString().TrimEnd(),
                Evidence = evidence.ToString().TrimEnd()
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.FromError(Id, ex));
        }
    }
}
