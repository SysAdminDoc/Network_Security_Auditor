namespace NetworkSecurityAuditor.Checks.IdentityAccess;

using System.DirectoryServices;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// IA08 - Guest/Vendor Accounts: Search AD for vendor/contractor/consultant/guest
/// accounts. Check AccountExpirationDate. Flag enabled accounts without expiration.
/// </summary>
public sealed class IA08_VendorAccountsCheck : ISecurityCheck
{
    public string Id => "IA08";

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

            using var rootEntry = new DirectoryEntry("LDAP://" + env.DomainName);
            using var searcher = new DirectorySearcher(rootEntry) { PageSize = 1000 };

            evidence.AppendLine("[Vendor/Guest Account Scan]");

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var accounts = new List<(string Sam, bool Enabled, string Expiration, string LastLogon, string Pattern)>();

            foreach (var pattern in VendorPatterns)
            {
                ct.ThrowIfCancellationRequested();
                searcher.Filter = $"(&(objectCategory=person)(objectClass=user)(sAMAccountName=*{pattern}*))";
                searcher.PropertiesToLoad.Clear();
                searcher.PropertiesToLoad.AddRange(["sAMAccountName", "distinguishedName",
                    "userAccountControl", "accountExpires", "lastLogonTimestamp"]);

                using var results = searcher.FindAll();
                foreach (SearchResult sr in results)
                {
                    string dn = sr.Properties["distinguishedName"][0]?.ToString() ?? "";
                    if (!seen.Add(dn)) continue;

                    string sam = sr.Properties["sAMAccountName"][0]?.ToString() ?? "";

                    int uac = sr.Properties["userAccountControl"].Count > 0
                        ? (int)sr.Properties["userAccountControl"][0] : 0;
                    bool enabled = (uac & 0x2) == 0;

                    // accountExpires: 0 or 0x7FFFFFFFFFFFFFFF = never expires
                    long expiresTicks = sr.Properties["accountExpires"].Count > 0
                        ? (long)sr.Properties["accountExpires"][0] : 0;

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
                        catch
                        {
                            expirationStr = "Invalid";
                            hasExpiration = false;
                        }
                    }

                    long logonTs = sr.Properties["lastLogonTimestamp"].Count > 0
                        ? (long)sr.Properties["lastLogonTimestamp"][0] : 0;
                    string lastLogon = logonTs > 0
                        ? DateTime.FromFileTimeUtc(logonTs).ToString("yyyy-MM-dd")
                        : "Never";

                    accounts.Add((sam, enabled, expirationStr, lastLogon, pattern));

                    // Flag enabled accounts without expiration
                    if (enabled && !hasExpiration)
                        hasIssue = true;
                }
            }

            int total = accounts.Count;
            int enabledNoExpiry = accounts.Count(a => a.Enabled && a.Expiration == "Never");

            sb.AppendLine($"Vendor/guest accounts found: {total}");

            if (enabledNoExpiry > 0)
            {
                sb.AppendLine($"CRITICAL: {enabledNoExpiry} enabled vendor/guest account(s) have NO expiration date set.");
                sb.AppendLine("  All vendor/contractor accounts should have an AccountExpirationDate.");
            }

            foreach (var (sam, enabled, expiration, lastLogon, pattern) in accounts.Take(30))
            {
                string flag = (enabled && expiration == "Never") ? " [NO EXPIRY]" : "";
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
