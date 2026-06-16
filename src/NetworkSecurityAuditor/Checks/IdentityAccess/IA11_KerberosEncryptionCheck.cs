namespace NetworkSecurityAuditor.Checks.IdentityAccess;

using System.DirectoryServices;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// IA11 - Kerberos Encryption Readiness: krbtgt password age, RC4/DES usage
/// on service accounts (msDS-SupportedEncryptionTypes). Flags accounts without AES.
/// </summary>
public sealed class IA11_KerberosEncryptionCheck : ISecurityCheck
{
    public string Id => "IA11";

    // msDS-SupportedEncryptionTypes bit flags
    private const int DES_CBC_CRC = 0x1;
    private const int DES_CBC_MD5 = 0x2;
    private const int RC4_HMAC = 0x4;
    private const int AES128_CTS = 0x8;
    private const int AES256_CTS = 0x10;

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

            using var rootEntry = new DirectoryEntry("LDAP://" + env.DomainName);
            using var searcher = new DirectorySearcher(rootEntry) { PageSize = 1000 };

            // 1. Check krbtgt password age
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("[krbtgt Account]");

            searcher.Filter = "(&(objectClass=user)(sAMAccountName=krbtgt))";
            searcher.PropertiesToLoad.Clear();
            searcher.PropertiesToLoad.AddRange(["pwdLastSet", "sAMAccountName"]);

            var krbtgtResult = searcher.FindOne();
            if (krbtgtResult != null)
            {
                long pwdTs = krbtgtResult.Properties["pwdLastSet"].Count > 0
                    ? (long)krbtgtResult.Properties["pwdLastSet"][0] : 0;

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

            // 2. Check encryption types on service accounts (accounts with SPNs)
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[Kerberos Encryption Types on SPN Accounts]");

            searcher.Filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))";
            searcher.PropertiesToLoad.Clear();
            searcher.PropertiesToLoad.AddRange(["sAMAccountName", "msDS-SupportedEncryptionTypes",
                "userAccountControl"]);

            int totalSpn = 0;
            int desEnabled = 0;
            int rc4Only = 0;
            int aesSupported = 0;
            int noEncTypeSet = 0;

            using var spnResults = searcher.FindAll();
            foreach (SearchResult sr in spnResults)
            {
                ct.ThrowIfCancellationRequested();
                totalSpn++;
                string sam = sr.Properties["sAMAccountName"][0]?.ToString() ?? "";

                int uac = sr.Properties["userAccountControl"].Count > 0
                    ? (int)sr.Properties["userAccountControl"][0] : 0;
                bool useDes = (uac & 0x200000) != 0; // ADS_UF_USE_DES_KEY_ONLY

                int encTypes = sr.Properties["msDS-SupportedEncryptionTypes"].Count > 0
                    ? (int)sr.Properties["msDS-SupportedEncryptionTypes"][0] : 0;

                bool hasDes = useDes || (encTypes & (DES_CBC_CRC | DES_CBC_MD5)) != 0;
                bool hasRc4 = (encTypes & RC4_HMAC) != 0;
                bool hasAes = (encTypes & (AES128_CTS | AES256_CTS)) != 0;

                if (encTypes == 0 && !useDes) noEncTypeSet++;
                if (hasDes) desEnabled++;
                if (hasRc4 && !hasAes) rc4Only++;
                if (hasAes) aesSupported++;

                string encStr = FormatEncTypes(encTypes, useDes);
                evidence.AppendLine($"  {sam} | EncTypes=0x{encTypes:X} ({encStr})");
            }

            sb.AppendLine($"\nService accounts with SPNs: {totalSpn}");
            sb.AppendLine($"  AES-capable: {aesSupported}");
            sb.AppendLine($"  RC4-only (no AES): {rc4Only}");
            sb.AppendLine($"  DES enabled: {desEnabled}");
            sb.AppendLine($"  No encryption type set: {noEncTypeSet}");

            if (desEnabled > 0)
            {
                hasIssue = true;
                sb.AppendLine($"CRITICAL: {desEnabled} account(s) support DES encryption (broken, must be disabled).");
            }
            if (rc4Only > 0)
            {
                hasIssue = true;
                sb.AppendLine($"FAIL: {rc4Only} account(s) support only RC4 (vulnerable to Kerberoasting). Enable AES.");
            }

            // 3. Check domain-level Kerberos encryption policy
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[Domain Kerberos Policy]");

            int domainEncTypes = 0;
            try
            {
                rootEntry.RefreshCache(["msDS-SupportedEncryptionTypes"]);
                var domEncVal = rootEntry.Properties["msDS-SupportedEncryptionTypes"]?.Value;
                if (domEncVal is int dei)
                    domainEncTypes = dei;
            }
            catch { /* attribute may not exist */ }

            evidence.AppendLine($"  Domain msDS-SupportedEncryptionTypes = 0x{domainEncTypes:X}");

            return Task.FromResult(new CheckResult
            {
                Status = hasIssue ? CheckStatus.Fail : CheckStatus.Pass,
                Findings = sb.ToString().TrimEnd(),
                Evidence = evidence.ToString().TrimEnd()
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.FromError(Id, ex));
        }
    }

    private static string FormatEncTypes(int enc, bool useDes)
    {
        var parts = new List<string>();
        if (useDes) parts.Add("DES(UAC)");
        if ((enc & DES_CBC_CRC) != 0) parts.Add("DES-CBC-CRC");
        if ((enc & DES_CBC_MD5) != 0) parts.Add("DES-CBC-MD5");
        if ((enc & RC4_HMAC) != 0) parts.Add("RC4-HMAC");
        if ((enc & AES128_CTS) != 0) parts.Add("AES128");
        if ((enc & AES256_CTS) != 0) parts.Add("AES256");
        return parts.Count > 0 ? string.Join("+", parts) : "None/Default";
    }
}
