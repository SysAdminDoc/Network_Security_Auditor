namespace NetworkSecurityAuditor.Checks.IdentityAccess;

using System.DirectoryServices;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// IA12 - dMSA/BadSuccessor Exposure: Check for delegated Managed Service Account
/// (dMSA) objects in AD and OU delegation ACLs for dMSA creation rights.
/// Reports exposure to BadSuccessor privilege escalation (CVE-2025-21293).
/// </summary>
public sealed class IA12_DmsaCheck : ISecurityCheck
{
    public string Id => "IA12";

    private readonly Func<EnvironmentInfo, IDirectoryReader> _directory;

    public IA12_DmsaCheck() : this(env => new LdapDirectoryReader(env.DomainName)) { }

    internal IA12_DmsaCheck(Func<EnvironmentInfo, IDirectoryReader> directory) => _directory = directory;

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        if (!env.IsDomainJoined)
        {
            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.NA,
                Findings = "Machine is not domain-joined. dMSA/BadSuccessor check requires Active Directory.",
                Evidence = $"IsDomainJoined=false @ {DateTime.Now:yyyy-MM-dd HH:mm}"
            });
        }

        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            bool hasIssue = false;

            var directory = _directory(env);

            // 1. Check for existing dMSA objects
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("[Delegated Managed Service Accounts (dMSA)]");

            int dmsaCount = 0;
            try
            {
                var dmsaQuery = new DirectoryQuery("(objectClass=msDS-DelegatedManagedServiceAccount)",
                    ["sAMAccountName", "distinguishedName",
                     "msDS-DelegatedManagedServiceAccountSuccessor", "whenCreated"]);

                foreach (var sr in directory.Search(dmsaQuery, ct))
                {
                    ct.ThrowIfCancellationRequested();
                    dmsaCount++;
                    string sam = sr.String("sAMAccountName") ?? "";
                    string dn = sr.String("distinguishedName") ?? "";

                    string successor = sr.Has("msDS-DelegatedManagedServiceAccountSuccessor")
                        ? sr.String("msDS-DelegatedManagedServiceAccountSuccessor") ?? "None"
                        : "None";

                    DateTime created = sr.Time("whenCreated") ?? DateTime.MinValue;

                    evidence.AppendLine($"  {sam} | DN={dn}");
                    evidence.AppendLine($"    Successor: {successor}");
                    evidence.AppendLine($"    Created: {created:yyyy-MM-dd}");
                }
            }
            catch (Exception ex)
            {
                evidence.AppendLine($"  dMSA query error (object class may not exist in schema): {ex.Message}");
            }

            sb.AppendLine($"Delegated Managed Service Accounts found: {dmsaCount}");

            if (dmsaCount > 0)
            {
                hasIssue = true;
                sb.AppendLine("WARNING: dMSA objects exist. Review successor chains for BadSuccessor exposure.");
                sb.AppendLine("  Any principal with CreateChild rights on an OU containing a dMSA can exploit");
                sb.AppendLine("  the successor mechanism to escalate to the dMSA's privileges.");
            }

            // 2. Check Managed Service Accounts container for delegation
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[Managed Service Accounts Container]");

            string domainDn = directory.ReadEntry(null, ["distinguishedName"], ct).String("distinguishedName") ?? "";
            string msaCn = $"CN=Managed Service Accounts,{domainDn}";

            try
            {
                // Binding the container proves it exists; its ACL is read separately below.
                directory.ReadEntry(msaCn, ["distinguishedName"], ct);

                // Report the container exists
                evidence.AppendLine($"  Container DN: {msaCn}");
                evidence.AppendLine("  Container exists and is accessible.");

                // Check for delegated permissions using the security descriptor
                try
                {
                    var rules = directory.ReadAccessRules(msaCn, ct);

                    int createChildRules = 0;
                    foreach (var adRule in rules)
                    {
                        // ADS_RIGHT_DS_CREATE_CHILD = 0x1
                        if (adRule.Rights.HasFlag(ActiveDirectoryRights.CreateChild))
                        {
                            createChildRules++;
                            string identity = adRule.Identity;
                            evidence.AppendLine($"  CreateChild ACE: {identity} | Type={adRule.Type}");

                            // Flag non-standard delegations (not SYSTEM, Domain Admins, Enterprise Admins)
                            if (!identity.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase) &&
                                !identity.Contains("Domain Admins", StringComparison.OrdinalIgnoreCase) &&
                                !identity.Contains("Enterprise Admins", StringComparison.OrdinalIgnoreCase) &&
                                !identity.Contains("Administrators", StringComparison.OrdinalIgnoreCase) &&
                                adRule.Type == System.Security.AccessControl.AccessControlType.Allow)
                            {
                                hasIssue = true;
                                sb.AppendLine($"CRITICAL: Non-standard CreateChild delegation on MSA container: {identity}");
                                sb.AppendLine("  This principal could create dMSA objects and exploit BadSuccessor.");
                            }
                        }
                    }

                    evidence.AppendLine($"  Total CreateChild ACEs: {createChildRules}");
                }
                catch (Exception ex)
                {
                    evidence.AppendLine($"  Could not read ACLs: {ex.Message}");
                    sb.AppendLine("INFO: Could not read MSA container ACLs (access denied or insufficient privileges).");
                }
            }
            catch
            {
                evidence.AppendLine("  Managed Service Accounts container not found or inaccessible.");
            }

            // 3. Check for OUs with delegated CreateChild for msDS-DelegatedManagedServiceAccount
            ct.ThrowIfCancellationRequested();
            evidence.AppendLine("\n[OU Delegation for dMSA Creation]");

            // Check domain functional level (dMSA requires Windows Server 2025 / FL 10)
            try
            {
                var rootDse = directory.ReadEntry(DirectoryReader.RootDse,
                    ["domainFunctionality", "forestFunctionality"], ct);
                string? domainFl = rootDse.String("domainFunctionality");
                string? forestFl = rootDse.String("forestFunctionality");
                evidence.AppendLine($"  Domain Functional Level: {domainFl}");
                evidence.AppendLine($"  Forest Functional Level: {forestFl}");

                // dMSA (BadSuccessor) primarily affects WS2025 DFL 10
                if (int.TryParse(domainFl, out int dfl) && dfl >= 10)
                {
                    sb.AppendLine("WARNING: Domain functional level >= 10 (WS2025). dMSA/BadSuccessor attack surface is ACTIVE.");
                    hasIssue = true;
                }
                else
                {
                    sb.AppendLine("INFO: Domain functional level < 10. dMSA object class may not be available (lower BadSuccessor risk).");
                }
            }
            catch (Exception ex)
            {
                evidence.AppendLine($"  Could not read RootDSE: {ex.Message}");
            }

            if (!hasIssue && dmsaCount == 0)
                sb.AppendLine("PASS: No dMSA objects or suspicious delegations detected.");

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
}
