using System.Security.Cryptography;
using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Export;

internal static class OscalIds
{
    public static string Observation(EnvironmentInfo env, CheckItemViewModel check)
        => StableUuid("observation", env.ComputerName, check.Id);

    public static string Finding(EnvironmentInfo env, CheckItemViewModel check)
        => StableUuid("finding", env.ComputerName, check.Id);

    public static string Risk(EnvironmentInfo env, CheckItemViewModel check)
        => StableUuid("risk", env.ComputerName, check.Id);

    public static string PoamItem(EnvironmentInfo env, CheckItemViewModel check)
        => StableUuid("poam-item", env.ComputerName, check.Id);

    public static string Milestone(EnvironmentInfo env, CheckItemViewModel check, string name)
        => StableUuid("milestone", env.ComputerName, check.Id, name);

    public static string Party(string role, string name)
        => StableUuid("party", role, name);

    public static string ExternalObservation(string source, string key)
        => StableUuid("external-observation", source, key);

    public static string ExternalFinding(string source, string key)
        => StableUuid("external-finding", source, key);

    private static string StableUuid(params string[] parts)
    {
        var input = string.Join('\u001f', parts.Prepend("network-security-auditor-oscal"));
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        var bytes = hash[..16];
        return new Guid(bytes).ToString();
    }
}
