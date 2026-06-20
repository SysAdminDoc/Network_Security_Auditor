using System.Management;
using System.Security.Principal;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Services;

public sealed class PreflightResult
{
    public required string Name { get; init; }
    public required bool Passed { get; init; }
    public required string Detail { get; init; }
}

public static class PreflightChecker
{
    public static List<PreflightResult> Run(EnvironmentInfo env)
    {
        var results = new List<PreflightResult>();

        results.Add(new PreflightResult
        {
            Name = "Administrator Elevation",
            Passed = env.IsAdmin,
            Detail = env.IsAdmin ? "Running as administrator" : "Not elevated. Some checks will return N/A. Right-click and Run as Administrator."
        });

        results.Add(new PreflightResult
        {
            Name = "Domain Membership",
            Passed = env.IsDomainJoined,
            Detail = env.IsDomainJoined
                ? $"Domain: {env.DomainName} ({env.JoinType})"
                : "Not domain-joined. AD checks (IA01-IA12, CF01, CF04) will be skipped."
        });

        results.Add(new PreflightResult
        {
            Name = "Active Directory Module",
            Passed = env.HasAD,
            Detail = env.HasAD ? "RSAT AD module available" : "AD module not found. Install RSAT for full AD check coverage."
        });

        results.Add(new PreflightResult
        {
            Name = "Windows Defender",
            Passed = env.HasDefender,
            Detail = env.HasDefender ? "Defender cmdlets available" : "Defender cmdlets not found. EP01 (AV/EDR) check may produce limited results."
        });

        results.Add(new PreflightResult
        {
            Name = "WinRM Service",
            Passed = env.WinRMRunning,
            Detail = env.WinRMRunning ? "WinRM is running" : "WinRM not running. Remote connectivity checks may be limited."
        });

        results.Add(new PreflightResult
        {
            Name = "BitLocker Module",
            Passed = env.HasBitLocker,
            Detail = env.HasBitLocker ? "BitLocker cmdlets available" : "BitLocker module not available. EP02 check will use registry fallback."
        });

        results.Add(new PreflightResult
        {
            Name = "SMB Module",
            Passed = env.HasSMB,
            Detail = env.HasSMB ? "SMB cmdlets available" : "SMB module not found. EP03/NP checks will use registry fallback."
        });

        return results;
    }
}
