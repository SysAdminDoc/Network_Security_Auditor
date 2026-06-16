namespace NetworkSecurityAuditor.Models;

public sealed class EnvironmentInfo
{
    public string ComputerName { get; set; } = Environment.MachineName;
    public bool IsAdmin { get; set; }
    public string OSCaption { get; set; } = "";
    public bool IsServer { get; set; }
    public bool IsDomainJoined { get; set; }
    public string DomainName { get; set; } = "";
    public bool HasAD { get; set; }
    public bool HasDNS { get; set; }
    public bool HasGPO { get; set; }
    public bool HasDefender { get; set; }
    public bool HasSMB { get; set; }
    public bool HasBitLocker { get; set; }
    public bool HasAppLocker { get; set; }
    public bool WinRMRunning { get; set; }
    public string JoinType { get; set; } = "Workgroup";
    public bool AzureADJoined { get; set; }
    public bool IntuneManaged { get; set; }
    public string TenantName { get; set; } = "";
    public int OSBuild { get; set; }
    public string OSVersion { get; set; } = "";
    public bool HasWindowsLAPS { get; set; }
    public bool HasLegacyLAPS { get; set; }
    public string PSVersion { get; set; } = "";
}
