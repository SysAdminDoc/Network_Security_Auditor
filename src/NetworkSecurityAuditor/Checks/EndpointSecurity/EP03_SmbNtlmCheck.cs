namespace NetworkSecurityAuditor.Checks.EndpointSecurity;

using System.Text;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// EP03 - SMB signing, SMBv1, NTLM restrictions, LLMNR, NetBIOS, Kerberos delegation posture.
/// </summary>
public sealed class EP03_SmbNtlmCheck : ISecurityCheck
{
    public string Id => "EP03";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();
            int failCount = 0;
            int totalChecks = 0;

            // 1. SMB Signing
            ct.ThrowIfCancellationRequested();
            CheckSmbSigning(sb, evidence, ref failCount, ref totalChecks);

            // 2. SMBv1
            ct.ThrowIfCancellationRequested();
            CheckSmbV1(sb, evidence, ref failCount, ref totalChecks);

            // 3. NTLM Restriction Level (LmCompatibilityLevel)
            ct.ThrowIfCancellationRequested();
            CheckNtlmLevel(sb, evidence, ref failCount, ref totalChecks);

            // 4. LLMNR
            ct.ThrowIfCancellationRequested();
            CheckLlmnr(sb, evidence, ref failCount, ref totalChecks);

            // 5. NetBIOS over TCP/IP
            ct.ThrowIfCancellationRequested();
            CheckNetBios(sb, evidence, ref failCount, ref totalChecks);

            // 6. Kerberos delegation markers
            ct.ThrowIfCancellationRequested();
            CheckKerberosDelegation(sb, evidence, ref failCount, ref totalChecks);

            // Server 2025 annotation
            if (env.IsServer2025OrLater)
            {
                evidence.AppendLine("\n[Server 2025+ Defaults]");
                evidence.AppendLine("  SMB signing: mandatory by default for this OS version");
                evidence.AppendLine("  LDAP signing: required by default for new AD deployments");
                evidence.AppendLine("  RC4/DES: disabled by default (AES only)");
            }

            // Summary
            var status = failCount == 0
                ? CheckStatus.Pass
                : failCount < totalChecks ? CheckStatus.Partial : CheckStatus.Fail;

            if (failCount == 0)
                sb.Insert(0, "All SMB/NTLM/protocol hardening checks passed.\n");

            return Task.FromResult(new CheckResult
            {
                Status = status,
                Findings = sb.ToString().TrimEnd(),
                Evidence = evidence.ToString().TrimEnd()
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.FromError(Id, ex));
        }
    }

    private static void CheckSmbSigning(StringBuilder sb, StringBuilder evidence, ref int failCount, ref int totalChecks)
    {
        totalChecks++;
        const string serverKey = @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
        const string clientKey = @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";

        int serverSign = RegistryHelper.GetValue<int>(serverKey, "RequireSecuritySignature", 0);
        int clientSign = RegistryHelper.GetValue<int>(clientKey, "RequireSecuritySignature", 0);

        evidence.AppendLine("[SMB Signing]");
        evidence.AppendLine($"  Server RequireSecuritySignature = {serverSign}");
        evidence.AppendLine($"  Client RequireSecuritySignature = {clientSign}");

        if (serverSign != 1)
        {
            failCount++;
            sb.AppendLine("FAIL: SMB server signing is NOT required. Vulnerable to relay attacks.");
        }

        if (clientSign != 1)
        {
            sb.AppendLine("WARNING: SMB client signing is not required.");
        }
    }

    private static void CheckSmbV1(StringBuilder sb, StringBuilder evidence, ref int failCount, ref int totalChecks)
    {
        totalChecks++;
        const string keyPath = @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
        int smbV1 = RegistryHelper.GetValue<int>(keyPath, "SMB1", -1);

        // Also check the feature state
        const string featureKey = @"HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10";
        int mrxStart = RegistryHelper.GetValue<int>(featureKey, "Start", -1);

        evidence.AppendLine("\n[SMBv1 Status]");
        evidence.AppendLine($"  LanmanServer\\SMB1 = {smbV1}");
        evidence.AppendLine($"  mrxsmb10 Start = {mrxStart}");

        bool smbv1Enabled = smbV1 == 1 || (smbV1 == -1 && mrxStart != 4);

        if (smbv1Enabled)
        {
            failCount++;
            sb.AppendLine("FAIL: SMBv1 appears to be enabled. This protocol has known exploits (EternalBlue/WannaCry).");
        }
        else
        {
            sb.AppendLine("PASS: SMBv1 is disabled.");
        }
    }

    private static void CheckNtlmLevel(StringBuilder sb, StringBuilder evidence, ref int failCount, ref int totalChecks)
    {
        totalChecks++;
        const string keyPath = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa";
        int lmLevel = RegistryHelper.GetValue<int>(keyPath, "LmCompatibilityLevel", -1);

        evidence.AppendLine("\n[NTLM / LAN Manager]");
        evidence.AppendLine($"  LmCompatibilityLevel = {lmLevel}");

        string levelDesc = lmLevel switch
        {
            0 => "Send LM & NTLM (least secure)",
            1 => "Send LM & NTLM, use NTLMv2 session security if negotiated",
            2 => "Send NTLM response only",
            3 => "Send NTLMv2 response only",
            4 => "Send NTLMv2 response only, refuse LM",
            5 => "Send NTLMv2 response only, refuse LM & NTLM",
            _ => "Not configured (defaults to 3 on modern Windows)"
        };

        evidence.AppendLine($"  Description: {levelDesc}");

        if (lmLevel < 3 && lmLevel >= 0)
        {
            failCount++;
            sb.AppendLine($"FAIL: LmCompatibilityLevel = {lmLevel}. Should be >= 3 (NTLMv2 only). Legacy LM/NTLM hashes are easily crackable.");
        }
        else if (lmLevel >= 3)
        {
            sb.AppendLine($"PASS: LmCompatibilityLevel = {lmLevel} (NTLMv2 enforced).");
        }

        // Check NoLMHash
        int noLmHash = RegistryHelper.GetValue<int>(keyPath, "NoLMHash", -1);
        evidence.AppendLine($"  NoLMHash = {noLmHash}");
        if (noLmHash != 1)
        {
            sb.AppendLine("WARNING: NoLMHash is not set. LM password hashes may be stored.");
        }

        // Restrict NTLM audit
        int restrictNtlm = RegistryHelper.GetValue<int>(
            @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "RestrictSendingNTLMTraffic", -1);
        evidence.AppendLine($"  RestrictSendingNTLMTraffic = {restrictNtlm}");
    }

    private static void CheckLlmnr(StringBuilder sb, StringBuilder evidence, ref int failCount, ref int totalChecks)
    {
        totalChecks++;
        const string keyPath = @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
        int enableMulticast = RegistryHelper.GetValue<int>(keyPath, "EnableMulticast", -1);

        evidence.AppendLine("\n[LLMNR]");
        evidence.AppendLine($"  EnableMulticast = {enableMulticast}");

        if (enableMulticast != 0)
        {
            failCount++;
            sb.AppendLine("FAIL: LLMNR is not disabled. This protocol is vulnerable to poisoning/relay attacks (Responder).");
        }
        else
        {
            sb.AppendLine("PASS: LLMNR is disabled via policy.");
        }
    }

    private static void CheckNetBios(StringBuilder sb, StringBuilder evidence, ref int failCount, ref int totalChecks)
    {
        totalChecks++;
        // NetBIOS over TCP/IP is per-adapter; check the global DHCP option
        const string tcpipKey = @"HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters";
        const string interfacesKey = @"HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces";

        int nodeType = RegistryHelper.GetValue<int>(tcpipKey, "NodeType", -1);
        evidence.AppendLine("\n[NetBIOS over TCP/IP]");
        evidence.AppendLine($"  NodeType = {nodeType} (2=P-node disables broadcast, recommended)");

        // Check per-interface NetbiosOptions
        var adapterOptions = new List<int>();
        var ifaces = RegistryHelper.GetSubKeyNames(interfacesKey);
        foreach (var iface in ifaces)
        {
            int nbOption = RegistryHelper.GetValue<int>($@"{interfacesKey}\{iface}", "NetbiosOptions", -1);
            adapterOptions.Add(nbOption);

            string description = nbOption switch
            {
                1 => "enabled",
                2 => "disabled",
                0 => "DHCP default / not explicit",
                _ => "not set / unknown"
            };
            evidence.AppendLine($"  Interface {iface}: NetbiosOptions={nbOption} ({description})");
        }

        var assessment = AssessNetBios(nodeType, adapterOptions);
        if (assessment.HasFailure)
        {
            failCount++;
            sb.AppendLine("FAIL: NetBIOS over TCP/IP is explicitly enabled on one or more interfaces. Vulnerable to NBNS poisoning.");
        }
        else if (assessment.HasStrongDisableSignal)
        {
            sb.AppendLine("PASS: NetBIOS over TCP/IP appears disabled or broadcast-hardened.");
        }
        else
        {
            sb.AppendLine("INFO: NetBIOS over TCP/IP is not explicitly enabled, but adapter settings are DHCP-default or unknown. Verify DHCP policy disables NetBIOS where required.");
        }
    }

    internal static NetBiosAssessment AssessNetBios(int nodeType, IEnumerable<int> adapterOptions)
    {
        bool hasExplicitEnabled = false;
        bool hasExplicitDisabled = false;
        bool hasDhcpDefault = false;
        bool hasUnknown = false;

        foreach (int option in adapterOptions)
        {
            switch (option)
            {
                case 1:
                    hasExplicitEnabled = true;
                    break;
                case 2:
                    hasExplicitDisabled = true;
                    break;
                case 0:
                    hasDhcpDefault = true;
                    break;
                default:
                    hasUnknown = true;
                    break;
            }
        }

        return new NetBiosAssessment(
            hasExplicitEnabled,
            hasExplicitDisabled,
            hasDhcpDefault,
            hasUnknown,
            BroadcastDisabled: nodeType == 2);
    }

    internal readonly record struct NetBiosAssessment(
        bool HasExplicitEnabledInterface,
        bool HasExplicitDisabledInterface,
        bool HasDhcpDefaultInterface,
        bool HasUnknownInterface,
        bool BroadcastDisabled)
    {
        public bool HasFailure => HasExplicitEnabledInterface;

        public bool HasStrongDisableSignal => HasExplicitDisabledInterface || BroadcastDisabled;
    }

    private static void CheckKerberosDelegation(StringBuilder sb, StringBuilder evidence, ref int failCount, ref int totalChecks)
    {
        totalChecks++;
        // Check if unconstrained delegation is configured on this machine
        // (local check only - full AD delegation audit is in AD checks)
        const string keyPath = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters";
        int allowTgtDelegation = RegistryHelper.GetValue<int>(keyPath, "AllowTgtSessionKey", -1);

        evidence.AppendLine("\n[Kerberos Delegation Posture]");
        evidence.AppendLine($"  AllowTgtSessionKey = {allowTgtDelegation}");

        // Check for WDigest plain-text credential caching
        int useLogonCredential = RegistryHelper.GetValue<int>(
            @"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", -1);
        evidence.AppendLine($"  WDigest UseLogonCredential = {useLogonCredential}");

        if (useLogonCredential == 1)
        {
            failCount++;
            sb.AppendLine("FAIL: WDigest credential caching is enabled. Plaintext passwords stored in memory (Mimikatz target).");
        }
        else
        {
            sb.AppendLine("PASS: WDigest credential caching is disabled.");
        }
    }
}
