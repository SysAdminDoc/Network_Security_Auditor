namespace NetworkSecurityAuditor.Checks.NetworkPerimeter;

using System.Management;
using System.Text;
using NetworkSecurityAuditor.Models;

/// <summary>
/// NP10 - Firmware Currency: Checklist/external check. Report BIOS/UEFI version
/// and network device firmware indicators.
/// </summary>
public sealed class NP10_FirmwareCheck : ISecurityCheck
{
    public string Id => "NP10";

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            var evidence = new StringBuilder();

            // 1. Get BIOS/UEFI information
            ct.ThrowIfCancellationRequested();
            GetBiosInfo(sb, evidence, ct);

            // 2. Get system baseboard info
            ct.ThrowIfCancellationRequested();
            GetBaseboardInfo(evidence, ct);

            // 3. Check Secure Boot status
            ct.ThrowIfCancellationRequested();
            CheckSecureBoot(sb, evidence);

            // 4. Report network device firmware (what we can detect)
            ct.ThrowIfCancellationRequested();
            GetNetworkAdapterDriverVersions(sb, evidence, ct);

            // Checklist
            sb.AppendLine();
            sb.AppendLine("CHECKLIST - Firmware Currency Review:");
            sb.AppendLine("  [ ] BIOS/UEFI firmware is latest available from manufacturer");
            sb.AppendLine("  [ ] Network switch/router firmware is current");
            sb.AppendLine("  [ ] Firewall appliance firmware is current");
            sb.AppendLine("  [ ] Access point firmware is current");
            sb.AppendLine("  [ ] UPS/PDU firmware is current (if networked)");
            sb.AppendLine("  [ ] Firmware update process is documented");
            sb.AppendLine();
            sb.AppendLine("MANUAL VERIFICATION REQUIRED: Compare detected firmware versions " +
                "against manufacturer-published latest versions.");

            return Task.FromResult(new CheckResult
            {
                Status = CheckStatus.Partial,
                Findings = sb.ToString().TrimEnd(),
                Evidence = evidence.ToString().TrimEnd()
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.FromError(Id, ex));
        }
    }

    private static void GetBiosInfo(StringBuilder sb, StringBuilder evidence, CancellationToken ct)
    {
        evidence.AppendLine("[BIOS/UEFI Information]");

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Manufacturer, Name, Version, SMBIOSBIOSVersion, ReleaseDate, " +
                "SerialNumber FROM Win32_BIOS");

            foreach (ManagementObject obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();

                string manufacturer = obj["Manufacturer"]?.ToString() ?? "Unknown";
                string name = obj["Name"]?.ToString() ?? "Unknown";
                string version = obj["Version"]?.ToString() ?? "Unknown";
                string smbiosVer = obj["SMBIOSBIOSVersion"]?.ToString() ?? "Unknown";
                string releaseDate = obj["ReleaseDate"]?.ToString() ?? "Unknown";

                // Parse WMI date
                string friendlyDate = releaseDate;
                if (releaseDate.Length >= 8)
                {
                    try
                    {
                        friendlyDate = $"{releaseDate[..4]}-{releaseDate[4..6]}-{releaseDate[6..8]}";
                    }
                    catch { /* Use raw */ }
                }

                evidence.AppendLine($"  Manufacturer: {manufacturer}");
                evidence.AppendLine($"  Name: {name}");
                evidence.AppendLine($"  Version: {version}");
                evidence.AppendLine($"  SMBIOS Version: {smbiosVer}");
                evidence.AppendLine($"  Release Date: {friendlyDate}");

                sb.AppendLine($"BIOS/UEFI: {manufacturer} - {smbiosVer} (Released: {friendlyDate}).");
            }
        }
        catch (ManagementException ex)
        {
            evidence.AppendLine($"  WMI error: {ex.Message}");
        }
    }

    private static void GetBaseboardInfo(StringBuilder evidence, CancellationToken ct)
    {
        evidence.AppendLine("\n[System Baseboard]");

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Manufacturer, Product, Version FROM Win32_BaseBoard");

            foreach (ManagementObject obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                evidence.AppendLine($"  Manufacturer: {obj["Manufacturer"]}");
                evidence.AppendLine($"  Product: {obj["Product"]}");
                evidence.AppendLine($"  Version: {obj["Version"]}");
            }
        }
        catch (ManagementException ex)
        {
            evidence.AppendLine($"  WMI error: {ex.Message}");
        }
    }

    private static void CheckSecureBoot(StringBuilder sb, StringBuilder evidence)
    {
        evidence.AppendLine("\n[Secure Boot]");

        int secureBoot = Services.RegistryHelper.GetValue<int>(
            @"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State",
            "UEFISecureBootEnabled", -1);

        if (secureBoot == 1)
        {
            evidence.AppendLine("  Secure Boot: Enabled");
            sb.AppendLine("Secure Boot: Enabled.");
        }
        else if (secureBoot == 0)
        {
            evidence.AppendLine("  Secure Boot: Disabled");
            sb.AppendLine("WARNING: Secure Boot is disabled. Enable to protect against boot-level firmware attacks.");
        }
        else
        {
            evidence.AppendLine("  Secure Boot: Unknown (registry key not found)");
        }
    }

    private static void GetNetworkAdapterDriverVersions(StringBuilder sb, StringBuilder evidence, CancellationToken ct)
    {
        evidence.AppendLine("\n[Network Adapter Driver Versions]");

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Description, DriverVersion, DriverDate FROM Win32_PnPSignedDriver " +
                "WHERE DeviceClass = 'NET'");

            int count = 0;
            foreach (ManagementObject obj in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                string desc = obj["Description"]?.ToString() ?? "Unknown";
                string driverVer = obj["DriverVersion"]?.ToString() ?? "Unknown";
                string driverDate = obj["DriverDate"]?.ToString() ?? "Unknown";

                if (driverDate.Length >= 8)
                {
                    try { driverDate = $"{driverDate[..4]}-{driverDate[4..6]}-{driverDate[6..8]}"; }
                    catch { /* Use raw */ }
                }

                evidence.AppendLine($"  {desc}: v{driverVer} ({driverDate})");
                count++;
            }

            sb.AppendLine($"Network adapter drivers enumerated: {count} device(s). " +
                "Review driver dates for staleness.");
        }
        catch (ManagementException ex)
        {
            evidence.AppendLine($"  WMI error: {ex.Message}");
        }
    }
}
