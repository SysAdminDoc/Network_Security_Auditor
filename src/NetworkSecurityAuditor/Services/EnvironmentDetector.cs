namespace NetworkSecurityAuditor.Services;

using System.Diagnostics;
using System.IO;
using System.Management;
using System.Security.Principal;
using Microsoft.Win32;
using NetworkSecurityAuditor.Models;

public static class EnvironmentDetector
{
    public static EnvironmentInfo Detect()
    {
        var env = new EnvironmentInfo
        {
            ComputerName = Environment.MachineName,
            IsAdmin = IsRunningAsAdmin()
        };

        DetectOS(env);
        DetectDomain(env);
        DetectModules(env);
        DetectAzureAD(env);
        DetectOSBuild(env);
        DetectLAPS(env);

        // Server 2025 = build 26100+; also covers Win11 24H2+ (26100+)
        env.IsServer2025OrLater = env.IsServer && env.OSBuild >= 26100;

        return env;
    }

    private static bool IsRunningAsAdmin()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static void DetectOS(EnvironmentInfo env)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT Caption, Version, BuildNumber, ProductType FROM Win32_OperatingSystem");
            foreach (ManagementObject obj in searcher.Get())
            {
                env.OSCaption = obj["Caption"]?.ToString() ?? "";
                env.OSVersion = obj["Version"]?.ToString() ?? "";

                if (int.TryParse(obj["BuildNumber"]?.ToString(), out int build))
                    env.OSBuild = build;

                // ProductType: 1=Workstation, 2=DomainController, 3=Server
                if (int.TryParse(obj["ProductType"]?.ToString(), out int pt))
                    env.IsServer = pt >= 2;
            }
        }
        catch
        {
            // Fallback to Environment
            env.OSVersion = Environment.OSVersion.VersionString;
        }
    }

    private static void DetectDomain(EnvironmentInfo env)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT Domain, PartOfDomain FROM Win32_ComputerSystem");
            foreach (ManagementObject obj in searcher.Get())
            {
                env.IsDomainJoined = obj["PartOfDomain"] is true;
                env.DomainName = obj["Domain"]?.ToString() ?? "";
                env.JoinType = env.IsDomainJoined ? "Domain" : "Workgroup";
            }
        }
        catch
        {
            // Leave defaults
        }
    }

    private static void DetectModules(EnvironmentInfo env)
    {
        var moduleRoot = Path.Combine(GetWindowsDirectory(), "System32", "WindowsPowerShell", "v1.0", "Modules");

        // Active Directory PowerShell module (RSAT)
        env.HasAD = File.Exists(Path.Combine(moduleRoot, "ActiveDirectory", "ActiveDirectory.psd1"))
                  || File.Exists(Path.Combine(moduleRoot, "ActiveDirectory", "Microsoft.ActiveDirectory.Management.dll"));

        // DNS Server module
        env.HasDNS = File.Exists(Path.Combine(moduleRoot, "DnsServer", "DnsServer.psd1"));

        // Group Policy module
        env.HasGPO = File.Exists(Path.Combine(moduleRoot, "GroupPolicy", "GroupPolicy.psd1"));

        // Windows Defender (check WMI availability)
        env.HasDefender = CheckDefenderAvailable();

        // SMB module
        env.HasSMB = File.Exists(Path.Combine(moduleRoot, "SmbShare", "SmbShare.psd1"));

        // BitLocker module
        env.HasBitLocker = File.Exists(Path.Combine(moduleRoot, "BitLocker", "BitLocker.psd1"))
                         || RegistryHelper.KeyExists(@"HKLM\SOFTWARE\Microsoft\BitLocker");

        // AppLocker
        env.HasAppLocker = RegistryHelper.KeyExists(@"HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2");

        // WinRM service
        env.WinRMRunning = CheckServiceRunning("WinRM");

        // PowerShell version
        env.PSVersion = DetectPSVersion();
    }

    private static bool CheckDefenderAvailable()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"root\Microsoft\Windows\Defender",
                "SELECT AMServiceEnabled FROM MSFT_MpComputerStatus");
            var results = searcher.Get();
            return results.Count > 0;
        }
        catch
        {
            return false;
        }
    }

    private static bool CheckServiceRunning(string serviceName)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT State FROM Win32_Service WHERE Name = '{serviceName}'");
            foreach (ManagementObject obj in searcher.Get())
            {
                return string.Equals(obj["State"]?.ToString(), "Running", StringComparison.OrdinalIgnoreCase);
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    private static void DetectAzureAD(EnvironmentInfo env)
    {
        try
        {
            var psi = new ProcessStartInfo("dsregcmd", "/status")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc is null) return;

            var outputTask = proc.StandardOutput.ReadToEndAsync();
            if (!proc.WaitForExit(5000))
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                return;
            }

            string output = outputTask.GetAwaiter().GetResult();

            env.AzureADJoined = output.Contains("AzureAdJoined : YES", StringComparison.OrdinalIgnoreCase);
            env.IntuneManaged = IsIntuneManagedFromDsregOutput(output);

            // Extract tenant name
            foreach (var line in output.Split('\n'))
            {
                if (line.Contains("TenantName", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = line.Split(':');
                    if (parts.Length >= 2)
                    {
                        env.TenantName = parts[1].Trim();
                        break;
                    }
                }
            }

            if (env.AzureADJoined && env.IsDomainJoined)
                env.JoinType = "Hybrid";
            else if (env.AzureADJoined)
                env.JoinType = "AzureAD";
        }
        catch
        {
            // dsregcmd not available
        }
    }

    private static void DetectOSBuild(EnvironmentInfo env)
    {
        // More precise build from registry (includes UBR)
        int ubr = RegistryHelper.GetValue<int>(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR", 0);
        if (ubr > 0 && env.OSBuild > 0)
        {
            env.OSVersion = $"{env.OSBuild}.{ubr}";
        }

        string? displayVersion = RegistryHelper.GetValue<string>(
            @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion");
        if (!string.IsNullOrEmpty(displayVersion))
        {
            env.OSCaption += $" ({displayVersion})";
        }
    }

    private static void DetectLAPS(EnvironmentInfo env)
    {
        // Windows LAPS (built-in, Win11 22H2+/Server 2025+)
        env.HasWindowsLAPS = RegistryHelper.KeyExists(@"HKLM\SOFTWARE\Microsoft\Policies\LAPS")
                          || RegistryHelper.KeyExists(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS");

        // Legacy (Microsoft) LAPS CSE
        env.HasLegacyLAPS = RegistryHelper.KeyExists(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{97E2CA7B-B657-4FF7-A6DB-30B73D4A349E}")
                         || File.Exists(Path.Combine(GetProgramFilesDirectory(), "LAPS", "CSE", "AdmPwd.dll"));
    }

    internal static bool IsIntuneManagedFromDsregOutput(string output)
    {
        foreach (var rawLine in output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = rawLine.Split(':', 2);
            if (parts.Length != 2)
                continue;

            var key = parts[0].Trim();
            var value = parts[1].Trim();
            if (key.Equals("IsDeviceManaged", StringComparison.OrdinalIgnoreCase) &&
                value.Equals("YES", StringComparison.OrdinalIgnoreCase))
                return true;

            if (key.Equals("EnrollmentType", StringComparison.OrdinalIgnoreCase) &&
                value.Length > 0 &&
                !value.Equals("none", StringComparison.OrdinalIgnoreCase) &&
                !value.Equals("unknown", StringComparison.OrdinalIgnoreCase) &&
                !value.Equals("0", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static string GetWindowsDirectory()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrWhiteSpace(windows)) return windows;
        return Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
    }

    private static string GetProgramFilesDirectory()
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (!string.IsNullOrWhiteSpace(programFiles)) return programFiles;
        return Environment.GetEnvironmentVariable("ProgramFiles") ?? @"C:\Program Files";
    }

    private static string DetectPSVersion()
    {
        try
        {
            // Check for PowerShell 7+ first
            string? ps7 = RegistryHelper.GetValue<string>(
                @"HKLM\SOFTWARE\Microsoft\PowerShellCore\InstalledVersions",
                "SemanticVersion");
            if (!string.IsNullOrEmpty(ps7)) return ps7;

            // Fall back to Windows PowerShell
            string? psVersion = RegistryHelper.GetValue<string>(
                @"HKLM\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine",
                "PowerShellVersion");
            return psVersion ?? "Unknown";
        }
        catch
        {
            return "Unknown";
        }
    }
}
