#Requires -Version 5.1
<#
.SYNOPSIS
    Network Security Audit Checklist v4.0 - Professional GUI Tool
.DESCRIPTION
    Comprehensive WPF-based security audit checklist for SMB environments.
    Features: auto system theme detection, 8 themes, categorized checks,
    context hints for junior auditors, compliance mapping (NIST/CIS/HIPAA),
    per-item findings/notes/evidence/remediation tracking, severity ratings,
    weighted risk scoring, auto-discovery scripts, executive summary,
    HTML/PDF export, save/load, audit diff comparison, scan profiles,
    headless/silent mode for RMM deployment, three-tier reporting,
    and risk-tier safety classification.
.PARAMETER Silent
    Run in headless mode (no GUI). Auto-scans, exports, and exits.
    Designed for RMM deployment via ConnectWise, Datto, NinjaRMM, etc.
.PARAMETER ScanProfile
    Scan profile to use: Quick, Standard, Full, ADOnly, LocalOnly,
    HIPAA, PCI, CMMC, SOC2, ISO27001.
    Default: Full (all 67 checks). Quick runs ~20 critical checks.
    Framework profiles run checks mapped to that compliance framework.
.PARAMETER OutputPath
    Path for report output. Default: Desktop\SecurityAudit_<client>_<date>.html
.PARAMETER ReportTier
    Report detail level: Executive, Management, Technical, All.
    Default: All (generates all three tiers in one report).
.PARAMETER ReadOnly
    Safety mode: skip any checks that could modify system state.
    Default: $true. Set -ReadOnly:$false to allow WinRM/audit policy setup.
.PARAMETER Client
    Client name for the report header. Default: domain or computer name.
.PARAMETER Auditor
    Auditor name for the report header. Default: current username.
.EXAMPLE
    .\NetworkSecurityAudit_v3.ps1
    # Normal GUI mode
.EXAMPLE
    .\NetworkSecurityAudit_v3.ps1 -Silent -ScanProfile Standard -OutputPath "C:\Reports\audit.html"
    # Headless mode for RMM: scan, export, exit
.EXAMPLE
    .\NetworkSecurityAudit_v3.ps1 -Silent -ScanProfile Quick -ReportTier Executive
    # Quick assessment with executive summary only
.AUTHOR
    SysAdminDoc
.VERSION
    4.0.0
#>
param(
    [switch]$Silent,
    [ValidateSet('Quick','Standard','Full','ADOnly','LocalOnly','HIPAA','PCI','CMMC','SOC2','ISO27001')]
    [string]$ScanProfile = 'Full',
    [string]$OutputPath = '',
    [ValidateSet('Executive','Management','Technical','All')]
    [string]$ReportTier = 'All',
    [bool]$ReadOnly = $true,
    [string]$Client = '',
    [string]$Auditor = '',
    [switch]$ExportJSON,
    [switch]$ExportCSV,
    [switch]$ExportJSONL
)

# ── Auto-Elevate to Administrator ────────────────────────────────────────────
$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $script:IsAdmin) {
    try {
        $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
        # Pass through all CLI parameters on re-launch
        if ($Silent)       { $argList += '-Silent' }
        if ($ScanProfile -ne 'Full') { $argList += '-ScanProfile'; $argList += $ScanProfile }
        if ($OutputPath)   { $argList += '-OutputPath'; $argList += "`"$OutputPath`"" }
        if ($ReportTier -ne 'All') { $argList += '-ReportTier'; $argList += $ReportTier }
        if (-not $ReadOnly) { $argList += '-ReadOnly:$false' }
        if ($Client)       { $argList += '-Client'; $argList += "`"$Client`"" }
        if ($Auditor)      { $argList += '-Auditor'; $argList += "`"$Auditor`"" }
        if ($ExportJSON)   { $argList += '-ExportJSON' }
        if ($ExportCSV)    { $argList += '-ExportCSV' }
        if ($ExportJSONL)  { $argList += '-ExportJSONL' }
        Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs -WindowStyle Hidden
        exit
    }
    catch {
        # User declined UAC or elevation failed - continue without admin
    }
}

# ── Store CLI config in script scope ─────────────────────────────────────────
$script:SilentMode  = $Silent.IsPresent
$script:CliProfile  = $ScanProfile
$script:CliOutput   = $OutputPath
$script:CliReport   = $ReportTier
$script:ReadOnlyMode = $ReadOnly
$script:CliClient   = $Client
$script:CliAuditor  = $Auditor
$script:CliExportJSON  = $ExportJSON.IsPresent
$script:CliExportCSV   = $ExportCSV.IsPresent
$script:CliExportJSONL = $ExportJSONL.IsPresent

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

# ── DPI Awareness + Console Hide ─────────────────────────────────────────────
try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class DpiHelper {
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("shcore.dll")] public static extern int SetProcessDpiAwareness(int awareness);
}
public class ConsoleHelper {
    [DllImport("kernel32.dll")] static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    public static void Hide() { IntPtr h = GetConsoleWindow(); if (h != IntPtr.Zero) ShowWindow(h, 0); }
    public static void Show() { IntPtr h = GetConsoleWindow(); if (h != IntPtr.Zero) ShowWindow(h, 5); }
}
'@ -ErrorAction SilentlyContinue
    try { [DpiHelper]::SetProcessDpiAwareness(2) } catch { [DpiHelper]::SetProcessDPIAware() }
    [ConsoleHelper]::Hide()
} catch { }

# ── Environment Detection ────────────────────────────────────────────────────
$script:Env = @{
    ComputerName = $env:COMPUTERNAME
    IsAdmin      = $script:IsAdmin
    PSVersion    = $PSVersionTable.PSVersion.ToString()
    OSCaption    = ''
    IsServer     = $false
    IsDomainJoined = $false
    DomainName   = ''
    HasAD        = $false
    HasDNS       = $false
    HasGPO       = $false
    HasDefender  = $false
    HasSMB       = $false
    HasBitLocker = $false
    HasAppLocker = $false
    WinRMRunning = $false
    MissingModules = [System.Collections.ArrayList]@()
    InstalledModules = [System.Collections.ArrayList]@()
}
try {
    $os = Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue
    if ($os) {
        $script:Env.OSCaption = $os.Caption
        $script:Env.IsServer = $os.Caption -match 'Server'
    }
} catch {}
try {
    $cs = Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue
    if ($cs) {
        $script:Env.IsDomainJoined = $cs.PartOfDomain
        if ($cs.PartOfDomain) { $script:Env.DomainName = $cs.Domain }
    }
} catch {}

# Check available modules and capabilities
$moduleChecks = @(
    @{ Name='ActiveDirectory'; EnvKey='HasAD'; RSATName='Rsat.ActiveDirectory.DS-LDS.Tools'; Feature='RSAT-AD-PowerShell' }
    @{ Name='DnsServer';       EnvKey='HasDNS'; RSATName='Rsat.Dns.Tools'; Feature='RSAT-DNS-Server' }
    @{ Name='GroupPolicy';     EnvKey='HasGPO'; RSATName='Rsat.GroupPolicy.Management.Tools'; Feature='GPMC' }
)
foreach ($mc in $moduleChecks) {
    if (Get-Module $mc.Name -ListAvailable -EA SilentlyContinue) {
        $script:Env[$mc.EnvKey] = $true
        $script:Env.InstalledModules.Add($mc.Name) | Out-Null
    } else {
        $script:Env.MissingModules.Add($mc) | Out-Null
    }
}

# Check features/services
try { if (Get-Command Get-MpComputerStatus -EA SilentlyContinue) { $script:Env.HasDefender = $true } } catch {}
try { if (Get-Command Get-SmbServerConfiguration -EA SilentlyContinue) { $script:Env.HasSMB = $true } } catch {}
try { if (Get-Command Get-BitLockerVolume -EA SilentlyContinue) { $script:Env.HasBitLocker = $true } } catch {}
try { if (Get-Command Get-AppLockerPolicy -EA SilentlyContinue) { $script:Env.HasAppLocker = $true } } catch {}

# WinRM service status
try {
    $winrm = Get-Service WinRM -EA SilentlyContinue
    $script:Env.WinRMRunning = ($winrm -and $winrm.Status -eq 'Running')
} catch {}

# Additional capabilities for turnkey auto-checks
try { if (Get-Command Get-Tpm -EA SilentlyContinue) { $script:Env['HasTPM'] = $true } } catch {}
try { if (Get-Command Get-VpnConnection -EA SilentlyContinue) { $script:Env['HasVPN'] = $true } } catch {}
try { if (Get-Command Get-NetFirewallProfile -EA SilentlyContinue) { $script:Env['HasFW'] = $true } } catch {}
try { if (Get-Command Get-LocalGroupMember -EA SilentlyContinue) { $script:Env['HasLocalUser'] = $true } } catch {}
try { if (Get-Command Get-DnsServerDiagnostics -EA SilentlyContinue) { $script:Env['HasDNSServer'] = $true } } catch {}
try { if (Get-Command Confirm-SecureBootUEFI -EA SilentlyContinue) { $script:Env['HasSecureBoot'] = $true } } catch {}

# ── Azure AD / Entra / Hybrid Join Detection ─────────────────────────────────
$script:Env['JoinType'] = 'Workgroup'
$script:Env['AzureADJoined'] = $false
$script:Env['IntuneManaged'] = $false
$script:Env['TenantName'] = ''
try {
    $dsreg = dsregcmd /status 2>&1 | Out-String
    $azJoined = $dsreg -match 'AzureAdJoined\s*:\s*YES'
    $domJoined = $dsreg -match 'DomainJoined\s*:\s*YES'
    $wpJoined = $dsreg -match 'WorkplaceJoined\s*:\s*YES'
    if ($azJoined -and $domJoined) { $script:Env['JoinType'] = 'Hybrid Azure AD' }
    elseif ($azJoined) { $script:Env['JoinType'] = 'Azure AD Joined' }
    elseif ($domJoined) { $script:Env['JoinType'] = 'Domain Joined' }
    elseif ($wpJoined) { $script:Env['JoinType'] = 'Workplace Joined' }
    $script:Env['AzureADJoined'] = $azJoined
    if ($dsreg -match 'TenantName\s*:\s*(.+)') { $script:Env['TenantName'] = $Matches[1].Trim() }
} catch {}
# Intune / MDM enrollment detection
try {
    $enrollKeys = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -EA SilentlyContinue
    foreach ($ek in $enrollKeys) {
        $prov = (Get-ItemProperty $ek.PSPath -EA SilentlyContinue).ProviderID
        if ($prov -eq 'MS DM Server') { $script:Env['IntuneManaged'] = $true; break }
    }
} catch {}

# ── OS Build / Version for Feature Gating ─────────────────────────────────────
try {
    $ntCur = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -EA SilentlyContinue
    $script:Env['OSBuild'] = [int]($ntCur.CurrentBuildNumber)
    $script:Env['OSVersion'] = $ntCur.DisplayVersion  # e.g. 22H2, 23H2, 24H2
} catch { $script:Env['OSBuild'] = 0; $script:Env['OSVersion'] = '' }

# ── LAPS Module Detection ─────────────────────────────────────────────────────
$script:Env['HasWindowsLAPS'] = $false
$script:Env['HasLegacyLAPS'] = $false
try { if (Get-Command Get-LapsADPassword -EA SilentlyContinue) { $script:Env['HasWindowsLAPS'] = $true } } catch {}
try {
    $lapsGPO = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' -EA SilentlyContinue
    $lapsCSE = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}' -EA SilentlyContinue
    if ($lapsGPO -or $lapsCSE) { $script:Env['HasLegacyLAPS'] = $true }
} catch {}

# ── Module Installer Functions ───────────────────────────────────────────────
function Install-AuditPrereqs {
    [CmdletBinding()]param()
    $results = [System.Collections.ArrayList]@()

    foreach ($mod in $script:Env.MissingModules) {
        $installed = $false
        $msg = ''

        if ($script:Env.IsServer) {
            # Server: Use Install-WindowsFeature
            try {
                $feat = Install-WindowsFeature -Name $mod.Feature -EA Stop
                if ($feat.Success) {
                    $installed = $true; $msg = "Installed server feature: $($mod.Feature)"
                } else { $msg = "Failed to install $($mod.Feature): Feature install returned failure" }
            }
            catch { $msg = "Failed to install $($mod.Feature): $($_.Exception.Message)" }
        }
        else {
            # Workstation: Use Add-WindowsCapability (Win10/11)
            try {
                $cap = Get-WindowsCapability -Online -Name "$($mod.RSATName)~~~~*" -EA Stop | Where-Object { $_.State -ne 'Installed' }
                if ($cap) {
                    foreach ($c in $cap) {
                        Add-WindowsCapability -Online -Name $c.Name -EA Stop | Out-Null
                    }
                    $installed = $true; $msg = "Installed RSAT capability: $($mod.RSATName)"
                } else {
                    $installed = $true; $msg = "Already installed: $($mod.RSATName)"
                }
            }
            catch { $msg = "Failed to install $($mod.RSATName): $($_.Exception.Message)" }
        }

        $results.Add(@{ Module=$mod.Name; Installed=$installed; Message=$msg }) | Out-Null
    }

    # Ensure NuGet provider
    try {
        $nuget = Get-PackageProvider -Name NuGet -ListAvailable -EA SilentlyContinue
        if (-not $nuget -or $nuget.Version -lt [Version]'2.8.5.201') {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -EA Stop | Out-Null
            $results.Add(@{ Module='NuGet'; Installed=$true; Message='NuGet provider installed' }) | Out-Null
        }
    } catch {
        $results.Add(@{ Module='NuGet'; Installed=$false; Message="NuGet: $($_.Exception.Message)" }) | Out-Null
    }

    return $results
}

function Enable-AuditWinRM {
    [CmdletBinding()]param([string]$Target, [PSCredential]$Credential)
    $isLocal = ($Target -eq 'localhost' -or $Target -eq '127.0.0.1' -or $Target -eq $env:COMPUTERNAME)

    if ($isLocal) {
        try {
            if (-not $script:Env.WinRMRunning) {
                Enable-PSRemoting -Force -SkipNetworkProfileCheck -EA Stop | Out-Null
                Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force -EA SilentlyContinue
                $script:Env.WinRMRunning = $true
                return @{ Success=$true; Message='WinRM enabled on local machine' }
            }
            return @{ Success=$true; Message='WinRM already running locally' }
        }
        catch { return @{ Success=$false; Message="WinRM local config failed: $($_.Exception.Message)" } }
    }
    else {
        # Remote WinRM setup - attempt via PsExec-style or WMI
        try {
            $params = @{ ComputerName=$Target; ErrorAction='Stop' }
            if ($Credential) { $params.Credential = $Credential }

            # First check if already reachable
            $test = Test-WSMan @params -EA SilentlyContinue
            if ($test) { return @{ Success=$true; Message="WinRM already configured on $Target" } }

            # Try enabling via WMI (works if WMI is accessible)
            $wmiParams = @{ ComputerName=$Target; Class='Win32_Process'; Name='Create'; ErrorAction='Stop' }
            if ($Credential) { $wmiParams.Credential = $Credential }
            $wmiParams.ArgumentList = @('powershell.exe -Command "Enable-PSRemoting -Force -SkipNetworkProfileCheck"')
            Invoke-WmiMethod @wmiParams | Out-Null

            # Wait and verify
            Start-Sleep -Seconds 5
            $verify = Test-WSMan @params -EA SilentlyContinue
            if ($verify) { return @{ Success=$true; Message="WinRM enabled on $Target via WMI" } }
            else { return @{ Success=$false; Message="WinRM command sent to $Target but verification failed - may need reboot" } }
        }
        catch { return @{ Success=$false; Message="Remote WinRM setup failed on $Target`: $($_.Exception.Message)" } }
    }
}

# ── Additional Turnkey Functions ─────────────────────────────────────────────
function Find-DomainControllers {
    [CmdletBinding()]param()
    $dcs = [System.Collections.ArrayList]@()
    $primary = $null

    # Method 1: DNS SRV records (fastest, works without AD module)
    try {
        $domain = if ($script:Env.IsDomainJoined) { $script:Env.DomainName } else { $null }
        if ($domain) {
            $srv = Resolve-DnsName "_ldap._tcp.dc._msdcs.$domain" -Type SRV -EA Stop
            foreach ($r in ($srv | Where-Object { $_.Type -eq 'SRV' } | Sort-Object Priority, Weight)) {
                $name = $r.NameTarget -replace '\.$',''
                if ($name -and $dcs -notcontains $name) { $dcs.Add($name) | Out-Null }
            }
        }
    } catch { }

    # Method 2: nltest (works without AD module, uses cached info)
    if ($dcs.Count -eq 0 -and $script:Env.IsDomainJoined) {
        try {
            $nl = nltest /dsgetdc:$($script:Env.DomainName) 2>&1
            $dcLine = ($nl | Select-String 'DC: \\\\(.+)' | Select-Object -First 1)
            if ($dcLine -and $dcLine.Matches) {
                $name = $dcLine.Matches[0].Groups[1].Value.Trim()
                if ($name -and $dcs -notcontains $name) { $dcs.Add($name) | Out-Null }
            }
        } catch { }
    }

    # Method 3: [System.DirectoryServices] (backup)
    if ($dcs.Count -eq 0 -and $script:Env.IsDomainJoined) {
        try {
            $ctx = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new('Domain', $script:Env.DomainName)
            $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)
            foreach ($dc in $dom.DomainControllers) {
                $name = $dc.Name
                if ($name -and $dcs -notcontains $name) { $dcs.Add($name) | Out-Null }
            }
        } catch { }
    }

    # Determine primary DC (PDC emulator if possible)
    if ($dcs.Count -gt 0) {
        try {
            $nl2 = nltest /dsgetdc:$($script:Env.DomainName) /pdc 2>&1
            $pdcLine = ($nl2 | Select-String 'DC: \\\\(.+)' | Select-Object -First 1)
            if ($pdcLine -and $pdcLine.Matches) { $primary = $pdcLine.Matches[0].Groups[1].Value.Trim() }
        } catch { }
        if (-not $primary) { $primary = $dcs[0] }
    }

    return @{ DCs=$dcs; Primary=$primary; Count=$dcs.Count }
}

function Enable-RemoteRegistry {
    [CmdletBinding()]param([string]$Target, [PSCredential]$Credential)
    $isLocal = ($Target -eq 'localhost' -or $Target -eq '127.0.0.1' -or $Target -eq $env:COMPUTERNAME)
    try {
        if ($isLocal) {
            $svc = Get-Service RemoteRegistry -EA Stop
            if ($svc.Status -ne 'Running') {
                Set-Service RemoteRegistry -StartupType Manual -EA Stop
                Start-Service RemoteRegistry -EA Stop
                return @{ Success=$true; Message='Remote Registry started locally' }
            }
            return @{ Success=$true; Message='Remote Registry already running' }
        }
        else {
            $params = @{ ComputerName=$Target; ErrorAction='Stop' }
            if ($Credential) { $params.Credential = $Credential }
            Invoke-Command @params -ScriptBlock {
                Set-Service RemoteRegistry -StartupType Manual -EA Stop
                Start-Service RemoteRegistry -EA Stop
            }
            return @{ Success=$true; Message="Remote Registry started on $Target" }
        }
    }
    catch { return @{ Success=$false; Message="Remote Registry: $($_.Exception.Message)" } }
}

function Open-WinRMFirewallRules {
    [CmdletBinding()]param()
    try {
        $rules = Get-NetFirewallRule -DisplayGroup 'Windows Remote Management' -EA SilentlyContinue
        $disabled = $rules | Where-Object { $_.Enabled -ne 'True' }
        if ($disabled) {
            Enable-NetFirewallRule -DisplayGroup 'Windows Remote Management' -EA Stop
            return @{ Success=$true; Message="Enabled $($disabled.Count) WinRM firewall rules" }
        }
        return @{ Success=$true; Message='WinRM firewall rules already enabled' }
    }
    catch { return @{ Success=$false; Message="Firewall: $($_.Exception.Message)" } }
}

function Set-PSGalleryTrust {
    [CmdletBinding()]param()
    try {
        $repo = Get-PSRepository -Name PSGallery -EA SilentlyContinue
        if ($repo -and $repo.InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -EA Stop
            return @{ Success=$true; Message='PSGallery set to Trusted' }
        }
        return @{ Success=$true; Message='PSGallery already trusted' }
    }
    catch { return @{ Success=$false; Message="PSGallery: $($_.Exception.Message)" } }
}

function Enable-RemoteWMI {
    [CmdletBinding()]param()
    try {
        $rules = Get-NetFirewallRule -DisplayGroup 'Windows Management Instrumentation (WMI)' -EA SilentlyContinue
        $disabled = $rules | Where-Object { $_.Enabled -ne 'True' }
        if ($disabled) {
            Enable-NetFirewallRule -DisplayGroup 'Windows Management Instrumentation (WMI)' -EA Stop
            return @{ Success=$true; Message="Enabled $($disabled.Count) WMI firewall rules" }
        }
        return @{ Success=$true; Message='WMI firewall rules already enabled' }
    }
    catch { return @{ Success=$false; Message="WMI Firewall: $($_.Exception.Message)" } }
}

function Enable-EventLogRemote {
    [CmdletBinding()]param()
    try {
        $rules = Get-NetFirewallRule -DisplayGroup 'Remote Event Log Management' -EA SilentlyContinue
        $disabled = $rules | Where-Object { $_.Enabled -ne 'True' }
        if ($disabled) {
            Enable-NetFirewallRule -DisplayGroup 'Remote Event Log Management' -EA Stop
            return @{ Success=$true; Message="Enabled $($disabled.Count) Event Log firewall rules" }
        }
        return @{ Success=$true; Message='Event Log firewall rules already enabled' }
    }
    catch { return @{ Success=$false; Message="Event Log Firewall: $($_.Exception.Message)" } }
}

# ── Turnkey Configuration State ──────────────────────────────────────────────
$script:TurnkeyAutoExport = $true
$script:TurnkeyAutoScan   = $false   # set to $true after user confirms
$script:TurnkeyLaunched   = $false
$script:FullAuditMode     = $false   # one-click: preflight + scan + export (no prompts)
$script:TurnkeyPS         = $null
$script:TurnkeyAsync      = $null
$script:TurnkeyStatus     = [hashtable]::Synchronized(@{
    Status = ''
    Phase  = ''
    Log    = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())
    Done   = $false
})
$script:DiscoveredDCs      = @()

# ── Theme Definitions ────────────────────────────────────────────────────────
$script:Themes = @{
    'Midnight' = @{
        WindowBg='#1a1a2e';PanelBg='#16213e';CardBg='#16213e';SurfaceBg='#0f3460'
        InputBg='#1e293b';BorderDim='#334155';TextPrimary='#e2e8f0';TextSecondary='#94a3b8'
        Accent='#0ea5e9';AccentHover='#38bdf8';AccentPress='#0284c7';BarBg='#1e293b'
        ProgressGood='#22c55e';ProgressMid='#eab308';ThumbBg='#475569'
        HoverBg='#0f3460';SelectedBg='#0ea5e9';CheckedBorder='#22c55e';CheckedBg='#1a2e1a'
        HeaderGrad1='#0f3460';HeaderGrad2='#16213e';HintBg='#0c2d4a';HintBorder='#1e4976'
    }
    'Slate' = @{
        WindowBg='#0f172a';PanelBg='#1e293b';CardBg='#1e293b';SurfaceBg='#334155'
        InputBg='#0f172a';BorderDim='#475569';TextPrimary='#f1f5f9';TextSecondary='#94a3b8'
        Accent='#6366f1';AccentHover='#818cf8';AccentPress='#4f46e5';BarBg='#0f172a'
        ProgressGood='#22c55e';ProgressMid='#eab308';ThumbBg='#64748b'
        HoverBg='#334155';SelectedBg='#6366f1';CheckedBorder='#22c55e';CheckedBg='#1a2e1a'
        HeaderGrad1='#1e293b';HeaderGrad2='#0f172a';HintBg='#1e1b4b';HintBorder='#3730a3'
    }
    'Nord' = @{
        WindowBg='#2e3440';PanelBg='#3b4252';CardBg='#3b4252';SurfaceBg='#434c5e'
        InputBg='#2e3440';BorderDim='#4c566a';TextPrimary='#eceff4';TextSecondary='#d8dee9'
        Accent='#88c0d0';AccentHover='#8fbcbb';AccentPress='#5e81ac';BarBg='#2e3440'
        ProgressGood='#a3be8c';ProgressMid='#ebcb8b';ThumbBg='#4c566a'
        HoverBg='#434c5e';SelectedBg='#5e81ac';CheckedBorder='#a3be8c';CheckedBg='#2e3b2e'
        HeaderGrad1='#434c5e';HeaderGrad2='#3b4252';HintBg='#2e3440';HintBorder='#4c566a'
    }
    'Dracula' = @{
        WindowBg='#282a36';PanelBg='#44475a';CardBg='#44475a';SurfaceBg='#6272a4'
        InputBg='#282a36';BorderDim='#6272a4';TextPrimary='#f8f8f2';TextSecondary='#bd93f9'
        Accent='#ff79c6';AccentHover='#ff92d0';AccentPress='#ff55b8';BarBg='#282a36'
        ProgressGood='#50fa7b';ProgressMid='#f1fa8c';ThumbBg='#6272a4'
        HoverBg='#6272a4';SelectedBg='#ff79c6';CheckedBorder='#50fa7b';CheckedBg='#2a3a2a'
        HeaderGrad1='#44475a';HeaderGrad2='#282a36';HintBg='#1e1f29';HintBorder='#44475a'
    }
    'Monokai' = @{
        WindowBg='#272822';PanelBg='#3e3d32';CardBg='#3e3d32';SurfaceBg='#49483e'
        InputBg='#272822';BorderDim='#75715e';TextPrimary='#f8f8f2';TextSecondary='#a6a68a'
        Accent='#a6e22e';AccentHover='#b8f340';AccentPress='#8cc41a';BarBg='#272822'
        ProgressGood='#a6e22e';ProgressMid='#e6db74';ThumbBg='#75715e'
        HoverBg='#49483e';SelectedBg='#a6e22e';CheckedBorder='#a6e22e';CheckedBg='#2e3a22'
        HeaderGrad1='#3e3d32';HeaderGrad2='#272822';HintBg='#272822';HintBorder='#49483e'
    }
    'Light' = @{
        WindowBg='#f8fafc';PanelBg='#ffffff';CardBg='#ffffff';SurfaceBg='#e2e8f0'
        InputBg='#f1f5f9';BorderDim='#cbd5e1';TextPrimary='#1e293b';TextSecondary='#64748b'
        Accent='#2563eb';AccentHover='#3b82f6';AccentPress='#1d4ed8';BarBg='#e2e8f0'
        ProgressGood='#16a34a';ProgressMid='#ca8a04';ThumbBg='#94a3b8'
        HoverBg='#e2e8f0';SelectedBg='#2563eb';CheckedBorder='#16a34a';CheckedBg='#dcfce7'
        HeaderGrad1='#e2e8f0';HeaderGrad2='#f1f5f9';HintBg='#eff6ff';HintBorder='#bfdbfe'
    }
    'Solarized Dark' = @{
        WindowBg='#002b36';PanelBg='#073642';CardBg='#073642';SurfaceBg='#586e75'
        InputBg='#002b36';BorderDim='#586e75';TextPrimary='#fdf6e3';TextSecondary='#93a1a1'
        Accent='#268bd2';AccentHover='#2aa0f0';AccentPress='#1a6fb5';BarBg='#002b36'
        ProgressGood='#859900';ProgressMid='#b58900';ThumbBg='#586e75'
        HoverBg='#586e75';SelectedBg='#268bd2';CheckedBorder='#859900';CheckedBg='#0a3a1a'
        HeaderGrad1='#073642';HeaderGrad2='#002b36';HintBg='#002b36';HintBorder='#586e75'
    }
    'Catppuccin Mocha' = @{
        WindowBg='#1e1e2e';PanelBg='#313244';CardBg='#313244';SurfaceBg='#45475a'
        InputBg='#1e1e2e';BorderDim='#585b70';TextPrimary='#cdd6f4';TextSecondary='#a6adc8'
        Accent='#cba6f7';AccentHover='#d4b8fa';AccentPress='#b48bf0';BarBg='#1e1e2e'
        ProgressGood='#a6e3a1';ProgressMid='#f9e2af';ThumbBg='#585b70'
        HoverBg='#45475a';SelectedBg='#cba6f7';CheckedBorder='#a6e3a1';CheckedBg='#2a3a2e'
        HeaderGrad1='#313244';HeaderGrad2='#1e1e2e';HintBg='#1e1e2e';HintBorder='#45475a'
    }
}

# ── System Theme Detection ───────────────────────────────────────────────────
function Get-SystemTheme {
    try {
        $v = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'AppsUseLightTheme' -EA Stop).AppsUseLightTheme
        if ($v -eq 0) { 'Dark' } else { 'Light' }
    } catch { 'Dark' }
}

$script:CurrentThemeName = if ((Get-SystemTheme) -eq 'Light') { 'Light' } else { 'Midnight' }
function Get-T { $script:Themes[$script:CurrentThemeName] }
function New-Brush([string]$hex) { New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString($hex)) }

# ── Severity Colors ──────────────────────────────────────────────────────────
$script:SeverityColors = @{ Critical='#ef4444'; High='#f97316'; Medium='#eab308'; Low='#22c55e' }
$script:CategoryAccents = @{
    'Network Perimeter'='#0ea5e9'; 'Identity & Access'='#a855f7'; 'Endpoint Security'='#22c55e'
    'Backup & Recovery'='#eab308'; 'Logging & Monitoring'='#f97316'; 'Network Architecture'='#06b6d4'
    'Physical Security'='#ec4899'; 'Common Findings'='#ef4444'
}

# ── Audit Data with Hints + Compliance Mapping ───────────────────────────────
$script:AuditCategories = [ordered]@{

    'Network Perimeter' = @{
        Desc = 'Where most breaches start - external attack surface assessment'
        Items = @(
            @{
                ID='NP01'; Severity='Critical'; Weight=10
                Text='Firewall rules review - check for any/any rules, unused rules, rules older than 2 years'
                Hint='Log into the firewall admin console (pfSense: Firewall > Rules, FortiGate: Policy & Objects > Firewall Policy, SonicWall: Policies > Rules and Policies). Export the full rule list. Search for rules where Source=Any AND Destination=Any AND Service=Any - these are effectively open doors. Flag any rule with no hit count in 90+ days and any rule with a creation date older than 2 years. Document the rule ID, description, creator if available, and last hit date. Ask the client: "Who requested this rule and is it still needed?"'
                Compliance='NIST CSF PR.AC-5, PR.PT-4 | CIS Control 4.4, 4.5, 9.2 | HIPAA 164.312(e)(1)'
            }
            @{
                ID='NP02'; Severity='Critical'; Weight=10
                Text='Open ports audit - every open port must have documented business justification'
                Hint='Run an external port scan using nmap from OUTSIDE the network: "nmap -sS -sV -p- <public_IP>" or use an online scanner like Shodan, Censys, or SecurityTrails. Compare results against a documented port justification list. Common dangerous findings: RDP (3389), SMB (445), Telnet (23), FTP (21), or database ports (1433, 3306, 5432) open to the internet. Every open port needs an owner and business reason documented. If they cannot justify it, it gets closed.'
                Compliance='NIST CSF PR.AC-5, DE.CM-7 | CIS Control 4.1, 4.4, 9.2 | HIPAA 164.312(e)(1)'
            }
            @{
                ID='NP03'; Severity='High'; Weight=7
                Text='VPN configuration - verify split tunneling policy and MFA requirement'
                Hint='Check the VPN concentrator/server config. For split tunneling: look at the client routing table when connected - if only specific subnets route through VPN, split tunneling is ON. This means internet traffic bypasses corporate security controls. Ask if this is intentional and documented. For MFA: verify the VPN authenticates against RADIUS/LDAP with a second factor (Duo, Azure MFA, etc.), not just username/password. Test by attempting a VPN login - you should be prompted for MFA. Check: FortiGate VPN settings, GlobalProtect portal config, or OpenVPN server.conf.'
                Compliance='NIST CSF PR.AC-3, PR.AC-7 | CIS Control 6.3, 6.4 | HIPAA 164.312(d), 164.312(e)(1)'
            }
            @{
                ID='NP04'; Severity='High'; Weight=7
                Text='DNS filtering enabled and configured (e.g., Umbrella, NextDNS, pfBlockerNG)'
                Hint='Check what DNS servers the DHCP scope hands out to clients. Run "nslookup" from a workstation and note the DNS server. If it is the ISP default (like 8.8.8.8 with no filtering layer), there is no DNS filtering. Solutions to look for: Cisco Umbrella, Cloudflare Gateway, NextDNS, pfBlockerNG (on pfSense), Pi-hole, or firewall-based DNS filtering. Verify that the filter blocks malware, phishing, and C2 domains at minimum. Test by visiting a known test block page (e.g., examplemalwaredomain.com from Umbrella). Also verify DNS cannot be bypassed - check if outbound port 53 is forced through the filter.'
                Compliance='NIST CSF PR.DS-5, DE.CM-1 | CIS Control 9.2, 9.3 | HIPAA 164.312(e)(1)'
            }
            @{
                ID='NP05'; Severity='High'; Weight=8
                Text='Egress filtering configured - not just ingress rules'
                Hint='This is the #1 thing people miss. Most firewalls only filter INBOUND traffic and allow ALL outbound. Log into the firewall and look at outbound/egress rules. If you see a default "Allow All" outbound rule with no restrictions, flag it. Proper egress filtering blocks: unusual outbound ports, direct IP connections (bypassing DNS), known bad destinations, and limits which internal hosts can reach the internet. At minimum, outbound should restrict ports to 80, 443, and business-required services. Check for outbound rules on: pfSense (LAN rules), FortiGate (outbound policies), SonicWall (LAN to WAN rules).'
                Compliance='NIST CSF PR.AC-5, PR.DS-5, DE.CM-1 | CIS Control 4.4, 4.5, 9.3 | HIPAA 164.312(e)(1)'
            }
            @{
                ID='NP06'; Severity='Medium'; Weight=5
                Text='Temporary firewall rules audit - identify and remove stale rules'
                Hint='Search the firewall rule list for anything with "temp", "test", "old", or a person name in the description. Also look at rule comments and creation dates. Temporary rules created for vendor access, troubleshooting, or one-time projects are the #1 source of forgotten attack surface. Ask: "Was there a specific ticket or change request for this rule? Does it have an expiration date?" Common finding: a rule from 3-5 years ago created to let a vendor in "just for today" that is still active. Document rule name, date created, last hit count, and whether anyone can justify it.'
                Compliance='NIST CSF PR.AC-5 | CIS Control 4.5 | HIPAA 164.312(e)(1)'
            }
            @{
                ID='NP07'; Severity='Medium'; Weight=5
                Text='IDS/IPS signatures are current and actively monitored'
                Hint='If the firewall has IDS/IPS (Snort, Suricata, FortiGate IPS, SonicWall GAV/IPS), check: 1) Is it actually ENABLED (not just licensed)? 2) When were signatures last updated? (should be daily or at least weekly) 3) Is it in DETECT mode or PREVENT/BLOCK mode? Detect-only means it logs but does not stop attacks. 4) Who reviews the alerts? If nobody looks at the logs, IDS/IPS is useless. Check the IPS dashboard for last update timestamp and top triggered rules. On pfSense: Services > Snort/Suricata. On FortiGate: Security Profiles > Intrusion Prevention.'
                Compliance='NIST CSF DE.CM-1, DE.DP-2 | CIS Control 13.3, 13.6 | HIPAA 164.312(e)(1)'
            }
            @{
                ID='NP08'; Severity='Low'; Weight=3
                Text='SSL/TLS inspection for outbound traffic'
                Hint='SSL/TLS inspection (also called HTTPS inspection, SSL decryption, or deep packet inspection) lets the firewall see inside encrypted traffic to detect malware and data exfiltration. Check if the firewall is configured to decrypt and inspect HTTPS traffic. This requires a CA certificate deployed to endpoints. On FortiGate: Security Profiles > SSL/SSH Inspection. On pfSense: this requires Squid proxy with SSL bump. Important: this has privacy implications - document any exclusions (banking, healthcare, personal sites) and ensure there is a policy that employees are aware of inspection. Many SMBs will not have this - note it as a recommendation rather than a critical finding.'
                Compliance='NIST CSF DE.CM-1 | CIS Control 9.3, 13.3 | HIPAA 164.312(e)(1)'
            }
            @{
                ID='NP09'; Severity='High'; Weight=7
                Text='NAT/PAT rules review - verify no unnecessary port forwarding to internal hosts'
                Hint='Check the firewall NAT/port forwarding rules. Every port forward maps an external port to an internal host. Run: on pfSense go to Firewall > NAT > Port Forward. On FortiGate check Policy & Objects > Virtual IPs. On SonicWall check Network > NAT Policies. Document each forward: external port, internal IP, internal port, and purpose. Dangerous findings: RDP (3389) forwarded directly, any port forward to a workstation (not a server), forwards to end-of-life systems. Compare against the open port scan from NP02 to verify consistency.'
                Compliance='NIST CSF PR.AC-5 | CIS Control 4.1, 4.4 | HIPAA 164.312(e)(1)'
            }
            @{
                ID='NP10'; Severity='Medium'; Weight=5
                Text='Firmware/software version on perimeter devices is current and supported'
                Hint='Check the firmware version of all perimeter devices: firewall, VPN concentrator, edge switches, WAPs. Compare against the vendor current/recommended version. Look for known CVEs affecting the running version - check CVE databases or the vendor security advisories page. Devices running end-of-life firmware are a critical finding because they no longer receive security patches. Check: pfSense System > Update, FortiGate System > Firmware, SonicWall System > Settings > Firmware. Document: device name, current version, latest available version, and any known CVEs.'
                Compliance='NIST CSF PR.IP-12, ID.RA-1 | CIS Control 2.1, 7.1 | HIPAA 164.312(a)(1)'
            }
        )
    }

    'Identity & Access' = @{
        Desc = 'Authentication, authorization, and account lifecycle management'
        Items = @(
            @{
                ID='IA01'; Severity='Critical'; Weight=10
                Text='Domain Admin account audit - document every account with DA privileges and justification'
                Hint='Run in PowerShell: Get-ADGroupMember "Domain Admins" -Recursive | Select Name,SamAccountName,Enabled | Format-Table. Also check: Enterprise Admins, Schema Admins, and Administrators groups. Every account in these groups needs a documented business justification. Common bad findings: IT staff daily accounts in DA (should use separate admin accounts), service accounts in DA (almost never needed), former employees, generic accounts like "admin" or "sysadmin". The gold standard is: nobody daily-drives a Domain Admin account. They should use a separate privileged account only when needed. Also run: Get-ADUser -Filter {AdminCount -eq 1} to find all accounts with elevated privileges.'
                Compliance='NIST CSF PR.AC-1, PR.AC-4, PR.AC-6 | CIS Control 5.1, 5.4, 5.5, 6.8 | HIPAA 164.312(a)(1), 164.312(a)(2)(i)'
            }
            @{
                ID='IA02'; Severity='Critical'; Weight=10
                Text='Service accounts audit - verify password age, rotation policy, and least privilege'
                Hint='Run: Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties PasswordLastSet,PasswordNeverExpires,ServicePrincipalName,MemberOf | Select Name,PasswordLastSet,PasswordNeverExpires. Also search for accounts with "svc", "service", "sql", "backup" in the name. Key checks: 1) Password age - if PasswordLastSet is more than 1 year old, flag it. If it is the account creation date, the password has NEVER been changed. 2) Is it in Domain Admins? Service accounts almost never need DA. 3) Is PasswordNeverExpires set to True? 4) Can you find the password? Check documentation, scripts, batch files, and scheduled tasks for hardcoded passwords. The classic finding: service account with DA + password = CompanyName2019.'
                Compliance='NIST CSF PR.AC-1, PR.AC-4 | CIS Control 5.2, 5.4, 5.5 | HIPAA 164.312(a)(1), 164.312(d)'
            }
            @{
                ID='IA03'; Severity='Critical'; Weight=10
                Text='MFA coverage - email, VPN, RDP, cloud admin portals, all remote access'
                Hint='Make a matrix of all remote access points and verify MFA on each: 1) Email (Exchange Online/M365 - check Entra ID > Security > MFA registration, or Conditional Access policies), 2) VPN (check VPN config for RADIUS integration with MFA provider like Duo, Azure MFA), 3) RDP (if exposed externally, must have NLA + MFA via Duo RDP or Azure MFA NPS extension), 4) Cloud admin portals (Azure, AWS, Google Workspace admin - check for MFA enforcement on admin roles), 5) Remote desktop gateways, 6) Any web apps with SSO. Run in Entra ID PowerShell: Get-MgUser -All | Where { $_.StrongAuthenticationMethods.Count -eq 0 } to find users without MFA registered. If any access point is username/password only, flag it as critical.'
                Compliance='NIST CSF PR.AC-7 | CIS Control 6.3, 6.4, 6.5 | HIPAA 164.312(d)'
            }
            @{
                ID='IA04'; Severity='Critical'; Weight=10
                Text='Terminated employee account review - cross-reference against HR separation list'
                Hint='Request a list of all employees who left the organization in the past 12-24 months from HR. Then run: Get-ADUser -Filter {Enabled -eq $true} -Properties WhenCreated,LastLogonDate | Select Name,SamAccountName,LastLogonDate,WhenCreated | Export-Csv. Cross-reference the HR list against active AD accounts. Also check: Entra ID/Azure AD, M365 licenses still assigned, VPN accounts, cloud service accounts (Salesforce, QuickBooks, etc.), building access badges, shared mailbox access. Common finding: 30-40% of terminated employees still have active accounts because there is no formal offboarding process. Ask to see the offboarding checklist - if there is not one, that is a finding too.'
                Compliance='NIST CSF PR.AC-1, PR.AC-6 | CIS Control 5.1, 5.3 | HIPAA 164.312(a)(2)(ii), 164.308(a)(3)(ii)(C)'
            }
            @{
                ID='IA05'; Severity='High'; Weight=7
                Text='Password policy review - length, complexity, expiration, history requirements'
                Hint='Run: Get-ADDefaultDomainPasswordPolicy. Check: MinPasswordLength (should be 12+ per current NIST guidance, 14+ is better), ComplexityEnabled (should be True), PasswordHistoryCount (should be 24 to prevent reuse), LockoutThreshold (3-5 attempts), LockoutDuration (15-30 min). Also check for Fine-Grained Password Policies: Get-ADFineGrainedPasswordPolicy -Filter *. Note: current NIST 800-63B guidance says forced password expiration is no longer recommended IF you have MFA and breach monitoring. However, many compliance frameworks still require rotation. Document the policy and compare against the applicable standard. If passwords are shorter than 12 characters, flag it.'
                Compliance='NIST CSF PR.AC-1, PR.AC-7 | CIS Control 5.2 | HIPAA 164.312(d), 164.308(a)(5)(ii)(D)'
            }
            @{
                ID='IA06'; Severity='High'; Weight=6
                Text='Privileged Access Management (PAM) - just-in-time access, session recording'
                Hint='Check if the organization uses any PAM solution (CyberArk, BeyondTrust, Thycotic/Delinea, ManageEngine PAM360, or even a basic password vault like KeePass for shared admin credentials). Key questions: 1) Are admin passwords stored in a vault or do people just remember them? 2) Is there a checkout/checkin process for privileged credentials? 3) Are privileged sessions recorded/logged? 4) Is there just-in-time (JIT) elevation where admin rights are granted temporarily? For Azure: check Entra ID PIM (Privileged Identity Management) - are admin roles permanently assigned or do users activate them on demand? Most SMBs will not have formal PAM - note as a recommendation with risk context.'
                Compliance='NIST CSF PR.AC-4, PR.AC-6 | CIS Control 5.4, 5.5, 6.8 | HIPAA 164.312(a)(1)'
            }
            @{
                ID='IA07'; Severity='Medium'; Weight=5
                Text='Shared/generic account inventory and remediation plan'
                Hint='Search AD for accounts that multiple people use: look for names like "reception", "front desk", "scanner", "warehouse", "shared", "generic", "admin" (without a person name). Run: Get-ADUser -Filter * -Properties Description | Where { $_.Description -match "shared|generic|multiple" }. Also ask: "Does anyone share login credentials?" and "Are there any accounts where multiple people know the password?" Shared accounts destroy accountability - you cannot determine WHO did something if 5 people use the same login. Document each shared account, how many people use it, and what it is used for. Recommend individual accounts with appropriate group permissions instead.'
                Compliance='NIST CSF PR.AC-1, PR.AC-6 | CIS Control 5.1, 5.4 | HIPAA 164.312(a)(2)(i)'
            }
            @{
                ID='IA08'; Severity='Medium'; Weight=5
                Text='Guest/vendor account lifecycle management'
                Hint='Ask: "How do you handle vendor/contractor access?" Look for: vendor accounts in AD (names like "vendor_companyname", "contractor_name"), VPN accounts for third parties, shared credentials given to vendors. Check if vendor accounts have: expiration dates set (Get-ADUser -Filter * -Properties AccountExpirationDate | Where { $_.AccountExpirationDate -ne $null }), limited group memberships, been used recently (check LastLogonDate). The finding is almost always: vendor accounts with no expiration, no review process, and too many permissions. Ask when the last vendor access review was performed. If the answer is "never", that is the finding.'
                Compliance='NIST CSF PR.AC-1, PR.AC-3 | CIS Control 5.1, 5.3, 6.1 | HIPAA 164.308(a)(4)(ii)(B), 164.312(a)(1)'
            }
            @{
                ID='IA09'; Severity='Medium'; Weight=5
                Text='Azure AD / Entra ID conditional access policies reviewed'
                Hint='If the org uses M365/Azure, log into Entra ID admin center > Protection > Conditional Access. Document all active policies. Key policies that SHOULD exist: 1) Require MFA for all users, 2) Block legacy authentication (Basic auth in IMAP, POP3, SMTP - these bypass MFA), 3) Require compliant device for access, 4) Block access from risky locations/countries, 5) Require MFA for admin roles. If there are NO conditional access policies, that is a significant finding. Also check: Entra ID > Security > Authentication methods to see which MFA methods are enabled (avoid SMS-only, prefer Authenticator app). Note: Conditional Access requires at minimum Entra ID P1 licensing.'
                Compliance='NIST CSF PR.AC-3, PR.AC-7 | CIS Control 6.3, 6.4, 6.5 | HIPAA 164.312(d), 164.312(e)(1)'
            }
            @{
                ID='IA10'; Severity='High'; Weight=7
                Text='Stale/inactive account cleanup - accounts with no login in 90+ days'
                Hint='Run: Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonTimestamp | Where { [DateTime]::FromFileTime($_.LastLogonTimestamp) -lt (Get-Date).AddDays(-90) } | Select Name,SamAccountName,@{N="LastLogon";E={[DateTime]::FromFileTime($_.LastLogonTimestamp)}}. This finds enabled accounts that have not logged in for 90+ days. These are prime targets for attackers because nobody notices unauthorized use of a forgotten account. Cross-reference against the terminated employee list (IA04) and service accounts. Some will be legitimate (seasonal workers, leave of absence), but most are just forgotten. Disable them immediately and delete after 30 days if unclaimed.'
                Compliance='NIST CSF PR.AC-1, PR.AC-6 | CIS Control 5.3 | HIPAA 164.312(a)(2)(ii)'
            }
        )
    }

    'Endpoint Security' = @{
        Desc = 'Device-level protection, patching, and hardening'
        Items = @(
            @{
                ID='EP01'; Severity='Critical'; Weight=10
                Text='EDR/AV deployment coverage verified at 100% - identify any gaps'
                Hint='Pull a report from the EDR/AV management console (CrowdStrike Falcon, SentinelOne, Sophos Central, Defender for Endpoint, Bitdefender GravityZone, etc.). Compare the agent count against total known endpoints from AD: (Get-ADComputer -Filter {Enabled -eq $true}).Count. The numbers should match. Common gaps: Linux servers, developer workstations with "exceptions", IoT devices, personal devices on the network, newly imaged machines, and Macs. Also check: is the agent active and updating? Look for agents that have not checked in for 7+ days - they may be offline, uninstalled, or malfunctioning. AV definitions should be no more than 24 hours old. If using Defender, run: Get-MpComputerStatus on endpoints to verify.'
                Compliance='NIST CSF DE.CM-4, PR.DS-5 | CIS Control 10.1, 10.2 | HIPAA 164.308(a)(5)(ii)(B)'
            }
            @{
                ID='EP02'; Severity='Critical'; Weight=10
                Text='Patch compliance - internet-facing systems and critical CVEs prioritized'
                Hint='Check the patch management tool (WSUS, Intune, SCCM/MECM, ConnectWise Automate, NinjaRMM, etc.) for compliance reports. Focus on: 1) Internet-facing systems (web servers, email gateways, VPN appliances) - these must be patched within 48-72 hours for critical CVEs, 2) Critical/High severity CVEs across all systems - check CISA KEV (Known Exploited Vulnerabilities) catalog for actively exploited vulns, 3) Servers first, then workstations. Run: Get-HotFix | Sort InstalledOn -Desc | Select -First 10 on sample systems to check recency. If the last patch was installed more than 30 days ago, flag it. Also check third-party patching (Adobe, Java, Chrome, Firefox, 7-Zip, etc.) - these are frequently exploited and often ignored.'
                Compliance='NIST CSF PR.IP-12, ID.RA-1 | CIS Control 7.1, 7.2, 7.3, 7.4 | HIPAA 164.308(a)(5)(ii)(B)'
            }
            @{
                ID='EP03'; Severity='High'; Weight=7
                Text='SMB/Protocol hardening - signing, encryption, NTLM level, LLMNR, NetBIOS'
                Hint='SMB and protocol hardening prevents lateral movement and credential relay attacks. Check: 1) SMBv1 disabled (Get-SmbServerConfiguration | Select EnableSMB1Protocol), 2) SMB signing required (RequireSecuritySignature=True on both server and client - prevents relay attacks), 3) SMB encryption enabled (EncryptData=True for SMB 3.0+), 4) NTLM level set to 5 (LmCompatibilityLevel=5 in HKLM:\SYSTEM\CurrentControlSet\Control\Lsa - NTLMv2 only, refuse LM and NTLM), 5) LLMNR disabled (EnableMulticast=0 in DNS Client GPO - prevents LLMNR poisoning/Responder attacks), 6) NetBIOS over TCP/IP disabled on all adapters (prevents NBT-NS poisoning). These are the most commonly exploited protocols in internal network penetration tests.'
                Compliance='NIST CSF PR.AC-5, PR.DS-2 | CIS Control 4.1, 4.8 | HIPAA 164.312(e)(1), 164.312(a)(1)'
            }
            @{
                ID='EP04'; Severity='High'; Weight=6
                Text='USB/removable media policy enforced via GPO or endpoint management'
                Hint='Check Group Policy: Computer Config > Admin Templates > System > Removable Storage Access. Policies should restrict or audit USB mass storage device access. Also check if the EDR platform has USB control (CrowdStrike Device Control, SentinelOne Device Control). This prevents data exfiltration and malware introduction via USB drives. Run: gpresult /h report.html on a sample workstation and search for "Removable" to see applied policies. If there is no USB restriction at all, flag it. For environments that need USB access (labs, manufacturing), recommend whitelisting specific approved devices by hardware ID rather than allowing all. BitLocker To Go can be required for removable media in the policy.'
                Compliance='NIST CSF PR.AC-3, PR.DS-5, PR.PT-2 | CIS Control 10.3 | HIPAA 164.310(d)(1), 164.312(a)(1)'
            }
            @{
                ID='EP05'; Severity='High'; Weight=7
                Text='BitLocker/disk encryption enabled on all endpoints'
                Hint='Run on endpoints: manage-bde -status or Get-BitLockerVolume. Check that the C: drive is fully encrypted with XTS-AES 256. For domain-wide view, check AD for BitLocker recovery keys: Get-ADObject -Filter {ObjectClass -eq "msFVE-RecoveryInformation"} -SearchBase "DC=domain,DC=com" | Group {$_.DistinguishedName.Split(",")[1]} | Select Count,Name. Compare against total computer count. For Intune-managed devices, check the Encryption Report in Endpoint Manager. Common findings: desktops are often skipped because "they do not leave the office" (but drives can be stolen from disposed machines), and servers rarely have BitLocker. If laptops are not encrypted and one is lost/stolen, that is a reportable data breach under HIPAA and most state laws.'
                Compliance='NIST CSF PR.DS-1, PR.DS-5 | CIS Control 3.6 | HIPAA 164.312(a)(2)(iv), 164.312(e)(2)(ii)'
            }
            @{
                ID='EP06'; Severity='Medium'; Weight=5
                Text='Host-based firewall enabled and configured on all endpoints'
                Hint='Check Windows Firewall status via GPO or locally: Get-NetFirewallProfile | Select Name,Enabled. All three profiles (Domain, Private, Public) should be Enabled. Then check: Get-NetFirewallRule | Where {$_.Enabled -eq "True" -and $_.Direction -eq "Inbound" -and $_.Action -eq "Allow"} | Select DisplayName,Profile. Look for overly permissive inbound rules. Common finding: Windows Firewall was disabled years ago because "it was causing problems" and nobody turned it back on. Also verify GPO enforces the firewall ON so users/techs cannot disable it: Computer Config > Windows Settings > Security Settings > Windows Defender Firewall. If the org has an EDR, check if its host firewall module is active instead.'
                Compliance='NIST CSF PR.AC-5, PR.PT-4 | CIS Control 4.4, 4.5 | HIPAA 164.312(e)(1)'
            }
            @{
                ID='EP07'; Severity='Medium'; Weight=5
                Text='Application whitelisting / AppLocker policies in place'
                Hint='Check if AppLocker or Windows Defender Application Control (WDAC) is configured: Get-AppLockerPolicy -Effective (will error if not configured). In Group Policy: Computer Config > Windows Settings > Security Settings > Application Control Policies > AppLocker. Application whitelisting prevents unauthorized executables from running - it is one of the most effective controls against malware and ransomware. Most SMBs will NOT have this. Note it as a strong recommendation. At minimum, recommend blocking execution from user-writable locations (%TEMP%, %APPDATA%, Downloads). Also check if SRP (Software Restriction Policies) are in use as a simpler alternative. Document current state and provide a recommendation for phased rollout.'
                Compliance='NIST CSF PR.DS-5, PR.IP-1 | CIS Control 2.5, 2.6, 2.7 | HIPAA 164.312(a)(1)'
            }
            @{
                ID='EP08'; Severity='High'; Weight=7
                Text='Hardware security features: VBS, Credential Guard, LSA Protection, TPM 2.0, Secure Boot'
                Hint='This check validates critical hardware-backed security features. VBS (Virtualization-Based Security) and Credential Guard protect credentials from theft even if the OS is compromised. Check via WMI: Get-CimInstance Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard. VBS Status=2 means Running. SecurityServicesRunning should include 1 (Credential Guard) and 2 (HVCI). LSA Protection (RunAsPPL) prevents credential dumping tools like Mimikatz. Check: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL should be 1. WDigest caching should be disabled: HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential should be 0. Secure Boot and TPM 2.0 are prerequisites for VBS. These controls are the #1 defense against credential theft attacks.'
                Compliance='NIST CSF PR.AC-2, PR.PT-1 | CIS Control 1.1, 4.1, 10.5 | HIPAA 164.310(a)(1) | CMMC L2 SC.L2-3.13.11'
            }
            @{
                ID='EP09'; Severity='Low'; Weight=3
                Text='Auto-run / auto-play disabled across the environment'
                Hint='Check Group Policy: Computer Config > Admin Templates > Windows Components > AutoPlay Policies. "Turn off AutoPlay" should be Enabled for "All drives". Also check: User Config > Admin Templates > Windows Components > AutoPlay Policies. Run on a sample endpoint: Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" NoDriveTypeAutoRun - a value of 255 disables autorun for all drive types. AutoPlay/AutoRun was a massive malware vector (Conficker worm spread this way). While modern Windows has improved defaults, older systems and USB drives with autorun.inf can still be exploited if this is not explicitly disabled via policy.'
                Compliance='NIST CSF PR.PT-2 | CIS Control 10.3 | HIPAA 164.308(a)(5)(ii)(B)'
            }
            @{
                ID='EP10'; Severity='High'; Weight=7
                Text='End-of-life operating systems identified and documented with migration plan'
                Hint='Run: Get-ADComputer -Filter {Enabled -eq $true} -Properties OperatingSystem,OperatingSystemVersion | Group OperatingSystem | Select Count,Name. Flag any: Windows 7, Windows 8/8.1, Windows Server 2008/R2, Server 2012/R2, any "Windows XP" or "Windows Vista". These no longer receive security patches and are actively targeted. Even Server 2012 R2 reached end of extended support in October 2023. For each EOL system, document: hostname, purpose, why it has not been upgraded (legacy app?), and compensating controls in place (network isolation, restricted access). If a system is EOL because of a legacy application, recommend virtualizing and isolating it on its own VLAN with strict firewall rules.'
                Compliance='NIST CSF PR.IP-12, ID.AM-2 | CIS Control 2.1, 2.2 | HIPAA 164.308(a)(5)(ii)(B)'
            }
        )
    }

    'Backup & Recovery' = @{
        Desc = 'Data protection, disaster recovery, and business continuity'
        Items = @(
            @{
                ID='BR01'; Severity='Critical'; Weight=10
                Text='3-2-1 backup rule compliance - 3 copies, 2 media types, 1 offsite'
                Hint='Interview the IT contact and document: 1) How many copies of data exist? (production + backup + offsite = 3 minimum), 2) What media types? (e.g., local NAS + cloud = 2 media types), 3) Is there an offsite copy? (cloud backup, tape rotation, replicated to another site). Check the backup software (Veeam, Datto, Acronis, Barracuda, BackupExec, Windows Server Backup) and verify all three are configured. Common failure: backups go to a NAS in the same server room. If the building floods or catches fire, both production AND backup are lost. Verify the offsite copy is in a different physical location or a cloud target. Also check: does the 3-2-1 rule apply to ALL critical data or just the file server?'
                Compliance='NIST CSF PR.IP-4 | CIS Control 11.1, 11.2, 11.3 | HIPAA 164.308(a)(7)(ii)(A), 164.310(d)(2)(iv)'
            }
            @{
                ID='BR02'; Severity='Critical'; Weight=10
                Text='Backup restore TEST completed and documented (not just backup verification)'
                Hint='This is the single most important backup check. Ask: "When was the last time you actually restored data from a backup?" Not "when was the last successful backup job" - when did you RESTORE something and verify it works? Ask to see documentation of the test: what was restored, from what date, how long did it take, was the data intact? If the answer is "we have never tested a restore" (extremely common), flag it as critical. A backup that has never been tested is not a backup - it is a hope. Recommend: quarterly restore tests at minimum, with full documentation. Test different scenarios: individual file, full server, entire VM, bare-metal recovery, and application-level (e.g., can you restore and bring up Exchange/SQL?).'
                Compliance='NIST CSF PR.IP-4, PR.IP-9 | CIS Control 11.4, 11.5 | HIPAA 164.308(a)(7)(ii)(D)'
            }
            @{
                ID='BR03'; Severity='Critical'; Weight=10
                Text='Air-gapped or immutable backups in place for ransomware protection'
                Hint='Modern ransomware specifically targets backup systems - it will encrypt or delete backups before encrypting production data. Check: 1) Are any backup copies air-gapped (physically disconnected from the network)? Examples: tape with offsite rotation, removable USB drives rotated offsite. 2) Are cloud backups immutable (cannot be deleted or modified for a retention period)? Check Veeam immutability settings, Datto cloud retention, Wasabi object lock, AWS S3 Object Lock, Azure immutable blob storage. 3) Can an admin with full access delete ALL backup copies? If yes, ransomware with stolen admin credentials can too. The test: if a ransomware operator gets Domain Admin, can they destroy every backup? If the answer is yes, this is critical.'
                Compliance='NIST CSF PR.IP-4 | CIS Control 11.3, 11.4 | HIPAA 164.308(a)(7)(ii)(A)'
            }
            @{
                ID='BR04'; Severity='High'; Weight=7
                Text='RTO/RPO defined and documented - business stakeholders are aware of targets'
                Hint='RTO = Recovery Time Objective (how long can the business be down?). RPO = Recovery Point Objective (how much data can we afford to lose?). Ask the IT lead AND a business stakeholder separately: "If your main server goes down, how long is acceptable before it is back up?" and "If we have to restore from backup, how many hours/days of lost data is acceptable?" If IT says "24 hours" and the business says "2 hours", there is a misalignment that needs to be resolved. Then check if the backup system can actually MEET the stated RTO/RPO. If RPO is 4 hours but backups only run nightly, the backup configuration does not meet the requirement. Document: stated RTO, stated RPO, actual backup frequency, actual tested restore time.'
                Compliance='NIST CSF ID.BE-5, PR.IP-9, RC.RP-1 | CIS Control 11.1 | HIPAA 164.308(a)(7)(ii)(B)'
            }
            @{
                ID='BR05'; Severity='High'; Weight=6
                Text='Backup encryption enabled for data at rest and in transit'
                Hint='Check backup software encryption settings. In Veeam: check job settings > Storage > Encryption. In Datto: encryption should be on by default - verify in device settings. Backup data contains everything - credentials, personal data, financial records. If backup media is unencrypted and a tape/drive is lost or stolen, it is a data breach. Check: 1) Are backup files encrypted at rest? (AES-256 preferred) 2) Are backup transfers encrypted in transit? (SSL/TLS to cloud targets) 3) Where are the encryption keys stored? (should NOT be only on the backup server itself - if the server is lost, you cannot decrypt the backups). 4) For cloud backups: is the data encrypted with a customer-managed key or only provider-managed?'
                Compliance='NIST CSF PR.DS-1, PR.DS-2 | CIS Control 3.6, 3.10 | HIPAA 164.312(a)(2)(iv), 164.312(e)(2)(ii)'
            }
            @{
                ID='BR06'; Severity='High'; Weight=7
                Text='Backup monitoring and alerting for failures is active'
                Hint='Ask: "When was the last backup failure and how did you find out about it?" Check the backup console for recent job history. Look for: failed jobs in the last 30 days, jobs with warnings (partial failures), jobs that have not run at all. Then check: is there automated alerting? Who receives the alerts? Is someone REVIEWING the alerts daily? Common finding: backup alerts go to an email distribution list that nobody reads, or alerts are configured but the email address is a former employee. The worst scenario: backups have been silently failing for months and nobody noticed. Check backup log/history going back 90 days. Also verify: are ALL critical systems included in backup jobs? Compare the backup job list against the server inventory.'
                Compliance='NIST CSF DE.CM-3, DE.DP-4 | CIS Control 11.2 | HIPAA 164.308(a)(7)(ii)(A)'
            }
            @{
                ID='BR07'; Severity='Medium'; Weight=5
                Text='DR plan documented and tabletop exercise completed within past 12 months'
                Hint='Ask to see the Disaster Recovery Plan document. Key elements it should contain: 1) Contact list/call tree, 2) System priority list (what gets recovered first), 3) Step-by-step recovery procedures for each critical system, 4) RTO/RPO targets per system, 5) Alternate site/work location plan, 6) Communication plan for employees/customers. Then ask: "When was the last time you walked through this plan as a team?" A tabletop exercise is a meeting where you simulate a disaster scenario and walk through the response steps. If there is no DR plan, that is a finding. If there is a plan but it has never been tested, that is also a finding. Plans that exist only on paper are often outdated and full of incorrect assumptions.'
                Compliance='NIST CSF PR.IP-9, RC.RP-1, RC.IM-1 | CIS Control 11.5 | HIPAA 164.308(a)(7)(i), 164.308(a)(7)(ii)(B-D)'
            }
            @{
                ID='BR08'; Severity='Medium'; Weight=5
                Text='Cloud/SaaS backup coverage (M365, Google Workspace, etc.)'
                Hint='A very common misconception: "Microsoft backs up our data in M365." Microsoft provides infrastructure resilience, NOT data backup. If a user deletes files or email, or ransomware encrypts SharePoint, the data can be permanently lost after retention periods expire. Check: 1) Is there a third-party backup of M365 data? (Veeam for M365, Datto SaaS Protection, Barracuda Cloud-to-Cloud, Spanning, AvePoint). 2) What is backed up? (Exchange mailboxes, OneDrive, SharePoint, Teams). 3) What is the retention period? 4) Has a restore test been performed? Also check for other SaaS apps that hold business data: Salesforce, QuickBooks Online, HubSpot, etc. If the business relies on it and it is not backed up, it is a finding.'
                Compliance='NIST CSF PR.IP-4 | CIS Control 11.1, 11.2 | HIPAA 164.308(a)(7)(ii)(A), 164.310(d)(2)(iv)'
            }
        )
    }

    'Logging & Monitoring' = @{
        Desc = 'Visibility into security events and incident detection capability'
        Items = @(
            @{
                ID='LM01'; Severity='High'; Weight=7
                Text='DNS query logging enabled and retained for incident response'
                Hint='DNS logs are a goldmine during incident response - they show every domain every device queried. Check: 1) On Windows DNS Server: DNS Manager > Server Properties > Debug Logging (legacy) or better: DNS Analytical logging via Event Viewer or PowerShell: Set-DnsServerDiagnostics -All $true. 2) On pfSense with pfBlockerNG/Unbound: check if query logging is enabled in Unbound settings. 3) If using a DNS filter (Umbrella, NextDNS): check their query log retention. Key: logs must be RETAINED for at least 90 days (preferably 1 year) for incident investigation. If an incident occurs and you need to know "what domains did the compromised host contact?" you need these logs. If DNS logging is not enabled, that is a significant visibility gap.'
                Compliance='NIST CSF DE.CM-1, DE.AE-3 | CIS Control 8.2, 8.9 | HIPAA 164.312(b), 164.308(a)(1)(ii)(D)'
            }
            @{
                ID='LM02'; Severity='High'; Weight=8
                Text='Centralized log collection (SIEM or log aggregator) deployed'
                Hint='Ask: "Where do your logs go?" If the answer is "they stay on each server" that is a finding - attackers delete local logs to cover tracks. Check for: SIEM solutions (Splunk, Microsoft Sentinel, Elastic SIEM, Wazuh, AlienVault/AT&T USM, Graylog, LogRhythm) or log aggregators (syslog server, Windows Event Collector). At minimum, these sources should feed centrally: Domain Controllers (authentication events), firewall (traffic logs), VPN (connection logs), DNS (query logs), file servers (access logs), and EDR/AV (detection logs). If there is no central logging, the org is essentially blind to security events and cannot perform effective incident response. For SMBs, Wazuh (free/open-source) or Microsoft Sentinel (if already on Azure) are cost-effective options to recommend.'
                Compliance='NIST CSF DE.CM-1, DE.CM-3, DE.AE-3 | CIS Control 8.2, 8.5, 8.9 | HIPAA 164.312(b), 164.308(a)(1)(ii)(D)'
            }
            @{
                ID='LM03'; Severity='High'; Weight=7
                Text='Windows Event Log forwarding configured for security events'
                Hint='Check if Windows Event Forwarding (WEF) or an agent-based collection is active. Key events to collect from DCs and servers: Event ID 4624/4625 (logon success/failure), 4672 (special privilege logon), 4720/4726 (user created/deleted), 4732/4733 (user added/removed from security group), 4740 (account lockout), 1102 (audit log cleared - VERY suspicious), 4688 (process creation with command line logging). Run on a DC: wevtutil qe Security /c:5 /rd:true /f:text to see recent security events. Check GPO: Computer Config > Windows Settings > Security Settings > Advanced Audit Policy Configuration. If "Audit Logon Events" is "No Auditing", critical visibility is missing. Increase audit policy and forward events to a central collector.'
                Compliance='NIST CSF DE.CM-1, DE.CM-3, DE.AE-3 | CIS Control 8.2, 8.5, 8.8 | HIPAA 164.312(b)'
            }
            @{
                ID='LM04'; Severity='Medium'; Weight=5
                Text='Firewall logging enabled with adequate retention period'
                Hint='Check the firewall logging configuration. On pfSense: Status > System Logs > Settings. On FortiGate: Log & Report > Log Settings. On SonicWall: Log > Settings. Verify: 1) Traffic logging is enabled for both allowed and denied traffic, 2) Logs are stored remotely (syslog to a log server, not just local disk that can fill up), 3) Retention period is at least 90 days. Check: how much disk space is allocated for logs? If the firewall has a 256MB log partition and generates 50MB/day, logs only go back 5 days. Remote syslog solves this. Also verify: are the logs being REVIEWED? Look at the firewall dashboard for top blocked connections, top talkers, and any suspicious patterns. If nobody looks at the logs, they serve limited purpose beyond post-incident forensics.'
                Compliance='NIST CSF DE.CM-1 | CIS Control 8.2, 8.5, 8.9 | HIPAA 164.312(b)'
            }
            @{
                ID='LM05'; Severity='Medium'; Weight=5
                Text='Failed login attempt monitoring and alerting'
                Hint='Check: 1) Account lockout policy is configured (Net accounts on any domain machine shows lockout threshold/duration), 2) Someone is alerted when accounts get locked out or when there are brute-force patterns. In AD: check Event ID 4740 (account lockout) on the PDC emulator DC. Run: Get-EventLog Security -InstanceId 4740 -Newest 20 | Format-Table TimeGenerated,Message. If there are frequent lockouts, investigate why - it could be a brute-force attack, a misconfigured service, or a user with a saved wrong password. For alerting: does the SIEM/monitoring tool have a rule for "more than X failed logins in Y minutes"? If there is no lockout policy AND no monitoring, an attacker can brute-force passwords indefinitely with no detection.'
                Compliance='NIST CSF DE.CM-1, DE.AE-2 | CIS Control 8.5 | HIPAA 164.312(b), 164.308(a)(1)(ii)(D)'
            }
            @{
                ID='LM06'; Severity='Medium'; Weight=5
                Text='File integrity monitoring on critical systems'
                Hint='FIM detects unauthorized changes to critical system files, configurations, and binaries. Check if the EDR or a dedicated FIM tool (Tripwire, OSSEC/Wazuh, CrowdStrike Falcon FIM) monitors changes to: system32 executables, registry keys (Run/RunOnce), scheduled tasks, services, startup items, critical application configs, and web server directories. On Windows: Sysmon (Event ID 11 - file create, Event ID 13 - registry modification) is a lightweight option. If there is no FIM, an attacker who modifies system files or installs a backdoor may go undetected. For SMBs, this is often a stretch goal - note as a recommendation. If they have Wazuh or an EDR with FIM capabilities, verify it is actually enabled and configured for key paths.'
                Compliance='NIST CSF DE.CM-1, DE.CM-5 | CIS Control 3.14 | HIPAA 164.312(b), 164.312(c)(2)'
            }
            @{
                ID='LM07'; Severity='Medium'; Weight=5
                Text='Log retention meets compliance and investigation requirements'
                Hint='Ask what the log retention policy is (if one exists) and verify actual retention. Compliance minimums: HIPAA requires 6 years for audit logs related to PHI, PCI DSS requires 1 year with 3 months immediately available, most cyber insurance policies require 90 days minimum. Check actual retention by looking at the oldest available log entry in: the SIEM, the firewall, the DC event logs (wevtutil el then check Security log size/retention), and the backup system. Common finding: logs are configured to "overwrite as needed" with a small max size, so actual retention is only days or weeks. Increase log file sizes and ensure remote/central logging has adequate storage for the required retention period.'
                Compliance='NIST CSF DE.CM-1, PR.PT-1 | CIS Control 8.1, 8.9, 8.10 | HIPAA 164.312(b), 164.530(j)(2)'
            }
            @{
                ID='LM08'; Severity='High'; Weight=7
                Text='Security alerting and incident response notification process defined'
                Hint='Ask: "If a critical security alert fires at 2am on Saturday, what happens?" There should be a documented process: who gets notified first, what is the escalation path, what are the first response steps, is there an IR retainer with a security firm? Check: 1) Does the EDR/SIEM have email/SMS/phone alerting configured? 2) Who receives the alerts - is it a person, or an unmonitored mailbox? 3) Is there 24/7 coverage or only business hours? 4) Is there an incident response plan/playbook? For SMBs, an MDR (Managed Detection and Response) service provides 24/7 monitoring. If the org has no alerting, no IR plan, and no MDR, they will only discover a breach when damage is visible (ransomware note, customer complaint, bank fraud alert).'
                Compliance='NIST CSF DE.DP-4, RS.CO-2, RS.CO-3 | CIS Control 17.1, 17.2, 17.4 | HIPAA 164.308(a)(6)(i), 164.308(a)(6)(ii)'
            }
        )
    }

    'Network Architecture' = @{
        Desc = 'Network design, segmentation, and traffic control'
        Items = @(
            @{
                ID='NA01'; Severity='Critical'; Weight=10
                Text='Network segmentation implemented - no flat network topology'
                Hint='A flat network means every device can talk to every other device - servers, workstations, printers, IoT, guests all on the same subnet. This is an attacker paradise because compromising one device gives immediate access to everything. Check: run "ipconfig /all" on a workstation and on a server - if they are on the same subnet (e.g., both 192.168.1.x/24), the network is flat. Proper segmentation puts: servers on their own VLAN/subnet, workstations on another, IoT/cameras/printers on another, guest WiFi completely isolated. Check the switch configuration for VLAN assignments and the firewall for inter-VLAN routing rules. If everything is on one subnet with no VLANs, this is a critical finding. Draw or request a network diagram to visualize the topology.'
                Compliance='NIST CSF PR.AC-5 | CIS Control 12.2, 12.8 | HIPAA 164.312(e)(1)'
            }
            @{
                ID='NA02'; Severity='High'; Weight=7
                Text='VLAN separation between user, server, IoT, and guest networks'
                Hint='Log into the core switch (managed switch) and review VLAN configuration. Common VLANs that should exist: Management (switch/AP management interfaces), Servers, Workstations/Users, VoIP phones, Security cameras/IoT, Guest WiFi, Printers. On Cisco: show vlan brief. On HP/Aruba: show vlans. On UniFi: check Networks in the controller. Then check the firewall/router inter-VLAN rules: the guest VLAN should have NO access to internal VLANs, IoT should only reach what it needs, workstations should access servers on specific ports only. If VLANs exist but there are no ACLs/firewall rules between them, the segmentation is cosmetic only. Common finding: VLANs were created but the firewall allows all inter-VLAN traffic, defeating the purpose.'
                Compliance='NIST CSF PR.AC-5 | CIS Control 12.2 | HIPAA 164.312(e)(1)'
            }
            @{
                ID='NA03'; Severity='High'; Weight=7
                Text='Wireless security - WPA3/WPA2-Enterprise, rogue AP detection'
                Hint='Check WiFi configuration on the wireless controller or APs. Key checks: 1) What encryption? WPA2-Personal (PSK) with a shared password is acceptable for guest but not for corporate. Corporate WiFi should use WPA2-Enterprise or WPA3-Enterprise with RADIUS authentication (users log in with their own AD credentials). 2) Is the PSK strong and rotated? If corporate WiFi uses a shared password that has not changed in years and every employee knows it (including former employees), flag it. 3) Rogue AP detection: does the wireless controller scan for unauthorized access points? (UniFi, Meraki, Aruba all have this). 4) Is guest WiFi truly isolated from the corporate network? Connect to guest and try to ping internal IPs. 5) Check for open/hidden SSIDs broadcasting that should not be.'
                Compliance='NIST CSF PR.AC-3, PR.AC-5 | CIS Control 12.6 | HIPAA 164.312(e)(1)'
            }
            @{
                ID='NA04'; Severity='Medium'; Weight=5
                Text='Network diagram is current and accurately documents infrastructure'
                Hint='Ask for the network diagram. Check: 1) Does one exist? (if not, that is a finding), 2) When was it last updated? 3) Does it show: all VLANs/subnets with IP ranges, firewall placement, switch interconnections, WAN/ISP connections, VPN tunnels, cloud connections, server locations, wireless AP placement? Walk the server room/closets and compare the physical setup against the diagram. Common finding: the diagram is 3 years old, shows equipment that has been replaced, and is missing new additions. An inaccurate diagram leads to security blind spots and slows incident response. Tools to recommend for maintaining diagrams: draw.io (free), Lucidchart, Visio, or even Netbox for automated documentation.'
                Compliance='NIST CSF ID.AM-1, ID.AM-2, ID.AM-4 | CIS Control 1.1, 1.2, 12.1 | HIPAA 164.310(d)(2)(iii)'
            }
            @{
                ID='NA05'; Severity='Medium'; Weight=5
                Text='802.1X / NAC deployed for network access control'
                Hint='802.1X prevents unauthorized devices from connecting to the network. When a device plugs into a switch port, it must authenticate before getting network access. Check: 1) Is 802.1X configured on switch ports? (show dot1x all on Cisco) 2) Is there a RADIUS server for authentication? (NPS on Windows, FreeRADIUS, Cisco ISE, Aruba ClearPass) 3) What happens to devices that fail authentication? (should go to a quarantine/guest VLAN, not get full access). Most SMBs will NOT have 802.1X. Note it as a recommendation. Alternative compensating control: MAC address filtering on switch ports (weak but better than nothing), or monitoring for new devices via network scanning. Also check if unused switch ports are administratively disabled - if you can plug in anywhere and get an IP, that is a finding.'
                Compliance='NIST CSF PR.AC-1, PR.AC-3 | CIS Control 1.4, 12.5 | HIPAA 164.312(a)(1)'
            }
            @{
                ID='NA06'; Severity='Medium'; Weight=5
                Text='Management interfaces isolated from production traffic'
                Hint='Management interfaces include: switch management IPs, AP management consoles, firewall admin portals, IPMI/iLO/iDRAC (server out-of-band management), UPS management cards, printer admin pages. These should NOT be accessible from the general user VLAN. Check: 1) Can you reach the switch admin page from a regular workstation? (try browsing to the switch IP from a user PC) 2) Is there a dedicated management VLAN? 3) Are iLO/iDRAC interfaces on their own network segment? 4) Is SSH/HTTPS used for management, not Telnet/HTTP? If management interfaces are on the same VLAN as users, a compromised workstation can access the entire infrastructure. Common finding: all management IPs are on the same subnet as users with no access restrictions.'
                Compliance='NIST CSF PR.AC-5, PR.PT-3 | CIS Control 12.2, 12.7 | HIPAA 164.312(e)(1)'
            }
            @{
                ID='NA07'; Severity='High'; Weight=7
                Text='Switch port security and unused port management'
                Hint='Check managed switches for: 1) Unused ports - are they administratively disabled? (show interfaces status on Cisco, look for "disabled" vs "notconnect") If unused ports are up and active, someone could plug in an unauthorized device. 2) Port security - is MAC address limiting configured to prevent MAC flooding attacks? 3) DHCP snooping - prevents rogue DHCP servers from handing out malicious network configs. 4) Dynamic ARP inspection (DAI) - prevents ARP spoofing/MITM attacks. On smaller switches (UniFi, Netgear, etc.), at least verify unused ports are disabled. Walk the physical space: are there active ethernet jacks in lobbies, conference rooms, or public areas? These should be on the guest VLAN or disabled.'
                Compliance='NIST CSF PR.AC-5, PR.PT-4 | CIS Control 1.4, 12.2, 12.5 | HIPAA 164.312(e)(1)'
            }
        )
    }

    'Physical Security' = @{
        Desc = 'Physical access controls and environmental protections'
        Items = @(
            @{
                ID='PS01'; Severity='High'; Weight=7
                Text='Server room / MDF / IDF locked with access control and logging'
                Hint='Physically inspect the server room and all network closets (MDF = Main Distribution Frame, IDF = Intermediate Distribution Frame). Check: 1) Is the door locked? (test it), 2) What type of lock? (key lock, badge reader, combination), 3) Who has access? (get a list), 4) Is access logged? (badge reader logs, sign-in sheet), 5) Is the door propped open? (common finding). Also check: are there windows into the server room that could allow visual access to screens/labels? Is the room shared with other uses (storage, break room)? Is there environmental monitoring (temperature/humidity)? Is there water detection (pipes overhead that could leak)? The classic finding: server "room" is actually an unlocked closet that doubles as a supply storage area with no access logging.'
                Compliance='NIST CSF PR.AC-2 | CIS Control 1.1 | HIPAA 164.310(a)(1), 164.310(a)(2)(ii-iv)'
            }
            @{
                ID='PS02'; Severity='Medium'; Weight=4
                Text='Visitor sign-in/sign-out log maintained at reception'
                Hint='Check the front desk/reception area. Is there a visitor log? Can you walk into the building without signing in? Key checks: 1) Is there a sign-in process for visitors? (paper log, digital system like Envoy), 2) Are visitors given badges that distinguish them from employees? 3) Are visitors escorted in sensitive areas? 4) Is there a sign-OUT process? (many have sign-in but no sign-out, so you cannot tell if someone is still in the building). Test: can you tailgate through a badge door behind an employee without challenge? For compliance-heavy environments (healthcare, financial), visitor logs may need to be retained. Ask how long they keep the logs and whether they can produce a list of who was in the building on a specific date.'
                Compliance='NIST CSF PR.AC-2 | CIS Control 1.1 | HIPAA 164.310(a)(2)(iii), 164.310(b)'
            }
            @{
                ID='PS03'; Severity='Medium'; Weight=4
                Text='Security cameras covering entry points and sensitive areas'
                Hint='Walk the facility and note camera placement. Key coverage areas: main entrance, server room door, parking lot, emergency exits, shipping/receiving. Check: 1) Are cameras operational? (look at the NVR/DVR - is it recording?), 2) What is the retention period? (30 days minimum, 90 days recommended), 3) Is the NVR in a secure location? (if the NVR is in an unlocked closet, someone could steal it and the footage). 4) Are cameras on a separate VLAN? (IoT cameras on the production network is a security risk - they are notoriously hackable). 5) Are default passwords changed on the cameras and NVR? (check for admin/admin or admin/12345). 6) Can cameras be accessed remotely? If so, is that access MFA-protected?'
                Compliance='NIST CSF PR.AC-2, DE.CM-2 | CIS Control 1.1 | HIPAA 164.310(a)(2)(iii), 164.310(d)(1)'
            }
            @{
                ID='PS04'; Severity='Medium'; Weight=4
                Text='Clean desk policy enforced - no credentials on sticky notes'
                Hint='Walk through the office space and look at desks, monitors, and walls. Common findings: passwords on sticky notes stuck to monitors, whiteboards with network diagrams and credentials, unlocked workstations with users away, sensitive documents left on printers, server credentials taped inside server room cabinets/doors. Check: 1) Are screens locked when users step away? (Windows key + L should be habit), 2) Is there an auto-lock GPO? (Screen saver timeout with password on resume - check GPO: User Config > Admin Templates > Control Panel > Personalization > Screen saver timeout), 3) Are sensitive printouts in the open? 4) Look inside the server room specifically for credentials written on equipment, taped to walls, or in obvious locations.'
                Compliance='NIST CSF PR.AC-2, PR.AT-1 | CIS Control 5.2 | HIPAA 164.310(b), 164.310(c)'
            }
            @{
                ID='PS05'; Severity='Low'; Weight=3
                Text='Network jacks in public areas disabled or on guest VLAN'
                Hint='Walk the public-facing areas: lobby, conference rooms, waiting areas, break rooms. Look for active ethernet wall jacks. Test by plugging in a laptop: 1) Do you get an IP address? 2) What VLAN/subnet are you on? 3) Can you ping internal servers? If a network jack in the lobby gives access to the production network, any visitor can plug in a device and access internal resources or run network attacks. These ports should either be: administratively disabled on the switch, placed on a guest VLAN with no internal access, or controlled via 802.1X. Also check for exposed network equipment (switches, patch panels) in non-secure areas like ceiling tiles in public spaces. Check conference rooms carefully - these often have active drops for presentation systems.'
                Compliance='NIST CSF PR.AC-2, PR.AC-5 | CIS Control 1.4, 12.5 | HIPAA 164.310(c)'
            }
            @{
                ID='PS06'; Severity='Low'; Weight=3
                Text='UPS/generator for critical infrastructure with regular testing'
                Hint='Check the server room/MDF power: 1) Is there a UPS (Uninterruptible Power Supply)? Check brand/model, battery age, and load percentage (batteries typically last 3-5 years), 2) Is the UPS monitored? (network card, USB to server for graceful shutdown), 3) Is there a generator for extended outages? 4) When was the UPS last tested under load? (not just a self-test - an actual power outage simulation), 5) Are all critical devices plugged into the UPS, or are some on regular power strips? Check UPS health: most have a front panel display or web interface showing battery health, load percentage, and estimated runtime. If the battery is showing "replace" or the UPS is overloaded (>80%), flag it. A dead UPS during a power blip means unclean server shutdowns and potential data loss.'
                Compliance='NIST CSF PR.PT-5 | CIS Control 1.1 | HIPAA 164.310(a)(2)(ii)'
            }
        )
    }

    'Common Findings' = @{
        Desc = 'Items found in virtually every SMB audit - verify these are addressed first'
        Items = @(
            @{
                ID='CF01'; Severity='Critical'; Weight=10
                Text='Service accounts with Domain Admin privileges and weak/default passwords'
                Hint='This is finding #1 across SMB audits. Run: Get-ADGroupMember "Domain Admins" -Recursive | Where { $_.objectClass -eq "user" } | ForEach { Get-ADUser $_ -Properties PasswordLastSet,Description,ServicePrincipalName } | Where { $_.ServicePrincipalName -or $_.Description -match "service|svc|sql|backup" } | Select Name,PasswordLastSet. If you find service accounts in DA with passwords set years ago, the password is almost certainly weak. Common passwords: CompanyName + Year (Acme2019), Season + Year (Summer2023), Password1, Welcome1, or the account name itself. This is how most real-world breaches escalate to full domain compromise. Kerberoasting attacks specifically target service accounts with SPNs. Recommend: remove from DA, set 25+ character random passwords, use Group Managed Service Accounts (gMSA) where possible.'
                Compliance='NIST CSF PR.AC-1, PR.AC-4 | CIS Control 5.2, 5.4, 5.5 | HIPAA 164.312(a)(1), 164.312(d)'
            }
            @{
                ID='CF02'; Severity='Critical'; Weight=10
                Text='No egress filtering configured on the firewall'
                Hint='This means the firewall allows ALL outbound traffic. Log into the firewall and check the outbound/LAN-to-WAN rules. If there is a single "Allow All" rule for outbound traffic with no restrictions, flag it. Why this matters: when malware infects a workstation, it needs to communicate with its command-and-control (C2) server. With no egress filtering, the malware can use ANY port to call home and exfiltrate data. Proper egress filtering: 1) Allow only needed outbound ports (80, 443, plus documented business needs), 2) Block direct IP connections that bypass DNS, 3) Force DNS through the filtering server. Even basic egress filtering (block everything except 80/443 outbound) would prevent most malware C2 channels. This is one of the highest-impact, lowest-cost improvements an SMB can make.'
                Compliance='NIST CSF PR.AC-5, PR.DS-5 | CIS Control 4.4, 4.5, 9.3 | HIPAA 164.312(e)(1)'
            }
            @{
                ID='CF03'; Severity='Critical'; Weight=10
                Text='Backups exist but have never been restore-tested'
                Hint='Ask the direct question: "When was the last time you performed a test restore from backup? Not a backup verification - an actual restore." If the answer is "never" or "I cannot remember," flag it as critical. Then ask: "How do you know your backups work?" Common response: "The backup software says it completed successfully." Backup software can report success while the data is corrupt, incomplete, or missing critical components. The ONLY way to verify a backup works is to restore it and confirm the data/application is functional. Recommend: perform a test restore during the audit if possible, then establish quarterly test restore schedule. Document: what was tested, how long the restore took (this is the actual RTO), and whether the data was intact.'
                Compliance='NIST CSF PR.IP-4, PR.IP-9 | CIS Control 11.4, 11.5 | HIPAA 164.308(a)(7)(ii)(D)'
            }
            @{
                ID='CF04'; Severity='Critical'; Weight=10
                Text='Former employee accounts remain active in AD/Entra ID'
                Hint='Get the HR termination list and cross-reference with: 1) AD: Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate,WhenCreated | Export-Csv, 2) Entra ID/Azure AD: Get-MgUser -Filter "accountEnabled eq true" | Select DisplayName,UserPrincipalName, 3) M365: Get-Mailbox | Select Alias, 4) VPN: check VPN user list, 5) Any other system with separate authentication. Common finding: 20-50% of employees who left in the last year still have active accounts. This is a critical risk because a disgruntled former employee or an attacker who finds these credentials has full access. Ask: "Is there a documented offboarding checklist? Who is responsible for disabling accounts?" If there is no formal process, recommend one that triggers the same day as separation with IT receiving automated notification from HR.'
                Compliance='NIST CSF PR.AC-1, PR.AC-6 | CIS Control 5.1, 5.3 | HIPAA 164.308(a)(3)(ii)(C), 164.312(a)(2)(ii)'
            }
            @{
                ID='CF05'; Severity='High'; Weight=7
                Text='Temporary firewall rules still in place from 3+ years ago'
                Hint='Export the full firewall rule list and sort by creation date. Flag any rule where: 1) Description contains "temp", "test", "troubleshooting", "vendor", or a person name, 2) Creation date is more than 2 years old, 3) Hit count is zero (rule is not being used), 4) There is no associated change ticket or documentation. Common story: "We opened this port for a vendor 4 years ago to fix something. We meant to close it after but forgot." These forgotten rules are often overly permissive (allow all from vendor IP) and the vendor may have recycled that IP address by now, meaning a random internet host now has access. Document each stale rule and recommend a firewall rule review process: every rule gets a review date, an owner, and an expiration.'
                Compliance='NIST CSF PR.AC-5, ID.AM-4 | CIS Control 4.5 | HIPAA 164.312(e)(1)'
            }
            @{
                ID='CF06'; Severity='High'; Weight=8
                Text='Flat network with no segmentation between workstations and servers'
                Hint='Test this: from a regular user workstation, can you ping the domain controller? The file server? The SQL server? Security cameras? Printers? If the answer is yes to all, the network is flat. Run: tracert to a server IP from a workstation - if it is a direct route (no hops through a firewall/router), there is no segmentation. Also run: arp -a to see what devices are visible on the same broadcast domain. In a flat network, if one workstation gets compromised (phishing email, drive-by download), the attacker can immediately see and reach every server. Proper segmentation forces traffic through a firewall with rules, creating choke points where you can detect and block lateral movement. This is one of the most common and most impactful findings in SMB audits.'
                Compliance='NIST CSF PR.AC-5 | CIS Control 12.2, 12.8 | HIPAA 164.312(e)(1)'
            }
            @{
                ID='CF07'; Severity='High'; Weight=7
                Text='Local admin rights granted broadly without documentation'
                Hint='On 5-10 sample workstations, run: net localgroup Administrators. If you see "Domain Users" or large security groups in the local Administrators group, every user is a local admin. Also check for specific users in the group beyond the built-in Administrator and Domain Admins. Ask IT: "Is there a policy for who gets local admin and how it is approved?" If the answer is "everyone has it because they complained they could not install things," that is the finding. Local admin allows: installing software (including malware), disabling antivirus, accessing other users data on the machine, running credential harvesting tools (Mimikatz), and pivoting to other systems. Recommend: remove local admin for all standard users, implement a self-service elevation tool (MakeMeAdmin, AutoElevate) or a software deployment solution.'
                Compliance='NIST CSF PR.AC-4, PR.AC-6 | CIS Control 5.4, 5.5 | HIPAA 164.312(a)(1)'
            }
            @{
                ID='CF08'; Severity='High'; Weight=7
                Text='No DNS filtering or content filtering in place'
                Hint='Test this from a workstation: run "nslookup" and check what DNS server is being used. If it is the ISP DNS directly (Comcast, AT&T, etc.) or a public resolver (8.8.8.8, 1.1.1.1) with no filtering layer, there is no DNS filtering. Try browsing to a known test malware domain - if it resolves and loads, there is no filtering. DNS filtering is one of the cheapest and most effective security controls: it blocks access to known malware, phishing, and C2 domains before the connection is even established. Solutions: Cisco Umbrella (enterprise, per-user pricing), NextDNS (very affordable for SMBs), Cloudflare Gateway (free tier available), pfBlockerNG (free on pfSense). If the org has none of these, recommend implementing one immediately. It can typically be deployed in under an hour by changing the DHCP DNS settings.'
                Compliance='NIST CSF DE.CM-1, PR.DS-5 | CIS Control 9.2, 9.3 | HIPAA 164.312(e)(1)'
            }
        )
    }
}

# ── Auto-Check Definitions ──────────────────────────────────────────────────
# Each entry maps an audit item ID to a scriptblock that returns:
#   @{ Status='Pass|Fail|Partial'; Findings='text'; Evidence='text' }
# Type: AD = requires domain controller, Local = runs on target endpoint,
#       Remote = runs via Invoke-Command on target
$script:AutoChecks = @{

    # ── Identity & Access ────────────────────────────────────────────────────
    'IA01' = @{ Type='AD'; Label='Scan Privileged Groups + Delegation'
        Script = {
            $groups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators')
            $sb = [System.Text.StringBuilder]::new()
            $totalPriv = 0; $issues = 0
            foreach ($g in $groups) {
                try {
                    $members = Get-ADGroupMember $g -Recursive -EA Stop | Select-Object Name,SamAccountName,objectClass
                    $count = ($members | Measure-Object).Count; $totalPriv += $count
                    [void]$sb.AppendLine("[$g] ($count members):")
                    foreach ($m in $members) { [void]$sb.AppendLine("  $($m.SamAccountName) ($($m.objectClass))") }
                    # CIS: Enterprise Admins and Schema Admins should be empty
                    if ($g -in @('Enterprise Admins','Schema Admins') -and $count -gt 0) {
                        $issues++; [void]$sb.AppendLine("  [!] CIS: $g should be EMPTY except during schema changes")
                    }
                    [void]$sb.AppendLine("")
                } catch { [void]$sb.AppendLine("[$g] Error: $_`n") }
            }
            # Protected Users group check
            try {
                $protectedUsers = (Get-ADGroupMember 'Protected Users' -EA SilentlyContinue | Measure-Object).Count
                [void]$sb.AppendLine("[Protected Users] ($protectedUsers members)")
                if ($protectedUsers -eq 0) { $issues++; [void]$sb.AppendLine("  [!] No privileged accounts in Protected Users group - Tier 0 accounts should be members") }
            } catch { [void]$sb.AppendLine("[Protected Users] Could not query") }
            # Kerberos unconstrained delegation scan
            try {
                $unconst = Get-ADComputer -Filter {TrustedForDelegation -eq $true -and PrimaryGroupID -ne 516} -Properties TrustedForDelegation,OperatingSystem -EA SilentlyContinue
                if ($unconst) {
                    $issues += $unconst.Count
                    [void]$sb.AppendLine("`n[CRITICAL] UNCONSTRAINED DELEGATION ($($unconst.Count) systems):")
                    foreach ($u in $unconst) { [void]$sb.AppendLine("  $($u.Name) | $($u.OperatingSystem)") }
                } else { [void]$sb.AppendLine("`nUnconstrained Delegation: None found (excluding DCs) [OK]") }
                $unconstUsers = Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation -EA SilentlyContinue
                if ($unconstUsers) {
                    $issues += $unconstUsers.Count
                    [void]$sb.AppendLine("[CRITICAL] USER accounts with unconstrained delegation:")
                    foreach ($uu in $unconstUsers) { [void]$sb.AppendLine("  $($uu.SamAccountName)") }
                }
            } catch {}
            $status = if ($issues -eq 0 -and $totalPriv -le 5) {'Pass'} elseif ($issues -eq 0 -and $totalPriv -le 10) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Privileged groups + delegation scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm')" }
        }
    }

    'IA02' = @{ Type='AD'; Label='Scan Service Accounts + Kerberoast Risk'
        Script = {
            $spn = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties PasswordLastSet,PasswordNeverExpires,ServicePrincipalName,MemberOf,Enabled,AdminCount -EA Stop
            $named = Get-ADUser -Filter 'SamAccountName -like "svc*" -or SamAccountName -like "*service*" -or SamAccountName -like "sql*" -or SamAccountName -like "backup*"' -Properties PasswordLastSet,PasswordNeverExpires,MemberOf,Enabled,AdminCount -EA SilentlyContinue
            $all = @($spn) + @($named) | Sort-Object -Property SamAccountName -Unique
            $sb = [System.Text.StringBuilder]::new(); $issues = 0; $kerberoastable = 0
            foreach ($a in $all) {
                $age = if ($a.PasswordLastSet) { ((Get-Date) - $a.PasswordLastSet).Days } else { 9999 }
                $inDA = ($a.MemberOf | Where-Object { $_ -match 'Domain Admins' }).Count -gt 0
                $hasSPN = ($a.ServicePrincipalName | Measure-Object).Count -gt 0
                $flags = @()
                if ($age -gt 365) { $flags += "PW_OLD_${age}d"; $issues++ }
                if ($a.PasswordNeverExpires) { $flags += 'NO_EXPIRE'; $issues++ }
                if ($inDA) { $flags += 'DOMAIN_ADMIN'; $issues++ }
                # Kerberoast risk: user account with SPN + old password + admin = CRITICAL
                if ($hasSPN -and $a.Enabled) {
                    $kerberoastable++
                    $risk = 'LOW'
                    if ($age -gt 365) { $risk = 'MEDIUM' }
                    if ($age -gt 365 -and ($a.AdminCount -eq 1 -or $inDA)) { $risk = 'CRITICAL' }
                    $flags += "KERBEROAST_RISK:$risk"
                    if ($risk -eq 'CRITICAL') { $issues += 2 }
                }
                $f = if ($flags) { " [$(($flags -join ', '))]" } else { '' }
                [void]$sb.AppendLine("$($a.SamAccountName) | Enabled:$($a.Enabled) | PW Age:${age}d$f")
            }
            # gMSA adoption check
            try {
                $gmsa = Get-ADServiceAccount -Filter * -EA SilentlyContinue
                $gmsaCount = ($gmsa | Measure-Object).Count
                [void]$sb.AppendLine("`ngMSA accounts found: $gmsaCount $(if($gmsaCount -eq 0){'[Consider migrating service accounts to gMSA]'}else{'[OK]'})")
            } catch { [void]$sb.AppendLine("`ngMSA: Could not query (requires AD schema support)") }
            [void]$sb.AppendLine("Kerberoastable accounts: $kerberoastable")
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 3) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Service account + Kerberoast scan ($($all.Count) found, $issues issues) @ $(Get-Date -f 'yyyy-MM-dd HH:mm')" }
        }
    }

    'IA04' = @{ Type='AD'; Label='Scan Terminated Accounts'
        Script = {
            $users = Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate,WhenCreated,Description -EA Stop
            $stale90 = $users | Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt (Get-Date).AddDays(-90) } | Sort-Object LastLogonDate
            $neverLogon = $users | Where-Object { -not $_.LastLogonDate } | Sort-Object WhenCreated
            $sb = [System.Text.StringBuilder]::new()
            [void]$sb.AppendLine("ENABLED accounts with NO logon in 90+ days: $($stale90.Count)")
            foreach ($u in ($stale90 | Select-Object -First 20)) { [void]$sb.AppendLine("  $($u.SamAccountName) | Last: $($u.LastLogonDate.ToString('yyyy-MM-dd')) | Created: $($u.WhenCreated.ToString('yyyy-MM-dd'))") }
            if ($stale90.Count -gt 20) { [void]$sb.AppendLine("  ... and $($stale90.Count - 20) more") }
            [void]$sb.AppendLine("`nENABLED accounts that have NEVER logged in: $($neverLogon.Count)")
            foreach ($u in ($neverLogon | Select-Object -First 10)) { [void]$sb.AppendLine("  $($u.SamAccountName) | Created: $($u.WhenCreated.ToString('yyyy-MM-dd'))") }
            $status = if ($stale90.Count -eq 0 -and $neverLogon.Count -eq 0) {'Pass'} elseif ($stale90.Count -le 5) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="AD stale account scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm')" }
        }
    }

    'IA05' = @{ Type='AD'; Label='Scan Password Policy'
        Script = {
            $pol = Get-ADDefaultDomainPasswordPolicy -EA Stop
            $fgpp = Get-ADFineGrainedPasswordPolicy -Filter * -EA SilentlyContinue
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            [void]$sb.AppendLine("DEFAULT DOMAIN PASSWORD POLICY (CIS Benchmarks 2025):")
            # Min Length: CIS requires 14+
            [void]$sb.AppendLine("  Min Length      : $($pol.MinPasswordLength) $(if($pol.MinPasswordLength -lt 14){'[WEAK - CIS requires 14+]'; $issues++} else {'[OK]'})")
            # Complexity
            [void]$sb.AppendLine("  Complexity      : $($pol.ComplexityEnabled) $(if(-not $pol.ComplexityEnabled){'[DISABLED]'; $issues++} else {'[OK]'})")
            # History: CIS requires 24
            [void]$sb.AppendLine("  History Count   : $($pol.PasswordHistoryCount) $(if($pol.PasswordHistoryCount -lt 24){'[LOW - CIS requires 24]'; $issues++} else {'[OK]'})")
            # Max Age
            $maxDays = $pol.MaxPasswordAge.Days
            $maxFlag = if ($maxDays -eq 0) {'[NEVER EXPIRES - passwords should have max age]'; $issues++} elseif ($maxDays -gt 365) {"[>365d - CIS max 365]"; $issues++} else {'[OK]'}
            [void]$sb.AppendLine("  Max Age         : ${maxDays}d $maxFlag")
            # Min Age: CIS requires >= 1 day
            $minDays = $pol.MinPasswordAge.Days
            [void]$sb.AppendLine("  Min Age         : ${minDays}d $(if($minDays -lt 1){'[Should be 1+ day to prevent cycling]'; $issues++} else {'[OK]'})")
            # Lockout Threshold: CIS requires 1-5
            $lockThresh = $pol.LockoutThreshold
            $lockFlag = if ($lockThresh -eq 0) {'[NO LOCKOUT - CRITICAL!]'; $issues += 2} elseif ($lockThresh -gt 5) {"[HIGH - CIS max 5 attempts]"; $issues++} else {'[OK]'}
            [void]$sb.AppendLine("  Lockout Thresh  : $lockThresh $lockFlag")
            # Lockout Duration: CIS requires >= 15 min
            $lockDurMin = $pol.LockoutDuration.TotalMinutes
            $lockDurFlag = if ($lockThresh -gt 0 -and $lockDurMin -lt 15) {"[SHORT - CIS min 15min]"; $issues++} elseif ($lockThresh -eq 0) {'[N/A - no lockout]'} else {'[OK]'}
            [void]$sb.AppendLine("  Lockout Duration: $($pol.LockoutDuration) $lockDurFlag")
            [void]$sb.AppendLine("  Lockout Window  : $($pol.LockoutObservationWindow)")
            # Reversible Encryption: must be disabled
            [void]$sb.AppendLine("  Reversible Enc  : $($pol.ReversibleEncryptionEnabled) $(if($pol.ReversibleEncryptionEnabled){'[CRITICAL - must be disabled!]'; $issues += 2} else {'[OK]'})")
            # Azure AD Password Protection agent
            try {
                $aadPP = Get-Service AzureADPasswordProtectionDCAgent -EA SilentlyContinue
                if ($aadPP -and $aadPP.Status -eq 'Running') { [void]$sb.AppendLine("`nAzure AD Password Protection: Active [OK]") }
                else { [void]$sb.AppendLine("`nAzure AD Password Protection: Not detected") }
            } catch {}
            if ($fgpp) {
                [void]$sb.AppendLine("`nFINE-GRAINED PASSWORD POLICIES:")
                foreach ($f in $fgpp) { [void]$sb.AppendLine("  $($f.Name) | MinLen:$($f.MinPasswordLength) | History:$($f.PasswordHistoryCount) | Complexity:$($f.ComplexityEnabled) | Precedence:$($f.Precedence)") }
            }
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 2) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Password policy scan (CIS 2025) @ $(Get-Date -f 'yyyy-MM-dd HH:mm')" }
        }
    }

    'IA10' = @{ Type='AD'; Label='Scan Inactive Accounts'
        Script = {
            $threshold = (Get-Date).AddDays(-90)
            $inactive = Get-ADUser -Filter {Enabled -eq $true -and LastLogonDate -lt $threshold} -Properties LastLogonDate,Description -EA Stop |
                Sort-Object LastLogonDate | Select-Object -First 30 SamAccountName,Name,LastLogonDate,Description
            $sb = [System.Text.StringBuilder]::new()
            [void]$sb.AppendLine("Enabled accounts with no logon in 90+ days: $($inactive.Count)+ found")
            foreach ($u in $inactive) { [void]$sb.AppendLine("  $($u.SamAccountName) | Last: $(if($u.LastLogonDate){$u.LastLogonDate.ToString('yyyy-MM-dd')}else{'Never'})") }
            $status = if ($inactive.Count -eq 0) {'Pass'} elseif ($inactive.Count -le 5) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Inactive account scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm')" }
        }
    }

    # ── Endpoint Security ────────────────────────────────────────────────────
    'EP01' = @{ Type='Local'; Label='Scan Defender / Endpoint Protection'
        Script = {
            $mp = Get-MpComputerStatus -EA Stop
            $pref = Get-MpPreference -EA SilentlyContinue
            $sigDate = $mp.AntivirusSignatureLastUpdated
            $daysOld = if ($sigDate -is [datetime]) { ((Get-Date) - $sigDate).Days } else { 999 }
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            [void]$sb.AppendLine("CORE PROTECTION:")
            [void]$sb.AppendLine("  AV Enabled        : $($mp.AntivirusEnabled) $(if(-not $mp.AntivirusEnabled){'[DISABLED!]';$issues++} else {'[OK]'})")
            [void]$sb.AppendLine("  Real-Time Protect  : $($mp.RealTimeProtectionEnabled) $(if(-not $mp.RealTimeProtectionEnabled){'[DISABLED!]';$issues++} else {'[OK]'})")
            [void]$sb.AppendLine("  Behavior Monitor   : $($mp.BehaviorMonitorEnabled) $(if(-not $mp.BehaviorMonitorEnabled){'[DISABLED]';$issues++} else {'[OK]'})")
            [void]$sb.AppendLine("  Tamper Protection  : $($mp.IsTamperProtected) $(if(-not $mp.IsTamperProtected){'[NOT PROTECTED]';$issues++} else {'[OK]'})")
            [void]$sb.AppendLine("  Signature Age      : ${daysOld}d $(if($daysOld -gt 7){'[STALE!]';$issues++} else {'[OK]'})")
            [void]$sb.AppendLine("  Signature Updated  : $(if($sigDate -is [datetime]){$sigDate.ToString('yyyy-MM-dd HH:mm')}else{'Unknown'})")
            [void]$sb.AppendLine("  Engine Version     : $($mp.AMEngineVersion)")
            [void]$sb.AppendLine("  Product Version    : $($mp.AMProductVersion)")
            # Defender for Endpoint (MDE) / Sense service
            $mde = Get-Service Sense -EA SilentlyContinue
            if ($mde -and $mde.Status -eq 'Running') { [void]$sb.AppendLine("  MDE Onboarding    : Active (Sense service running) [OK]") }
            elseif ($mde) { [void]$sb.AppendLine("  MDE Onboarding    : Sense service $($mde.Status) [!]") }
            else { [void]$sb.AppendLine("  MDE Onboarding    : Not installed") }
            # AMSI provider check
            try {
                $amsiProviders = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -EA SilentlyContinue
                [void]$sb.AppendLine("  AMSI Providers    : $(if($amsiProviders){$amsiProviders.Count}else{0})")
            } catch {}
            # ASR (Attack Surface Reduction) rules
            if ($pref) {
                [void]$sb.AppendLine("`nATTACK SURFACE REDUCTION (ASR):")
                $asrIds = $pref.AttackSurfaceReductionRules_Ids
                $asrActions = $pref.AttackSurfaceReductionRules_Actions
                if ($asrIds -and $asrIds.Count -gt 0) {
                    $blockCount = 0; $auditCount = 0; $offCount = 0
                    for ($i = 0; $i -lt $asrIds.Count; $i++) {
                        $action = if ($i -lt $asrActions.Count) { $asrActions[$i] } else { 0 }
                        switch ($action) { 1 { $blockCount++ } 2 { $auditCount++ } 6 { $blockCount++ } default { $offCount++ } }
                    }
                    [void]$sb.AppendLine("  Rules configured : $($asrIds.Count) (Block:$blockCount, Audit:$auditCount, Off:$offCount)")
                    if ($blockCount -eq 0) { $issues++; [void]$sb.AppendLine("  [!] No ASR rules in Block mode") }
                } else { $issues++; [void]$sb.AppendLine("  No ASR rules configured [!]") }
                # Controlled Folder Access
                $cfa = $pref.EnableControlledFolderAccess
                $cfaStatus = switch ($cfa) { 1 {'Enabled [OK]'} 2 {'Audit Mode'} default {'Disabled [!]'} }
                [void]$sb.AppendLine("  Controlled Folder : $cfaStatus")
                # Network Protection
                $np = $pref.EnableNetworkProtection
                $npStatus = switch ($np) { 1 {'Enabled (Block) [OK]'} 2 {'Audit Mode'} default {'Disabled [!]'} }
                [void]$sb.AppendLine("  Network Protection: $npStatus")
                # PUA Protection
                $pua = $pref.PUAProtection
                [void]$sb.AppendLine("  PUA Protection    : $(if($pua -eq 1){'Enabled [OK]'}elseif($pua -eq 2){'Audit'}else{'Disabled'})")
                # Cloud Protection
                [void]$sb.AppendLine("  Cloud Protection  : $(if($mp.CloudEnabled -or $pref.MAPSReporting -gt 0){'Enabled [OK]'}else{'Disabled'})")
            }
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 2) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Defender + ASR scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'EP02' = @{ Type='Local'; Label='Scan BitLocker'
        Script = {
            $vols = Get-BitLockerVolume -EA Stop
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            foreach ($v in $vols) {
                $ok = $v.ProtectionStatus -eq 'On' -and $v.VolumeStatus -eq 'FullyEncrypted'
                if (-not $ok) { $issues++ }
                [void]$sb.AppendLine("$($v.MountPoint) | Status:$($v.VolumeStatus) | Protection:$($v.ProtectionStatus) | Method:$($v.EncryptionMethod) $(if($ok){'[OK]'}else{'[ISSUE]'})")
            }
            $status = if ($issues -eq 0 -and $vols.Count -gt 0) {'Pass'} elseif ($vols.Count -eq 0) {'Fail'} else {'Partial'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Get-BitLockerVolume @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'EP03' = @{ Type='Local'; Label='Scan SMB / Protocol Hardening'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # SMBv1 and SMB server configuration
            try {
                $cfg = Get-SmbServerConfiguration -EA Stop
                [void]$sb.AppendLine("SMB SERVER CONFIGURATION:")
                [void]$sb.AppendLine("  SMB1Protocol     : $($cfg.EnableSMB1Protocol) $(if($cfg.EnableSMB1Protocol){'[ENABLED - VULNERABLE!]'; $issues += 2}else{'[OK - Disabled]'})")
                [void]$sb.AppendLine("  SMB2Protocol     : $($cfg.EnableSMB2Protocol)")
                [void]$sb.AppendLine("  EncryptData      : $($cfg.EncryptData) $(if(-not $cfg.EncryptData){'[Should be True for SMB 3.0+ encryption]'; $issues++}else{'[OK]'})")
                [void]$sb.AppendLine("  RejectUnencrypted: $($cfg.RejectUnencryptedAccess) $(if(-not $cfg.RejectUnencryptedAccess){'[Consider enabling]'}else{'[OK]'})")
                # SMB Signing
                [void]$sb.AppendLine("  RequireSign (Srv): $($cfg.RequireSecuritySignature) $(if(-not $cfg.RequireSecuritySignature){'[NOT REQUIRED - relay risk!]'; $issues++}else{'[OK]'})")
                [void]$sb.AppendLine("  EnableSign (Srv) : $($cfg.EnableSecuritySignature)")
            } catch { [void]$sb.AppendLine("SmbServerConfiguration: $_"); $issues++ }
            # SMB Client signing
            try {
                $cliSign = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -EA SilentlyContinue)
                if ($cliSign) {
                    [void]$sb.AppendLine("  RequireSign (Cli): $(if($cliSign.RequireSecuritySignature -eq 1){'True [OK]'}else{'False [!]'; $issues++})")
                }
            } catch {}
            # SMB1 Feature State
            try {
                $feat = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -EA Stop
                [void]$sb.AppendLine("  SMB1 Feature     : $($feat.State) $(if($feat.State -eq 'Enabled'){'[STILL INSTALLED]'}else{'[OK - Removed]'})")
                if ($feat.State -eq 'Enabled') { $issues++ }
            } catch { [void]$sb.AppendLine("  SMB1 Feature     : Not available (may require elevation)") }
            # NTLM Configuration
            [void]$sb.AppendLine("`nNTLM / AUTHENTICATION:")
            try {
                $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -EA SilentlyContinue
                $lmLevel = $lsa.LmCompatibilityLevel
                $lmDesc = switch ($lmLevel) { 0 {'LM & NTLM'} 1 {'LM & NTLM + NTLMv2 session'} 2 {'NTLM only'} 3 {'NTLMv2 only'} 4 {'NTLMv2 only, refuse LM'} 5 {'NTLMv2 only, refuse LM & NTLM'} default {'Not set (OS default)'} }
                $lmFlag = if ($lmLevel -ge 5) {'[OK]'} elseif ($lmLevel -ge 3) {'[PARTIAL - CIS recommends 5]'} else {'[WEAK - CIS requires 5 (NTLMv2 only)]'; $issues++}
                [void]$sb.AppendLine("  LmCompatibility  : $lmLevel ($lmDesc) $lmFlag")
            } catch {}
            # LLMNR (should be disabled)
            try {
                $llmnr = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -EA SilentlyContinue).EnableMulticast
                [void]$sb.AppendLine("  LLMNR            : $(if($llmnr -eq 0){'Disabled [OK]'}else{'Enabled/Not configured [!] - poisoning risk'; $issues++})")
            } catch { [void]$sb.AppendLine("  LLMNR            : Could not query") }
            # NetBIOS over TCP/IP
            try {
                $nbAdapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' -EA SilentlyContinue
                $nbEnabled = @($nbAdapters | Where-Object { $_.TcpipNetbiosOptions -ne 2 })
                [void]$sb.AppendLine("  NetBIOS over TCP : $(if($nbEnabled.Count -eq 0){'Disabled on all adapters [OK]'}else{"Enabled on $($nbEnabled.Count) adapter(s) [!]"; $issues++})")
            } catch {}
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 2) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="SMB/protocol hardening scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'EP04' = @{ Type='Local'; Label='Scan Patch Level'
        Script = {
            $fixes = Get-HotFix -EA Stop | Sort-Object InstalledOn -Descending -EA SilentlyContinue
            $latest = $fixes | Select-Object -First 1
            $sb = [System.Text.StringBuilder]::new()
            $daysSince = if ($latest.InstalledOn) { ((Get-Date) - $latest.InstalledOn).Days } else { 999 }
            [void]$sb.AppendLine("Total patches installed: $($fixes.Count)")
            [void]$sb.AppendLine("Most recent patch      : $($latest.HotFixID) on $(if($latest.InstalledOn){$latest.InstalledOn.ToString('yyyy-MM-dd')}else{'Unknown'}) ($daysSince days ago)")
            [void]$sb.AppendLine("`nLast 10 patches:")
            foreach ($h in ($fixes | Select-Object -First 10)) {
                [void]$sb.AppendLine("  $($h.HotFixID) | $($h.Description) | $(if($h.InstalledOn){$h.InstalledOn.ToString('yyyy-MM-dd')}else{'N/A'})")
            }
            $status = if ($daysSince -le 30) {'Pass'} elseif ($daysSince -le 60) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Get-HotFix @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'EP05' = @{ Type='Local'; Label='Scan Local Admin / Privilege Escalation'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Local admin group members
            try {
                $admins = Get-LocalGroupMember -Group 'Administrators' -EA Stop
                [void]$sb.AppendLine("LOCAL ADMINISTRATORS ($($admins.Count) members):")
                foreach ($m in $admins) {
                    $concern = $m.Name -match 'Domain Users|Everyone|Authenticated Users|Users'
                    if ($concern) { $issues++ }
                    [void]$sb.AppendLine("  $($m.Name) | Type:$($m.ObjectClass) | Source:$($m.PrincipalSource) $(if($concern){'[BROAD ACCESS!]'})")
                }
            } catch {
                $raw = net localgroup Administrators 2>&1 | Where-Object { $_ -and $_ -notmatch '^(The command|Members|---|-$|Alias)' }
                [void]$sb.AppendLine("LOCAL ADMINISTRATORS:")
                foreach ($r in $raw) { if ($r.Trim()) { [void]$sb.AppendLine("  $($r.Trim())") } }
            }
            # Unquoted service paths (privilege escalation)
            [void]$sb.AppendLine("`nUNQUOTED SERVICE PATHS:")
            try {
                $services = Get-CimInstance Win32_Service -EA SilentlyContinue | Where-Object {
                    $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match '\s' -and $_.PathName -notmatch '^[A-Za-z]:\\Windows\\' }
                if ($services) {
                    foreach ($svc in ($services | Select-Object -First 10)) {
                        $issues++
                        [void]$sb.AppendLine("  [!] $($svc.Name): $($svc.PathName)")
                    }
                    if ($services.Count -gt 10) { [void]$sb.AppendLine("  ... +$($services.Count - 10) more") }
                } else { [void]$sb.AppendLine("  None found [OK]") }
            } catch { [void]$sb.AppendLine("  Could not query services") }
            # AlwaysInstallElevated (privesc via MSI)
            [void]$sb.AppendLine("`nALWAYS INSTALL ELEVATED:")
            try {
                $aieLM = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -EA SilentlyContinue).AlwaysInstallElevated
                $aieCU = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -EA SilentlyContinue).AlwaysInstallElevated
                if ($aieLM -eq 1 -and $aieCU -eq 1) {
                    $issues += 2; [void]$sb.AppendLine("  [CRITICAL] AlwaysInstallElevated enabled in BOTH HKLM+HKCU - any user can install as SYSTEM!")
                } elseif ($aieLM -eq 1 -or $aieCU -eq 1) {
                    $issues++; [void]$sb.AppendLine("  [!] AlwaysInstallElevated partially set (HKLM=$aieLM, HKCU=$aieCU)")
                } else { [void]$sb.AppendLine("  Not enabled [OK]") }
            } catch { [void]$sb.AppendLine("  Could not query") }
            # Cached logon count
            try {
                $cached = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -EA SilentlyContinue).CachedLogonsCount
                [void]$sb.AppendLine("`nCached Logons: $cached $(if([int]$cached -gt 4){'[HIGH - CIS recommends 4 or less]'}else{'[OK]'})")
            } catch {}
            # Token privileges: SeImpersonatePrivilege on service accounts (Potato attacks)
            [void]$sb.AppendLine("`nDANGEROUS TOKEN PRIVILEGES:")
            try {
                $dangerousPrivs = @('SeImpersonatePrivilege','SeAssignPrimaryTokenPrivilege','SeTcbPrivilege','SeDebugPrivilege','SeLoadDriverPrivilege','SeRestorePrivilege','SeTakeOwnershipPrivilege')
                $svcAccounts = Get-CimInstance Win32_Service -EA SilentlyContinue | Where-Object { $_.StartName -and $_.StartName -notmatch '^(LocalSystem|NT AUTHORITY|NT SERVICE|LocalService|NetworkService)$' -and $_.State -eq 'Running' } | Select-Object Name,StartName -Unique
                if ($svcAccounts) {
                    foreach ($svc in ($svcAccounts | Select-Object -First 15)) {
                        # Services running as domain/local user accounts with SeImpersonate are Potato-exploitable
                        [void]$sb.AppendLine("  Service: $($svc.Name) runs as $($svc.StartName)")
                    }
                    [void]$sb.AppendLine("  [i] $($svcAccounts.Count) services run as non-built-in accounts - verify these don't have SeImpersonatePrivilege")
                    if ($svcAccounts.Count -gt 3) { $issues++ }
                } else { [void]$sb.AppendLine("  All services run as built-in accounts [OK]") }
                # Check current process token for dangerous privs (shows what this admin session has)
                $myPrivs = whoami /priv /fo csv 2>&1 | ConvertFrom-Csv -EA SilentlyContinue
                if ($myPrivs) {
                    $dangerFound = $myPrivs | Where-Object { $_.'Privilege Name' -in $dangerousPrivs -and $_.State -eq 'Enabled' }
                    if ($dangerFound) {
                        [void]$sb.AppendLine("  Current session elevated privileges:")
                        foreach ($dp in $dangerFound) { [void]$sb.AppendLine("    $($_.'Privilege Name') = Enabled") }
                    }
                }
            } catch { [void]$sb.AppendLine("  Token privilege scan: Could not query") }
            # DLL search order hijacking: writable directories in system PATH
            [void]$sb.AppendLine("`nDLL SEARCH ORDER HIJACKING:")
            try {
                $systemPath = [Environment]::GetEnvironmentVariable('PATH', 'Machine') -split ';' | Where-Object { $_ }
                $writablePaths = @()
                foreach ($dir in $systemPath) {
                    if (-not (Test-Path $dir -EA SilentlyContinue)) { continue }
                    # Skip Windows and Program Files (normally protected)
                    if ($dir -match '^[A-Za-z]:\\(Windows|Program Files)') { continue }
                    try {
                        $acl = Get-Acl $dir -EA SilentlyContinue
                        $builtinUsers = $acl.Access | Where-Object {
                            $_.IdentityReference -match 'BUILTIN\\Users|Everyone|Authenticated Users' -and
                            $_.FileSystemRights -match 'Write|FullControl|Modify' -and
                            $_.AccessControlType -eq 'Allow'
                        }
                        if ($builtinUsers) { $writablePaths += $dir }
                    } catch {}
                }
                if ($writablePaths.Count -gt 0) {
                    $issues += $writablePaths.Count
                    [void]$sb.AppendLine("  [!] Writable directories in system PATH (DLL hijack risk):")
                    foreach ($wp in ($writablePaths | Select-Object -First 10)) { [void]$sb.AppendLine("    $wp") }
                } else { [void]$sb.AppendLine("  No user-writable directories in system PATH [OK]") }
            } catch { [void]$sb.AppendLine("  PATH analysis: Could not check") }
            $status = if ($issues -eq 0 -and $admins.Count -le 3) {'Pass'} elseif ($issues -gt 2) {'Fail'} else {'Partial'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Local admin + privesc scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'EP06' = @{ Type='Local'; Label='Scan Host Firewall + Attack Surface'
        Script = {
            $profiles = Get-NetFirewallProfile -EA Stop
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            [void]$sb.AppendLine("FIREWALL PROFILES:")
            foreach ($p in $profiles) {
                $ok = $p.Enabled
                if (-not $ok) { $issues++ }
                $outBlock = $p.DefaultOutboundAction -eq 'Block'
                [void]$sb.AppendLine("  $($p.Name): Enabled=$($p.Enabled) | InDefault=$($p.DefaultInboundAction) | OutDefault=$($p.DefaultOutboundAction) $(if(-not $ok){'[DISABLED!]'}elseif($outBlock){'[OK - outbound filtered]'}else{'[Outbound=Allow]'})")
                # CIS: Firewall log size >= 16,384 KB per profile
                $logSize = $p.LogMaxSizeKilobytes
                $logOk = $logSize -ge 16384
                if (-not $logOk -and $ok) { $issues++ }
                [void]$sb.AppendLine("    Log Size: ${logSize} KB $(if($logOk){'[OK]'}else{"[LOW - CIS requires 16,384+ KB]"}) | LogBlocked: $($p.LogBlocked) | LogAllowed: $($p.LogAllowed)")
            }
            # Inbound allow rule summary
            $inboundAllow = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -EA SilentlyContinue | Measure-Object
            [void]$sb.AppendLine("`nInbound Allow rules (enabled): $($inboundAllow.Count)")
            # High-risk inbound ports check
            $riskyPorts = @(21,23,69,135,139,445,1433,3389,5900,5985,5986)
            $riskyOpen = @()
            foreach ($port in $riskyPorts) {
                $found = Get-NetFirewallPortFilter -EA SilentlyContinue | Where-Object { $_.LocalPort -eq $port } |
                    Get-NetFirewallRule -EA SilentlyContinue | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' }
                if ($found) { $riskyOpen += $port }
            }
            if ($riskyOpen.Count -gt 0) {
                [void]$sb.AppendLine("[!] High-risk inbound ports allowed: $($riskyOpen -join ', ')")
            }
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 1) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Host firewall + attack surface scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'EP09' = @{ Type='Local'; Label='Scan AutoRun/AutoPlay'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            $paths = @(
                @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer';Scope='Machine'}
                @{Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer';Scope='User'}
            )
            foreach ($p in $paths) {
                try {
                    $val = (Get-ItemProperty $p.Path -Name NoDriveTypeAutoRun -EA Stop).NoDriveTypeAutoRun
                    $disabled = $val -eq 255
                    if (-not $disabled) { $issues++ }
                    [void]$sb.AppendLine("$($p.Scope) NoDriveTypeAutoRun: $val $(if($disabled){'[OK - All disabled]'}else{'[NOT FULLY DISABLED]'})")
                } catch {
                    $issues++
                    [void]$sb.AppendLine("$($p.Scope) NoDriveTypeAutoRun: NOT SET [AutoRun may be enabled]")
                }
            }
            try {
                $gp = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoAutorun -EA SilentlyContinue
                [void]$sb.AppendLine("NoAutorun policy    : $(if($gp.NoAutorun -eq 1){'Enabled [OK]'}else{'Not set'})")
            } catch {}
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -eq 1) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="AutoRun registry scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'EP10' = @{ Type='AD'; Label='Scan EOL Operating Systems'
        Script = {
            $comps = Get-ADComputer -Filter {Enabled -eq $true} -Properties OperatingSystem,OperatingSystemVersion,LastLogonDate -EA Stop
            $eolPatterns = @('Windows XP','Windows Vista','Windows 7','Windows 8','Server 2003','Server 2008','Server 2012')
            $sb = [System.Text.StringBuilder]::new(); $eolCount = 0
            $grouped = $comps | Group-Object OperatingSystem | Sort-Object Count -Descending
            [void]$sb.AppendLine("OS DISTRIBUTION ($($comps.Count) total computers):")
            foreach ($g in $grouped) {
                $isEOL = $eolPatterns | Where-Object { $g.Name -match [regex]::Escape($_) }
                if ($isEOL) { $eolCount += $g.Count }
                [void]$sb.AppendLine("  $($g.Count.ToString().PadLeft(4)) x $($g.Name) $(if($isEOL){'[END OF LIFE!]'})")
            }
            if ($eolCount -gt 0) {
                [void]$sb.AppendLine("`nEOL SYSTEMS ($eolCount):")
                $eolSystems = $comps | Where-Object { $eolPatterns | Where-Object { $_.OperatingSystem -match [regex]::Escape($_) } } | Select-Object -First 20
                foreach ($c in $eolSystems) { [void]$sb.AppendLine("  $($c.Name) | $($c.OperatingSystem) | Last logon: $(if($c.LastLogonDate){$c.LastLogonDate.ToString('yyyy-MM-dd')}else{'Never'})") }
            }
            $status = if ($eolCount -eq 0) {'Pass'} elseif ($eolCount -le 3) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="AD computer OS scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm')" }
        }
    }

    # ── Logging & Monitoring ─────────────────────────────────────────────────
    'LM03' = @{ Type='Local'; Label='Scan Audit Policy + PowerShell Logging'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Check legacy audit policy override prerequisite
            try {
                $scenoLegacy = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -EA SilentlyContinue).SCENoApplyLegacyAuditPolicy
                if ($scenoLegacy -ne 1) { [void]$sb.AppendLine("[!] SCENoApplyLegacyAuditPolicy not set - advanced audit may be overridden by basic policy") }
            } catch {}
            # Parse audit policy via CSV for reliable subcategory checking
            [void]$sb.AppendLine("ADVANCED AUDIT POLICY (CIS Required Subcategories):")
            try {
                $csvRaw = auditpol /get /category:* /r 2>&1
                $auditData = $csvRaw | ConvertFrom-Csv -EA Stop
                # CIS-required subcategories and their minimum setting
                $cisRequired = @{
                    'Credential Validation' = 'Success and Failure'
                    'Application Group Management' = 'Success and Failure'
                    'Security Group Management' = 'Success and Failure'
                    'User Account Management' = 'Success and Failure'
                    'Computer Account Management' = 'Success'
                    'Logon' = 'Success and Failure'
                    'Logoff' = 'Success'
                    'Account Lockout' = 'Failure'
                    'Special Logon' = 'Success'
                    'Audit Policy Change' = 'Success'
                    'Authentication Policy Change' = 'Success'
                    'Sensitive Privilege Use' = 'Success and Failure'
                    'System Integrity' = 'Success and Failure'
                    'Security State Change' = 'Success'
                    'Security System Extension' = 'Success'
                    'Other Object Access Events' = 'Success and Failure'
                    'Removable Storage' = 'Success and Failure'
                    'Process Creation' = 'Success'
                }
                foreach ($sub in $cisRequired.Keys) {
                    $entry = $auditData | Where-Object { $_.Subcategory -match [regex]::Escape($sub) } | Select-Object -First 1
                    if ($entry) {
                        $setting = $entry.'Inclusion Setting'
                        $noAudit = $setting -match 'No Auditing'
                        if ($noAudit) { $issues++; [void]$sb.AppendLine("  [!] $sub : No Auditing [FAIL]") }
                    }
                }
                $noAuditCount = ($auditData | Where-Object { $_.'Inclusion Setting' -match 'No Auditing' }).Count
                $totalSubs = $auditData.Count
                [void]$sb.AppendLine("  Subcategories audited: $($totalSubs - $noAuditCount)/$totalSubs")
            } catch {
                # Fallback to text parsing
                $raw = auditpol /get /category:* 2>&1
                $critical = @('Logon','Account Logon','Account Management','Object Access','Policy Change','Privilege Use')
                $current = ''
                foreach ($line in $raw) {
                    $l = $line.ToString().Trim()
                    if ($l -match '^[A-Z]') { $current = $l }
                    if ($l -match 'No Auditing' -and ($critical | Where-Object { $current -match $_ })) {
                        $issues++; [void]$sb.AppendLine("  [!] $current > $l")
                    }
                }
            }
            if ($issues -eq 0) { [void]$sb.AppendLine("  All CIS-required subcategories have auditing enabled. [OK]") }
            # PowerShell logging
            [void]$sb.AppendLine("`nPOWERSHELL LOGGING:")
            try {
                $psScriptBlock = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -EA SilentlyContinue).EnableScriptBlockLogging
                $psModule = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -EA SilentlyContinue).EnableModuleLogging
                $psTranscript = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -EA SilentlyContinue).EnableTranscripting
                [void]$sb.AppendLine("  Script Block Logging : $(if($psScriptBlock -eq 1){'Enabled [OK]'}else{'Disabled [!]'; $issues++})")
                [void]$sb.AppendLine("  Module Logging       : $(if($psModule -eq 1){'Enabled [OK]'}else{'Disabled [!]'; $issues++})")
                [void]$sb.AppendLine("  Transcription        : $(if($psTranscript -eq 1){'Enabled [OK]'}else{'Disabled'})")
            } catch {}
            # Command-line process auditing
            try {
                $cmdLine = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -EA SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
                [void]$sb.AppendLine("  Cmd-line in 4688    : $(if($cmdLine -eq 1){'Enabled [OK]'}else{'Disabled [!]'; $issues++})")
            } catch { [void]$sb.AppendLine("  Cmd-line in 4688    : Not configured") }
            # PowerShell v2 engine (AMSI bypass risk)
            try {
                $psv2 = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -EA SilentlyContinue).State
                [void]$sb.AppendLine("  PowerShell v2 Engine : $(if($psv2 -eq 'Enabled'){'Installed [!] - AMSI bypass risk, remove if not needed'; $issues++}else{'Removed [OK]'})")
            } catch {}
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 3) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Audit policy + PS logging scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'LM05' = @{ Type='Local'; Label='Scan Failed Logons'
        Script = {
            $sb = [System.Text.StringBuilder]::new()
            try {
                $events = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddDays(-7)} -MaxEvents 100 -EA Stop
                [void]$sb.AppendLine("Failed logon events (4625) in last 7 days: $($events.Count)+ found")
                $byUser = $events | ForEach-Object {
                    $xml = [xml]$_.ToXml(); $user = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                    $ip = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                    [PSCustomObject]@{User=$user;IP=$ip}
                } | Group-Object User | Sort-Object Count -Descending | Select-Object -First 10
                [void]$sb.AppendLine("`nTop accounts by failed attempts:")
                foreach ($u in $byUser) { [void]$sb.AppendLine("  $($u.Count.ToString().PadLeft(4))x $($u.Name)") }
                $highCount = ($byUser | Where-Object { $_.Count -ge 20 }).Count
                $status = if ($events.Count -le 10) {'Pass'} elseif ($highCount -gt 0) {'Fail'} else {'Partial'}
            } catch {
                [void]$sb.AppendLine("No failed logon events found in last 7 days (or access denied)")
                $status = 'Pass'
            }
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Event 4625 scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    # ── Common Findings ──────────────────────────────────────────────────────
    'CF01' = @{ Type='AD'; Label='Scan Privileged Service Accounts'
        Script = {
            $da = Get-ADGroupMember 'Domain Admins' -Recursive -EA Stop | Where-Object { $_.objectClass -eq 'user' }
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            foreach ($m in $da) {
                $u = Get-ADUser $m -Properties PasswordLastSet,ServicePrincipalName,PasswordNeverExpires -EA SilentlyContinue
                if (-not $u) { continue }
                $isSvc = $u.SamAccountName -match 'svc|service|sql|backup' -or $u.ServicePrincipalName
                if ($isSvc) {
                    $age = if ($u.PasswordLastSet) { ((Get-Date) - $u.PasswordLastSet).Days } else { 9999 }
                    $issues++
                    [void]$sb.AppendLine("[!] $($u.SamAccountName) | DA + Service Account | PW Age: ${age}d | NeverExpires: $($u.PasswordNeverExpires)")
                }
            }
            if ($issues -eq 0) { [void]$sb.AppendLine("No service accounts found in Domain Admins. Good.") }
            # gMSA adoption check
            try {
                $gmsa = Get-ADServiceAccount -Filter * -Properties PasswordLastSet,Enabled,PrincipalsAllowedToRetrieveManagedPassword -EA SilentlyContinue
                $gmsaCount = ($gmsa | Measure-Object).Count
                [void]$sb.AppendLine("`ngMSA ACCOUNTS: $gmsaCount found")
                if ($gmsaCount -gt 0) {
                    foreach ($g in ($gmsa | Select-Object -First 10)) { [void]$sb.AppendLine("  $($g.SamAccountName) | Enabled:$($g.Enabled)") }
                } else { [void]$sb.AppendLine("  No gMSA accounts - consider migrating service accounts to gMSA for automatic password rotation") }
            } catch {}
            # GPP password check (cpassword in SYSVOL)
            if ($script:Env.DomainName) {
                try {
                    $sysvolPath = "\\$($script:Env.DomainName)\SYSVOL\$($script:Env.DomainName)\Policies"
                    $gppFiles = @('Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Drives.xml')
                    $gppFound = @()
                    foreach ($gppFile in $gppFiles) {
                        $matches = Get-ChildItem $sysvolPath -Recurse -Filter $gppFile -EA SilentlyContinue | Select-String 'cpassword' -EA SilentlyContinue
                        if ($matches) { $gppFound += "$gppFile ($($matches.Count) entries)" }
                    }
                    if ($gppFound.Count -gt 0) {
                        $issues += 2
                        [void]$sb.AppendLine("`n[CRITICAL] GPP PASSWORDS IN SYSVOL (trivially decryptable):")
                        foreach ($g in $gppFound) { [void]$sb.AppendLine("  $g") }
                    } else { [void]$sb.AppendLine("`nGPP Passwords: None found in SYSVOL [OK]") }
                } catch { [void]$sb.AppendLine("`nGPP Passwords: Could not scan SYSVOL") }
            }
            # ADCS (Active Directory Certificate Services) vulnerability scan
            if ($script:Env.HasAD) {
                [void]$sb.AppendLine("`nAD CERTIFICATE SERVICES (ADCS):")
                try {
                    $configNC = (Get-ADRootDSE -EA Stop).configurationNamingContext
                    # Find Enterprise CAs
                    $cas = Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC" -Filter {objectClass -eq 'pKIEnrollmentService'} -Properties * -EA SilentlyContinue
                    if ($cas) {
                        foreach ($ca in $cas) {
                            [void]$sb.AppendLine("  CA: $($ca.Name) | DNS: $($ca.dNSHostName)")
                        }
                        # ESC1: Templates allowing SAN (Subject Alternative Name) from requester
                        $templates = Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC" -Filter {objectClass -eq 'pKICertificateTemplate'} -Properties * -EA SilentlyContinue
                        $esc1Count = 0; $esc6Count = 0
                        foreach ($tmpl in $templates) {
                            # ESC1: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (bit 0x00000001) in msPKI-Certificate-Name-Flag
                            $nameFlag = $tmpl.'msPKI-Certificate-Name-Flag'
                            $enrolleeSAN = ($nameFlag -band 1) -eq 1
                            # Check if template allows client auth EKU
                            $ekus = $tmpl.'pKIExtendedKeyUsage'
                            $clientAuth = $ekus -contains '1.3.6.1.5.5.7.3.2'  # Client Authentication
                            $anyPurpose = $ekus -contains '2.5.29.37.0'         # Any Purpose
                            $hasAuthEKU = $clientAuth -or $anyPurpose -or ($ekus.Count -eq 0)
                            if ($enrolleeSAN -and $hasAuthEKU) {
                                $esc1Count++
                                if ($esc1Count -le 5) { [void]$sb.AppendLine("  [CRITICAL] ESC1: $($tmpl.Name) - enrollee supplies SAN + client auth") }
                            }
                            # ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag (checked at CA level below)
                        }
                        if ($esc1Count -gt 5) { [void]$sb.AppendLine("  ... +$($esc1Count - 5) more ESC1 templates") }
                        if ($esc1Count -gt 0) { $issues += 2 }
                        else { [void]$sb.AppendLine("  ESC1 (enrollee SAN + auth): None found [OK]") }
                        # ESC6: Check CA for EDITF_ATTRIBUTESUBJECTALTNAME2 via registry (if local CA)
                        try {
                            $caEditFlags = (certutil -getreg policy\EditFlags 2>&1) -join ' '
                            if ($caEditFlags -match 'EDITF_ATTRIBUTESUBJECTALTNAME2') {
                                $issues += 2
                                [void]$sb.AppendLine("  [CRITICAL] ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 enabled on local CA - any cert can specify SAN!")
                            } else { [void]$sb.AppendLine("  ESC6 (SAN edit flag on CA): Not detected on this host [OK*] (*check all CA servers)") }
                        } catch { [void]$sb.AppendLine("  ESC6: Could not check (not a CA server or certutil unavailable)") }
                        # ESC8: HTTP enrollment endpoints (NTLM relay to web enrollment)
                        try {
                            $webEnroll = Get-Service CertSvc -EA SilentlyContinue
                            if ($webEnroll -and $webEnroll.Status -eq 'Running') {
                                $httpBinding = netsh http show sslcert 2>&1 | Select-String 'certsrv' -EA SilentlyContinue
                                if (-not $httpBinding) {
                                    $issues++
                                    [void]$sb.AppendLine("  [HIGH] ESC8: Certificate web enrollment may be on HTTP (NTLM relay risk)")
                                }
                            }
                        } catch {}
                        # ESC10: Certificate mapping - StrongCertificateBindingEnforcement
                        try {
                            $certBinding = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -EA SilentlyContinue).StrongCertificateBindingEnforcement
                            $cbStatus = switch ($certBinding) { 0 {'Disabled [CRITICAL - vulnerable to ESC10]'; $issues += 2} 1 {'Compatibility mode [!]'; $issues++} 2 {'Full enforcement [OK]'} default {'Not set (default behavior)'} }
                            [void]$sb.AppendLine("  ESC10 (StrongCertificateBinding): $cbStatus")
                        } catch {}
                    } else { [void]$sb.AppendLine("  No Enterprise CAs found in AD") }
                } catch { [void]$sb.AppendLine("  ADCS scan: Could not query ($($_.Exception.Message))") }
                # LDAP Signing + Channel Binding (DC relay protection)
                [void]$sb.AppendLine("`nLDAP SIGNING / CHANNEL BINDING:")
                try {
                    $ldapSigning = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -EA SilentlyContinue).LDAPServerIntegrity
                    $ldapSignStatus = switch ($ldapSigning) { 0 {'None [CRITICAL - unsigned LDAP allowed]'; $issues += 2} 1 {'Negotiated (default)'} 2 {'Required [OK]'} default {'Not set (default=negotiated)'} }
                    [void]$sb.AppendLine("  LDAP Server Signing: $ldapSignStatus")
                } catch { [void]$sb.AppendLine("  LDAP Signing: Could not query (may not be a DC)") }
                try {
                    $channelBind = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -EA SilentlyContinue).LdapEnforceChannelBinding
                    $cbStatus = switch ($channelBind) { 0 {'Never [!] - LDAP relay vulnerable'; $issues++} 1 {'When supported'} 2 {'Always [OK]'} default {'Not set (default=never)'; $issues++} }
                    [void]$sb.AppendLine("  LDAP Channel Binding: $cbStatus")
                } catch {}
                # DSRM (Directory Services Restore Mode) admin logon behavior
                try {
                    $dsrm = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -EA SilentlyContinue).DsrmAdminLogonBehavior
                    if ($dsrm -eq 2) {
                        $issues += 2
                        [void]$sb.AppendLine("  [CRITICAL] DsrmAdminLogonBehavior=2: DSRM account can logon at any time (DC persistence backdoor!)")
                    } elseif ($dsrm -eq 1) {
                        $issues++
                        [void]$sb.AppendLine("  [!] DsrmAdminLogonBehavior=1: DSRM account can logon when NTDS service is stopped")
                    } else { [void]$sb.AppendLine("  DsrmAdminLogonBehavior: $dsrm (default - DSRM only in restore mode) [OK]") }
                } catch {}
            }
            $status = if ($issues -eq 0) {'Pass'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="DA svc + gMSA + GPP + ADCS + LDAP scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm')" }
        }
    }

    'CF07' = @{ Type='Local'; Label='Scan Local Admin Rights'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $broadAccess = $false
            try {
                $admins = Get-LocalGroupMember -Group 'Administrators' -EA Stop
                [void]$sb.AppendLine("Local Administrators ($($admins.Count) members):")
                foreach ($m in $admins) {
                    $broad = $m.Name -match 'Domain Users|Everyone|Authenticated Users|^Users$'
                    if ($broad) { $broadAccess = $true }
                    [void]$sb.AppendLine("  $($m.Name) ($($m.ObjectClass)) $(if($broad){'[OVERLY BROAD!]'})")
                }
            } catch { [void]$sb.AppendLine("Could not enumerate local admins: $_") }
            $status = if ($broadAccess) {'Fail'} elseif ($admins.Count -gt 4) {'Partial'} else {'Pass'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Local admin audit @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    # ── Phase 2 Auto-Checks ──────────────────────────────────────────────────

    'NP01' = @{ Type='Local'; Label='Scan Firewall Rules'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            $rules = Get-NetFirewallRule -Enabled True -EA Stop
            $inbound = $rules | Where-Object { $_.Direction -eq 'Inbound' }
            $outbound = $rules | Where-Object { $_.Direction -eq 'Outbound' }
            [void]$sb.AppendLine("FIREWALL RULES SUMMARY:")
            [void]$sb.AppendLine("  Total enabled  : $($rules.Count)")
            [void]$sb.AppendLine("  Inbound Allow  : $(($inbound | Where-Object Action -eq 'Allow').Count)")
            [void]$sb.AppendLine("  Inbound Block  : $(($inbound | Where-Object Action -eq 'Block').Count)")
            [void]$sb.AppendLine("  Outbound Allow : $(($outbound | Where-Object Action -eq 'Allow').Count)")
            [void]$sb.AppendLine("  Outbound Block : $(($outbound | Where-Object Action -eq 'Block').Count)")
            # Check for any/any rules (inbound allow with no port restriction)
            $anyAny = @()
            foreach ($r in ($inbound | Where-Object Action -eq 'Allow')) {
                $ports = ($r | Get-NetFirewallPortFilter -EA SilentlyContinue)
                $addr = ($r | Get-NetFirewallAddressFilter -EA SilentlyContinue)
                if ($ports.LocalPort -eq 'Any' -and $addr.RemoteAddress -eq 'Any') {
                    $anyAny += $r; $issues++
                }
            }
            if ($anyAny.Count -gt 0) {
                [void]$sb.AppendLine("`n[!] INBOUND ANY/ANY ALLOW RULES ($($anyAny.Count)):")
                foreach ($a in ($anyAny | Select-Object -First 15)) { [void]$sb.AppendLine("  $($a.DisplayName) | Profile:$($a.Profile) | Program:$($a.Program)") }
            } else { [void]$sb.AppendLine("`nNo inbound any/any allow rules found. Good.") }
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 3) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Get-NetFirewallRule scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'IA07' = @{ Type='AD'; Label='Scan Shared/Generic Accounts'
        Script = {
            $patterns = @('shared','generic','admin','scanner','reception','front*desk','warehouse','conference','kiosk','training','test','temp')
            $sb = [System.Text.StringBuilder]::new(); $found = 0
            foreach ($p in $patterns) {
                $accts = Get-ADUser -Filter "SamAccountName -like '*$p*' -or Name -like '*$p*'" -Properties Enabled,LastLogonDate,Description,PasswordLastSet -EA SilentlyContinue
                foreach ($a in $accts) {
                    $found++
                    $age = if ($a.PasswordLastSet) { ((Get-Date) - $a.PasswordLastSet).Days } else { 9999 }
                    [void]$sb.AppendLine("$($a.SamAccountName) | Enabled:$($a.Enabled) | PW Age:${age}d | Last:$(if($a.LastLogonDate){$a.LastLogonDate.ToString('yyyy-MM-dd')}else{'Never'}) | Desc:$($a.Description)")
                }
            }
            if ($found -eq 0) { [void]$sb.AppendLine("No shared/generic accounts found by pattern matching.") }
            else { [void]$sb.Insert(0, "Potential shared/generic accounts ($found found):`n") }
            $status = if ($found -eq 0) {'Pass'} elseif ($found -le 3) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="AD shared account scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm')" }
        }
    }

    'IA08' = @{ Type='AD'; Label='Scan Guest/Vendor Accounts'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            $patterns = @('vendor','contractor','consultant','extern','guest','partner','3rdparty','thirdparty')
            $vendorAccts = @()
            foreach ($p in $patterns) {
                $vendorAccts += Get-ADUser -Filter "SamAccountName -like '*$p*' -or Name -like '*$p*' -or Description -like '*$p*'" -Properties Enabled,AccountExpirationDate,LastLogonDate,Description -EA SilentlyContinue
            }
            $vendorAccts = $vendorAccts | Sort-Object -Property SamAccountName -Unique
            # Also find accounts WITH expiration dates (common for vendors)
            $expiring = Get-ADUser -Filter {AccountExpirationDate -ne "$null"} -Properties AccountExpirationDate,Enabled,LastLogonDate -EA SilentlyContinue
            [void]$sb.AppendLine("VENDOR/GUEST ACCOUNTS BY NAME ($($vendorAccts.Count) found):")
            foreach ($a in $vendorAccts) {
                $noExpiry = -not $a.AccountExpirationDate
                $expired = $a.AccountExpirationDate -and $a.AccountExpirationDate -lt (Get-Date)
                $flags = @()
                if ($a.Enabled -and $noExpiry) { $flags += 'NO_EXPIRY'; $issues++ }
                if ($a.Enabled -and $expired) { $flags += 'EXPIRED_BUT_ENABLED'; $issues++ }
                $f = if ($flags) { " [$(($flags -join ', '))]" } else { '' }
                [void]$sb.AppendLine("  $($a.SamAccountName) | Enabled:$($a.Enabled) | Expires:$(if($a.AccountExpirationDate){$a.AccountExpirationDate.ToString('yyyy-MM-dd')}else{'NEVER'})$f")
            }
            [void]$sb.AppendLine("`nACCOUNTS WITH EXPIRATION DATES: $($expiring.Count)")
            $status = if ($issues -eq 0 -and $vendorAccts.Count -eq 0) {'Pass'} elseif ($issues -eq 0) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="AD guest/vendor scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm')" }
        }
    }

    'EP07' = @{ Type='Local'; Label='Scan Application Control + Macro Policy'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # AppLocker
            try {
                $policy = Get-AppLockerPolicy -Effective -EA Stop
                $rules = $policy.RuleCollections
                [void]$sb.AppendLine("APPLOCKER POLICY DETECTED:")
                foreach ($rc in $rules) {
                    [void]$sb.AppendLine("  Collection: $($rc.RuleCollectionType) ($($rc.Count) rules)")
                    foreach ($r in ($rc | Select-Object -First 5)) { [void]$sb.AppendLine("    $($r.Name) | Action:$($r.Action) | Type:$($r.GetType().Name)") }
                    if ($rc.Count -gt 5) { [void]$sb.AppendLine("    ... +$($rc.Count - 5) more") }
                }
            } catch {
                [void]$sb.AppendLine("AppLocker: NOT configured on this system.")
                $issues++
            }
            # WDAC (Windows Defender Application Control) - check for active code integrity policy
            [void]$sb.AppendLine("`nWDAC / CODE INTEGRITY:")
            try {
                $ciPolicy = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -EA SilentlyContinue
                if ($ciPolicy) {
                    $ciStatus = $ciPolicy.CodeIntegrityPolicyEnforcementStatus
                    $umci = $ciPolicy.UsermodeCodeIntegrityPolicyEnforcementStatus
                    [void]$sb.AppendLine("  Kernel CI Enforcement: $(switch($ciStatus){ 0 {'Off'} 1 {'Audit'} 2 {'Enforced [OK]'} default {'Unknown'} })")
                    [void]$sb.AppendLine("  User-mode CI (UMCI) : $(switch($umci){ 0 {'Off'} 1 {'Audit'} 2 {'Enforced [OK]'} default {'Unknown'} })")
                }
            } catch { [void]$sb.AppendLine("  WDAC: Could not query DeviceGuard WMI") }
            # Check for CI policy files
            try {
                $sipolicy = Test-Path "$env:SystemRoot\System32\CodeIntegrity\SIPolicy.p7b" -EA SilentlyContinue
                $cipolicies = Get-ChildItem "$env:SystemRoot\System32\CodeIntegrity\CIPolicies\Active\*.cip" -EA SilentlyContinue
                if ($sipolicy -or $cipolicies) { [void]$sb.AppendLine("  CI Policy files found: SIPolicy.p7b=$sipolicy, CIP files=$($cipolicies.Count)") }
                else { [void]$sb.AppendLine("  No WDAC policy files deployed") }
            } catch {}
            # Office macro restrictions (VBA Warnings via GPO registry)
            [void]$sb.AppendLine("`nOFFICE MACRO RESTRICTIONS:")
            $officeVersions = @('16.0','15.0')  # Office 2016/365, Office 2013
            $officeApps = @(
                @{App='Word'; Key='word'}; @{App='Excel'; Key='excel'}
                @{App='PowerPoint'; Key='powerpoint'}; @{App='Outlook'; Key='outlook'}
            )
            $macroConfigured = $false; $macroBlocked = $false
            foreach ($ver in $officeVersions) {
                foreach ($app in $officeApps) {
                    $policyPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\$ver\$($app.Key)\security"
                    $vbaWarning = (Get-ItemProperty $policyPath -Name 'VBAWarnings' -EA SilentlyContinue).VBAWarnings
                    $blockExec = (Get-ItemProperty $policyPath -Name 'blockcontentexecutionfrominternet' -EA SilentlyContinue).blockcontentexecutionfrominternet
                    if ($vbaWarning) {
                        $macroConfigured = $true
                        $vbaDesc = switch ($vbaWarning) { 1 {'Enable all (DANGEROUS!)'} 2 {'Disable with notification (default)'} 3 {'Disable except digitally signed'} 4 {'Disable all [SECURE]'} default {"Unknown ($vbaWarning)"} }
                        if ($vbaWarning -le 1) { $issues++ }
                        if ($vbaWarning -ge 3) { $macroBlocked = $true }
                        [void]$sb.AppendLine("  $($app.App) $ver VBAWarnings: $vbaDesc")
                    }
                    if ($blockExec -eq 1) { $macroBlocked = $true }
                }
            }
            # Machine-level macro policy (GPO: Computer Config)
            foreach ($ver in $officeVersions) {
                foreach ($app in $officeApps) {
                    $machinePath = "HKLM:\SOFTWARE\Policies\Microsoft\Office\$ver\$($app.Key)\security"
                    $vbaWarning = (Get-ItemProperty $machinePath -Name 'VBAWarnings' -EA SilentlyContinue).VBAWarnings
                    if ($vbaWarning) {
                        $macroConfigured = $true
                        $vbaDesc = switch ($vbaWarning) { 1 {'Enable all (DANGEROUS!)'} 2 {'Disable with notification'} 3 {'Disable except signed'} 4 {'Disable all [SECURE]'} default {"Unknown"} }
                        if ($vbaWarning -ge 3) { $macroBlocked = $true }
                        [void]$sb.AppendLine("  $($app.App) $ver (Machine): $vbaDesc")
                    }
                }
            }
            # Block macros from internet (Office 2016+ feature)
            foreach ($ver in $officeVersions) {
                foreach ($app in $officeApps) {
                    foreach ($hive in @('HKCU:','HKLM:')) {
                        $blockInet = (Get-ItemProperty "$hive\SOFTWARE\Policies\Microsoft\Office\$ver\$($app.Key)\security" -Name 'blockcontentexecutionfrominternet' -EA SilentlyContinue).blockcontentexecutionfrominternet
                        if ($blockInet -eq 1) {
                            $macroBlocked = $true
                            [void]$sb.AppendLine("  $($app.App) ${ver}: Block macros from internet = Enabled [OK]")
                            break
                        }
                    }
                }
            }
            if (-not $macroConfigured) {
                $issues++
                [void]$sb.AppendLine("  No Office macro GPO restrictions detected [!]")
                [void]$sb.AppendLine("  Recommend: Set VBAWarnings=4 or blockcontentexecutionfrominternet=1 via GPO")
            }
            if ($issues -eq 0 -and $macroBlocked) { $status = 'Pass' }
            elseif ($issues -eq 0) { $status = 'Partial' }
            else { $status = 'Fail' }
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="AppLocker + WDAC + macro scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'LM01' = @{ Type='Local'; Label='Scan DNS Logging'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Check if DNS Server role is installed
            try {
                $dns = Get-DnsServerDiagnostics -EA Stop
                [void]$sb.AppendLine("DNS SERVER DIAGNOSTICS:")
                [void]$sb.AppendLine("  Query Logging    : $($dns.EnableLoggingForLocalLookupEvent) $(if(-not $dns.EnableLoggingForLocalLookupEvent){'[DISABLED]';$issues++}else{'[OK]'})")
                [void]$sb.AppendLine("  Recursive Queries: $($dns.EnableLoggingForRecursiveLookupEvent)")
                [void]$sb.AppendLine("  Remote Server    : $($dns.EnableLoggingForRemoteServerEvent)")
                [void]$sb.AppendLine("  Plugin Events    : $($dns.EnableLoggingForPluginDllEvent)")
                [void]$sb.AppendLine("  Log File Path    : $($dns.LogFilePath)")
                [void]$sb.AppendLine("  Max Log Size     : $($dns.MaxMBFileSize) MB")
            } catch {
                [void]$sb.AppendLine("DNS Server role not detected or not accessible on this host.")
                [void]$sb.AppendLine("Check DNS logging on the actual DNS server.")
                $issues++
            }
            # Check DNS client analytics log
            try {
                $log = Get-WinEvent -ListLog 'Microsoft-Windows-DNS-Client/Operational' -EA Stop
                [void]$sb.AppendLine("`nDNS CLIENT OPERATIONAL LOG:")
                [void]$sb.AppendLine("  Enabled: $($log.IsEnabled) | MaxSize: $([math]::Round($log.MaximumSizeInBytes/1MB,1)) MB | Records: $($log.RecordCount)")
            } catch {}
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -eq 1) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="DNS logging scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'LM04' = @{ Type='Local'; Label='Scan Firewall Logging'
        Script = {
            $profiles = Get-NetFirewallProfile -EA Stop
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            foreach ($p in $profiles) {
                $logAllowed = $p.LogAllowed; $logBlocked = $p.LogBlocked; $logFile = $p.LogFileName; $logSize = $p.LogMaxSizeKilobytes
                $ok = $logBlocked -eq 'True'
                if (-not $ok) { $issues++ }
                # CIS: Firewall log size >= 16,384 KB
                $sizeOk = $logSize -ge 16384
                if (-not $sizeOk) { $issues++ }
                [void]$sb.AppendLine("$($p.Name) Profile:")
                [void]$sb.AppendLine("  Log Allowed : $logAllowed")
                [void]$sb.AppendLine("  Log Blocked : $logBlocked $(if(-not $ok){'[NOT LOGGING BLOCKED TRAFFIC]'}else{'[OK]'})")
                [void]$sb.AppendLine("  Log File    : $logFile")
                [void]$sb.AppendLine("  Max Size    : $logSize KB $(if($sizeOk){'[OK]'}else{'[LOW - CIS requires 16,384+ KB]'})")
            }
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 2) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Firewall logging scan (CIS 2025) @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'LM07' = @{ Type='Local'; Label='Scan Log Retention + Event Log Sizes'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # CIS 2025 minimum log sizes in KB
            $cisMinKB = @{
                'Security' = 196608         # 192 MB
                'Application' = 32768       # 32 MB
                'System' = 32768            # 32 MB
                'Setup' = 32768             # 32 MB
                'Microsoft-Windows-PowerShell/Operational' = 16384  # 16 MB
            }
            $logs = @('Security','System','Application','Setup','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-Sysmon/Operational')
            [void]$sb.AppendLine("EVENT LOG SIZES (CIS Benchmarks 2025):")
            foreach ($logName in $logs) {
                try {
                    $log = Get-WinEvent -ListLog $logName -EA Stop
                    $sizeKB = [math]::Round($log.MaximumSizeInBytes / 1KB)
                    $sizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 1)
                    $minKB = $cisMinKB[$logName]
                    $small = $minKB -and $sizeKB -lt $minKB
                    if ($small) { $issues++ }
                    $minLabel = if ($minKB) { " (CIS min: $([math]::Round($minKB/1024)) MB)" } else { '' }
                    [void]$sb.AppendLine("  $logName : ${sizeMB} MB | Enabled:$($log.IsEnabled) | Records:$($log.RecordCount) $(if($small){"[LOW$minLabel]"}else{if($minKB){'[OK]'}})$minLabel")
                } catch {
                    [void]$sb.AppendLine("  $logName : NOT FOUND")
                }
            }
            # Sysmon detection
            $sysmon = Get-Service Sysmon,Sysmon64 -EA SilentlyContinue | Where-Object { $_.Status -eq 'Running' }
            [void]$sb.AppendLine("`nSysmon: $(if($sysmon){'RUNNING [OK]'}else{'Not installed'})")
            # Security log overflow action
            try {
                $sec = Get-WinEvent -ListLog 'Security' -EA Stop
                [void]$sb.AppendLine("Security log mode: $($sec.LogMode) $(if($sec.LogMode -eq 'Circular'){'[Circular - old events overwritten]'})")
            } catch {}
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 1) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Event log size scan (CIS 2025) @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'NA01' = @{ Type='Local'; Label='Scan Network Segmentation'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            $adapters = Get-NetIPConfiguration -Detailed -EA Stop | Where-Object { $_.IPv4Address }
            [void]$sb.AppendLine("NETWORK CONFIGURATION:")
            foreach ($a in $adapters) {
                [void]$sb.AppendLine("  Interface: $($a.InterfaceAlias)")
                [void]$sb.AppendLine("    IP     : $($a.IPv4Address.IPAddress)/$($a.IPv4Address.PrefixLength)")
                [void]$sb.AppendLine("    Gateway: $($a.IPv4DefaultGateway.NextHop)")
                [void]$sb.AppendLine("    DNS    : $(($a.DNSServer.ServerAddresses) -join ', ')")
                # Large subnet = likely flat network
                if ($a.IPv4Address.PrefixLength -le 16) { $issues++; [void]$sb.AppendLine("    [!] Very large subnet (/$($a.IPv4Address.PrefixLength)) - possible flat network") }
                elseif ($a.IPv4Address.PrefixLength -le 22) { [void]$sb.AppendLine("    [!] Large subnet (/$($a.IPv4Address.PrefixLength)) - verify segmentation") }
            }
            # ARP table analysis
            $arp = Get-NetNeighbor -State Reachable,Stale -EA SilentlyContinue | Where-Object { $_.IPAddress -notmatch ':' -and $_.IPAddress -ne '255.255.255.255' }
            $arpCount = ($arp | Measure-Object).Count
            [void]$sb.AppendLine("`nARP TABLE: $arpCount reachable/stale entries")
            if ($arpCount -gt 50) { $issues++; [void]$sb.AppendLine("  [!] Large number of neighbors visible - suggests flat network or large subnet") }
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 1) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Network segmentation scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'NA02' = @{ Type='Local'; Label='Scan VLAN Configuration'
        Script = {
            $sb = [System.Text.StringBuilder]::new()
            $adapters = Get-NetAdapter -EA Stop | Where-Object { $_.Status -eq 'Up' }
            [void]$sb.AppendLine("ACTIVE NETWORK ADAPTERS:")
            foreach ($a in $adapters) {
                $ip = Get-NetIPAddress -InterfaceIndex $a.InterfaceIndex -AddressFamily IPv4 -EA SilentlyContinue
                $vlanId = $a.VlanID
                [void]$sb.AppendLine("  $($a.Name) | MAC: $($a.MacAddress) | Speed: $($a.LinkSpeed)")
                [void]$sb.AppendLine("    IP: $(if($ip){$ip.IPAddress}else{'N/A'}) | VLAN ID: $(if($vlanId){"$vlanId"}else{'None/Default'})")
            }
            # Check if multiple subnets are reachable (suggests routing between VLANs)
            $routes = Get-NetRoute -AddressFamily IPv4 -EA SilentlyContinue | Where-Object { $_.DestinationPrefix -ne '0.0.0.0/0' -and $_.DestinationPrefix -ne '255.255.255.255/32' -and $_.NextHop -ne '0.0.0.0' }
            if ($routes) {
                [void]$sb.AppendLine("`nSTATIC ROUTES (non-default):")
                foreach ($r in ($routes | Select-Object -First 10)) { [void]$sb.AppendLine("  $($r.DestinationPrefix) via $($r.NextHop) if#$($r.InterfaceIndex)") }
            }
            $vlanCount = ($adapters | Where-Object { $_.VlanID }).Count
            $status = if ($vlanCount -gt 0) {'Pass'} else {'Partial'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="VLAN/adapter scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'CF02' = @{ Type='Local'; Label='Test Egress Filtering'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $openPorts = 0
            $testPorts = @(
                @{Port=25;   Desc='SMTP (email relay)'}
                @{Port=445;  Desc='SMB (file sharing)'}
                @{Port=3389; Desc='RDP (remote desktop)'}
                @{Port=1433; Desc='MSSQL (database)'}
                @{Port=3306; Desc='MySQL (database)'}
                @{Port=22;   Desc='SSH'}
                @{Port=23;   Desc='Telnet'}
                @{Port=4444; Desc='Metasploit default'}
                @{Port=8080; Desc='Alt HTTP/Proxy'}
            )
            [void]$sb.AppendLine("EGRESS PORT TEST (outbound to 1.1.1.1):")
            foreach ($tp in $testPorts) {
                try {
                    $tcp = New-Object System.Net.Sockets.TcpClient
                    $connect = $tcp.BeginConnect('1.1.1.1', $tp.Port, $null, $null)
                    $wait = $connect.AsyncWaitHandle.WaitOne(2000, $false)
                    if ($wait -and $tcp.Connected) {
                        $openPorts++; [void]$sb.AppendLine("  Port $($tp.Port) ($($tp.Desc)): OPEN [!]")
                    } else {
                        [void]$sb.AppendLine("  Port $($tp.Port) ($($tp.Desc)): Blocked [OK]")
                    }
                    $tcp.Close()
                } catch {
                    [void]$sb.AppendLine("  Port $($tp.Port) ($($tp.Desc)): Blocked/Error [OK]")
                }
            }
            [void]$sb.AppendLine("`n$openPorts of $($testPorts.Count) non-standard ports reachable outbound")
            $status = if ($openPorts -le 1) {'Pass'} elseif ($openPorts -le 3) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Egress port test @ $(Get-Date -f 'yyyy-MM-dd HH:mm') from $env:COMPUTERNAME" }
        }
    }

    'CF04' = @{ Type='AD'; Label='Scan Former Employee Accounts'
        Script = {
            $threshold = (Get-Date).AddDays(-90)
            $users = Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate,WhenCreated,Description,Manager -EA Stop
            $stale = $users | Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $threshold } | Sort-Object LastLogonDate
            $noManager = $users | Where-Object { -not $_.Manager -and $_.LastLogonDate -and $_.LastLogonDate -lt (Get-Date).AddDays(-60) }
            $sb = [System.Text.StringBuilder]::new()
            [void]$sb.AppendLine("POTENTIALLY ORPHANED ACCOUNTS (enabled, no logon 90+ days): $($stale.Count)")
            foreach ($u in ($stale | Select-Object -First 25)) {
                [void]$sb.AppendLine("  $($u.SamAccountName) | Last: $($u.LastLogonDate.ToString('yyyy-MM-dd')) | Created: $($u.WhenCreated.ToString('yyyy-MM-dd'))")
            }
            if ($stale.Count -gt 25) { [void]$sb.AppendLine("  ... +$($stale.Count - 25) more") }
            [void]$sb.AppendLine("`nACCOUNTS WITH NO MANAGER + 60d INACTIVE: $($noManager.Count)")
            $status = if ($stale.Count -eq 0) {'Pass'} elseif ($stale.Count -le 5) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Former employee account scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm')" }
        }
    }

    'CF06' = @{ Type='Local'; Label='Scan Network Flatness'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $flat = $false
            $ip = Get-NetIPAddress -AddressFamily IPv4 -EA Stop | Where-Object { $_.PrefixOrigin -ne 'WellKnown' -and $_.IPAddress -ne '127.0.0.1' } | Select-Object -First 1
            $arp = Get-NetNeighbor -State Reachable,Stale -EA SilentlyContinue | Where-Object { $_.IPAddress -notmatch ':' }
            $arpCount = ($arp | Measure-Object).Count
            [void]$sb.AppendLine("THIS HOST: $($ip.IPAddress)/$($ip.PrefixLength)")
            [void]$sb.AppendLine("Visible neighbors (ARP): $arpCount")
            if ($ip.PrefixLength -le 22 -and $arpCount -gt 30) {
                $flat = $true
                [void]$sb.AppendLine("`n[!] FLAT NETWORK INDICATORS:")
                [void]$sb.AppendLine("  Large subnet (/$($ip.PrefixLength)) with $arpCount visible hosts")
                [void]$sb.AppendLine("  Workstations and servers likely share same broadcast domain")
            }
            # Try pinging common server ports to assess reachability
            $gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -EA SilentlyContinue | Select-Object -First 1).NextHop
            [void]$sb.AppendLine("`nDefault Gateway: $gw")
            [void]$sb.AppendLine("Subnet mask: /$($ip.PrefixLength) (~$([math]::Pow(2, 32 - $ip.PrefixLength)) addresses)")
            $status = if ($flat) {'Fail'} elseif ($arpCount -gt 20) {'Partial'} else {'Pass'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Network flatness scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'CF08' = @{ Type='Local'; Label='Test DNS Filtering'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $filtered = $false
            $testDomains = @(
                @{Domain='examplemalwaredomain.com';  Desc='Umbrella malware test'}
                @{Domain='internetbadguys.com';       Desc='Umbrella test block'}
                @{Domain='testmalware.cf';            Desc='Generic malware test'}
            )
            # Get current DNS servers
            $dns = Get-DnsClientServerAddress -AddressFamily IPv4 -EA SilentlyContinue | Where-Object { $_.ServerAddresses } | Select-Object -First 1
            [void]$sb.AppendLine("DNS SERVERS: $(($dns.ServerAddresses) -join ', ')")
            [void]$sb.AppendLine("`nDNS FILTERING TEST:")
            foreach ($td in $testDomains) {
                try {
                    $r = Resolve-DnsName $td.Domain -EA Stop -DnsOnly
                    [void]$sb.AppendLine("  $($td.Domain): RESOLVED ($($r.IPAddress -join ',')) [NOT FILTERED]")
                } catch {
                    $filtered = $true
                    [void]$sb.AppendLine("  $($td.Domain): BLOCKED/NXDOMAIN [FILTERED - Good]")
                }
            }
            # Check if using known filtering DNS
            $knownFilters = @('208.67.222.222','208.67.220.220','9.9.9.9','149.112.112.112')
            $usingFilter = ($dns.ServerAddresses | Where-Object { $_ -in $knownFilters }).Count -gt 0
            if ($usingFilter) { [void]$sb.AppendLine("`nUsing known filtering DNS resolver. Good."); $filtered = $true }
            $status = if ($filtered) {'Pass'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="DNS filtering test @ $(Get-Date -f 'yyyy-MM-dd HH:mm') from $env:COMPUTERNAME" }
        }
    }

    # ── Phase 3: Full Coverage Auto-Checks ────────────────────────────────────

    'IA03' = @{ Type='AD'; Label='Scan MFA Coverage'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Check RDP NLA (Network Level Auth - basic MFA indicator)
            try {
                $rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -EA Stop
                $nla = $rdp.UserAuthentication -eq 1
                [void]$sb.AppendLine("RDP Network Level Auth: $(if($nla){'Enabled [OK]'}else{'DISABLED [!]'; $issues++})")
            } catch { [void]$sb.AppendLine("RDP NLA: Could not check") }
            # Check for Azure AD / Entra modules
            $hasAzureAD = (Get-Module AzureAD,AzureADPreview,Microsoft.Graph -ListAvailable -EA SilentlyContinue | Measure-Object).Count -gt 0
            [void]$sb.AppendLine("Azure AD/Graph modules installed: $hasAzureAD")
            # Check for ADFS
            try { $adfs = Get-Service adfssrv -EA SilentlyContinue; if ($adfs) { [void]$sb.AppendLine("ADFS Service: $($adfs.Status)") } else { [void]$sb.AppendLine("ADFS: Not installed on this host") } } catch {}
            # Check for common MFA/SSO agents (registry - fast)
            $mfaAgents = @('Duo Authentication','Okta Verify','RSA Authentication','Azure MFA','AuthPoint')
            $regPaths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
            $allApps = Get-ItemProperty $regPaths -EA SilentlyContinue | Where-Object { $_.DisplayName }
            $installed = @($allApps | Where-Object { $n=$_.DisplayName; ($mfaAgents | Where-Object { $n -match $_ }).Count -gt 0 })
            if ($installed.Count -gt 0) { foreach ($a in $installed) { [void]$sb.AppendLine("MFA Agent found: $($a.DisplayName) v$($a.DisplayVersion)") } }
            else { [void]$sb.AppendLine("No MFA agent software detected on this host"); $issues++ }
            # Check smart card enforcement
            try {
                $scLogon = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'scforceoption' -EA SilentlyContinue).scforceoption
                [void]$sb.AppendLine("Smart card required for logon: $(if($scLogon -eq 1){'Yes'}else{'No'})")
            } catch {}
            # Windows Hello for Business
            [void]$sb.AppendLine("`nWINDOWS HELLO FOR BUSINESS:")
            try {
                $whfbPolicy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork' -EA SilentlyContinue
                $whfbEnabled = $whfbPolicy.Enabled
                if ($whfbEnabled -eq 1) { [void]$sb.AppendLine("  Policy: Enabled [OK]") }
                elseif ($whfbEnabled -eq 0) { [void]$sb.AppendLine("  Policy: Explicitly Disabled") }
                else { [void]$sb.AppendLine("  Policy: Not configured via GPO") }
                # Check user enrollment status
                $ngcKeys = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\NgcPin' -EA SilentlyContinue
                $ngcContainers = Get-ChildItem "$env:SystemDrive\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc" -EA SilentlyContinue
                if ($ngcKeys -or $ngcContainers) { [void]$sb.AppendLine("  Enrollment: Keys detected on this device [OK]") }
                else { [void]$sb.AppendLine("  Enrollment: No WHfB keys found on this device") }
                # Check if PIN complexity is configured
                $pinPolicy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity' -EA SilentlyContinue
                if ($pinPolicy) {
                    [void]$sb.AppendLine("  PIN Complexity: Configured (MinLength:$($pinPolicy.MinimumPINLength))")
                }
            } catch { [void]$sb.AppendLine("  Windows Hello: Could not query") }
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -eq 1) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="MFA coverage scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'IA06' = @{ Type='AD'; Label='Scan PAM / Privileged Access'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Check LAPS deployment - Windows LAPS (built-in since Apr 2023) vs Legacy LAPS
            $lapsType = 'None'
            try {
                # Try Windows LAPS first (msLAPS-EncryptedPassword attribute)
                $lapsComputers = Get-ADComputer -Filter * -Properties 'msLAPS-EncryptedPassword','msLAPS-PasswordExpirationTime','ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime' -EA Stop
                $total = $lapsComputers.Count
                $winLAPS = ($lapsComputers | Where-Object { $_.'msLAPS-EncryptedPassword' }).Count
                $legLAPS = ($lapsComputers | Where-Object { $_.'ms-Mcs-AdmPwd' }).Count
                $lapsDeployed = [math]::Max($winLAPS, $legLAPS)
                $pct = if ($total -gt 0) { [math]::Round(($lapsDeployed/$total)*100,1) } else { 0 }
                if ($winLAPS -gt 0) { $lapsType = 'Windows LAPS (encrypted)' }
                elseif ($legLAPS -gt 0) { $lapsType = 'Legacy LAPS (cleartext)' }
                [void]$sb.AppendLine("LAPS DEPLOYMENT: $lapsDeployed/$total computers ($pct%)")
                [void]$sb.AppendLine("  LAPS Type: $lapsType")
                if ($lapsType -eq 'Legacy LAPS (cleartext)') { [void]$sb.AppendLine("  [!] Legacy LAPS stores passwords in cleartext - migrate to Windows LAPS") }
                if ($pct -lt 80) { $issues++; [void]$sb.AppendLine("  [!] Low LAPS coverage - target 80%+") }
                if ($winLAPS -gt 0 -and $legLAPS -gt 0) { [void]$sb.AppendLine("  [i] Mixed deployment: $winLAPS Windows LAPS, $legLAPS Legacy LAPS") }
            } catch { [void]$sb.AppendLine("LAPS: Could not query (schema extension may not be deployed)"); $issues++ }
            # Check admin logon sessions (who is currently admin-logged-in)
            try {
                $daMembers = (Get-ADGroupMember 'Domain Admins' -EA Stop).SamAccountName
                $recentAdminLogons = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=(Get-Date).AddDays(-7)} -MaxEvents 500 -EA SilentlyContinue |
                    Where-Object { $xml=[xml]$_.ToXml(); $u=($xml.Event.EventData.Data|Where-Object{$_.Name -eq 'TargetUserName'}).'#text'; $u -in $daMembers } |
                    Select-Object -First 20
                [void]$sb.AppendLine("`nDA LOGON EVENTS (last 7d): $($recentAdminLogons.Count)+ events")
                if ($recentAdminLogons.Count -gt 50) { $issues++; [void]$sb.AppendLine("  [!] High admin logon volume - admin accounts may be used for daily work") }
            } catch { [void]$sb.AppendLine("`nAdmin logon event scan: access denied or audit not configured") }
            # Check for PAM solutions (registry - fast)
            $pamIndicators = @('CyberArk','BeyondTrust','Thycotic','Delinea','Privileged Access','ManageEngine PAM')
            $regPaths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
            $allApps = Get-ItemProperty $regPaths -EA SilentlyContinue | Where-Object { $_.DisplayName }
            $foundPAM = @($allApps | Where-Object { $n=$_.DisplayName; ($pamIndicators | Where-Object { $n -match $_ }).Count -gt 0 })
            if ($foundPAM.Count -gt 0) { foreach ($p in $foundPAM) { [void]$sb.AppendLine("`nPAM Software: $($p.DisplayName)") } }
            else { [void]$sb.AppendLine("`nNo PAM/JIT access solution detected"); $issues++ }
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 1) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="PAM/LAPS/Privileged Access scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm')" }
        }
    }

    'IA09' = @{ Type='Local'; Label='Scan Conditional Access / Remote Access'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Check RDP settings
            try {
                $ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -EA Stop
                $rdpEnabled = $ts.fDenyTSConnections -eq 0
                [void]$sb.AppendLine("RDP Enabled: $rdpEnabled")
                $nla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -EA SilentlyContinue).UserAuthentication
                [void]$sb.AppendLine("RDP NLA Required: $(if($nla -eq 1){'Yes [OK]'}else{'No [!]'; if($rdpEnabled){$issues++}})")
                $rdpPort = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -EA SilentlyContinue).PortNumber
                [void]$sb.AppendLine("RDP Port: $rdpPort $(if($rdpPort -eq 3389){'(default)'}else{'(custom)'})")
            } catch {}
            # Check VPN connections/adapters
            $vpnAdapters = Get-NetAdapter -EA SilentlyContinue | Where-Object { $_.InterfaceDescription -match 'VPN|WireGuard|OpenVPN|Cisco|Fortinet|Palo Alto|SonicWall|Juniper|GlobalProtect|Pulse|AnyConnect' }
            if ($vpnAdapters) { foreach ($v in $vpnAdapters) { [void]$sb.AppendLine("`nVPN Adapter: $($v.Name) ($($v.InterfaceDescription)) Status:$($v.Status)") } }
            $vpnConnections = Get-VpnConnection -EA SilentlyContinue
            if ($vpnConnections) {
                [void]$sb.AppendLine("`nCONFIGURED VPN CONNECTIONS:")
                foreach ($vc in $vpnConnections) {
                    $split = if ($vc.SplitTunneling) {'SPLIT TUNNEL [!]'} else {'Full Tunnel [OK]'}
                    [void]$sb.AppendLine("  $($vc.Name) | Server:$($vc.ServerAddress) | Auth:$($vc.AuthenticationMethod) | $split")
                    if ($vc.SplitTunneling) { $issues++ }
                }
            } else { [void]$sb.AppendLine("`nNo built-in VPN connections configured") }
            # Check for VPN software
            $vpnSoft = Get-CimInstance Win32_Product -EA SilentlyContinue | Where-Object { $_.Name -match 'VPN|AnyConnect|GlobalProtect|FortiClient|Pulse|WireGuard|OpenVPN' }
            if ($vpnSoft) { foreach ($vs in $vpnSoft) { [void]$sb.AppendLine("VPN Software: $($vs.Name) v$($vs.Version)") } }
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 1) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Remote access scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'EP08' = @{ Type='Local'; Label='Scan Hardware Security (UEFI/TPM/VBS)'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Secure Boot
            try {
                $sb2 = Confirm-SecureBootUEFI -EA Stop
                [void]$sb.AppendLine("Secure Boot     : $(if($sb2){'ENABLED [OK]'}else{'DISABLED [!]'; $issues++})")
            } catch { [void]$sb.AppendLine("Secure Boot     : Not supported or inaccessible"); $issues++ }
            # TPM with version check
            try {
                $tpm = Get-Tpm -EA Stop
                [void]$sb.AppendLine("TPM Present     : $($tpm.TpmPresent) | Ready: $($tpm.TpmReady) | Enabled: $($tpm.TpmEnabled)")
                $tpmSpec = (Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -EA SilentlyContinue).SpecVersion
                $tpm2 = $tpmSpec -match '^2\.'
                [void]$sb.AppendLine("TPM Version     : $tpmSpec $(if($tpm2){'[TPM 2.0 OK]'}else{'[TPM 1.2 - upgrade recommended]'})")
                if (-not $tpm.TpmPresent -or -not $tpm.TpmReady) { $issues++ }
            } catch { [void]$sb.AppendLine("TPM: Could not query"); $issues++ }
            # Boot mode / firmware type
            try {
                $firmwareType = if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot') {'UEFI'} else {'Legacy BIOS'}
                [void]$sb.AppendLine("Firmware Type   : $firmwareType $(if($firmwareType -eq 'Legacy BIOS'){'[!] UEFI required for VBS/Credential Guard'})")
            } catch {}
            # VBS / Credential Guard via Win32_DeviceGuard WMI (running state, not just configured)
            [void]$sb.AppendLine("`nVIRTUALIZATION-BASED SECURITY (VBS):")
            try {
                $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -EA Stop
                $vbsStatus = switch ($dg.VirtualizationBasedSecurityStatus) { 0 {'Not running [!]'} 1 {'Not running (reboot required)'} 2 {'Running [OK]'} default {'Unknown'} }
                [void]$sb.AppendLine("  VBS Status    : $vbsStatus")
                if ($dg.VirtualizationBasedSecurityStatus -ne 2) { $issues++ }
                # SecurityServicesRunning: 1=Credential Guard, 2=HVCI, 3=System Guard
                $runningServices = $dg.SecurityServicesRunning
                $credGuard = 1 -in $runningServices
                $hvci = 2 -in $runningServices
                [void]$sb.AppendLine("  Credential Guard: $(if($credGuard){'RUNNING [OK]'}else{'Not running [!]'; $issues++})")
                [void]$sb.AppendLine("  HVCI (Memory Integrity): $(if($hvci){'RUNNING [OK]'}else{'Not running [!]'; $issues++})")
                # Configured services
                $cfgServices = $dg.SecurityServicesConfigured
                [void]$sb.AppendLine("  Configured    : $(if($cfgServices){($cfgServices -join ', ')}else{'None'})")
            } catch { [void]$sb.AppendLine("  Win32_DeviceGuard: Not available (VBS may not be supported)"); $issues++ }
            # LSA Protection (RunAsPPL)
            [void]$sb.AppendLine("`nCREDENTIAL PROTECTION:")
            try {
                $runAsPPL = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -EA SilentlyContinue).RunAsPPL
                $lsaCfg = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -EA SilentlyContinue).LsaCfgFlags
                [void]$sb.AppendLine("  LSA Protection (RunAsPPL): $(if($runAsPPL -eq 1){'Enabled [OK]'}else{'Disabled [!]'; $issues++})")
                if ($lsaCfg) { [void]$sb.AppendLine("  LsaCfgFlags   : $lsaCfg") }
            } catch {}
            # WDigest credential caching (should be 0 or absent)
            try {
                $wdigest = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -EA SilentlyContinue).UseLogonCredential
                [void]$sb.AppendLine("  WDigest Cache : $(if($wdigest -eq 1){'ENABLED [CRITICAL - cleartext passwords in memory!]'; $issues += 2}else{'Disabled [OK]'})")
            } catch { [void]$sb.AppendLine("  WDigest Cache : Key not present (disabled by default on Win10+) [OK]") }
            # BIOS Info
            try {
                $bios = Get-CimInstance Win32_BIOS -EA Stop
                $biosAge = if ($bios.ReleaseDate -is [datetime]) { ((Get-Date) - $bios.ReleaseDate).Days } else { $null }
                [void]$sb.AppendLine("`nBIOS: $($bios.Manufacturer) | $($bios.SMBIOSBIOSVersion) | $(if($bios.ReleaseDate -is [datetime]){$bios.ReleaseDate.ToString('yyyy-MM-dd')}else{'Unknown'})")
                if ($biosAge -and $biosAge -gt 730) { [void]$sb.AppendLine("  [!] BIOS is $biosAge days old - check for firmware updates"); $issues++ }
            } catch {}
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 2) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Hardware security + VBS/CG scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'LM02' = @{ Type='Local'; Label='Scan Centralized Logging / SIEM'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Check for Sysmon
            $sysmon = Get-Service Sysmon,Sysmon64 -EA SilentlyContinue | Where-Object { $_.Status -eq 'Running' }
            if ($sysmon) { [void]$sb.AppendLine("Sysmon: RUNNING [OK]") }
            else { [void]$sb.AppendLine("Sysmon: NOT INSTALLED [!]"); $issues++ }
            # Check Windows Event Forwarding
            try {
                $wef = Get-Service wecsvc -EA SilentlyContinue
                [void]$sb.AppendLine("WEF Collector Service: $(if($wef){$wef.Status}else{'Not installed'})")
                $subs = wecutil es 2>$null
                if ($subs) { [void]$sb.AppendLine("WEF Subscriptions: $($subs.Count)"); foreach ($s in ($subs|Select-Object -First 5)) { [void]$sb.AppendLine("  $s") } }
            } catch {}
            # Check for SIEM agents
            $siemServices = @(
                @{Name='SplunkForwarder';Desc='Splunk Universal Forwarder'}
                @{Name='ossec*';Desc='Wazuh/OSSEC Agent'}
                @{Name='filebeat';Desc='Elastic Filebeat'}
                @{Name='winlogbeat';Desc='Elastic Winlogbeat'}
                @{Name='nxlog';Desc='NXLog'}
                @{Name='snare*';Desc='Snare Agent'}
                @{Name='QualysAgent';Desc='Qualys Agent'}
                @{Name='TaniumClient';Desc='Tanium Client'}
                @{Name='cb*Defense*';Desc='Carbon Black'}
                @{Name='MsSense';Desc='Microsoft Defender for Endpoint'}
            )
            $foundAgents = @()
            foreach ($ss in $siemServices) {
                $svc = Get-Service $ss.Name -EA SilentlyContinue
                if ($svc) { $foundAgents += "$($ss.Desc): $($svc.Status)"; [void]$sb.AppendLine("$($ss.Desc): $($svc.Status)") }
            }
            if ($foundAgents.Count -eq 0) { [void]$sb.AppendLine("`nNo SIEM/log forwarding agents detected [!]"); $issues++ }
            # Check PowerShell logging
            try {
                $psLog = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -EA SilentlyContinue
                $psTranscript = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -EA SilentlyContinue
                [void]$sb.AppendLine("`nPS Script Block Logging: $(if($psLog.EnableScriptBlockLogging -eq 1){'Enabled [OK]'}else{'Disabled [!]'; $issues++})")
                [void]$sb.AppendLine("PS Transcription: $(if($psTranscript.EnableTranscripting -eq 1){'Enabled [OK]'}else{'Disabled'})")
            } catch {}
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 1) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="SIEM/centralized logging scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'LM06' = @{ Type='Local'; Label='Scan File Integrity Monitoring'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Check for Sysmon (file create/modify events)
            $sysmon = Get-Service Sysmon,Sysmon64 -EA SilentlyContinue | Where-Object { $_.Status -eq 'Running' }
            if ($sysmon) {
                [void]$sb.AppendLine("Sysmon: RUNNING (provides file creation monitoring)")
                try {
                    $sysmonEvents = (Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -EA Stop)
                    [void]$sb.AppendLine("  Sysmon log has events - actively collecting")
                } catch { [void]$sb.AppendLine("  Sysmon log: no events or inaccessible") }
            } else { [void]$sb.AppendLine("Sysmon: NOT INSTALLED"); $issues++ }
            # Check for common FIM solutions
            $fimServices = @('OSSEC','Wazuh','Tripwire','AIDE','SamhainSvc','MsSense','CarbonBlack')
            foreach ($f in $fimServices) {
                $svc = Get-Service "*$f*" -EA SilentlyContinue
                if ($svc) { [void]$sb.AppendLine("FIM Agent: $($svc.DisplayName) ($($svc.Status))") }
            }
            # Check Windows built-in auditing for file system
            try {
                $objAccess = auditpol /get /subcategory:"File System" 2>&1 | Select-String 'File System'
                [void]$sb.AppendLine("`nFile System Auditing: $($objAccess.ToString().Trim())")
                if ($objAccess -match 'No Auditing') { $issues++; [void]$sb.AppendLine("  [!] File system auditing not configured") }
            } catch {}
            # Check for SACLs on critical paths
            $criticalPaths = @("$env:SystemRoot\System32","$env:ProgramFiles")
            foreach ($cp in $criticalPaths) {
                try {
                    $acl = Get-Acl $cp -Audit -EA SilentlyContinue
                    $auditRules = $acl.Audit.Count
                    [void]$sb.AppendLine("Audit rules on $cp`: $auditRules")
                } catch {}
            }
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -eq 1) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="FIM scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'LM08' = @{ Type='Local'; Label='Scan Security Alerting'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Check for scheduled tasks related to monitoring/alerting
            $monTasks = @()
            $monPattern = 'monitor|alert|backup|security|scan|update|patch|audit'
            try {
                # Check root and key Microsoft paths where monitoring/security tasks typically live
                foreach ($tp in @('\','\Microsoft\Windows\','\Microsoft\Windows\Backup\','\Microsoft\Windows\WindowsUpdate\','\Microsoft\Windows\Windows Defender\')) {
                    try { $monTasks += @(Get-ScheduledTask -TaskPath $tp -EA SilentlyContinue | Where-Object { $_.TaskName -match $monPattern -and $_.State -ne 'Disabled' }) } catch {}
                }
            } catch {}
            [void]$sb.AppendLine("ACTIVE MONITORING SCHEDULED TASKS ($($monTasks.Count)):")
            foreach ($t in ($monTasks | Select-Object -First 15)) {
                [void]$sb.AppendLine("  $($t.TaskName) | State:$($t.State) | Path:$($t.TaskPath)")
            }
            if ($monTasks.Count -eq 0) { $issues++ }
            # Check for Event Log subscriptions (email triggers)
            $eventSubs = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Subscriptions' -EA SilentlyContinue
            [void]$sb.AppendLine("`nEvent Log Subscriptions: $(if($eventSubs){$eventSubs.Count}else{0})")
            # Check for monitoring agents
            $monServices = @('zabbix*','snmpd','SNMP','nagios*','prtg*','DatadogAgent','newrelic*','Icinga*','CheckMK*','prometheus*','grafana*')
            $foundMon = @()
            foreach ($ms in $monServices) {
                $svc = Get-Service $ms -EA SilentlyContinue
                if ($svc) { $foundMon += $svc; [void]$sb.AppendLine("Monitoring Agent: $($svc.DisplayName) ($($svc.Status))") }
            }
            if ($foundMon.Count -eq 0) { [void]$sb.AppendLine("`nNo monitoring agents detected"); $issues++ }
            # Check SNMP
            $snmp = Get-Service SNMP -EA SilentlyContinue
            if ($snmp) {
                [void]$sb.AppendLine("`nSNMP Service: $($snmp.Status)")
                $community = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities' -EA SilentlyContinue
                if ($community) {
                    $names = $community.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $_.Name }
                    if ('public' -in $names) { [void]$sb.AppendLine("  [!] Default 'public' community string in use"); $issues++ }
                }
            }
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 1) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Security alerting scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'NA03' = @{ Type='Local'; Label='Scan Wireless Security'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Get wireless profiles
            try {
                $profiles = netsh wlan show profiles 2>&1
                if ($profiles -match 'is not running') {
                    [void]$sb.AppendLine("WLAN AutoConfig service is not running - no wireless capability")
                    $status = 'Pass'
                } else {
                    $profileNames = ($profiles | Select-String 'All User Profile\s+:\s+(.+)$' | ForEach-Object { $_.Matches.Groups[1].Value.Trim() })
                    [void]$sb.AppendLine("WIRELESS PROFILES ($($profileNames.Count)):")
                    foreach ($pn in $profileNames) {
                        $detail = netsh wlan show profile name="$pn" key=clear 2>&1
                        $auth = ($detail | Select-String 'Authentication\s+:\s+(.+)$' | Select-Object -First 1)
                        $cipher = ($detail | Select-String 'Cipher\s+:\s+(.+)$' | Select-Object -First 1)
                        $connMode = ($detail | Select-String 'Connection mode\s+:\s+(.+)$' | Select-Object -First 1)
                        $authType = if ($auth) { $auth.Matches.Groups[1].Value.Trim() } else { 'Unknown' }
                        $cipherType = if ($cipher) { $cipher.Matches.Groups[1].Value.Trim() } else { 'Unknown' }
                        $weak = $authType -match 'Open|WEP|WPA-Personal' -and $authType -notmatch 'WPA2|WPA3'
                        if ($weak) { $issues++ }
                        [void]$sb.AppendLine("  $pn | Auth:$authType | Cipher:$cipherType $(if($weak){'[WEAK!]'})")
                    }
                    $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 1) {'Partial'} else {'Fail'}
                }
            } catch { [void]$sb.AppendLine("Wireless scan failed: $_"); $status = 'Partial' }
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Wireless security scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'NA04' = @{ Type='Local'; Label='Scan Network Documentation / Diagram Data'
        Script = {
            $sb = [System.Text.StringBuilder]::new()
            # Gather comprehensive network info that would appear on a diagram
            [void]$sb.AppendLine("=== NETWORK INFRASTRUCTURE DISCOVERY ===")
            # All interfaces
            $adapters = Get-NetIPConfiguration -Detailed -EA SilentlyContinue
            [void]$sb.AppendLine("`nINTERFACES ($($adapters.Count)):")
            foreach ($a in $adapters) {
                if ($a.IPv4Address) {
                    [void]$sb.AppendLine("  $($a.InterfaceAlias): $($a.IPv4Address.IPAddress)/$($a.IPv4Address.PrefixLength) GW:$($a.IPv4DefaultGateway.NextHop) DNS:$(($a.DNSServer.ServerAddresses) -join ',')")
                }
            }
            # Domain controllers
            try {
                $dcs = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
                [void]$sb.AppendLine("`nDOMAIN CONTROLLERS ($($dcs.Count)):")
                foreach ($dc in $dcs) { [void]$sb.AppendLine("  $($dc.Name) ($($dc.IPAddress)) - Roles: $($dc.Roles -join ', ')") }
            } catch { [void]$sb.AppendLine("`nDomain Controllers: Not in domain or cannot query") }
            # Default gateway and routes
            $routes = Get-NetRoute -AddressFamily IPv4 -EA SilentlyContinue | Where-Object { $_.NextHop -ne '0.0.0.0' -and $_.DestinationPrefix -ne '255.255.255.255/32' } | Select-Object -First 15
            [void]$sb.AppendLine("`nROUTING TABLE (non-default, $($routes.Count) entries):")
            foreach ($r in $routes) { [void]$sb.AppendLine("  $($r.DestinationPrefix) via $($r.NextHop)") }
            # DNS configuration
            $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 -EA SilentlyContinue | Where-Object { $_.ServerAddresses } | Select-Object InterfaceAlias,ServerAddresses -Unique
            [void]$sb.AppendLine("`nDNS SERVERS:")
            foreach ($d in $dnsServers) { [void]$sb.AppendLine("  $($d.InterfaceAlias): $($d.ServerAddresses -join ', ')") }
            [void]$sb.AppendLine("`n[NOTE] Use this data to verify network diagram accuracy. If no diagram exists, this is the finding.")
            @{ Status='Partial'; Findings=$sb.ToString().Trim(); Evidence="Network infrastructure discovery @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'NA05' = @{ Type='Local'; Label='Scan 802.1X / NAC Status'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Check 802.1X service
            $dot1x = Get-Service dot3svc -EA SilentlyContinue
            [void]$sb.AppendLine("Wired AutoConfig (802.1X) Service: $(if($dot1x){"$($dot1x.Status)"}else{'Not found'})")
            if (-not $dot1x -or $dot1x.Status -ne 'Running') { $issues++ }
            # Check for EAP configuration
            try {
                $eap = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\Eaphost\Methods' -EA SilentlyContinue -Recurse
                [void]$sb.AppendLine("EAP Methods configured: $(if($eap){$eap.Count}else{0})")
            } catch {}
            # Check for NAC agents
            $nacAgents = @('Cisco ISE','ForeScout','Aruba ClearPass','Portnox','PacketFence','Bradford','Forescout')
            $foundNAC = Get-CimInstance Win32_Product -EA SilentlyContinue | Where-Object { $n=$_.Name; $nacAgents | Where-Object { $n -match $_ } }
            if ($foundNAC) { foreach ($na in $foundNAC) { [void]$sb.AppendLine("NAC Agent: $($na.Name)") } }
            else { [void]$sb.AppendLine("No NAC agent software detected"); $issues++ }
            # Check for certificate-based auth
            $certs = Get-ChildItem Cert:\LocalMachine\My -EA SilentlyContinue | Where-Object { $_.EnhancedKeyUsageList.FriendlyName -match 'Client Authentication' }
            [void]$sb.AppendLine("`nClient auth certificates: $(if($certs){$certs.Count}else{0})")
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 1) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="802.1X/NAC scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'NA06' = @{ Type='Local'; Label='Scan Management Interface Isolation'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Check for management ports listening
            $mgmtPorts = @(
                @{Port=22;Desc='SSH'},@{Port=23;Desc='Telnet'},@{Port=161;Desc='SNMP'},
                @{Port=443;Desc='HTTPS Mgmt'},@{Port=3389;Desc='RDP'},@{Port=5985;Desc='WinRM HTTP'},
                @{Port=5986;Desc='WinRM HTTPS'},@{Port=8443;Desc='Alt HTTPS'},@{Port=9090;Desc='Cockpit/Mgmt'}
            )
            $listeners = Get-NetTCPConnection -State Listen -EA SilentlyContinue
            [void]$sb.AppendLine("MANAGEMENT PORTS LISTENING:")
            foreach ($mp in $mgmtPorts) {
                $listening = $listeners | Where-Object { $_.LocalPort -eq $mp.Port }
                if ($listening) {
                    $bindAddr = ($listening.LocalAddress | Select-Object -Unique) -join ', '
                    $allInterfaces = $bindAddr -match '0\.0\.0\.0|::'
                    if ($allInterfaces) { $issues++ }
                    [void]$sb.AppendLine("  Port $($mp.Port) ($($mp.Desc)): LISTENING on $bindAddr $(if($allInterfaces){'[ALL INTERFACES - not isolated!]'}else{'[Specific bind]'})")
                }
            }
            # Check if WinRM has IP restrictions
            try {
                $winrmFilter = (Get-Item WSMan:\localhost\Service\IPv4Filter -EA SilentlyContinue).Value
                [void]$sb.AppendLine("`nWinRM IPv4 Filter: $(if($winrmFilter){"$winrmFilter"}else{'* (all)'})")
                if ($winrmFilter -eq '*' -or -not $winrmFilter) { $issues++ }
            } catch {}
            # Check for IPMI/iLO/iDRAC
            $bmc = Get-CimInstance Win32_NetworkAdapter -EA SilentlyContinue | Where-Object { $_.Name -match 'BMC|IPMI|iLO|iDRAC|Baseboard' }
            if ($bmc) { foreach ($b in $bmc) { [void]$sb.AppendLine("`nBMC/OOB Interface: $($b.Name)") } }
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 2) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Management isolation scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'NA07' = @{ Type='Local'; Label='Scan Switch Port / Network Port Security'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Enumerate active adapters vs total
            $allAdapters = Get-NetAdapter -EA SilentlyContinue
            $active = $allAdapters | Where-Object { $_.Status -eq 'Up' }
            $down = $allAdapters | Where-Object { $_.Status -ne 'Up' }
            [void]$sb.AppendLine("NETWORK ADAPTERS:")
            [void]$sb.AppendLine("  Active: $($active.Count) | Inactive: $($down.Count)")
            foreach ($a in $active) { [void]$sb.AppendLine("  [UP] $($a.Name) | $($a.InterfaceDescription) | Speed:$($a.LinkSpeed) | MAC:$($a.MacAddress)") }
            foreach ($d in ($down | Select-Object -First 5)) { [void]$sb.AppendLine("  [--] $($d.Name) | $($d.InterfaceDescription)") }
            # Check for MAC address filtering indicators
            $macFilter = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'DisableMediaSense' -EA SilentlyContinue
            # Check for network bridge
            $bridge = $allAdapters | Where-Object { $_.InterfaceDescription -match 'Bridge|MAC Bridge' }
            if ($bridge) { [void]$sb.AppendLine("`n[!] Network bridge detected: $($bridge.Name)"); $issues++ }
            # Check for promiscuous mode indicators
            try {
                $promiscReg = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'EnablePromiscuousMode' -EA SilentlyContinue
                if ($promiscReg.EnablePromiscuousMode) { [void]$sb.AppendLine("[!] Promiscuous mode enabled"); $issues++ }
            } catch {}
            [void]$sb.AppendLine("`n[NOTE] Physical switch port security (802.1X, port disable, MAC limit) must be verified on the switch itself.")
            $status = if ($issues -eq 0) {'Pass'} else {'Partial'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Network port scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'NP02' = @{ Type='Local'; Label='Scan Open Ports'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            $listeners = Get-NetTCPConnection -State Listen -EA Stop | Sort-Object LocalPort
            $grouped = $listeners | Group-Object LocalPort
            [void]$sb.AppendLine("LISTENING TCP PORTS ($($grouped.Count) unique):")
            foreach ($g in $grouped) {
                $port = $g.Name; $binds = ($g.Group.LocalAddress | Select-Object -Unique) -join ', '
                $proc = $g.Group[0].OwningProcess
                $procName = try { (Get-Process -Id $proc -EA Stop).ProcessName } catch { 'Unknown' }
                $concern = $port -in @(21,23,25,69,110,135,139,445,1433,1434,3306,3389,5432,5900,8080,8443)
                if ($concern -and $binds -match '0\.0\.0\.0|::') { $issues++ }
                [void]$sb.AppendLine("  :$port | Bind:$binds | Process:$procName (PID:$proc) $(if($concern){'[REVIEW]'})")
            }
            # UDP listeners
            $udp = Get-NetUDPEndpoint -EA SilentlyContinue | Where-Object { $_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::' } | Group-Object LocalPort | Sort-Object { [int]$_.Name }
            [void]$sb.AppendLine("`nUDP LISTENERS (all-interface, $($udp.Count) ports):")
            foreach ($u in ($udp | Select-Object -First 15)) { [void]$sb.AppendLine("  :$($u.Name)") }
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 3) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Open port scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'NP03' = @{ Type='Local'; Label='Scan VPN Configuration'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Built-in VPN connections
            $vpns = Get-VpnConnection -EA SilentlyContinue
            if ($vpns) {
                [void]$sb.AppendLine("CONFIGURED VPN CONNECTIONS ($($vpns.Count)):")
                foreach ($v in $vpns) {
                    $flags = @()
                    if ($v.SplitTunneling) { $flags += 'SPLIT_TUNNEL'; $issues++ }
                    if ($v.AuthenticationMethod -contains 'Pap') { $flags += 'PAP_AUTH'; $issues++ }
                    $f = if ($flags) { " [$(($flags -join ', '))]" } else { '' }
                    [void]$sb.AppendLine("  $($v.Name) | Server:$($v.ServerAddress) | Protocol:$($v.TunnelType) | Auth:$($v.AuthenticationMethod -join ',')$f")
                }
            } else { [void]$sb.AppendLine("No built-in VPN connections configured") }
            # Check for VPN software
            $vpnSoft = @('AnyConnect','GlobalProtect','FortiClient','PulseSecure','Ivanti','WireGuard','OpenVPN','SonicWall','Palo Alto','NetExtender')
            $procs = Get-Process -EA SilentlyContinue | Where-Object { $n=$_.ProcessName; $vpnSoft | Where-Object { $n -match $_ } }
            if ($procs) {
                [void]$sb.AppendLine("`nVPN PROCESSES RUNNING:")
                foreach ($p in $procs) { [void]$sb.AppendLine("  $($p.ProcessName) (PID:$($p.Id))") }
            }
            # Check for VPN adapters
            $vpnAdapters = Get-NetAdapter -EA SilentlyContinue | Where-Object { $_.InterfaceDescription -match 'VPN|WireGuard|TAP-Windows|Cisco|Fortinet|Palo Alto|SonicWall|Juniper|Pulse' }
            if ($vpnAdapters) {
                [void]$sb.AppendLine("`nVPN ADAPTERS:")
                foreach ($va in $vpnAdapters) { [void]$sb.AppendLine("  $($va.Name) | $($va.InterfaceDescription) | Status:$($va.Status)") }
            }
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 1) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="VPN config scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'NP04' = @{ Type='Local'; Label='Scan DNS Filtering Config'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $filtered = $false
            # DNS servers in use
            $dnsConfig = Get-DnsClientServerAddress -AddressFamily IPv4 -EA SilentlyContinue | Where-Object { $_.ServerAddresses }
            [void]$sb.AppendLine("DNS CONFIGURATION:")
            foreach ($dc in $dnsConfig) { [void]$sb.AppendLine("  $($dc.InterfaceAlias): $($dc.ServerAddresses -join ', ')") }
            # Check for known filtering DNS
            $filterDNS = @{
                '208.67.222.222'='OpenDNS/Umbrella'; '208.67.220.220'='OpenDNS/Umbrella'
                '9.9.9.9'='Quad9'; '149.112.112.112'='Quad9'
                '185.228.168.168'='CleanBrowsing'; '185.228.169.168'='CleanBrowsing'
                '76.76.2.0'='ControlD'; '76.76.10.0'='ControlD'
            }
            $allDNS = $dnsConfig.ServerAddresses | Select-Object -Unique
            foreach ($d in $allDNS) {
                if ($filterDNS.Contains($d)) { [void]$sb.AppendLine("  [OK] $d = $($filterDNS[$d]) (filtering DNS)"); $filtered = $true }
            }
            # Check for Umbrella/DNS proxy agents
            $umbrellaAgent = Get-Service 'Umbrella*','csc_*' -EA SilentlyContinue
            if ($umbrellaAgent) { [void]$sb.AppendLine("`nCisco Umbrella agent: $($umbrellaAgent.DisplayName) ($($umbrellaAgent.Status))"); $filtered = $true }
            # Test known bad domains
            [void]$sb.AppendLine("`nDNS FILTER TEST:")
            $testDomains = @('examplemalwaredomain.com','internetbadguys.com')
            foreach ($td in $testDomains) {
                try { $r = Resolve-DnsName $td -EA Stop -DnsOnly; [void]$sb.AppendLine("  $td`: RESOLVED [NOT FILTERED]") }
                catch { $filtered = $true; [void]$sb.AppendLine("  $td`: BLOCKED [FILTERED - Good]") }
            }
            $status = if ($filtered) {'Pass'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="DNS filtering scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'NP05' = @{ Type='Local'; Label='Scan Egress / Outbound Rules'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            $profiles = Get-NetFirewallProfile -EA Stop
            [void]$sb.AppendLine("FIREWALL DEFAULT OUTBOUND ACTIONS:")
            foreach ($p in $profiles) {
                $blockOut = $p.DefaultOutboundAction -eq 'Block'
                if (-not $blockOut) { $issues++ }
                [void]$sb.AppendLine("  $($p.Name): DefaultOutbound=$($p.DefaultOutboundAction) $(if($blockOut){'[RESTRICTIVE - Good]'}else{'[ALLOW ALL - No egress filtering]'})")
            }
            # Check outbound block rules
            $outBlock = Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True -EA SilentlyContinue
            [void]$sb.AppendLine("`nOutbound BLOCK rules (enabled): $(($outBlock | Measure-Object).Count)")
            if ($outBlock) {
                foreach ($r in ($outBlock | Select-Object -First 10)) { [void]$sb.AppendLine("  $($r.DisplayName)") }
            }
            # Check proxy configuration
            try {
                $proxy = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -EA SilentlyContinue
                [void]$sb.AppendLine("`nProxy Enabled: $($proxy.ProxyEnable -eq 1)")
                if ($proxy.ProxyServer) { [void]$sb.AppendLine("Proxy Server: $($proxy.ProxyServer)") }
                if ($proxy.AutoConfigURL) { [void]$sb.AppendLine("PAC/WPAD URL: $($proxy.AutoConfigURL)") }
            } catch {}
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 1) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Egress filtering scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'NP06' = @{ Type='Local'; Label='Scan Stale Firewall Rules'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            $rules = Get-NetFirewallRule -Enabled True -EA Stop
            # Find potentially stale rules (common indicators)
            $staleIndicators = @('temp','test','troubleshoot','vendor','old','backup','delete','remove','fixme','TODO','trial')
            $staleRules = @()
            foreach ($r in $rules) {
                $isStale = $staleIndicators | Where-Object { $r.DisplayName -match $_ -or $r.Description -match $_ }
                if ($isStale) { $staleRules += $r }
            }
            [void]$sb.AppendLine("POTENTIALLY STALE FIREWALL RULES ($($staleRules.Count)):")
            foreach ($sr in ($staleRules | Select-Object -First 20)) {
                $issues++
                [void]$sb.AppendLine("  $($sr.DisplayName) | Dir:$($sr.Direction) | Action:$($sr.Action) | Profile:$($sr.Profile)")
            }
            if ($staleRules.Count -eq 0) { [void]$sb.AppendLine("  No rules with stale-looking names found") }
            # Check total rule count (excessive rules = likely uncurated)
            [void]$sb.AppendLine("`nTOTAL ENABLED RULES: $($rules.Count)")
            if ($rules.Count -gt 200) { [void]$sb.AppendLine("  [!] High rule count suggests rules may not be regularly reviewed"); $issues++ }
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 3) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Stale firewall rule scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'NP07' = @{ Type='Local'; Label='Scan IDS/IPS Presence'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $found = $false
            # Check for IDS/IPS services
            $idsServices = @(
                @{Name='Snort*';Desc='Snort IDS'},@{Name='Suricata*';Desc='Suricata IDS'},
                @{Name='OSSEC*';Desc='OSSEC HIDS'},@{Name='Wazuh*';Desc='Wazuh HIDS'},
                @{Name='MsSense';Desc='Defender for Endpoint'},@{Name='cb*';Desc='Carbon Black'},
                @{Name='CrowdStrike*';Desc='CrowdStrike Falcon'},@{Name='SentinelAgent*';Desc='SentinelOne'},
                @{Name='SophosSafestore*';Desc='Sophos'},@{Name='Symantec*';Desc='Symantec/Broadcom'}
            )
            [void]$sb.AppendLine("IDS/IPS AND EDR DETECTION:")
            foreach ($ids in $idsServices) {
                $svc = Get-Service $ids.Name -EA SilentlyContinue
                if ($svc) { $found = $true; [void]$sb.AppendLine("  $($ids.Desc): $($svc.DisplayName) ($($svc.Status))") }
            }
            if (-not $found) { [void]$sb.AppendLine("  No IDS/IPS/EDR agents detected on this host [!]") }
            # Check Windows Defender advanced features
            try {
                $mp = Get-MpPreference -EA SilentlyContinue
                if ($mp) {
                    [void]$sb.AppendLine("`nDEFENDER FEATURES:")
                    [void]$sb.AppendLine("  Network Protection: $(if($mp.EnableNetworkProtection -eq 1){'Enabled'}else{'Disabled'})")
                    [void]$sb.AppendLine("  PUA Protection: $($mp.PUAProtection)")
                    [void]$sb.AppendLine("  Cloud Protection: $($mp.MAPSReporting)")
                    [void]$sb.AppendLine("  ASR Rules: $(($mp.AttackSurfaceReductionRules_Actions | Where-Object {$_ -gt 0}).Count) active")
                }
            } catch {}
            $status = if ($found) {'Pass'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="IDS/IPS scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'NP08' = @{ Type='Local'; Label='Scan TLS / Crypto Configuration'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Check TLS registry settings with proper Enabled + DisabledByDefault validation
            $protocols = @(
                @{Name='SSL 2.0'; Legacy=$true}; @{Name='SSL 3.0'; Legacy=$true}
                @{Name='TLS 1.0'; Legacy=$true}; @{Name='TLS 1.1'; Legacy=$true}
                @{Name='TLS 1.2'; Legacy=$false}; @{Name='TLS 1.3'; Legacy=$false}
            )
            [void]$sb.AppendLine("PROTOCOL STATUS (SCHANNEL Registry):")
            foreach ($p in $protocols) {
                $basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$($p.Name)"
                $sEnabled = (Get-ItemProperty "$basePath\Server" -Name 'Enabled' -EA SilentlyContinue).Enabled
                $sDisabled = (Get-ItemProperty "$basePath\Server" -Name 'DisabledByDefault' -EA SilentlyContinue).DisabledByDefault
                $cEnabled = (Get-ItemProperty "$basePath\Client" -Name 'Enabled' -EA SilentlyContinue).Enabled
                # Determine effective state
                $explicitlyDisabled = ($sEnabled -eq 0) -or ($sDisabled -eq 1)
                $status_str = if ($sEnabled -eq 0) {'Explicitly Disabled'} elseif ($sEnabled -eq 1) {'Explicitly Enabled'} else {'OS Default'}
                # Legacy protocols should be explicitly disabled
                if ($p.Legacy -and -not $explicitlyDisabled) {
                    $issues++
                    [void]$sb.AppendLine("  $($p.Name): $status_str [!] Should be explicitly disabled (Enabled=0, DisabledByDefault=1)")
                } else {
                    [void]$sb.AppendLine("  $($p.Name): $status_str $(if($p.Legacy -and $explicitlyDisabled){'[OK]'})")
                }
            }
            # .NET TLS enforcement (both 64-bit and WOW6432Node)
            [void]$sb.AppendLine("`n.NET FRAMEWORK TLS SETTINGS:")
            $dotNetPaths = @(
                @{Path='HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'; Label='64-bit'}
                @{Path='HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'; Label='32-bit'}
            )
            foreach ($dp in $dotNetPaths) {
                try {
                    $strong = (Get-ItemProperty $dp.Path -EA SilentlyContinue).SchUseStrongCrypto
                    $sysDef = (Get-ItemProperty $dp.Path -EA SilentlyContinue).SystemDefaultTlsVersions
                    $strongOk = $strong -eq 1
                    $sysOk = $sysDef -eq 1
                    if (-not $strongOk) { $issues++ }
                    if (-not $sysOk) { $issues++ }
                    [void]$sb.AppendLine("  $($dp.Label): SchUseStrongCrypto=$(if($strongOk){'1 [OK]'}else{'Not set [!]'}) | SystemDefaultTlsVersions=$(if($sysOk){'1 [OK]'}else{'Not set [!]'})")
                } catch { [void]$sb.AppendLine("  $($dp.Label): Could not query") }
            }
            # Certificates
            $certs = Get-ChildItem Cert:\LocalMachine\My -EA SilentlyContinue
            if ($certs) {
                [void]$sb.AppendLine("`nMACHINE CERTIFICATES ($($certs.Count)):")
                foreach ($c in ($certs | Select-Object -First 10)) {
                    $daysLeft = ($c.NotAfter - (Get-Date)).Days
                    $weak = $c.SignatureAlgorithm.FriendlyName -match 'SHA1|MD5'
                    if ($daysLeft -lt 30) { $issues++ }
                    if ($weak) { $issues++ }
                    [void]$sb.AppendLine("  $($c.Subject) | Expires:$($c.NotAfter.ToString('yyyy-MM-dd')) (${daysLeft}d) | Algo:$($c.SignatureAlgorithm.FriendlyName) $(if($weak){'[WEAK ALGO!]'})$(if($daysLeft -lt 30){'[EXPIRING!]'})")
                }
            }
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 2) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="TLS/crypto scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'NP09' = @{ Type='Local'; Label='Scan NAT / Port Forwarding'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Check netsh port proxy rules
            try {
                $portProxy = netsh interface portproxy show all 2>&1
                if ($portProxy -match 'Listen|Connect') {
                    $issues++
                    [void]$sb.AppendLine("PORT PROXY RULES DETECTED:")
                    foreach ($line in $portProxy) { [void]$sb.AppendLine("  $line") }
                } else { [void]$sb.AppendLine("No port proxy rules configured") }
            } catch { [void]$sb.AppendLine("Port proxy check: $_") }
            # Check for IP routing enabled
            try {
                $ipFwd = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -EA SilentlyContinue).IPEnableRouter
                [void]$sb.AppendLine("`nIP Forwarding/Routing: $(if($ipFwd -eq 1){'ENABLED [!]'; $issues++}else{'Disabled'})")
            } catch {}
            # Check for ICS (Internet Connection Sharing)
            $ics = Get-Service SharedAccess -EA SilentlyContinue
            if ($ics -and $ics.Status -eq 'Running') { [void]$sb.AppendLine("Internet Connection Sharing: RUNNING [!]"); $issues++ }
            # Check for RRAS (Routing and Remote Access)
            $rras = Get-Service RemoteAccess -EA SilentlyContinue
            if ($rras -and $rras.Status -eq 'Running') { [void]$sb.AppendLine("RRAS Service: RUNNING - may be performing NAT/routing") }
            [void]$sb.AppendLine("`n[NOTE] Check perimeter firewall/router for port forwarding rules - cannot be detected from this host alone.")
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 1) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="NAT/port forwarding scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'NP10' = @{ Type='Local'; Label='Scan Firmware / Software / Config Hygiene'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # BIOS/Firmware
            $bios = Get-CimInstance Win32_BIOS -EA SilentlyContinue -OperationTimeoutSec 10
            if ($bios) {
                $biosDateStr = 'Unknown'
                $biosAge = $null
                if ($bios.ReleaseDate -is [datetime]) {
                    $biosAge = ((Get-Date) - $bios.ReleaseDate).Days
                    $biosDateStr = $bios.ReleaseDate.ToString('yyyy-MM-dd')
                }
                [void]$sb.AppendLine("BIOS: $($bios.Manufacturer) | Version: $($bios.SMBIOSBIOSVersion) | Date: $biosDateStr$(if($biosAge){" ($biosAge days ago)"})")
                if ($biosAge -and $biosAge -gt 1095) { $issues++; [void]$sb.AppendLine("  [!] BIOS older than 3 years - check for firmware updates") }
            }
            # OS Build
            $os = Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue -OperationTimeoutSec 10
            if ($os) {
                $installStr = if ($os.InstallDate -is [datetime]) { $os.InstallDate.ToString('yyyy-MM-dd') } else { 'Unknown' }
                [void]$sb.AppendLine("OS: $($os.Caption) Build $($os.BuildNumber) | Installed: $installStr")
            }
            # .NET versions
            $dotnet = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -EA SilentlyContinue
            if ($dotnet) { [void]$sb.AppendLine(".NET Framework: $(($dotnet | Get-ItemProperty).Release)") }
            # PowerShell version
            [void]$sb.AppendLine("PowerShell: $($PSVersionTable.PSVersion)")
            # WSUS configuration - verify HTTPS
            [void]$sb.AppendLine("`nWSUS CONFIGURATION:")
            try {
                $wu = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -EA SilentlyContinue
                if ($wu -and $wu.WUServer) {
                    $wsusHttps = $wu.WUServer -match '^https://'
                    [void]$sb.AppendLine("  WSUS Server  : $($wu.WUServer) $(if(-not $wsusHttps){'[HTTP - should use HTTPS!]'; $issues++}else{'[HTTPS OK]'})")
                    [void]$sb.AppendLine("  Status Server: $($wu.WUStatusServer)")
                } else { [void]$sb.AppendLine("  No WSUS configured (using Windows Update or other)") }
            } catch {}
            # Print Spooler on servers/DCs (PrintNightmare risk)
            [void]$sb.AppendLine("`nPRINT SPOOLER SERVICE:")
            try {
                $spooler = Get-Service Spooler -EA SilentlyContinue
                $isServer = $script:Env.IsServer
                $isDC = $script:Env.IsDomainJoined -and ($os.Caption -match 'Server')
                if ($spooler -and $spooler.Status -eq 'Running' -and $isServer) {
                    $issues++; [void]$sb.AppendLine("  Spooler: RUNNING on server$(if($isDC){' (DC)'}) [!] - disable unless print server role required (PrintNightmare)")
                } elseif ($spooler) { [void]$sb.AppendLine("  Spooler: $($spooler.Status) $(if($isServer -and $spooler.Status -ne 'Running'){'[OK - disabled on server]'})") }
            } catch {}
            # Network driver versions
            [void]$sb.AppendLine("`nNETWORK DRIVER VERSIONS:")
            $adapters = Get-NetAdapter -EA SilentlyContinue | Where-Object { $_.Status -eq 'Up' }
            foreach ($a in $adapters) {
                $drv = $a.DriverVersion
                $drvDateStr = ''
                if ($a.DriverDate -is [datetime]) { $drvDateStr = " ($($a.DriverDate.ToString('yyyy-MM-dd')))" }
                [void]$sb.AppendLine("  $($a.InterfaceDescription): v$drv$drvDateStr")
            }
            # Security software via registry (fast, avoids slow Win32_Product WMI class)
            [void]$sb.AppendLine("`nINSTALLED SECURITY SOFTWARE:")
            $secPattern = 'Security|Antivirus|Firewall|VPN|Endpoint|CrowdStrike|Sentinel|Sophos|Defender|ESET|Kaspersky|Malware|Norton|McAfee|Bitdefender'
            $regPaths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
            $secSoft = @()
            foreach ($rp in $regPaths) {
                try { $secSoft += @(Get-ItemProperty $rp -EA SilentlyContinue | Where-Object { $_.DisplayName -match $secPattern } | Select-Object -Property DisplayName,DisplayVersion -First 10) } catch {}
            }
            $secSoft = $secSoft | Sort-Object DisplayName -Unique | Select-Object -First 10
            if ($secSoft) { foreach ($ss in $secSoft) { [void]$sb.AppendLine("  $($ss.DisplayName) v$($ss.DisplayVersion)") } }
            else { [void]$sb.AppendLine("  No security software detected in registry") }
            $status = if ($issues -eq 0) {'Pass'} else {'Partial'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Firmware/software/config scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    # ── Backup & Recovery Auto-Checks ─────────────────────────────────────────

    'BR01' = @{ Type='Local'; Label='Scan Backup Solutions'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $found = $false
            # Single Get-Service call for all services, then match
            $backupPatterns = @{
                'wbengine'='Windows Server Backup'; 'vss'='Volume Shadow Copy';
                'VeeamBackupSvc'='Veeam'; 'VeeamAgent'='Veeam Agent';
                'AcronisAgent'='Acronis'; 'BackupExecAgent'='Veritas Backup Exec';
                'DattoBackupAgent'='Datto/Kaseya'; 'StorageCraft'='StorageCraft';
                'ArcserveUDP'='Arcserve'; 'CarboniteService'='Carbonite';
                'CrashPlanService'='CrashPlan'; 'CloudBerry'='MSP360/CloudBerry';
                'ShadowProtect'='ShadowProtect'; 'NableBM'='N-able Backup'
            }
            [void]$sb.AppendLine("BACKUP SOLUTIONS DETECTED:")
            try {
                $allSvc = Get-Service -EA SilentlyContinue
                foreach ($svc in $allSvc) {
                    foreach ($pat in $backupPatterns.Keys) {
                        if ($svc.ServiceName -like "*${pat}*") {
                            $found = $true
                            [void]$sb.AppendLine("  $($backupPatterns[$pat]): $($svc.DisplayName) ($($svc.Status))")
                        }
                    }
                }
            } catch { [void]$sb.AppendLine("  Service query failed: $_") }
            if (-not $found) { [void]$sb.AppendLine("  No backup agent/service detected [CRITICAL!]") }
            # Check VSS (Shadow Copies)
            try {
                $shadows = Get-CimInstance Win32_ShadowCopy -EA SilentlyContinue -OperationTimeoutSec 10
                [void]$sb.AppendLine("`nSHADOW COPIES: $(if($shadows){@($shadows).Count}else{0})")
                if ($shadows) {
                    $latest = $shadows | Sort-Object InstallDate -Descending | Select-Object -First 3
                    foreach ($sh in $latest) { [void]$sb.AppendLine("  $($sh.VolumeName) | Created: $($sh.InstallDate)") }
                }
            } catch { [void]$sb.AppendLine("`nSHADOW COPIES: Query failed") }
            # Check for backup scheduled tasks - targeted task paths to avoid full enumeration
            try {
                $backupTasks = @()
                foreach ($tp in @('\','\Microsoft\Windows\Backup\','\Microsoft\Windows\WindowsBackup\')) {
                    try { $backupTasks += @(Get-ScheduledTask -TaskPath $tp -EA SilentlyContinue | Where-Object { $_.TaskName -match 'backup|veeam|acronis|shadow|wbadmin' -and $_.State -ne 'Disabled' }) } catch {}
                }
                if ($backupTasks.Count -gt 0) {
                    [void]$sb.AppendLine("`nBACKUP SCHEDULED TASKS ($($backupTasks.Count)):")
                    foreach ($bt in ($backupTasks | Select-Object -First 5)) { [void]$sb.AppendLine("  $($bt.TaskName) | State:$($bt.State)") }
                }
            } catch { [void]$sb.AppendLine("`nScheduled task query failed") }
            # Windows Server Backup status - only if cmdlet exists
            if (Get-Command Get-WBSummary -EA SilentlyContinue) {
                try {
                    $wbStatus = Get-WBSummary -EA SilentlyContinue
                    if ($wbStatus) {
                        [void]$sb.AppendLine("`nWINDOWS SERVER BACKUP:")
                        [void]$sb.AppendLine("  Last Success: $($wbStatus.LastSuccessfulBackupTime)")
                        [void]$sb.AppendLine("  Last Backup: $($wbStatus.LastBackupTime)")
                        [void]$sb.AppendLine("  Next Backup: $($wbStatus.NextBackupTime)")
                    }
                } catch {}
            }
            $status = if ($found) {'Pass'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Backup solution scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'BR02' = @{ Type='Local'; Label='Scan Backup Restore Test Evidence'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Check event logs for restore events
            [void]$sb.AppendLine("BACKUP RESTORE EVENT SEARCH:")
            try {
                $restoreEvents = Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=(Get-Date).AddDays(-90)} -MaxEvents 1000 -EA SilentlyContinue |
                    Where-Object { $_.Message -match 'restore|recovered|recovery completed' }
                [void]$sb.AppendLine("  Restore-related events (last 90d): $(($restoreEvents | Measure-Object).Count)")
                foreach ($re in ($restoreEvents | Select-Object -First 5)) { [void]$sb.AppendLine("  [$($re.TimeCreated.ToString('yyyy-MM-dd'))] $($re.Message.Substring(0,[math]::Min(120,$re.Message.Length)))...") }
            } catch { [void]$sb.AppendLine("  Could not search event logs") }
            # Check for VSS restore points
            try {
                $rp = Get-ComputerRestorePoint -EA SilentlyContinue
                [void]$sb.AppendLine("`nSYSTEM RESTORE POINTS: $(if($rp){$rp.Count}else{0})")
                if ($rp) { foreach ($r in ($rp | Select-Object -Last 3)) { [void]$sb.AppendLine("  $($r.Description) | $($r.CreationTime)") } }
            } catch {}
            [void]$sb.AppendLine("`n[!] IMPORTANT: A successful backup verification is NOT a restore test.")
            [void]$sb.AppendLine("[!] Ask: When was the last actual restore FROM backup performed?")
            [void]$sb.AppendLine("[!] If never tested, this is a CRITICAL finding.")
            $issues++
            $status = 'Partial'
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Backup restore evidence scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'BR03' = @{ Type='Local'; Label='Scan Immutable / Air-Gapped Backups'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Check backup destinations
            [void]$sb.AppendLine("BACKUP DESTINATION ANALYSIS:")
            # Check for network shares used by backup
            try {
                $shares = Get-SmbShare -EA SilentlyContinue | Where-Object { $_.Name -match 'backup|bak|archive' }
                if ($shares) {
                    [void]$sb.AppendLine("BACKUP-RELATED SMB SHARES:")
                    foreach ($sh in $shares) { [void]$sb.AppendLine("  $($sh.Name) -> $($sh.Path) (Access: $($sh.CurrentUsers) users)") }
                    [void]$sb.AppendLine("  [!] Network shares are NOT air-gapped - ransomware can encrypt them"); $issues++
                }
            } catch {}
            # Check for removable/external drives
            $removable = Get-CimInstance Win32_DiskDrive -EA SilentlyContinue -OperationTimeoutSec 10 | Where-Object { $_.InterfaceType -eq 'USB' -or $_.MediaType -match 'External|Removable' }
            if ($removable) {
                [void]$sb.AppendLine("`nEXTERNAL/USB DRIVES:")
                foreach ($r in $removable) { [void]$sb.AppendLine("  $($r.Model) | Size: $([math]::Round($r.Size/1GB,1))GB | Interface: $($r.InterfaceType)") }
            }
            # Check Volume Shadow Copy storage
            try {
                $vssStorage = vssadmin list shadowstorage 2>&1
                if ($vssStorage -notmatch 'No items') { [void]$sb.AppendLine("`nVSS STORAGE:"); foreach ($l in $vssStorage) { if ($l.Trim()) { [void]$sb.AppendLine("  $($l.Trim())") } } }
            } catch {}
            [void]$sb.AppendLine("`n[!] Verify: Are backups stored on a medium that ransomware cannot reach?")
            [void]$sb.AppendLine("[!] True immutability requires: offline tapes, cloud with object lock, or hardware WORM.")
            $status = if ($issues -eq 0) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Immutable backup scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'BR04' = @{ Type='Local'; Label='Scan RTO/RPO Documentation'
        Script = {
            $sb = [System.Text.StringBuilder]::new()
            # Check backup frequency indicators
            [void]$sb.AppendLine("BACKUP FREQUENCY INDICATORS:")
            try {
                $shadows = Get-CimInstance Win32_ShadowCopy -EA SilentlyContinue -OperationTimeoutSec 10 | Sort-Object InstallDate -Descending
                if ($shadows -and $shadows.Count -ge 2) {
                    $interval = ($shadows[0].InstallDate - $shadows[1].InstallDate)
                    [void]$sb.AppendLine("  VSS snapshot interval: ~$([math]::Round($interval.TotalHours,1)) hours (RPO indicator)")
                    [void]$sb.AppendLine("  Latest snapshot: $($shadows[0].InstallDate)")
                    [void]$sb.AppendLine("  Snapshots in last 30d: $(($shadows | Where-Object { $_.InstallDate -gt (Get-Date).AddDays(-30) }).Count)")
                }
            } catch {}
            # Check backup scheduled task timing
            $backupTasks = @()
            try {
                foreach ($tp in @('\','\Microsoft\Windows\Backup\','\Microsoft\Windows\WindowsBackup\')) {
                    try { $backupTasks += @(Get-ScheduledTask -TaskPath $tp -EA SilentlyContinue | Where-Object { $_.TaskName -match 'backup|veeam|acronis|shadow' -and $_.State -ne 'Disabled' }) } catch {}
                }
            } catch {}
            if ($backupTasks) {
                [void]$sb.AppendLine("`nBACKUP SCHEDULE (from scheduled tasks):")
                foreach ($bt in $backupTasks) {
                    $triggers = $bt.Triggers
                    foreach ($tr in $triggers) { [void]$sb.AppendLine("  $($bt.TaskName): $($tr.CimClass.CimClassName -replace 'MSFT_Task','')") }
                }
            }
            [void]$sb.AppendLine("`n[!] Ask the client:")
            [void]$sb.AppendLine("  1. What is your target Recovery Time Objective (RTO)?")
            [void]$sb.AppendLine("  2. What is your target Recovery Point Objective (RPO)?")
            [void]$sb.AppendLine("  3. Are these documented and approved by business stakeholders?")
            [void]$sb.AppendLine("  4. Has an actual restore ever been timed to validate the RTO?")
            @{ Status='Partial'; Findings=$sb.ToString().Trim(); Evidence="RTO/RPO data scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'BR05' = @{ Type='Local'; Label='Scan Backup Encryption'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Check BitLocker on potential backup volumes
            try {
                $vols = Get-BitLockerVolume -EA SilentlyContinue
                [void]$sb.AppendLine("BITLOCKER STATUS (all volumes):")
                foreach ($v in $vols) {
                    $encrypted = $v.ProtectionStatus -eq 'On'
                    [void]$sb.AppendLine("  $($v.MountPoint) $($v.VolumeStatus) | Protection:$($v.ProtectionStatus) | Method:$($v.EncryptionMethod)")
                }
            } catch { [void]$sb.AppendLine("BitLocker: Not available") }
            # Check EFS configuration
            try {
                $efs = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\EFS' -EA SilentlyContinue
                [void]$sb.AppendLine("`nEFS Policy: $(if($efs){'Configured'}else{'Default (available but not enforced)'})")
            } catch {}
            # Check for backup software encryption indicators
            [void]$sb.AppendLine("`n[!] Verify with backup software:")
            [void]$sb.AppendLine("  1. Is backup data encrypted at rest?")
            [void]$sb.AppendLine("  2. Is backup data encrypted in transit?")
            [void]$sb.AppendLine("  3. Where are encryption keys stored?")
            [void]$sb.AppendLine("  4. Are keys separate from the backup data?")
            $status = 'Partial'
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Backup encryption scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'BR06' = @{ Type='Local'; Label='Scan Backup Monitoring / Alerting'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Check for backup-related events in last 7 days
            [void]$sb.AppendLine("BACKUP EVENT LOG ACTIVITY (last 7 days):")
            try {
                $events = Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=(Get-Date).AddDays(-7)} -MaxEvents 2000 -EA SilentlyContinue |
                    Where-Object { $_.ProviderName -match 'Backup|VSS|Veeam|Acronis|Wbadmin|SPP' }
                $grouped = $events | Group-Object ProviderName
                foreach ($g in $grouped) { [void]$sb.AppendLine("  $($g.Name): $($g.Count) events") }
                $errors = $events | Where-Object { $_.Level -eq 2 }
                if ($errors) { [void]$sb.AppendLine("`n  [!] BACKUP ERRORS: $($errors.Count)"); $issues++ }
                if (-not $events) { [void]$sb.AppendLine("  No backup events found [!]"); $issues++ }
            } catch { [void]$sb.AppendLine("  Event log query failed") }
            # Check for backup-related scheduled tasks (monitoring)
            $monTasks = @()
            try {
                foreach ($tp in @('\','\Microsoft\Windows\Backup\','\Microsoft\Windows\WindowsBackup\')) {
                    try { $monTasks += @(Get-ScheduledTask -TaskPath $tp -EA SilentlyContinue | Where-Object { $_.TaskName -match 'backup.*report|backup.*alert|backup.*monitor|backup.*notify' }) } catch {}
                }
            } catch {}
            if ($monTasks) {
                [void]$sb.AppendLine("`nBACKUP MONITORING TASKS:")
                foreach ($mt in $monTasks) { [void]$sb.AppendLine("  $($mt.TaskName) ($($mt.State))") }
            } else { [void]$sb.AppendLine("`nNo backup monitoring/alerting tasks found"); $issues++ }
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -eq 1) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Backup monitoring scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'BR07' = @{ Type='Local'; Label='Scan DR Plan / Documentation'
        Script = {
            $sb = [System.Text.StringBuilder]::new()
            # Check for DR-related GPOs
            try {
                $gpos = Get-GPO -All -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'disaster|recovery|DR|business.continuity|BCP' }
                if ($gpos) {
                    [void]$sb.AppendLine("DR-RELATED GPOs:")
                    foreach ($g in $gpos) { [void]$sb.AppendLine("  $($g.DisplayName) | Modified: $($g.ModificationTime.ToString('yyyy-MM-dd'))") }
                } else { [void]$sb.AppendLine("No DR-related GPOs found") }
            } catch { [void]$sb.AppendLine("GPO check: Not available (non-domain or no GPMC)") }
            # Check for recovery partition
            $parts = Get-Partition -EA SilentlyContinue | Where-Object { $_.Type -eq 'Recovery' }
            [void]$sb.AppendLine("`nRecovery Partitions: $(if($parts){$parts.Count}else{0})")
            # Check System Restore
            try {
                $sr = Get-ComputerRestorePoint -EA SilentlyContinue
                [void]$sb.AppendLine("System Restore Points: $(if($sr){$sr.Count}else{0})")
            } catch {}
            [void]$sb.AppendLine("`n[!] DR DOCUMENTATION CHECKLIST - verify these exist:")
            [void]$sb.AppendLine("  [ ] Written DR plan document")
            [void]$sb.AppendLine("  [ ] Recovery procedure runbooks")
            [void]$sb.AppendLine("  [ ] Contact/escalation tree")
            [void]$sb.AppendLine("  [ ] Tabletop exercise completed (last 12 months)")
            [void]$sb.AppendLine("  [ ] Roles and responsibilities assigned")
            [void]$sb.AppendLine("  [ ] Off-site meeting location designated")
            @{ Status='Partial'; Findings=$sb.ToString().Trim(); Evidence="DR documentation scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'BR08' = @{ Type='Local'; Label='Scan Cloud/SaaS Backup'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Check for cloud backup agents
            $cloudBackup = @(
                @{Name='OneDrive*';Desc='OneDrive (M365)'},@{Name='Dropbox*';Desc='Dropbox'},
                @{Name='Box*Sync*';Desc='Box'},@{Name='GoogleDrive*';Desc='Google Drive'},
                @{Name='iDriveService';Desc='iDrive'},@{Name='Backblaze*';Desc='Backblaze'},
                @{Name='SpanningBackup*';Desc='Spanning Backup'},@{Name='AvePoint*';Desc='AvePoint'},
                @{Name='Veeam*O365*';Desc='Veeam for M365'},@{Name='AFI*';Desc='AFI Backup'}
            )
            [void]$sb.AppendLine("CLOUD BACKUP AGENTS:")
            $foundCloud = $false
            foreach ($cb in $cloudBackup) {
                $svc = Get-Service $cb.Name -EA SilentlyContinue
                if ($svc) { $foundCloud = $true; [void]$sb.AppendLine("  $($cb.Desc): $($svc.DisplayName) ($($svc.Status))") }
            }
            # Check for OneDrive Known Folder Move
            try {
                $kfm = Get-ItemProperty 'HKCU:\Software\Microsoft\OneDrive\Accounts\Business1' -Name 'KfmFoldersProtectedNow' -EA SilentlyContinue
                if ($kfm) { $foundCloud = $true; [void]$sb.AppendLine("  OneDrive Known Folder Move: Active") }
            } catch {}
            if (-not $foundCloud) { [void]$sb.AppendLine("  No cloud backup agents detected"); $issues++ }
            # Check M365 connectivity
            $outlook = Get-Process OUTLOOK -EA SilentlyContinue
            $teams = Get-Process Teams -EA SilentlyContinue
            [void]$sb.AppendLine("`nM365 INDICATORS:")
            [void]$sb.AppendLine("  Outlook running: $(if($outlook){'Yes'}else{'No'})")
            [void]$sb.AppendLine("  Teams running: $(if($teams){'Yes'}else{'No'})")
            [void]$sb.AppendLine("`n[!] CRITICAL: M365 data (Exchange, SharePoint, OneDrive, Teams)")
            [void]$sb.AppendLine("    is NOT backed up by Microsoft by default!")
            [void]$sb.AppendLine("    Ask: Do you have a third-party M365 backup solution?")
            $status = if ($foundCloud) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Cloud/SaaS backup scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    # ── Common Findings: Remaining ────────────────────────────────────────────

    'CF03' = @{ Type='Local'; Label='Scan Backup Restore Testing'
        Script = {
            $sb = [System.Text.StringBuilder]::new()
            # Check for any recent restore activity
            try {
                $restoreEvents = Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=(Get-Date).AddDays(-180)} -MaxEvents 5000 -EA SilentlyContinue |
                    Where-Object { $_.Message -match 'restore|recovery completed|recovery succeeded' }
                [void]$sb.AppendLine("RESTORE EVENTS (last 180 days): $(($restoreEvents | Measure-Object).Count)")
                foreach ($re in ($restoreEvents | Select-Object -First 5)) {
                    [void]$sb.AppendLine("  [$($re.TimeCreated.ToString('yyyy-MM-dd'))] $($re.ProviderName): $($re.Message.Substring(0,[math]::Min(100,$re.Message.Length)))")
                }
            } catch {}
            # Check backup software status
            $veeam = Get-Service Veeam* -EA SilentlyContinue
            $wsb = Get-Command wbadmin -EA SilentlyContinue
            [void]$sb.AppendLine("`nBACKUP SOFTWARE:")
            if ($veeam) { [void]$sb.AppendLine("  Veeam: Installed") }
            if ($wsb) { [void]$sb.AppendLine("  Windows Server Backup: Available") }
            [void]$sb.AppendLine("`n=== THIS IS THE #1 FINDING IN SMB AUDITS ===")
            [void]$sb.AppendLine("Ask: 'When did you last perform an actual restore test?'")
            [void]$sb.AppendLine("If answer is 'never' or 'I don't remember' -> CRITICAL finding")
            [void]$sb.AppendLine("A backup that has never been restore-tested is NOT a backup.")
            @{ Status='Partial'; Findings=$sb.ToString().Trim(); Evidence="Backup restore test scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'CF05' = @{ Type='Local'; Label='Scan Open File Shares'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Check SMB shares
            try {
                $shares = Get-SmbShare -EA Stop | Where-Object { $_.Name -notmatch '^\$|^IPC\$|^ADMIN\$|^print\$' }
                [void]$sb.AppendLine("NON-DEFAULT SMB SHARES ($($shares.Count)):")
                foreach ($sh in $shares) {
                    $access = Get-SmbShareAccess $sh.Name -EA SilentlyContinue
                    $everyone = $access | Where-Object { $_.AccountName -match 'Everyone|ANONYMOUS|Authenticated Users|Domain Users' -and $_.AccessControlType -eq 'Allow' }
                    if ($everyone) { $issues++ }
                    [void]$sb.AppendLine("  \\$env:COMPUTERNAME\$($sh.Name) -> $($sh.Path) $(if($everyone){'[BROAD ACCESS!]'})")
                    foreach ($e in $everyone) { [void]$sb.AppendLine("    [!] $($e.AccountName): $($e.AccessRight)") }
                }
            } catch { [void]$sb.AppendLine("SMB Share enumeration failed: $_") }
            # Check for hidden admin shares
            $adminShares = Get-SmbShare -EA SilentlyContinue | Where-Object { $_.Name -match '^\w\$$' }
            [void]$sb.AppendLine("`nADMIN SHARES: $(($adminShares | Measure-Object).Count) (C$, D$, etc.)")
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 2) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="File share scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    # ── Policies & Standards Auto-Checks ──────────────────────────────────────

    'PS01' = @{ Type='Local'; Label='Scan Physical Security Indicators'
        Script = {
            $sb = [System.Text.StringBuilder]::new()
            # Check for screen lock policy
            try {
                $lock = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -EA SilentlyContinue
                $timeout = Get-ItemProperty 'HKCU:\Control Panel\Desktop' -Name ScreenSaveTimeOut -EA SilentlyContinue
                [void]$sb.AppendLine("SCREEN LOCK POLICY:")
                [void]$sb.AppendLine("  Screen saver timeout: $(if($timeout.ScreenSaveTimeOut){"$($timeout.ScreenSaveTimeOut)s"}else{'Not set'})")
                $ssActive = (Get-ItemProperty 'HKCU:\Control Panel\Desktop' -Name ScreenSaveActive -EA SilentlyContinue).ScreenSaveActive
                [void]$sb.AppendLine("  Screen saver active: $ssActive")
                $ssSecure = (Get-ItemProperty 'HKCU:\Control Panel\Desktop' -Name ScreenSaverIsSecure -EA SilentlyContinue).ScreenSaverIsSecure
                [void]$sb.AppendLine("  Password on resume: $ssSecure")
            } catch {}
            # Check for camera/physical security software
            $secSoft = Get-Process -EA SilentlyContinue | Where-Object { $_.ProcessName -match 'camera|surveillance|DVR|NVR|milestone|genetec|exacq|avigilon|hikvision' }
            if ($secSoft) {
                [void]$sb.AppendLine("`nSECURITY CAMERA SOFTWARE RUNNING:")
                foreach ($ss in $secSoft) { [void]$sb.AppendLine("  $($ss.ProcessName)") }
            }
            [void]$sb.AppendLine("`n[!] PHYSICAL SECURITY CHECKLIST:")
            [void]$sb.AppendLine("  [ ] Server room / MDF / IDF locked")
            [void]$sb.AppendLine("  [ ] Access control (badge/key) with logging")
            [void]$sb.AppendLine("  [ ] Security cameras at entry points")
            [void]$sb.AppendLine("  [ ] Visitor sign-in/out process")
            [void]$sb.AppendLine("  [ ] Clean desk policy enforced")
            @{ Status='Partial'; Findings=$sb.ToString().Trim(); Evidence="Physical security scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'PS02' = @{ Type='Local'; Label='Scan Visitor / Access Policy'
        Script = {
            $sb = [System.Text.StringBuilder]::new()
            # Check for badge system software
            $badgeSoft = Get-Process -EA SilentlyContinue | Where-Object { $_.ProcessName -match 'Lenel|S2|Brivo|Keri|HID|Verkada|openpath|swiftconnect' }
            if ($badgeSoft) {
                [void]$sb.AppendLine("ACCESS CONTROL SOFTWARE DETECTED:")
                foreach ($bs in $badgeSoft) { [void]$sb.AppendLine("  $($bs.ProcessName)") }
            } else { [void]$sb.AppendLine("No badge/access control software detected on this host") }
            # Check AD for visitor/guest accounts
            try {
                $guests = Get-ADUser -Filter 'SamAccountName -like "*visitor*" -or SamAccountName -like "*guest*"' -Properties Enabled,LastLogonDate -EA SilentlyContinue
                if ($guests) {
                    [void]$sb.AppendLine("`nVISITOR/GUEST AD ACCOUNTS:")
                    foreach ($g in $guests) { [void]$sb.AppendLine("  $($g.SamAccountName) Enabled:$($g.Enabled)") }
                }
            } catch {}
            [void]$sb.AppendLine("`n[!] VISITOR MANAGEMENT CHECKLIST:")
            [void]$sb.AppendLine("  [ ] Visitor sign-in/sign-out log at reception")
            [void]$sb.AppendLine("  [ ] Visitor badges issued and collected")
            [void]$sb.AppendLine("  [ ] Visitors escorted in sensitive areas")
            [void]$sb.AppendLine("  [ ] Visitor network access restricted to guest VLAN")
            @{ Status='Partial'; Findings=$sb.ToString().Trim(); Evidence="Visitor/access policy scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm')" }
        }
    }

    'PS03' = @{ Type='Local'; Label='Scan Camera / Surveillance'
        Script = {
            $sb = [System.Text.StringBuilder]::new()
            # Scan for camera/NVR software
            $camProcs = Get-Process -EA SilentlyContinue | Where-Object { $_.ProcessName -match 'camera|NVR|DVR|milestone|genetec|exacq|avigilon|hikvision|dahua|axis|verkada|reolink|blue.iris|ispy|zoneminder' }
            if ($camProcs) {
                [void]$sb.AppendLine("SURVEILLANCE SOFTWARE RUNNING:")
                foreach ($cp in $camProcs) { [void]$sb.AppendLine("  $($cp.ProcessName) (PID:$($cp.Id))") }
            } else { [void]$sb.AppendLine("No surveillance/camera software detected on this host") }
            # Check for camera-related services
            $camSvcs = Get-Service -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'camera|NVR|surveillance|milestone|genetec|video' }
            if ($camSvcs) {
                [void]$sb.AppendLine("`nSURVEILLANCE SERVICES:")
                foreach ($cs in $camSvcs) { [void]$sb.AppendLine("  $($cs.DisplayName) ($($cs.Status))") }
            }
            # Scan network for common camera ports
            [void]$sb.AppendLine("`n[!] SECURITY CAMERA CHECKLIST:")
            [void]$sb.AppendLine("  [ ] Cameras cover all entry/exit points")
            [void]$sb.AppendLine("  [ ] Camera footage retained 30+ days")
            [void]$sb.AppendLine("  [ ] NVR/DVR password changed from default")
            [void]$sb.AppendLine("  [ ] Camera network isolated from production")
            [void]$sb.AppendLine("  [ ] Remote viewing secured with VPN/MFA")
            @{ Status='Partial'; Findings=$sb.ToString().Trim(); Evidence="Surveillance scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'PS04' = @{ Type='Local'; Label='Scan Clean Desk / Credential Exposure'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Check for credentials in common locations
            $credFiles = @()
            $searchPaths = @("$env:USERPROFILE\Desktop","$env:USERPROFILE\Documents","$env:PUBLIC\Desktop")
            foreach ($sp in $searchPaths) {
                $found = Get-ChildItem $sp -File -EA SilentlyContinue | Where-Object { $_.Name -match 'password|credential|login|secret|\.rdp$|\.pgpass|\.my\.cnf' }
                if ($found) { $credFiles += $found }
            }
            if ($credFiles) {
                $issues++
                [void]$sb.AppendLine("POTENTIAL CREDENTIAL FILES FOUND:")
                foreach ($cf in $credFiles) { [void]$sb.AppendLine("  $($cf.FullName) ($($cf.LastWriteTime.ToString('yyyy-MM-dd')))") }
            } else { [void]$sb.AppendLine("No obvious credential files found on Desktop/Documents") }
            # Check for saved RDP credentials
            $rdpFiles = Get-ChildItem "$env:USERPROFILE\Documents" -Filter '*.rdp' -Recurse -EA SilentlyContinue
            if ($rdpFiles) { $issues++; [void]$sb.AppendLine("`nRDP FILES (may contain saved credentials): $($rdpFiles.Count)") }
            # Check Credential Manager
            try {
                $creds = cmdkey /list 2>&1
                $savedCreds = ($creds | Select-String 'Target:').Count
                [void]$sb.AppendLine("`nWindows Credential Manager: $savedCreds saved credentials")
            } catch {}
            # Check for auto-logon
            $autoLogon = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultPassword' -EA SilentlyContinue).DefaultPassword
            if ($autoLogon) { $issues++; [void]$sb.AppendLine("`n[!] AUTO-LOGON with stored password detected!") }
            $status = if ($issues -eq 0) {'Pass'} elseif ($issues -le 1) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="Credential exposure scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'PS05' = @{ Type='Local'; Label='Scan Network Jack / Guest VLAN Security'
        Script = {
            $sb = [System.Text.StringBuilder]::new()
            # Check for guest wireless profiles
            $profiles = netsh wlan show profiles 2>&1
            $guestProfiles = ($profiles | Select-String 'All User Profile\s+:\s+(.+)$' | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }) | Where-Object { $_ -match 'guest|visitor|public' }
            if ($guestProfiles) {
                [void]$sb.AppendLine("GUEST WIRELESS PROFILES:")
                foreach ($gp in $guestProfiles) { [void]$sb.AppendLine("  $gp") }
            }
            # Network adapter enumeration
            $adapters = Get-NetAdapter -EA SilentlyContinue
            $physicalAdapters = $adapters | Where-Object { $_.PhysicalMediaType -and $_.PhysicalMediaType -ne 'Unspecified' }
            [void]$sb.AppendLine("`nPHYSICAL NETWORK ADAPTERS ($($physicalAdapters.Count)):")
            foreach ($a in $physicalAdapters) {
                $ip = (Get-NetIPAddress -InterfaceIndex $a.InterfaceIndex -AddressFamily IPv4 -EA SilentlyContinue).IPAddress
                [void]$sb.AppendLine("  $($a.Name) | Status:$($a.Status) | IP:$(if($ip){$ip}else{'N/A'}) | VLAN:$(if($a.VlanID){$a.VlanID}else{'None'})")
            }
            [void]$sb.AppendLine("`n[!] NETWORK JACK SECURITY CHECKLIST:")
            [void]$sb.AppendLine("  [ ] Unused wall jacks in public areas disabled at switch")
            [void]$sb.AppendLine("  [ ] Public area jacks on guest/isolated VLAN")
            [void]$sb.AppendLine("  [ ] 802.1X authentication required for wired connections")
            [void]$sb.AppendLine("  [ ] Guest WiFi isolated from production network")
            @{ Status='Partial'; Findings=$sb.ToString().Trim(); Evidence="Network jack security scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

    'PS06' = @{ Type='Local'; Label='Scan UPS / Power Protection'
        Script = {
            $sb = [System.Text.StringBuilder]::new(); $issues = 0
            # Check for UPS
            try {
                $battery = Get-CimInstance Win32_Battery -EA SilentlyContinue
                if ($battery) {
                    [void]$sb.AppendLine("BATTERY/UPS DETECTED:")
                    foreach ($b in $battery) { [void]$sb.AppendLine("  $($b.Name) | Status:$($b.BatteryStatus) | Charge:$($b.EstimatedChargeRemaining)% | Runtime:$($b.EstimatedRunTime)min") }
                } else { [void]$sb.AppendLine("No battery/UPS detected via WMI") }
            } catch {}
            # Check for UPS software/services
            $upsSvcs = Get-Service -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'UPS|APC|CyberPower|Eaton|Liebert|Tripp|NUT|PowerChute|PowerPanel' }
            if ($upsSvcs) {
                [void]$sb.AppendLine("`nUPS MANAGEMENT SOFTWARE:")
                foreach ($us in $upsSvcs) { [void]$sb.AppendLine("  $($us.DisplayName) ($($us.Status))") }
            }
            # Check for UPS processes
            $upsProcs = Get-Process -EA SilentlyContinue | Where-Object { $_.ProcessName -match 'PowerChute|PowerPanel|Eaton|NUT' }
            if ($upsProcs) { foreach ($up in $upsProcs) { [void]$sb.AppendLine("UPS Process: $($up.ProcessName)") } }
            # Windows power settings
            $powerPlan = powercfg /getactivescheme 2>&1
            [void]$sb.AppendLine("`nActive Power Plan: $powerPlan")
            [void]$sb.AppendLine("`n[!] UPS/POWER CHECKLIST:")
            [void]$sb.AppendLine("  [ ] UPS on all critical infrastructure (servers, switches, firewall)")
            [void]$sb.AppendLine("  [ ] UPS batteries tested within last 12 months")
            [void]$sb.AppendLine("  [ ] Graceful shutdown configured on UPS software")
            [void]$sb.AppendLine("  [ ] Generator available for extended outages (if applicable)")
            $status = if ($upsSvcs -or $battery) {'Partial'} else {'Fail'}
            @{ Status=$status; Findings=$sb.ToString().Trim(); Evidence="UPS/power scan @ $(Get-Date -f 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME" }
        }
    }

}

# Items that have auto-checks available
$script:AutoCheckIDs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($k in $script:AutoChecks.Keys) { $script:AutoCheckIDs.Add($k) | Out-Null }

# ── Scan Profiles ────────────────────────────────────────────────────────────
# Quick: ~20 critical/high checks - fast field assessment (15 min)
# Standard: ~45 checks - solid audit without the deep dives (30 min)
# Full: all 67 checks - comprehensive compliance audit (45-60 min)
# ADOnly / LocalOnly: type-filtered subsets
$script:ScanProfiles = @{
    Quick = @{
        Label = 'Quick Assessment (~20 checks, ~15 min)'
        Description = 'Critical and high-severity checks only. Fast field triage.'
        IDs = @(
            'NP01','NP02','NP07','NP08'          # Firewall, open ports, IDS, SSL/TLS
            'IA01','IA02','IA03','IA04','IA05'    # Admin groups, service accts, MFA, stale, password policy
            'EP01','EP02','EP04','EP05'            # Defender, patching, BitLocker, firewall status
            'LM01','LM02'                          # Audit config, SIEM
            'BR01','BR06'                          # Backup solution, backup monitoring
            'CF01','CF02','CF05'                   # SMB signing, SMBv1, open shares
        )
    }
    Standard = @{
        Label = 'Standard Audit (~45 checks, ~30 min)'
        Description = 'All critical/high plus key medium checks. Covers most compliance needs.'
        IDs = @(
            'NP01','NP02','NP03','NP04','NP05','NP07','NP08','NP09','NP10'
            'IA01','IA02','IA03','IA04','IA05','IA06','IA07','IA08','IA09'
            'EP01','EP02','EP03','EP04','EP05','EP06','EP07','EP08'
            'LM01','LM02','LM03','LM04','LM06','LM08'
            'BR01','BR02','BR03','BR05','BR06','BR08'
            'CF01','CF02','CF03','CF04','CF05'
            'NA01','NA02','NA03','NA04'
            'PS01','PS04'
        )
    }
    Full = @{
        Label = 'Full Compliance Audit (67 checks, ~60 min)'
        Description = 'All checks across all categories. Complete NIST/CIS/HIPAA coverage.'
        IDs = @()  # Empty = all checks
    }
    ADOnly = @{
        Label = 'AD-Focused (domain checks only)'
        Description = 'Only Active Directory and domain-dependent checks.'
        IDs = @()  # Populated dynamically by Type filter
    }
    LocalOnly = @{
        Label = 'Local Endpoint (local checks only)'
        Description = 'Only local machine checks - no AD/domain required.'
        IDs = @()  # Populated dynamically by Type filter
    }
    # ── Framework-Specific Profiles ──
    HIPAA = @{
        Label = 'HIPAA Assessment (~45 checks)'
        Description = 'Checks mapped to HIPAA Security Rule (164.3xx) requirements for healthcare compliance.'
        IDs = @('IA01','IA02','IA03','IA04','IA05','IA06','IA07','IA08','IA09','IA10','EP01','EP02','EP03','EP04','EP05','EP06','EP07','EP08','EP09','EP10','LM01','LM02','LM03','LM04','LM05','LM06','LM07','LM08','BR01','BR02','BR03','BR04','BR05','BR06','BR07','BR08','CF01','CF02','CF03','CF05','CF07','NP01','NP02','NP08','PS01','PS03','PS04')
    }
    PCI = @{
        Label = 'PCI-DSS 4.0.1 Scan (~48 checks)'
        Description = 'Checks mapped to PCI-DSS 4.0.1 requirements for payment card data environments.'
        IDs = @('NP01','NP02','NP03','NP04','NP05','NP08','NP09','NP10','IA01','IA02','IA03','IA04','IA05','IA06','IA07','IA08','IA09','EP01','EP02','EP03','EP04','EP05','EP06','EP07','EP08','LM01','LM02','LM03','LM04','LM05','LM06','LM07','LM08','NA01','NA02','NA04','BR01','BR02','BR03','BR05','CF01','CF02','CF04','CF05','PS01','PS03','PS04','PS05','PS06')
    }
    CMMC = @{
        Label = 'CMMC 2.0 Level 2 (all 67 checks)'
        Description = 'CMMC 2.0 Level 2 maps to NIST 800-171 - full audit coverage required for DoD contractors.'
        IDs = @()  # All checks apply
    }
    SOC2 = @{
        Label = 'SOC 2 Type II (~60 checks)'
        Description = 'Checks mapped to SOC 2 Trust Services Criteria (CC/A1) for service organization audits.'
        IDs = @('IA01','IA02','IA03','IA04','IA05','IA06','IA07','IA08','IA09','IA10','EP01','EP02','EP03','EP04','EP05','EP06','EP07','EP08','EP09','LM01','LM02','LM03','LM04','LM05','LM06','LM07','LM08','NA01','NA02','NA03','NA04','NA05','NA06','NP01','NP02','NP03','NP04','NP05','NP06','NP07','NP08','NP09','NP10','BR01','BR02','BR03','BR04','BR05','BR06','BR07','BR08','CF01','CF02','CF03','CF04','CF05','CF06','CF07','CF08','PS01','PS02','PS03','PS04','PS05','PS06')
    }
    ISO27001 = @{
        Label = 'ISO 27001:2022 (all 67 checks)'
        Description = 'Full coverage for ISO 27001:2022 Annex A controls with specific clause mapping.'
        IDs = @()  # All checks apply
    }
}

# ── Risk Tier Classification ─────────────────────────────────────────────────
# Tier 0: Pure read-only (Get-* cmdlets only) - safe in any environment
# Tier 1: Read-only remote (WinRM Get-* on remote targets)
# Tier 2: Probing reads (Test-*, connectivity checks, generates log entries)
# Tier 3: Potentially modifying (enables services, changes settings) - opt-in only
$script:RiskTiers = @{
    # ── Identity & Access (all Tier 0-1: pure AD reads) ──
    'IA01' = 0; 'IA02' = 0; 'IA03' = 0; 'IA04' = 0; 'IA05' = 0
    'IA06' = 0; 'IA07' = 0; 'IA08' = 0; 'IA09' = 0; 'IA10' = 0
    # ── Endpoint Security (Tier 0: local reads) ──
    'EP01' = 0; 'EP02' = 0; 'EP03' = 0; 'EP04' = 0; 'EP05' = 0
    'EP06' = 0; 'EP07' = 0; 'EP08' = 0; 'EP09' = 0; 'EP10' = 0
    # ── Logging & Monitoring (Tier 0: event log reads) ──
    'LM01' = 0; 'LM02' = 0; 'LM03' = 0; 'LM04' = 0; 'LM05' = 0
    'LM06' = 0; 'LM07' = 0; 'LM08' = 0
    # ── Network Architecture (Tier 0-1: config reads) ──
    'NA01' = 0; 'NA02' = 0; 'NA03' = 0; 'NA04' = 0; 'NA05' = 0
    'NA06' = 0; 'NA07' = 0
    # ── Network Perimeter (Tier 0: firewall/port reads) ──
    'NP01' = 0; 'NP02' = 0; 'NP03' = 0; 'NP04' = 2  # DNS filtering tests resolution
    'NP05' = 0; 'NP06' = 0; 'NP07' = 0; 'NP08' = 0
    'NP09' = 0; 'NP10' = 0
    # ── Backup & Recovery (Tier 0: service/event reads) ──
    'BR01' = 0; 'BR02' = 0; 'BR03' = 0; 'BR04' = 0
    'BR05' = 0; 'BR06' = 0; 'BR07' = 0; 'BR08' = 0
    # ── Common Findings (Tier 0: SMB/config reads) ──
    'CF01' = 0; 'CF02' = 0; 'CF03' = 0; 'CF04' = 0
    'CF05' = 0; 'CF06' = 0; 'CF07' = 0; 'CF08' = 0
    # ── Policies & Standards (Tier 0: policy reads) ──
    'PS01' = 0; 'PS02' = 0; 'PS03' = 0; 'PS04' = 0; 'PS05' = 0; 'PS06' = 0
}
$script:RiskTierLabels = @{ 0='Read-Only'; 1='Remote Read'; 2='Probing'; 3='Modifying' }

# ── Category Risk Weights (for weighted scoring) ────────────────────────────
$script:CategoryWeights = @{
    'Identity & Access'   = 1.5   # Most critical - keys to the kingdom
    'Endpoint Security'   = 1.2   # Direct attack surface
    'Network Perimeter'   = 1.3   # External exposure
    'Logging & Monitoring'= 1.0   # Detection capability
    'Network Architecture'= 0.9   # Infrastructure design
    'Backup & Recovery'   = 1.1   # Resilience
    'Common Findings'     = 1.0   # Frequent issues
    'Physical Security'   = 0.7   # Softer controls
}

# ── Phase 3: Compliance Framework Integration ────────────────────────────────
# Structured mapping of all 67 checks to 7 compliance frameworks with specific control IDs.
# NIST CSF, CIS Controls v8, and HIPAA are already in the per-check Compliance string.
# This table adds: NIST 800-171 Rev 3, CMMC 2.0, PCI-DSS 4.0.1, SOC 2, ISO 27001:2022
$script:ComplianceTarget = 'All'   # Active framework filter: All, CIS, NIST, CMMC, HIPAA, PCI, SOC2, ISO27001

$script:FrameworkMeta = [ordered]@{
    'CIS'      = @{ Name='CIS Controls v8.1'; Color='#38bdf8'; Short='CIS' }
    'NIST'     = @{ Name='NIST 800-171 Rev 3'; Color='#818cf8'; Short='800-171' }
    'CMMC'     = @{ Name='CMMC 2.0 Level 2'; Color='#a855f7'; Short='CMMC' }
    'HIPAA'    = @{ Name='HIPAA Security Rule'; Color='#22c55e'; Short='HIPAA' }
    'PCI'      = @{ Name='PCI-DSS 4.0.1'; Color='#f97316'; Short='PCI' }
    'SOC2'     = @{ Name='SOC 2 Type II'; Color='#eab308'; Short='SOC2' }
    'ISO27001' = @{ Name='ISO 27001:2022'; Color='#ec4899'; Short='ISO' }
}

# Per-check mapping: each key = check ID, value = hashtable of framework -> control IDs
# CIS and HIPAA are parsed from existing Compliance string; these add the remaining 5 frameworks
$script:FrameworkMap = @{
    # ── Identity & Access ──
    'IA01' = @{ 'NIST'='3.1.1, 3.1.2, 3.1.5'; 'CMMC'='AC.L2-3.1.1, AC.L2-3.1.2, AC.L2-3.1.5'; 'PCI'='7.2.1, 7.2.2, 8.6.1'; 'SOC2'='CC6.1, CC6.3'; 'ISO27001'='A.5.15, A.5.18, A.8.2' }
    'IA02' = @{ 'NIST'='3.1.1, 3.1.5, 3.7.5'; 'CMMC'='AC.L2-3.1.1, AC.L2-3.1.5'; 'PCI'='7.2.2, 8.6.1, 8.6.2'; 'SOC2'='CC6.1, CC6.3'; 'ISO27001'='A.5.15, A.5.17, A.8.2' }
    'IA03' = @{ 'NIST'='3.5.3, 3.7.5'; 'CMMC'='IA.L2-3.5.3'; 'PCI'='8.4.1, 8.4.2, 8.4.3'; 'SOC2'='CC6.1, CC6.6'; 'ISO27001'='A.5.17, A.8.5' }
    'IA04' = @{ 'NIST'='3.1.1, 3.1.12'; 'CMMC'='AC.L2-3.1.1, PS.L2-3.9.2'; 'PCI'='8.1.4, 8.2.6'; 'SOC2'='CC6.1, CC6.2'; 'ISO27001'='A.5.18, A.6.5' }
    'IA05' = @{ 'NIST'='3.5.7, 3.5.8, 3.5.9, 3.5.10'; 'CMMC'='IA.L2-3.5.7, IA.L2-3.5.8'; 'PCI'='8.3.6, 8.3.7, 8.3.9'; 'SOC2'='CC6.1'; 'ISO27001'='A.5.17, A.8.5' }
    'IA06' = @{ 'NIST'='3.1.5, 3.1.6, 3.1.7'; 'CMMC'='AC.L2-3.1.5, AC.L2-3.1.6, AC.L2-3.1.7'; 'PCI'='7.2.1, 8.2.4'; 'SOC2'='CC6.1, CC6.3'; 'ISO27001'='A.5.15, A.8.2, A.8.18' }
    'IA07' = @{ 'NIST'='3.1.1, 3.5.1'; 'CMMC'='AC.L2-3.1.1, IA.L2-3.5.1'; 'PCI'='8.2.1, 8.2.2'; 'SOC2'='CC6.1'; 'ISO27001'='A.5.15, A.5.17' }
    'IA08' = @{ 'NIST'='3.1.1, 3.1.12'; 'CMMC'='AC.L2-3.1.1, PS.L2-3.9.2'; 'PCI'='8.1.4, 8.6.1'; 'SOC2'='CC6.1, CC6.2'; 'ISO27001'='A.5.18, A.5.19, A.5.20' }
    'IA09' = @{ 'NIST'='3.1.3, 3.5.3'; 'CMMC'='AC.L2-3.1.3, IA.L2-3.5.3'; 'PCI'='7.2.1, 8.4.1'; 'SOC2'='CC6.1, CC6.6'; 'ISO27001'='A.5.15, A.8.5' }
    'IA10' = @{ 'NIST'='3.1.1, 3.1.12'; 'CMMC'='AC.L2-3.1.1'; 'PCI'='8.2.6'; 'SOC2'='CC6.1, CC6.2'; 'ISO27001'='A.5.18, A.6.5' }
    # ── Endpoint Security ──
    'EP01' = @{ 'NIST'='3.14.1, 3.14.2, 3.14.4, 3.14.5'; 'CMMC'='SI.L2-3.14.1, SI.L2-3.14.2'; 'PCI'='5.2.1, 5.2.2, 5.3.1, 5.3.2'; 'SOC2'='CC6.8, CC7.1'; 'ISO27001'='A.8.7' }
    'EP02' = @{ 'NIST'='3.8.6, 3.13.11'; 'CMMC'='MP.L2-3.8.6, SC.L2-3.13.11'; 'PCI'='3.5.1, 9.4.1'; 'SOC2'='CC6.1, CC6.7'; 'ISO27001'='A.8.24' }
    'EP03' = @{ 'NIST'='3.1.13, 3.13.1, 3.13.8'; 'CMMC'='AC.L2-3.1.13, SC.L2-3.13.1'; 'PCI'='2.2.7, 4.2.1'; 'SOC2'='CC6.1, CC6.7'; 'ISO27001'='A.8.20, A.8.24' }
    'EP04' = @{ 'NIST'='3.14.1, 3.4.8, 3.4.9'; 'CMMC'='SI.L2-3.14.1, CM.L2-3.4.8'; 'PCI'='6.3.1, 6.3.3'; 'SOC2'='CC7.1, CC8.1'; 'ISO27001'='A.8.8, A.8.19' }
    'EP05' = @{ 'NIST'='3.1.5, 3.1.6, 3.4.6'; 'CMMC'='AC.L2-3.1.5, AC.L2-3.1.6'; 'PCI'='7.2.1, 7.2.2'; 'SOC2'='CC6.1, CC6.3'; 'ISO27001'='A.5.15, A.8.2' }
    'EP06' = @{ 'NIST'='3.13.1, 3.13.5'; 'CMMC'='SC.L2-3.13.1, SC.L2-3.13.5'; 'PCI'='1.2.1, 1.3.1, 1.4.1'; 'SOC2'='CC6.1, CC6.6'; 'ISO27001'='A.8.20, A.8.21' }
    'EP07' = @{ 'NIST'='3.4.6, 3.4.8'; 'CMMC'='CM.L2-3.4.6, CM.L2-3.4.8'; 'PCI'='2.2.4, 6.3.2'; 'SOC2'='CC6.8, CC7.1'; 'ISO27001'='A.8.7, A.8.19' }
    'EP08' = @{ 'NIST'='3.13.11, 3.14.1'; 'CMMC'='SC.L2-3.13.11, SI.L2-3.14.1'; 'PCI'='9.4.1, 2.2.1'; 'SOC2'='CC6.1, CC6.7'; 'ISO27001'='A.8.1, A.8.24' }
    'EP09' = @{ 'NIST'='3.4.1, 3.4.2'; 'CMMC'='CM.L2-3.4.1, CM.L2-3.4.2'; 'PCI'='2.2.1, 2.2.2'; 'SOC2'='CC6.1, CC8.1'; 'ISO27001'='A.8.9, A.8.19' }
    'EP10' = @{ 'NIST'='3.8.9'; 'CMMC'='MP.L2-3.8.9'; 'PCI'='9.4.1, 9.4.5'; 'SOC2'='CC6.7'; 'ISO27001'='A.7.9, A.8.1' }
    # ── Logging & Monitoring ──
    'LM01' = @{ 'NIST'='3.3.1, 3.3.2'; 'CMMC'='AU.L2-3.3.1, AU.L2-3.3.2'; 'PCI'='10.2.1, 10.2.2'; 'SOC2'='CC7.2, CC7.3'; 'ISO27001'='A.8.15, A.8.16' }
    'LM02' = @{ 'NIST'='3.3.1, 3.3.4'; 'CMMC'='AU.L2-3.3.1, AU.L2-3.3.4'; 'PCI'='10.3.1, 10.3.3'; 'SOC2'='CC7.2, CC7.3'; 'ISO27001'='A.8.15, A.8.16' }
    'LM03' = @{ 'NIST'='3.3.1, 3.3.2, 3.3.8'; 'CMMC'='AU.L2-3.3.1, AU.L2-3.3.2'; 'PCI'='10.2.1, 10.2.2, 10.6.3'; 'SOC2'='CC7.2, CC7.3'; 'ISO27001'='A.8.15, A.8.16' }
    'LM04' = @{ 'NIST'='3.3.1, 3.13.1'; 'CMMC'='AU.L2-3.3.1, SC.L2-3.13.1'; 'PCI'='10.2.1, 1.2.1'; 'SOC2'='CC7.2'; 'ISO27001'='A.8.15, A.8.20' }
    'LM05' = @{ 'NIST'='3.3.3, 3.3.4'; 'CMMC'='AU.L2-3.3.3, AU.L2-3.3.4'; 'PCI'='10.3.1, 10.3.2'; 'SOC2'='CC7.2, CC7.3'; 'ISO27001'='A.8.15, A.8.16' }
    'LM06' = @{ 'NIST'='3.3.5'; 'CMMC'='AU.L2-3.3.5'; 'PCI'='10.3.4, 10.5.1'; 'SOC2'='CC7.2, CC7.4'; 'ISO27001'='A.8.15' }
    'LM07' = @{ 'NIST'='3.3.4, 3.3.8'; 'CMMC'='AU.L2-3.3.4, AU.L2-3.3.8'; 'PCI'='10.5.1, 10.7.1'; 'SOC2'='CC7.2'; 'ISO27001'='A.8.15' }
    'LM08' = @{ 'NIST'='3.3.1, 3.6.1'; 'CMMC'='AU.L2-3.3.1, IR.L2-3.6.1'; 'PCI'='10.4.1, 10.7.2'; 'SOC2'='CC7.2, CC7.3'; 'ISO27001'='A.8.15, A.8.16' }
    # ── Network Architecture ──
    'NA01' = @{ 'NIST'='3.13.1, 3.13.2'; 'CMMC'='SC.L2-3.13.1, SC.L2-3.13.2'; 'PCI'='1.2.1, 1.3.1, 1.3.2'; 'SOC2'='CC6.1, CC6.6'; 'ISO27001'='A.8.20, A.8.22' }
    'NA02' = @{ 'NIST'='3.13.1, 3.13.2'; 'CMMC'='SC.L2-3.13.1, SC.L2-3.13.2'; 'PCI'='1.2.1, 1.3.1'; 'SOC2'='CC6.1'; 'ISO27001'='A.8.20, A.8.22' }
    'NA03' = @{ 'NIST'='3.13.2, 3.13.6'; 'CMMC'='SC.L2-3.13.2, SC.L2-3.13.6'; 'PCI'='1.2.1, 1.3.2'; 'SOC2'='CC6.6'; 'ISO27001'='A.8.20' }
    'NA04' = @{ 'NIST'='3.13.1, 3.13.7'; 'CMMC'='SC.L2-3.13.1'; 'PCI'='11.3.1, 11.3.2'; 'SOC2'='CC7.1'; 'ISO27001'='A.8.20, A.8.21' }
    'NA05' = @{ 'NIST'='3.1.20'; 'CMMC'='AC.L2-3.1.20'; 'PCI'='1.4.1'; 'SOC2'='CC6.6'; 'ISO27001'='A.8.20' }
    'NA06' = @{ 'NIST'='3.13.3'; 'CMMC'='SC.L2-3.13.3'; 'PCI'='11.4.1'; 'SOC2'='CC7.1, CC7.2'; 'ISO27001'='A.8.16, A.8.23' }
    'NA07' = @{ 'NIST'='3.13.1'; 'CMMC'='SC.L2-3.13.1'; 'PCI'='1.2.5'; 'SOC2'='CC6.6'; 'ISO27001'='A.8.20' }
    # ── Network Perimeter ──
    'NP01' = @{ 'NIST'='3.13.1, 3.13.5'; 'CMMC'='SC.L2-3.13.1, SC.L2-3.13.5'; 'PCI'='1.2.1, 1.3.1, 1.4.1'; 'SOC2'='CC6.1, CC6.6'; 'ISO27001'='A.8.20, A.8.21' }
    'NP02' = @{ 'NIST'='3.13.1, 3.13.5'; 'CMMC'='SC.L2-3.13.1, SC.L2-3.13.5'; 'PCI'='11.3.1, 11.3.2'; 'SOC2'='CC6.6, CC7.1'; 'ISO27001'='A.8.20, A.8.34' }
    'NP03' = @{ 'NIST'='3.1.12, 3.1.20'; 'CMMC'='AC.L2-3.1.12, AC.L2-3.1.20'; 'PCI'='1.4.1, 8.2.1'; 'SOC2'='CC6.1, CC6.6'; 'ISO27001'='A.8.20' }
    'NP04' = @{ 'NIST'='3.13.1, 3.13.15'; 'CMMC'='SC.L2-3.13.1'; 'PCI'='1.2.5, 11.5.1'; 'SOC2'='CC6.6, CC6.8'; 'ISO27001'='A.8.20, A.8.23' }
    'NP05' = @{ 'NIST'='3.13.1, 3.13.6'; 'CMMC'='SC.L2-3.13.1, SC.L2-3.13.6'; 'PCI'='1.2.1, 1.3.1'; 'SOC2'='CC6.6'; 'ISO27001'='A.8.20, A.8.21' }
    'NP06' = @{ 'NIST'='3.13.1, 3.13.8'; 'CMMC'='SC.L2-3.13.1, SC.L2-3.13.8'; 'PCI'='11.5.1'; 'SOC2'='CC6.6, CC7.1'; 'ISO27001'='A.8.20, A.8.21' }
    'NP07' = @{ 'NIST'='3.13.1, 3.14.6'; 'CMMC'='SC.L2-3.13.1, SI.L2-3.14.6'; 'PCI'='11.5.1, 11.6.1'; 'SOC2'='CC6.8, CC7.1'; 'ISO27001'='A.8.16, A.8.23' }
    'NP08' = @{ 'NIST'='3.13.8, 3.13.11'; 'CMMC'='SC.L2-3.13.8, SC.L2-3.13.11'; 'PCI'='4.2.1, 4.2.2'; 'SOC2'='CC6.1, CC6.7'; 'ISO27001'='A.8.24' }
    'NP09' = @{ 'NIST'='3.13.1, 3.13.5'; 'CMMC'='SC.L2-3.13.1, SC.L2-3.13.5'; 'PCI'='1.2.1, 1.3.1'; 'SOC2'='CC6.6'; 'ISO27001'='A.8.20' }
    'NP10' = @{ 'NIST'='3.4.8, 3.14.1'; 'CMMC'='CM.L2-3.4.8, SI.L2-3.14.1'; 'PCI'='6.3.1, 6.3.3'; 'SOC2'='CC7.1, CC8.1'; 'ISO27001'='A.8.8, A.8.19' }
    # ── Backup & Recovery ──
    'BR01' = @{ 'NIST'='3.8.9'; 'CMMC'='MP.L2-3.8.9'; 'PCI'='12.10.1'; 'SOC2'='CC7.5, A1.2'; 'ISO27001'='A.8.13' }
    'BR02' = @{ 'NIST'='3.8.9'; 'CMMC'='MP.L2-3.8.9'; 'PCI'='12.10.1'; 'SOC2'='CC7.5, A1.2'; 'ISO27001'='A.8.13, A.8.14' }
    'BR03' = @{ 'NIST'='3.6.1, 3.6.2'; 'CMMC'='IR.L2-3.6.1, IR.L2-3.6.2'; 'PCI'='12.10.1, 12.10.2'; 'SOC2'='CC7.4, CC7.5, A1.2'; 'ISO27001'='A.5.29, A.5.30, A.8.14' }
    'BR04' = @{ 'NIST'='3.8.9'; 'CMMC'='MP.L2-3.8.9'; 'PCI'='12.10.1'; 'SOC2'='A1.2'; 'ISO27001'='A.8.13' }
    'BR05' = @{ 'NIST'='3.6.1, 3.6.3'; 'CMMC'='IR.L2-3.6.1, IR.L2-3.6.3'; 'PCI'='12.10.1, 12.10.2'; 'SOC2'='CC7.4, CC7.5, A1.2'; 'ISO27001'='A.5.29, A.5.30' }
    'BR06' = @{ 'NIST'='3.8.9'; 'CMMC'='MP.L2-3.8.9'; 'PCI'='12.10.1'; 'SOC2'='A1.2, A1.3'; 'ISO27001'='A.8.13' }
    'BR07' = @{ 'NIST'='3.13.11'; 'CMMC'='SC.L2-3.13.11'; 'PCI'='3.5.1, 9.4.1'; 'SOC2'='CC6.7, A1.2'; 'ISO27001'='A.8.13, A.8.24' }
    'BR08' = @{ 'NIST'='3.6.1'; 'CMMC'='IR.L2-3.6.1'; 'PCI'='12.10.1'; 'SOC2'='CC7.5, A1.2'; 'ISO27001'='A.5.29, A.8.13' }
    # ── Common Findings ──
    'CF01' = @{ 'NIST'='3.1.5, 3.7.5, 3.13.8'; 'CMMC'='AC.L2-3.1.5, SC.L2-3.13.8'; 'PCI'='7.2.2, 8.6.1, 8.6.2'; 'SOC2'='CC6.1, CC6.3'; 'ISO27001'='A.5.15, A.5.17, A.8.5' }
    'CF02' = @{ 'NIST'='3.4.6, 3.4.7'; 'CMMC'='CM.L2-3.4.6, CM.L2-3.4.7'; 'PCI'='2.2.4, 2.2.7'; 'SOC2'='CC6.1, CC6.8'; 'ISO27001'='A.8.19, A.8.20' }
    'CF03' = @{ 'NIST'='3.2.1, 3.2.2'; 'CMMC'='AT.L2-3.2.1, AT.L2-3.2.2'; 'PCI'='12.6.1, 12.6.2'; 'SOC2'='CC1.4, CC2.2'; 'ISO27001'='A.6.3' }
    'CF04' = @{ 'NIST'='3.1.1, 3.1.2'; 'CMMC'='AC.L2-3.1.1, AC.L2-3.1.2'; 'PCI'='7.2.1, 7.2.4'; 'SOC2'='CC6.1, CC6.3'; 'ISO27001'='A.5.15, A.8.3' }
    'CF05' = @{ 'NIST'='3.1.1, 3.8.1'; 'CMMC'='AC.L2-3.1.1, MP.L2-3.8.1'; 'PCI'='7.2.4'; 'SOC2'='CC6.1, CC6.3'; 'ISO27001'='A.5.15, A.8.3' }
    'CF06' = @{ 'NIST'='3.1.17'; 'CMMC'='AC.L2-3.1.17'; 'PCI'='7.2.5'; 'SOC2'='CC6.1'; 'ISO27001'='A.5.15, A.8.20' }
    'CF07' = @{ 'NIST'='3.1.5, 3.1.6'; 'CMMC'='AC.L2-3.1.5, AC.L2-3.1.6'; 'PCI'='7.2.1, 7.2.2'; 'SOC2'='CC6.1, CC6.3'; 'ISO27001'='A.5.15, A.8.2' }
    'CF08' = @{ 'NIST'='3.14.1, 3.14.6'; 'CMMC'='SI.L2-3.14.1, SI.L2-3.14.6'; 'PCI'='5.2.1, 11.5.1'; 'SOC2'='CC7.1, CC7.2'; 'ISO27001'='A.8.7, A.8.8' }
    # ── Policies & Standards ──
    'PS01' = @{ 'NIST'='3.12.1, 3.12.4'; 'CMMC'='CA.L2-3.12.1, CA.L2-3.12.4'; 'PCI'='12.1.1, 12.1.2'; 'SOC2'='CC1.1, CC1.2, CC5.2'; 'ISO27001'='A.5.1, A.5.2' }
    'PS02' = @{ 'NIST'='3.12.1, 3.12.3'; 'CMMC'='CA.L2-3.12.1, CA.L2-3.12.3'; 'PCI'='12.1.1'; 'SOC2'='CC1.1, CC1.2'; 'ISO27001'='A.5.1' }
    'PS03' = @{ 'NIST'='3.6.1, 3.6.2, 3.6.3'; 'CMMC'='IR.L2-3.6.1, IR.L2-3.6.2, IR.L2-3.6.3'; 'PCI'='12.10.1, 12.10.2'; 'SOC2'='CC7.3, CC7.4, CC7.5'; 'ISO27001'='A.5.24, A.5.25, A.5.26' }
    'PS04' = @{ 'NIST'='3.12.1'; 'CMMC'='CA.L2-3.12.1'; 'PCI'='12.4.1'; 'SOC2'='CC1.1, CC4.1, CC4.2'; 'ISO27001'='A.5.35, A.5.36' }
    'PS05' = @{ 'NIST'='3.12.2'; 'CMMC'='CA.L2-3.12.2'; 'PCI'='12.1.2, 12.3.1'; 'SOC2'='CC3.1, CC3.2'; 'ISO27001'='A.5.7, A.5.8' }
    'PS06' = @{ 'NIST'='3.2.1, 3.2.2'; 'CMMC'='AT.L2-3.2.1, AT.L2-3.2.2'; 'PCI'='12.6.1, 12.6.2, 12.6.3'; 'SOC2'='CC1.4, CC2.2'; 'ISO27001'='A.6.3' }
}

# Checks relevant to each framework (for framework-specific scan profiles)
$script:FrameworkChecks = @{
    'CIS'      = @($script:FrameworkMap.Keys)  # CIS covers all checks
    'NIST'     = @($script:FrameworkMap.Keys | Where-Object { $script:FrameworkMap[$_].NIST })
    'CMMC'     = @($script:FrameworkMap.Keys | Where-Object { $script:FrameworkMap[$_].CMMC })
    'HIPAA'    = @('IA01','IA02','IA03','IA04','IA05','IA06','IA07','IA08','IA09','IA10','EP01','EP02','EP03','EP04','EP05','EP06','EP07','EP08','EP09','EP10','LM01','LM02','LM03','LM04','LM05','LM06','LM07','LM08','BR01','BR02','BR03','BR04','BR05','BR06','BR07','BR08','CF01','CF02','CF03','CF05','CF07','NP01','NP02','NP08','PS01','PS03','PS04')
    'PCI'      = @('NP01','NP02','NP03','NP04','NP05','NP08','NP09','NP10','IA01','IA02','IA03','IA04','IA05','IA06','IA07','IA08','IA09','EP01','EP02','EP03','EP04','EP05','EP06','EP07','EP08','LM01','LM02','LM03','LM04','LM05','LM06','LM07','LM08','NA01','NA02','NA04','BR01','BR02','BR03','BR05','CF01','CF02','CF04','CF05','PS01','PS03','PS04','PS05','PS06')
    'SOC2'     = @('IA01','IA02','IA03','IA04','IA05','IA06','IA07','IA08','IA09','IA10','EP01','EP02','EP03','EP04','EP05','EP06','EP07','EP08','EP09','LM01','LM02','LM03','LM04','LM05','LM06','LM07','LM08','NA01','NA02','NA03','NA04','NA05','NA06','NP01','NP02','NP03','NP04','NP05','NP06','NP07','NP08','NP09','NP10','BR01','BR02','BR03','BR04','BR05','BR06','BR07','BR08','CF01','CF02','CF03','CF04','CF05','CF06','CF07','CF08','PS01','PS02','PS03','PS04','PS05','PS06')
    'ISO27001' = @($script:FrameworkMap.Keys)  # ISO 27001 covers all checks
}

# Helper: Get formatted compliance string for a check ID and optional framework filter
function Get-ComplianceString {
    param([string]$CheckID, [string]$Framework = 'All')
    $parts = @()
    # Always include the built-in Compliance string (NIST CSF, CIS, HIPAA) parsed from check item
    $item = $null
    foreach ($cn in $script:AuditCategories.Keys) {
        $item = $script:AuditCategories[$cn].Items | Where-Object { $_.ID -eq $CheckID }
        if ($item) { break }
    }
    $builtIn = if ($item) { $item.Compliance } else { '' }
    if ($Framework -eq 'All' -or $Framework -eq 'CIS') {
        if ($builtIn -match 'CIS Control ([^|]+)') { $parts += "CIS: $($Matches[1].Trim())" }
    }
    if ($Framework -eq 'All' -or $Framework -eq 'NIST') {
        if ($builtIn -match 'NIST CSF ([^|]+)') { $parts += "NIST CSF: $($Matches[1].Trim())" }
        if ($script:FrameworkMap.Contains($CheckID) -and $script:FrameworkMap[$CheckID].NIST) {
            $parts += "800-171: $($script:FrameworkMap[$CheckID].NIST)"
        }
    }
    if ($Framework -eq 'All' -or $Framework -eq 'CMMC') {
        if ($script:FrameworkMap.Contains($CheckID) -and $script:FrameworkMap[$CheckID].CMMC) {
            $parts += "CMMC: $($script:FrameworkMap[$CheckID].CMMC)"
        }
    }
    if ($Framework -eq 'All' -or $Framework -eq 'HIPAA') {
        if ($builtIn -match 'HIPAA (.+)$') { $parts += "HIPAA: $($Matches[1].Trim())" }
    }
    if ($Framework -eq 'All' -or $Framework -eq 'PCI') {
        if ($script:FrameworkMap.Contains($CheckID) -and $script:FrameworkMap[$CheckID].PCI) {
            $parts += "PCI: $($script:FrameworkMap[$CheckID].PCI)"
        }
    }
    if ($Framework -eq 'All' -or $Framework -eq 'SOC2') {
        if ($script:FrameworkMap.Contains($CheckID) -and $script:FrameworkMap[$CheckID].SOC2) {
            $parts += "SOC2: $($script:FrameworkMap[$CheckID].SOC2)"
        }
    }
    if ($Framework -eq 'All' -or $Framework -eq 'ISO27001') {
        if ($script:FrameworkMap.Contains($CheckID) -and $script:FrameworkMap[$CheckID].ISO27001) {
            $parts += "ISO: $($script:FrameworkMap[$CheckID].ISO27001)"
        }
    }
    return ($parts -join ' | ')
}

# Framework-specific scoring: calculate pass/fail/partial per framework
function Get-FrameworkScores {
    param([string]$Framework = 'All')
    $frameworks = if ($Framework -eq 'All') { $script:FrameworkMeta.Keys } else { @($Framework) }
    $scores = @{}
    foreach ($fw in $frameworks) {
        $checkIds = if ($script:FrameworkChecks.Contains($fw)) { $script:FrameworkChecks[$fw] } else { @() }
        $pass = 0; $fail = 0; $partial = 0; $na = 0; $notAssessed = 0
        foreach ($id in $checkIds) {
            $sv = if ($script:StatusCombos[$id] -and $script:StatusCombos[$id].SelectedItem) { $script:StatusCombos[$id].SelectedItem.ToString() } else { 'Not Assessed' }
            switch ($sv) { 'Pass' { $pass++ } 'Fail' { $fail++ } 'Partial' { $partial++ } 'N/A' { $na++ } default { $notAssessed++ } }
        }
        $assessed = $pass + $fail + $partial
        $score = if ($assessed -gt 0) { [math]::Round(($pass + $partial * 0.5) / $assessed * 100) } else { 0 }
        $total = $checkIds.Count
        $scores[$fw] = @{ Pass=$pass; Fail=$fail; Partial=$partial; NA=$na; NotAssessed=$notAssessed; Assessed=$assessed; Total=$total; Score=$score }
    }
    return $scores
}

# ── End Phase 3A ─────────────────────────────────────────────────────────────

# ── Phase 4A: MITRE ATT&CK Mapping ──────────────────────────────────────────
# Maps all 67 checks to ATT&CK Enterprise techniques (v15.1)
# Format: CheckID -> @{ Tactics=@('TA00xx',...); Techniques=@('T1xxx',...); Desc='short attack context' }
$script:MitreMap = @{
    # ── Identity & Access ──
    'IA01' = @{ Tactics=@('TA0004','TA0003'); Techniques=@('T1078.002','T1078.001','T1098'); Desc='Compromised DA accounts enable domain-wide persistence and privilege escalation' }
    'IA02' = @{ Tactics=@('TA0006','TA0004'); Techniques=@('T1558.003','T1558.004','T1078.002'); Desc='Service accounts with SPNs are Kerberoastable; stale passwords make cracking trivial' }
    'IA03' = @{ Tactics=@('TA0001','TA0006'); Techniques=@('T1078','T1110.001','T1110.003','T1556'); Desc='Missing MFA allows credential stuffing, password spraying, and phishing-to-access' }
    'IA04' = @{ Tactics=@('TA0001','TA0003'); Techniques=@('T1078.002','T1078.001'); Desc='Stale accounts from terminated employees are prime targets for unauthorized access' }
    'IA05' = @{ Tactics=@('TA0006','TA0001'); Techniques=@('T1110.001','T1110.002','T1110.003'); Desc='Weak password policy enables brute force, dictionary attacks, and credential spraying' }
    'IA06' = @{ Tactics=@('TA0004','TA0003','TA0006'); Techniques=@('T1078.002','T1550.002','T1550.003'); Desc='Without PAM/LAPS, lateral movement via pass-the-hash and golden ticket attacks' }
    'IA07' = @{ Tactics=@('TA0001','TA0005'); Techniques=@('T1078','T1078.001'); Desc='Shared accounts eliminate attribution and enable insider threat denial' }
    'IA08' = @{ Tactics=@('TA0001','TA0003'); Techniques=@('T1078','T1199'); Desc='Vendor accounts with persistent access enable trusted relationship attacks' }
    'IA09' = @{ Tactics=@('TA0001','TA0005'); Techniques=@('T1078.004','T1556.006'); Desc='Missing conditional access allows cloud compromise from any device/location' }
    'IA10' = @{ Tactics=@('TA0001','TA0003'); Techniques=@('T1078','T1078.002'); Desc='Stale accounts expand the attack surface for credential-based initial access' }
    # ── Endpoint Security ──
    'EP01' = @{ Tactics=@('TA0005','TA0002'); Techniques=@('T1562.001','T1562.004','T1059'); Desc='Disabled/misconfigured AV allows malware execution, defense evasion, and payload delivery' }
    'EP02' = @{ Tactics=@('TA0005','TA0002'); Techniques=@('T1486','T1059'); Desc='Missing encryption exposes data at rest; enables theft on stolen/decommissioned devices' }
    'EP03' = @{ Tactics=@('TA0006','TA0008','TA0005'); Techniques=@('T1557.001','T1040','T1570','T1187'); Desc='SMB/NTLM misconfig enables relay attacks, credential capture, and lateral tool transfer' }
    'EP04' = @{ Tactics=@('TA0001','TA0002'); Techniques=@('T1190','T1203','T1210'); Desc='Unpatched systems enable exploitation of public-facing apps, client-side vulns, and remote services' }
    'EP05' = @{ Tactics=@('TA0004','TA0003','TA0002'); Techniques=@('T1574.009','T1574.001','T1547.001','T1053'); Desc='Unquoted service paths, AlwaysInstallElevated, cached creds enable local privesc and persistence' }
    'EP06' = @{ Tactics=@('TA0005','TA0011'); Techniques=@('T1562.004','T1071','T1048'); Desc='Firewall gaps allow C2 communication, data exfiltration, and inbound exploitation' }
    'EP07' = @{ Tactics=@('TA0002','TA0005'); Techniques=@('T1059','T1204.002','T1137','T1221'); Desc='Missing AppLocker/WDAC and unrestricted macros enable arbitrary code execution and initial access via documents' }
    'EP08' = @{ Tactics=@('TA0006','TA0005','TA0004'); Techniques=@('T1003.001','T1003.004','T1003.005','T1547.008'); Desc='Missing Credential Guard/LSA Protection enables LSASS dumping, DCSync, and credential theft' }
    'EP09' = @{ Tactics=@('TA0005','TA0003'); Techniques=@('T1562.001','T1112'); Desc='Misconfigured systems expand attack surface through unnecessary services and weak defaults' }
    'EP10' = @{ Tactics=@('TA0005','TA0010'); Techniques=@('T1091','T1052'); Desc='Uncontrolled removable media enables physical delivery of malware and data exfiltration' }
    # ── Logging & Monitoring ──
    'LM01' = @{ Tactics=@('TA0005'); Techniques=@('T1562.002','T1070.001'); Desc='Inadequate audit policy creates blind spots; attackers operate undetected' }
    'LM02' = @{ Tactics=@('TA0005','TA0040'); Techniques=@('T1562.002','T1485'); Desc='No SIEM means no correlation, alerting, or forensic capability during active compromise' }
    'LM03' = @{ Tactics=@('TA0002','TA0005'); Techniques=@('T1059.001','T1059.003','T1562.002','T1070'); Desc='Missing PS logging/auditing allows script-based attacks to execute without trace' }
    'LM04' = @{ Tactics=@('TA0005','TA0011'); Techniques=@('T1562.002','T1071'); Desc='No firewall/IDS logging means network-based attacks go undetected' }
    'LM05' = @{ Tactics=@('TA0005'); Techniques=@('T1562.002','T1070.001','T1070.002'); Desc='Logs without integrity protection can be tampered with to cover tracks' }
    'LM06' = @{ Tactics=@('TA0005'); Techniques=@('T1070.001','T1562.002'); Desc='Missing log review means alerts are generated but never acted upon' }
    'LM07' = @{ Tactics=@('TA0005'); Techniques=@('T1070.001','T1562.002'); Desc='Small log sizes cause critical events to be overwritten before detection' }
    'LM08' = @{ Tactics=@('TA0005','TA0011'); Techniques=@('T1562.002','T1071'); Desc='Missing alerting means real-time attacks proceed without response' }
    # ── Network Architecture ──
    'NA01' = @{ Tactics=@('TA0008'); Techniques=@('T1021','T1570','T1210'); Desc='Flat networks enable unrestricted lateral movement after initial compromise' }
    'NA02' = @{ Tactics=@('TA0008','TA0011'); Techniques=@('T1021','T1071'); Desc='Missing segmentation between client/server tiers enables lateral movement to high-value targets' }
    'NA03' = @{ Tactics=@('TA0008','TA0011'); Techniques=@('T1021','T1071','T1048'); Desc='No DMZ exposes internal services directly and enables pivot from compromised public services' }
    'NA04' = @{ Tactics=@('TA0008','TA0011'); Techniques=@('T1021','T1071'); Desc='Missing wireless segmentation enables network pivot from compromised WiFi clients' }
    'NA05' = @{ Tactics=@('TA0001','TA0011'); Techniques=@('T1133','T1071'); Desc='VPN without segmentation grants full network access on compromise' }
    'NA06' = @{ Tactics=@('TA0008','TA0040'); Techniques=@('T1021','T1570','T1210'); Desc='Missing IDS/monitoring means lateral movement and exploitation go undetected' }
    'NA07' = @{ Tactics=@('TA0011','TA0010'); Techniques=@('T1071','T1048','T1568'); Desc='Missing DNS filtering allows C2 channels, data exfil via DNS, and drive-by downloads' }
    # ── Network Perimeter ──
    'NP01' = @{ Tactics=@('TA0005','TA0011'); Techniques=@('T1562.004','T1071'); Desc='Weak firewall rules expose attack surface and allow C2/exfil channels' }
    'NP02' = @{ Tactics=@('TA0001','TA0043'); Techniques=@('T1190','T1046'); Desc='Open ports expose services to exploitation and enable reconnaissance' }
    'NP03' = @{ Tactics=@('TA0001','TA0008'); Techniques=@('T1133','T1021.001'); Desc='Exposed RDP/remote access enables brute force and RDP-based ransomware delivery' }
    'NP04' = @{ Tactics=@('TA0001','TA0005'); Techniques=@('T1190','T1562.004'); Desc='WAF/edge protection gaps allow web app exploitation and injection attacks' }
    'NP05' = @{ Tactics=@('TA0001','TA0008'); Techniques=@('T1190','T1210'); Desc='Permissive ACLs expose internal services to external exploitation' }
    'NP06' = @{ Tactics=@('TA0001','TA0011'); Techniques=@('T1190','T1071.001'); Desc='Missing SSL inspection allows encrypted C2, malware delivery, and data exfiltration' }
    'NP07' = @{ Tactics=@('TA0005','TA0011'); Techniques=@('T1071','T1568','T1562.004'); Desc='No IDS/IPS means network-level attacks bypass perimeter undetected' }
    'NP08' = @{ Tactics=@('TA0006','TA0009'); Techniques=@('T1557','T1040','T1552.001'); Desc='Weak TLS/SSL enables credential interception, MitM, and data collection from encrypted channels' }
    'NP09' = @{ Tactics=@('TA0001','TA0008'); Techniques=@('T1190','T1021'); Desc='Unnecessary NAT/port forwards expose internal hosts to direct exploitation' }
    'NP10' = @{ Tactics=@('TA0001','TA0002'); Techniques=@('T1190','T1210'); Desc='Unpatched perimeter firmware contains known exploitable vulnerabilities' }
    # ── Backup & Recovery ──
    'BR01' = @{ Tactics=@('TA0040'); Techniques=@('T1486','T1490','T1485'); Desc='No backup means ransomware encryption is catastrophic with no recovery path' }
    'BR02' = @{ Tactics=@('TA0040'); Techniques=@('T1486','T1490'); Desc='Backups without offsite/immutable copies are destroyed alongside primary in ransomware attacks' }
    'BR03' = @{ Tactics=@('TA0040'); Techniques=@('T1486','T1490','T1485'); Desc='No DR plan means extended downtime and uncoordinated recovery during incidents' }
    'BR04' = @{ Tactics=@('TA0040'); Techniques=@('T1486','T1490'); Desc='Untested backups may fail during actual recovery, extending downtime' }
    'BR05' = @{ Tactics=@('TA0040'); Techniques=@('T1486','T1489'); Desc='No documented RTO/RPO means no recovery time expectations or prioritization' }
    'BR06' = @{ Tactics=@('TA0040'); Techniques=@('T1490','T1486'); Desc='Unmonitored backup failures mean data loss is discovered only during recovery attempt' }
    'BR07' = @{ Tactics=@('TA0040','TA0010'); Techniques=@('T1486','T1048'); Desc='Unencrypted backups expose sensitive data if storage is compromised or stolen' }
    'BR08' = @{ Tactics=@('TA0040'); Techniques=@('T1486','T1490','T1561'); Desc='Missing backup for critical systems means targeted destruction is irrecoverable' }
    # ── Common Findings ──
    'CF01' = @{ Tactics=@('TA0006','TA0004','TA0003'); Techniques=@('T1558.003','T1078.002','T1098'); Desc='DA service accounts, missing LAPS, GPP passwords, ADCS vulns enable domain compromise chains' }
    'CF02' = @{ Tactics=@('TA0008','TA0005'); Techniques=@('T1021.002','T1570'); Desc='SMBv1 and legacy protocols enable EternalBlue-class exploits and relay attacks' }
    'CF03' = @{ Tactics=@('TA0001','TA0043'); Techniques=@('T1566.001','T1566.002','T1598'); Desc='Untrained users fall for phishing, social engineering, and credential harvesting campaigns' }
    'CF04' = @{ Tactics=@('TA0009','TA0010'); Techniques=@('T1005','T1039','T1048'); Desc='Excessive permissions enable data collection from shared drives and data exfiltration' }
    'CF05' = @{ Tactics=@('TA0009','TA0010'); Techniques=@('T1039','T1005','T1048'); Desc='Open shares expose sensitive data for collection and enable lateral data access' }
    'CF06' = @{ Tactics=@('TA0008','TA0011'); Techniques=@('T1021.001','T1071'); Desc='Unrestricted remote access enables lateral movement and persistent C2 channels' }
    'CF07' = @{ Tactics=@('TA0004','TA0008'); Techniques=@('T1078.001','T1021'); Desc='Excessive local admin rights enable privilege escalation and lateral movement' }
    'CF08' = @{ Tactics=@('TA0001','TA0005'); Techniques=@('T1190','T1211','T1562.001'); Desc='Missing vulnerability management leaves known CVEs exploitable across the environment' }
    # ── Policies & Standards ──
    'PS01' = @{ Tactics=@('TA0001','TA0042'); Techniques=@('T1078','T1595'); Desc='Missing security policies leave the organization without defined security posture or baselines' }
    'PS02' = @{ Tactics=@('TA0042'); Techniques=@('T1595','T1589'); Desc='No AUP means no policy enforcement for acceptable behavior and security expectations' }
    'PS03' = @{ Tactics=@('TA0040','TA0042'); Techniques=@('T1486','T1489','T1485'); Desc='Missing IR plan means uncoordinated, delayed response to active breaches' }
    'PS04' = @{ Tactics=@('TA0042'); Techniques=@('T1595'); Desc='No compliance monitoring means security drift goes undetected over time' }
    'PS05' = @{ Tactics=@('TA0042','TA0043'); Techniques=@('T1595','T1592'); Desc='Missing risk assessment leaves unknown vulnerabilities and threat vectors unaddressed' }
    'PS06' = @{ Tactics=@('TA0001','TA0043'); Techniques=@('T1566','T1598','T1204'); Desc='Without ongoing training, users remain the weakest link for phishing and social engineering' }
}

# ATT&CK Tactic metadata for heatmap display
$script:MitreTactics = [ordered]@{
    'TA0043' = @{ Name='Reconnaissance'; Short='Recon'; Color='#94a3b8' }
    'TA0042' = @{ Name='Resource Development'; Short='ResDev'; Color='#a1a1aa' }
    'TA0001' = @{ Name='Initial Access'; Short='InitAccess'; Color='#ef4444' }
    'TA0002' = @{ Name='Execution'; Short='Execution'; Color='#f97316' }
    'TA0003' = @{ Name='Persistence'; Short='Persist'; Color='#eab308' }
    'TA0004' = @{ Name='Privilege Escalation'; Short='PrivEsc'; Color='#84cc16' }
    'TA0005' = @{ Name='Defense Evasion'; Short='DefEvade'; Color='#22c55e' }
    'TA0006' = @{ Name='Credential Access'; Short='CredAccess'; Color='#14b8a6' }
    'TA0007' = @{ Name='Discovery'; Short='Discovery'; Color='#06b6d4' }
    'TA0008' = @{ Name='Lateral Movement'; Short='LatMove'; Color='#3b82f6' }
    'TA0009' = @{ Name='Collection'; Short='Collection'; Color='#6366f1' }
    'TA0010' = @{ Name='Exfiltration'; Short='Exfil'; Color='#8b5cf6' }
    'TA0011' = @{ Name='Command & Control'; Short='C2'; Color='#a855f7' }
    'TA0040' = @{ Name='Impact'; Short='Impact'; Color='#ec4899' }
}

# Calculate ATT&CK tactic coverage from current check statuses
function Get-MitreCoverage {
    $tacticCoverage = @{}
    foreach ($ta in $script:MitreTactics.Keys) {
        $tacticCoverage[$ta] = @{ Covered=0; Failed=0; Total=0; Checks=@() }
    }
    foreach ($id in $script:MitreMap.Keys) {
        $m = $script:MitreMap[$id]
        $sv = if ($script:StatusCombos[$id] -and $script:StatusCombos[$id].SelectedItem) { $script:StatusCombos[$id].SelectedItem.ToString() } else { 'Not Assessed' }
        foreach ($ta in $m.Tactics) {
            if (-not $tacticCoverage.Contains($ta)) { continue }
            $tacticCoverage[$ta].Total++
            $tacticCoverage[$ta].Checks += @{ ID=$id; Status=$sv }
            if ($sv -eq 'Pass') { $tacticCoverage[$ta].Covered++ }
            elseif ($sv -eq 'Fail') { $tacticCoverage[$ta].Failed++ }
            elseif ($sv -eq 'Partial') { $tacticCoverage[$ta].Covered += 0.5 }
        }
    }
    return $tacticCoverage
}

# Generate attack path narratives from failed checks
function Get-AttackPaths {
    $paths = @()
    $failedIds = @()
    foreach ($id in $script:MitreMap.Keys) {
        $sv = if ($script:StatusCombos[$id] -and $script:StatusCombos[$id].SelectedItem) { $script:StatusCombos[$id].SelectedItem.ToString() } else { 'Not Assessed' }
        if ($sv -eq 'Fail') { $failedIds += $id }
    }
    # Chain 1: Phishing -> Credential Harvest -> Domain Compromise
    $chain1 = @()
    if ('IA03' -in $failedIds) { $chain1 += @{ID='IA03';Step='Phishing bypasses MFA-less email (T1566)'} }
    if ('CF03' -in $failedIds) { $chain1 += @{ID='CF03';Step='Untrained users click malicious links (T1204)'} }
    if ('EP07' -in $failedIds) { $chain1 += @{ID='EP07';Step='Malicious macro executes payload (T1059, T1204.002)'} }
    if ('EP01' -in $failedIds) { $chain1 += @{ID='EP01';Step='AV fails to detect/block payload (T1562.001)'} }
    if ('EP08' -in $failedIds) { $chain1 += @{ID='EP08';Step='Credentials dumped from LSASS (T1003.001)'} }
    if ('IA01' -in $failedIds) { $chain1 += @{ID='IA01';Step='Stolen DA creds grant domain admin (T1078.002)'} }
    if ('CF01' -in $failedIds) { $chain1 += @{ID='CF01';Step='ADCS/LDAP vulns enable persistence (T1098)'} }
    if ($chain1.Count -ge 3) { $paths += @{ Name='Phishing to Domain Compromise'; Severity='CRITICAL'; Steps=$chain1 } }
    # Chain 2: Lateral Movement -> Ransomware
    $chain2 = @()
    if ('NA01' -in $failedIds) { $chain2 += @{ID='NA01';Step='Flat network enables unrestricted movement (T1021)'} }
    if ('EP03' -in $failedIds) { $chain2 += @{ID='EP03';Step='SMB/NTLM relay enables credential theft (T1557.001)'} }
    if ('CF07' -in $failedIds) { $chain2 += @{ID='CF07';Step='Excessive local admin enables lateral spread (T1078.001)'} }
    if ('LM02' -in $failedIds) { $chain2 += @{ID='LM02';Step='No SIEM - lateral movement goes undetected (T1562.002)'} }
    if ('BR01' -in $failedIds -or 'BR02' -in $failedIds) { $chain2 += @{ID=$(if('BR01' -in $failedIds){'BR01'}else{'BR02'});Step='No backup recovery path - ransomware is catastrophic (T1486)'} }
    if ($chain2.Count -ge 3) { $paths += @{ Name='Lateral Movement to Ransomware'; Severity='CRITICAL'; Steps=$chain2 } }
    # Chain 3: External Exploitation -> Data Exfiltration
    $chain3 = @()
    if ('NP02' -in $failedIds) { $chain3 += @{ID='NP02';Step='Open ports expose vulnerable services (T1190)'} }
    if ('EP04' -in $failedIds) { $chain3 += @{ID='EP04';Step='Unpatched software exploited (T1203)'} }
    if ('NP03' -in $failedIds) { $chain3 += @{ID='NP03';Step='RDP exposed - brute force or BlueKeep (T1021.001)'} }
    if ('CF05' -in $failedIds) { $chain3 += @{ID='CF05';Step='Open shares expose sensitive data (T1039)'} }
    if ('EP06' -in $failedIds) { $chain3 += @{ID='EP06';Step='Firewall gaps allow data exfiltration (T1048)'} }
    if ('NA07' -in $failedIds) { $chain3 += @{ID='NA07';Step='No DNS filtering - C2 via DNS tunneling (T1071)'} }
    if ($chain3.Count -ge 3) { $paths += @{ Name='External Exploitation to Data Exfiltration'; Severity='HIGH'; Steps=$chain3 } }
    # Chain 4: Insider Threat / Credential Abuse
    $chain4 = @()
    if ('IA04' -in $failedIds) { $chain4 += @{ID='IA04';Step='Terminated employee accounts still active (T1078)'} }
    if ('IA07' -in $failedIds) { $chain4 += @{ID='IA07';Step='Shared accounts eliminate attribution (T1078.001)'} }
    if ('LM01' -in $failedIds) { $chain4 += @{ID='LM01';Step='Inadequate auditing hides insider activity (T1562.002)'} }
    if ('CF04' -in $failedIds) { $chain4 += @{ID='CF04';Step='Excessive permissions enable data theft (T1005)'} }
    if ($chain4.Count -ge 3) { $paths += @{ Name='Insider Threat / Credential Abuse'; Severity='HIGH'; Steps=$chain4 } }
    return $paths
}

# ── Phase 4B: Ransomware Preparedness Score ──────────────────────────────────
# Evaluates 4 domains: Prevention, Protection, Detection, Recovery
# Each domain has weighted checks; overall score 0-100 with letter grade
function Get-RansomwareScore {
    $domains = [ordered]@{
        Prevention = @{
            Weight = 0.30
            Checks = @(
                @{ID='EP01'; Factor='AV/EDR active with ASR rules'; Points=15}
                @{ID='EP07'; Factor='AppLocker/WDAC + Office macros restricted'; Points=15}
                @{ID='IA03'; Factor='MFA on all remote access'; Points=12}
                @{ID='IA05'; Factor='Strong password policy'; Points=8}
                @{ID='NP07'; Factor='IDS/IPS on perimeter'; Points=8}
                @{ID='CF03'; Factor='Security awareness training'; Points=8}
                @{ID='NA07'; Factor='DNS filtering active'; Points=6}
                @{ID='NP08'; Factor='TLS properly configured'; Points=5}
                @{ID='EP04'; Factor='Patching current'; Points=10}
                @{ID='NP03'; Factor='RDP/remote access secured'; Points=8}
                @{ID='CF02'; Factor='SMBv1 disabled'; Points=5}
            )
        }
        Protection = @{
            Weight = 0.25
            Checks = @(
                @{ID='EP08'; Factor='Credential Guard / LSA Protection / WDigest disabled'; Points=18}
                @{ID='EP02'; Factor='BitLocker / disk encryption'; Points=12}
                @{ID='EP03'; Factor='SMB signing + NTLM hardened'; Points=12}
                @{ID='EP05'; Factor='Local admin controlled / no privesc paths'; Points=10}
                @{ID='EP06'; Factor='Host firewall properly configured'; Points=10}
                @{ID='IA01'; Factor='Privileged accounts minimized'; Points=12}
                @{ID='IA06'; Factor='PAM / LAPS deployed'; Points=10}
                @{ID='NA01'; Factor='Network segmentation'; Points=10}
                @{ID='CF01'; Factor='Service account hygiene / ADCS secure'; Points=6}
            )
        }
        Detection = @{
            Weight = 0.25
            Checks = @(
                @{ID='LM02'; Factor='SIEM deployed with log aggregation'; Points=20}
                @{ID='LM03'; Factor='Audit policy + PowerShell logging comprehensive'; Points=18}
                @{ID='LM01'; Factor='Audit configuration baseline'; Points=12}
                @{ID='LM08'; Factor='Alerting and monitoring active'; Points=15}
                @{ID='LM07'; Factor='Log sizes adequate for retention'; Points=8}
                @{ID='LM06'; Factor='Regular log review process'; Points=10}
                @{ID='LM04'; Factor='Firewall/IDS logging'; Points=8}
                @{ID='CF08'; Factor='Vulnerability scanning active'; Points=9}
            )
        }
        Recovery = @{
            Weight = 0.20
            Checks = @(
                @{ID='BR01'; Factor='Backup solution operational'; Points=20}
                @{ID='BR02'; Factor='Offsite / immutable / air-gapped copies'; Points=20}
                @{ID='BR04'; Factor='Backup restore tested'; Points=15}
                @{ID='BR03'; Factor='DR plan documented'; Points=12}
                @{ID='BR05'; Factor='RTO/RPO defined and achievable'; Points=10}
                @{ID='BR06'; Factor='Backup monitoring and alerting'; Points=10}
                @{ID='BR08'; Factor='Critical system backup coverage'; Points=8}
                @{ID='BR07'; Factor='Backup encryption'; Points=5}
            )
        }
    }
    $domainScores = [ordered]@{}
    $overallWeighted = 0
    foreach ($dName in $domains.Keys) {
        $d = $domains[$dName]
        $maxPoints = ($d.Checks | ForEach-Object { $_.Points } | Measure-Object -Sum).Sum
        $earnedPoints = 0
        $details = @()
        foreach ($ck in $d.Checks) {
            $sv = if ($script:StatusCombos[$ck.ID] -and $script:StatusCombos[$ck.ID].SelectedItem) { $script:StatusCombos[$ck.ID].SelectedItem.ToString() } else { 'Not Assessed' }
            $earned = switch ($sv) { 'Pass' { $ck.Points } 'Partial' { [math]::Round($ck.Points * 0.5) } default { 0 } }
            $earnedPoints += $earned
            $details += @{ ID=$ck.ID; Factor=$ck.Factor; MaxPoints=$ck.Points; Earned=$earned; Status=$sv }
        }
        $pct = if ($maxPoints -gt 0) { [math]::Round($earnedPoints / $maxPoints * 100) } else { 0 }
        $domainScores[$dName] = @{ Score=$pct; Earned=$earnedPoints; Max=$maxPoints; Weight=$d.Weight; Details=$details }
        $overallWeighted += $pct * $d.Weight
    }
    $overall = [math]::Round($overallWeighted)
    $grade = switch($true) { ($overall -ge 90){'A'} ($overall -ge 80){'B'} ($overall -ge 70){'C'} ($overall -ge 60){'D'} default{'F'} }
    return @{ Overall=$overall; Grade=$grade; Domains=$domainScores }
}

# ── End Phase 4 Data Layer ───────────────────────────────────────────────────

# Scan state
$script:ScanTarget = 'localhost'
$script:ScanCredential = $null
$script:ScanRunning = $false
$script:ScanButtons = @{}   # ID -> scan button element
$script:ActiveFilter = 'All'

# Async scan infrastructure
$script:ScanQueue = [System.Collections.Queue]::Synchronized([System.Collections.Queue]::new())
$script:CurrentPS = $null          # current [PowerShell] instance
$script:CurrentAsyncResult = $null # IAsyncResult handle
$script:CurrentScanId = $null      # ID being scanned

# Cache InitialSessionState (expensive to create, reusable) for per-check runspaces
$script:ScanISS = $null
try {
    $script:ScanISS = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
} catch {
    $script:ScanISS = $null
}
$script:ScanBatchTotal = 0
$script:ScanBatchDone = 0
$script:ScanBatchMode = $null      # 'Batch','Single','Preflight' or $null
$script:ScanBatchStopwatch = $null # [Stopwatch] for total batch time
$script:ScanBatchTally = $null     # @{Pass=0;Fail=0;Partial=0;Error=0}
$script:CurrentScanStopwatch = $null  # [Stopwatch] for per-check time
$script:CurrentScanHeartbeat = 0      # last heartbeat second logged
$script:ConsoleLineCount = 0
$script:CheckStates    = @{}
$script:StatusCombos   = @{}
$script:NotesBoxes     = @{}
$script:FindingsBoxes  = @{}
$script:EvidenceBoxes  = @{}
$script:RemAssignBoxes = @{}
$script:RemDueBoxes    = @{}
$script:RemStatusCombos = @{}
$script:CheckBoxes     = @{}
$script:HintBlocks     = @{}
$script:TotalItems     = 0
$script:CategoryProgress = @{}
$script:ThemedElements = [System.Collections.ArrayList]@()
$script:AllCombos      = [System.Collections.ArrayList]@()

# Collapse/advance tracking
$script:ItemCards      = @{}   # ID -> outer card Border
$script:ItemPanels     = @{}   # ID -> inner StackPanel (for collapsing children)
$script:TabItemIDs     = @{}   # tabIndex -> [ordered list of item IDs]
$script:ItemTabIndex   = @{}   # ID -> tabIndex
$script:TabScrollViews = @{}   # tabIndex -> ScrollViewer
$script:TabIndex       = 0     # current tab build counter
$script:HighlightedCard = $null
$script:SuppressAdvance = $false

# ── XAML ─────────────────────────────────────────────────────────────────────
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Network Security Audit Checklist v4.0"
        Width="1250" Height="860" MinWidth="900" MinHeight="600"
        WindowStartupLocation="CenterScreen"
        SnapsToDevicePixels="True" UseLayoutRounding="True">
    <Grid x:Name="RootGrid">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <Border x:Name="HeaderBar" Grid.Row="0" Padding="20,12">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0">
                    <TextBlock x:Name="TitleText" Text="Network Security Audit Checklist"
                               FontSize="20" FontWeight="Bold"/>
                    <TextBlock x:Name="SubtitleText" Text="SMB Security Assessment Tool v4.0 - Guided Audit with Compliance Mapping"
                               FontSize="11.5" Margin="0,2,0,0"/>
                </StackPanel>
                <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center" Margin="0,0,16,0">
                    <TextBlock x:Name="ThemeLabel" Text="Theme:" FontSize="12"
                               VerticalAlignment="Center" Margin="0,0,6,0"/>
                    <ComboBox x:Name="ThemeSelector" Width="155" Height="26" FontSize="11.5"/>
                </StackPanel>
                <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
                    <StackPanel Orientation="Vertical" Margin="0,0,12,0">
                        <TextBlock x:Name="ProgLabel" Text="Overall" FontSize="10" Margin="0,0,0,3"/>
                        <Grid><Border x:Name="ProgBarBg" CornerRadius="4" Height="10" Width="180"/>
                        <Border x:Name="ProgBarFill" CornerRadius="4" Height="10" HorizontalAlignment="Left" Width="0"/></Grid>
                    </StackPanel>
                    <TextBlock x:Name="ProgText" Text="0/0" FontSize="15" FontWeight="Bold" VerticalAlignment="Center"/>
                </StackPanel>
            </Grid>
        </Border>

        <Border x:Name="InfoBar" Grid.Row="1" Padding="20,8">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/><ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0" Margin="0,0,8,0">
                    <TextBlock x:Name="lblClient" Text="Client" FontSize="10.5" Margin="0,0,0,2"/>
                    <TextBox x:Name="txtClient" Padding="6,4" FontSize="12"/>
                </StackPanel>
                <StackPanel Grid.Column="1" Margin="8,0">
                    <TextBlock x:Name="lblAuditor" Text="Auditor" FontSize="10.5" Margin="0,0,0,2"/>
                    <TextBox x:Name="txtAuditor" Padding="6,4" FontSize="12"/>
                </StackPanel>
                <StackPanel Grid.Column="2" Margin="8,0">
                    <TextBlock x:Name="lblDate" Text="Date" FontSize="10.5" Margin="0,0,0,2"/>
                    <TextBox x:Name="txtDate" Padding="6,4" FontSize="12" IsReadOnly="True"/>
                </StackPanel>
                <StackPanel Grid.Column="3" Orientation="Horizontal" VerticalAlignment="Bottom" Margin="8,0,0,0">
                    <Button x:Name="btnSave" Content="Save" Padding="14,5" Margin="0,0,4,0" FontSize="12" FontWeight="SemiBold" Cursor="Hand"/>
                    <Button x:Name="btnLoad" Content="Load" Padding="14,5" Margin="0,0,4,0" FontSize="12" FontWeight="SemiBold" Cursor="Hand"/>
                    <Button x:Name="btnDiff" Content="Diff" Padding="14,5" FontSize="12" FontWeight="SemiBold" Cursor="Hand" ToolTip="Compare two saved audits"/>
                </StackPanel>
            </Grid>
        </Border>

        <Border x:Name="ScanBar" Grid.Row="2" Padding="20,6" Visibility="Collapsed">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBlock x:Name="lblScanIcon" Grid.Column="0" Text="[SCAN]" FontSize="11" FontWeight="Bold"
                           VerticalAlignment="Center" Margin="0,0,10,0"/>
                <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock x:Name="lblTarget" Text="Target:" FontSize="11" VerticalAlignment="Center" Margin="0,0,4,0"/>
                    <TextBox x:Name="txtScanTarget" Width="180" Padding="6,3" FontSize="11.5" Text="localhost"
                             ToolTip="Hostname or IP of scan target. Use 'localhost' for local scans."/>
                    <Button x:Name="btnSetCreds" Content="Credentials" Padding="10,3" Margin="8,0,0,0" FontSize="11" Cursor="Hand"
                            ToolTip="Set domain credentials for remote scans (Get-Credential)"/>
                    <TextBlock x:Name="lblCredStatus" Text="[Local]" FontSize="10.5" VerticalAlignment="Center" Margin="8,0,0,0"/>
                    <Button x:Name="btnConfigWinRM" Content="WinRM" Padding="10,3" Margin="8,0,0,0" FontSize="11" Cursor="Hand"
                            ToolTip="Auto-configure WinRM on current target"/>
                    <Button x:Name="btnPreflight" Content="Pre-flight" Padding="10,3" Margin="8,0,0,0" FontSize="11" Cursor="Hand"
                            ToolTip="Test connectivity to target - checks WinRM, AD, SMB, DNS reachability"/>
                </StackPanel>
                <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center" Margin="8,0,0,0">
                    <TextBlock x:Name="lblProfile" Text="Profile:" FontSize="10.5" VerticalAlignment="Center" Margin="0,0,4,0"/>
                    <ComboBox x:Name="cboProfile" Width="195" FontSize="10.5" Padding="4,2"
                              ToolTip="Scan profile: Quick, Standard, Full, AD-only, Local-only, or compliance framework"/>
                    <TextBlock x:Name="lblFramework" Text="Framework:" FontSize="10.5" VerticalAlignment="Center" Margin="12,0,4,0"/>
                    <ComboBox x:Name="cboFramework" Width="120" FontSize="10.5" Padding="4,2"
                              ToolTip="Compliance framework to highlight in reports: All, CIS, NIST 800-171, CMMC, HIPAA, PCI-DSS, SOC 2, ISO 27001"/>
                </StackPanel>
                <Button x:Name="btnFullAudit" Grid.Column="3" Content="Full Audit" Padding="14,4" Margin="8,0,0,0"
                        FontSize="11.5" FontWeight="Bold" Cursor="Hand"
                        ToolTip="One-click: Pre-flight + Scan Profile + Auto-Export to Desktop"/>
                <Button x:Name="btnScanAll" Grid.Column="4" Content="Scan Profile" Padding="14,4" Margin="4,0,0,0"
                        FontSize="11.5" FontWeight="SemiBold" Cursor="Hand" ToolTip="Run selected profile's auto-checks"/>
                <Button x:Name="btnScanAD" Grid.Column="5" Content="Scan AD" Padding="10,4" Margin="4,0,0,0"
                        FontSize="11" Cursor="Hand" ToolTip="Run Active Directory checks only"/>
                <Button x:Name="btnScanLocal" Grid.Column="6" Content="Scan Local" Padding="10,4" Margin="4,0,0,0"
                        FontSize="11" Cursor="Hand" ToolTip="Run local endpoint checks only"/>
                <TextBlock x:Name="lblScanProgress" Grid.Column="7" Text="" FontSize="10.5"
                           VerticalAlignment="Center" Margin="10,0,0,0"/>
            </Grid>
        </Border>

        <TabControl x:Name="MainTabs" Grid.Row="3" Margin="10,4,10,0" BorderThickness="0"/>

        <Border x:Name="ConsolePanel" Grid.Row="4" Padding="10,4" MaxHeight="220">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                </Grid.RowDefinitions>
                <Grid Grid.Row="0">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <TextBlock x:Name="lblConsole" Grid.Column="0" Text="Console" FontSize="11" FontWeight="SemiBold" VerticalAlignment="Center" Margin="4,0,0,0"/>
                    <TextBlock x:Name="lblConsoleCount" Grid.Column="1" Text="" FontSize="10" VerticalAlignment="Center" Margin="8,0,0,0"/>
                    <Button x:Name="btnConsoleClear" Grid.Column="2" Content="Clear" Padding="8,2" Margin="4,0,0,0" FontSize="10" Cursor="Hand"/>
                    <Button x:Name="btnConsoleToggle" Grid.Column="3" Content="Hide" Padding="8,2" Margin="4,0,0,0" FontSize="10" Cursor="Hand"/>
                </Grid>
                <TextBox x:Name="txtConsole" Grid.Row="1" IsReadOnly="True" AcceptsReturn="True" TextWrapping="NoWrap"
                         VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                         FontFamily="Consolas" FontSize="11" Margin="0,4,0,0" Padding="6,4"
                         BorderThickness="1" MinHeight="100"/>
            </Grid>
        </Border>

        <Border x:Name="FooterBar" Grid.Row="5" Padding="14,8">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBlock x:Name="ScoreText" Grid.Column="0" FontSize="12.5" FontWeight="Bold" VerticalAlignment="Center" Margin="0,0,16,0"/>
                <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center" Margin="0,0,12,0">
                    <TextBlock x:Name="lblFilter" Text="View:" FontSize="10.5" VerticalAlignment="Center" Margin="0,0,4,0"/>
                    <Button x:Name="btnFilterAll" Content="All" Padding="8,3" Margin="0,0,2,0" FontSize="10.5" Cursor="Hand"/>
                    <Button x:Name="btnFilterIncomplete" Content="Incomplete" Padding="8,3" Margin="0,0,2,0" FontSize="10.5" Cursor="Hand"/>
                    <Button x:Name="btnFilterFail" Content="Failures" Padding="8,3" Margin="0,0,2,0" FontSize="10.5" Cursor="Hand"/>
                    <Button x:Name="btnFilterScanned" Content="Scanned" Padding="8,3" FontSize="10.5" Cursor="Hand"/>
                </StackPanel>
                <TextBlock x:Name="StatusText" Grid.Column="2" Text="Ready" FontSize="11.5" VerticalAlignment="Center"/>
                <StackPanel Grid.Column="3" Orientation="Horizontal">
                    <Button x:Name="btnReset" Content="Reset All" Padding="14,5" Margin="0,0,4,0" FontSize="12" FontWeight="SemiBold" Cursor="Hand"/>
                    <Button x:Name="btnExportHTML" Content="Export HTML" Padding="14,5" Margin="0,0,4,0" FontSize="12" FontWeight="SemiBold" Cursor="Hand"/>
                    <Button x:Name="btnExportJSON" Content="Export JSON" Padding="14,5" Margin="0,0,4,0" FontSize="12" FontWeight="SemiBold" Cursor="Hand" ToolTip="Export structured findings JSON with full compliance + MITRE metadata"/>
                    <Button x:Name="btnExportCSV" Content="Export CSV" Padding="14,5" Margin="0,0,4,0" FontSize="12" FontWeight="SemiBold" Cursor="Hand" ToolTip="Export CSV for MSP pivot table analysis across clients"/>
                </StackPanel>
            </Grid>
        </Border>
    </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

$el = @{}
@(
    'RootGrid','HeaderBar','InfoBar','ScanBar','FooterBar','MainTabs',
    'ConsolePanel','lblConsole','lblConsoleCount','btnConsoleClear','btnConsoleToggle','txtConsole',
    'TitleText','SubtitleText','ThemeLabel','ThemeSelector',
    'ProgLabel','ProgBarBg','ProgBarFill','ProgText',
    'lblClient','lblAuditor','lblDate','txtClient','txtAuditor','txtDate',
    'btnSave','btnLoad','btnDiff','btnReset','btnExportHTML','btnExportJSON','btnExportCSV',
    'ScoreText','StatusText',
    'lblFilter','btnFilterAll','btnFilterIncomplete','btnFilterFail','btnFilterScanned',
    'lblScanIcon','lblTarget','txtScanTarget','btnSetCreds','lblCredStatus','btnConfigWinRM','btnPreflight',
    'btnFullAudit','btnScanAll','btnScanAD','btnScanLocal','lblScanProgress',
    'cboProfile','lblProfile',
    'cboFramework','lblFramework'
) | ForEach-Object { $el[$_] = $window.FindName($_) }

$el['txtDate'].Text = (Get-Date -Format 'yyyy-MM-dd')

# ── Initialize Scan Profile ComboBox ─────────────────────────────────────────
$profileOrder = @('Quick','Standard','Full','ADOnly','LocalOnly','HIPAA','PCI','CMMC','SOC2','ISO27001')
foreach ($pn in $profileOrder) {
    $el['cboProfile'].Items.Add($script:ScanProfiles[$pn].Label) | Out-Null
}
$el['cboProfile'].SelectedIndex = 2  # Default: Full
# Map CLI profile to ComboBox index
if ($script:CliProfile) {
    $idx = $profileOrder.IndexOf($script:CliProfile)
    if ($idx -ge 0) { $el['cboProfile'].SelectedIndex = $idx }
}

# ── Initialize Framework Selector ComboBox ────────────────────────────────────
$frameworkOrder = @('All','CIS','NIST','CMMC','HIPAA','PCI','SOC2','ISO27001')
$frameworkLabels = @{ 'All'='All Frameworks'; 'CIS'='CIS v8.1'; 'NIST'='NIST 800-171'; 'CMMC'='CMMC 2.0'; 'HIPAA'='HIPAA'; 'PCI'='PCI-DSS 4.0.1'; 'SOC2'='SOC 2'; 'ISO27001'='ISO 27001' }
foreach ($fw in $frameworkOrder) { $el['cboFramework'].Items.Add($frameworkLabels[$fw]) | Out-Null }
$el['cboFramework'].SelectedIndex = 0  # Default: All
$el['cboFramework'].Add_SelectionChanged({
    $fwIdx = $el['cboFramework'].SelectedIndex; if ($fwIdx -lt 0) { $fwIdx = 0 }
    $script:ComplianceTarget = $frameworkOrder[$fwIdx]
    $el['StatusText'].Text = "Compliance target: $($frameworkLabels[$frameworkOrder[$fwIdx]])"
    Write-Log "Framework target changed: $($script:ComplianceTarget)" 'INFO'
})

# ── Theme Application ────────────────────────────────────────────────────────
function Apply-ButtonTheme([System.Windows.Controls.Button]$btn, [string]$bg, [string]$hover) {
    $tmpl = New-Object System.Windows.Controls.ControlTemplate ([System.Windows.Controls.Button])
    $bf = New-Object System.Windows.FrameworkElementFactory ([System.Windows.Controls.Border])
    $bf.Name = 'bd'
    $bf.SetValue([System.Windows.Controls.Border]::BackgroundProperty, (New-Brush $bg))
    $bf.SetValue([System.Windows.Controls.Border]::CornerRadiusProperty, [System.Windows.CornerRadius]::new(5))
    $bf.SetValue([System.Windows.Controls.Border]::PaddingProperty, [System.Windows.Thickness]::new(14,5,14,5))
    $cp = New-Object System.Windows.FrameworkElementFactory ([System.Windows.Controls.ContentPresenter])
    $cp.SetValue([System.Windows.FrameworkElement]::HorizontalAlignmentProperty, [System.Windows.HorizontalAlignment]::Center)
    $cp.SetValue([System.Windows.FrameworkElement]::VerticalAlignmentProperty, [System.Windows.VerticalAlignment]::Center)
    $bf.AppendChild($cp)
    $tmpl.VisualTree = $bf
    $tr = New-Object System.Windows.Trigger
    $tr.Property = [System.Windows.UIElement]::IsMouseOverProperty; $tr.Value = $true
    $tr.Setters.Add((New-Object System.Windows.Setter ([System.Windows.Controls.Border]::BackgroundProperty, (New-Brush $hover), 'bd')))
    $tmpl.Triggers.Add($tr)
    $btn.Template = $tmpl; $btn.Foreground = [System.Windows.Media.Brushes]::White
}

function Apply-ComboTheme([System.Windows.Controls.ComboBox]$combo) {
    $t = Get-T
    $combo.Foreground = New-Brush $t.TextPrimary

    # Use XAML string parsing - the only reliable way to template ComboBox in PowerShell WPF
    $xamlStr = @"
<ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                 xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
                 TargetType="{x:Type ComboBox}">
    <Grid>
        <ToggleButton x:Name="ToggleBtn" Focusable="False" ClickMode="Press"
                      IsChecked="{Binding IsDropDownOpen, RelativeSource={RelativeSource TemplatedParent}, Mode=TwoWay}">
            <ToggleButton.Template>
                <ControlTemplate TargetType="{x:Type ToggleButton}">
                    <Border x:Name="TBdr" Background="$($t.InputBg)"
                            BorderBrush="$($t.BorderDim)" BorderThickness="1" CornerRadius="4">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="24"/>
                            </Grid.ColumnDefinitions>
                            <Path Grid.Column="1" Data="M0,0 L4,4 L8,0" Stroke="$($t.TextSecondary)"
                                  StrokeThickness="1.5" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Grid>
                    </Border>
                    <ControlTemplate.Triggers>
                        <Trigger Property="IsMouseOver" Value="True">
                            <Setter TargetName="TBdr" Property="BorderBrush" Value="$($t.Accent)"/>
                        </Trigger>
                        <Trigger Property="IsChecked" Value="True">
                            <Setter TargetName="TBdr" Property="BorderBrush" Value="$($t.Accent)"/>
                        </Trigger>
                    </ControlTemplate.Triggers>
                </ControlTemplate>
            </ToggleButton.Template>
        </ToggleButton>
        <ContentPresenter x:Name="ContentSite" Content="{TemplateBinding SelectionBoxItem}"
                          ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}"
                          IsHitTestVisible="False" Margin="8,0,28,0"
                          VerticalAlignment="Center" HorizontalAlignment="Left"/>
        <Popup x:Name="Popup" Placement="Bottom" AllowsTransparency="True" Focusable="False"
               IsOpen="{TemplateBinding IsDropDownOpen}" PopupAnimation="Slide">
            <Border Background="$($t.InputBg)" BorderBrush="$($t.BorderDim)"
                    BorderThickness="1" CornerRadius="4" Margin="0,2,0,0"
                    MinWidth="{TemplateBinding ActualWidth}" MaxHeight="200">
                <ScrollViewer CanContentScroll="True">
                    <StackPanel IsItemsHost="True"/>
                </ScrollViewer>
            </Border>
        </Popup>
    </Grid>
</ControlTemplate>
"@

    $xamlItem = @"
<Style xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
       xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
       TargetType="{x:Type ComboBoxItem}">
    <Setter Property="Foreground" Value="$($t.TextPrimary)"/>
    <Setter Property="Background" Value="Transparent"/>
    <Setter Property="Cursor" Value="Hand"/>
    <Setter Property="Template">
        <Setter.Value>
            <ControlTemplate TargetType="{x:Type ComboBoxItem}">
                <Border x:Name="ItemBd" Background="Transparent" Padding="8,5,8,5">
                    <ContentPresenter/>
                </Border>
                <ControlTemplate.Triggers>
                    <Trigger Property="IsHighlighted" Value="True">
                        <Setter TargetName="ItemBd" Property="Background" Value="$($t.HoverBg)"/>
                    </Trigger>
                    <Trigger Property="IsSelected" Value="True">
                        <Setter TargetName="ItemBd" Property="Background" Value="$($t.Accent)"/>
                        <Setter Property="Foreground" Value="White"/>
                    </Trigger>
                </ControlTemplate.Triggers>
            </ControlTemplate>
        </Setter.Value>
    </Setter>
</Style>
"@

    try {
        $comboTmpl = [System.Windows.Markup.XamlReader]::Parse($xamlStr)
        $combo.Template = $comboTmpl
        $itemStyle = [System.Windows.Markup.XamlReader]::Parse($xamlItem)
        $combo.ItemContainerStyle = $itemStyle
    } catch {
        # Fallback: at minimum set the basic colors
        $combo.Background = New-Brush $t.InputBg
        $combo.BorderBrush = New-Brush $t.BorderDim
    }
}

function Apply-Theme {
    $t = Get-T
    $window.Background = New-Brush $t.WindowBg
    $el['HeaderBar'].Background = New-Brush $t.HeaderGrad1
    $el['TitleText'].Foreground = New-Brush $t.TextPrimary
    $el['SubtitleText'].Foreground = New-Brush $t.TextSecondary
    $el['ThemeLabel'].Foreground = New-Brush $t.TextSecondary
    $el['ProgLabel'].Foreground = New-Brush $t.TextSecondary
    $el['ProgBarBg'].Background = New-Brush $t.BarBg
    $el['MainTabs'].Background = New-Brush $t.WindowBg
    $el['InfoBar'].Background = New-Brush $t.PanelBg
    $el['InfoBar'].BorderBrush = New-Brush $t.BorderDim
    $el['InfoBar'].BorderThickness = [System.Windows.Thickness]::new(0,0,0,1)
    $el['FooterBar'].Background = New-Brush $t.HeaderGrad1
    $el['StatusText'].Foreground = New-Brush $t.TextSecondary
    $el['ScoreText'].Foreground = New-Brush $t.Accent

    foreach ($l in @('lblClient','lblAuditor','lblDate')) { $el[$l].Foreground = New-Brush $t.TextSecondary }
    foreach ($tb in @('txtClient','txtAuditor','txtDate')) {
        $el[$tb].Background = New-Brush $t.InputBg; $el[$tb].Foreground = New-Brush $t.TextPrimary
        $el[$tb].BorderBrush = New-Brush $t.BorderDim; $el[$tb].CaretBrush = New-Brush $t.TextPrimary
    }

    Apply-ButtonTheme $el['btnSave'] $t.Accent $t.AccentHover
    Apply-ButtonTheme $el['btnLoad'] '#6366f1' '#818cf8'
    Apply-ButtonTheme $el['btnDiff'] '#8b5cf6' '#a78bfa'
    Apply-ButtonTheme $el['btnReset'] '#dc2626' '#ef4444'
    Apply-ButtonTheme $el['btnExportHTML'] '#16a34a' '#22c55e'
    Apply-ButtonTheme $el['btnExportJSON'] '#0ea5e9' '#38bdf8'
    Apply-ButtonTheme $el['btnExportCSV'] '#f59e0b' '#fbbf24'
    # Filter buttons
    $el['lblFilter'].Foreground = New-Brush $t.TextSecondary
    $filterActive = if ($script:ActiveFilter) { $script:ActiveFilter } else { 'All' }
    foreach ($fb in @('btnFilterAll','btnFilterIncomplete','btnFilterFail','btnFilterScanned')) {
        $btnMode = $fb -replace 'btnFilter',''
        $isActive = ($btnMode -eq $filterActive)
        if ($isActive) { Apply-ButtonTheme $el[$fb] $t.Accent $t.AccentHover }
        else {
            Apply-ButtonTheme $el[$fb] $t.SurfaceBg $t.HoverBg
            $el[$fb].Foreground = New-Brush $t.TextPrimary
        }
    }
    if ($script:exRefreshBtn) { Apply-ButtonTheme $script:exRefreshBtn $t.Accent $t.AccentHover }

    # Scan bar theming
    $el['ScanBar'].Background = New-Brush $t.PanelBg
    $el['ScanBar'].BorderBrush = New-Brush $t.BorderDim
    $el['ScanBar'].BorderThickness = [System.Windows.Thickness]::new(0,0,0,1)
    $el['lblScanIcon'].Foreground = New-Brush $t.Accent
    $el['lblTarget'].Foreground = New-Brush $t.TextSecondary
    $el['txtScanTarget'].Background = New-Brush $t.InputBg
    $el['txtScanTarget'].Foreground = New-Brush $t.TextPrimary
    $el['txtScanTarget'].BorderBrush = New-Brush $t.BorderDim
    $el['txtScanTarget'].CaretBrush = New-Brush $t.TextPrimary
    $el['lblCredStatus'].Foreground = New-Brush $t.TextSecondary
    $el['lblScanProgress'].Foreground = New-Brush $t.TextSecondary
    Apply-ButtonTheme $el['btnScanAll'] '#0ea5e9' '#38bdf8'
    Apply-ButtonTheme $el['btnFullAudit'] '#eab308' '#facc15'
    Apply-ButtonTheme $el['btnSetCreds'] '#6366f1' '#818cf8'
    Apply-ButtonTheme $el['btnConfigWinRM'] '#06b6d4' '#22d3ee'
    Apply-ButtonTheme $el['btnPreflight'] '#f97316' '#fb923c'
    Apply-ButtonTheme $el['btnScanAD'] '#a855f7' '#c084fc'
    Apply-ButtonTheme $el['btnScanLocal'] '#22c55e' '#4ade80'
    # Theme per-item scan buttons
    foreach ($sbtn in $script:ScanButtons.Values) { Apply-ButtonTheme $sbtn '#0ea5e9' '#38bdf8' }

    # Console panel theming
    $el['ConsolePanel'].Background = New-Brush $t.PanelBg
    $el['ConsolePanel'].BorderBrush = New-Brush $t.BorderDim
    $el['ConsolePanel'].BorderThickness = [System.Windows.Thickness]::new(0,1,0,0)
    $el['lblConsole'].Foreground = New-Brush $t.Accent
    $el['lblConsoleCount'].Foreground = New-Brush $t.TextSecondary
    $el['txtConsole'].Background = New-Brush $t.WindowBg
    $el['txtConsole'].Foreground = New-Brush '#22c55e'
    $el['txtConsole'].BorderBrush = New-Brush $t.BorderDim
    $el['txtConsole'].CaretBrush = New-Brush '#22c55e'
    Apply-ButtonTheme $el['btnConsoleClear'] '#475569' '#64748b'
    Apply-ButtonTheme $el['btnConsoleToggle'] '#475569' '#64748b'

    foreach ($entry in $script:ThemedElements) {
        switch ($entry.Type) {
            'Card'       { $entry.Element.Background = New-Brush $t.CardBg; $entry.Element.BorderBrush = New-Brush $t.BorderDim }
            'CatHeader'  { $entry.Element.Background = New-Brush $t.PanelBg }
            'TextPri'    { $entry.Element.Foreground = New-Brush $t.TextPrimary }
            'TextSec'    { $entry.Element.Foreground = New-Brush $t.TextSecondary }
            'Input'      {
                if ($entry.Element -is [System.Windows.Controls.TextBox]) {
                    $entry.Element.Background = New-Brush $t.InputBg; $entry.Element.Foreground = New-Brush $t.TextPrimary
                    $entry.Element.BorderBrush = New-Brush $t.BorderDim; $entry.Element.CaretBrush = New-Brush $t.TextPrimary
                    $entry.Element.SelectionBrush = New-Brush $t.Accent
                }
            }
            'BarBg'      { $entry.Element.Background = New-Brush $t.BarBg }
            'Hint'       { $entry.Element.Background = New-Brush $t.HintBg; $entry.Element.BorderBrush = New-Brush $t.HintBorder }
            'HintText'   { $entry.Element.Foreground = New-Brush $t.TextSecondary }
        }
    }

    # Apply full dark ControlTemplate to every ComboBox
    Apply-ComboTheme $el['ThemeSelector']
    Apply-ComboTheme $el['cboProfile']
    if ($el['cboFramework']) { Apply-ComboTheme $el['cboFramework'] }
    foreach ($cb in $script:AllCombos) { Apply-ComboTheme $cb }
    # Theme profile and framework labels
    if ($el['lblProfile']) { $el['lblProfile'].Foreground = New-Brush $t.TextSec }
    if ($el['lblFramework']) { $el['lblFramework'].Foreground = New-Brush $t.TextSec }

    # Re-theme all checkboxes for current theme (fixes light mode)
    $newCbStyle = New-CBStyle
    foreach ($cbx in $script:CheckBoxes.Values) { $cbx.Style = $newCbStyle }

    Update-TabStyles
}

function Update-TabStyles {
    $t = Get-T
    foreach ($tab in $el['MainTabs'].Items) {
        $style = New-Object System.Windows.Style ([System.Windows.Controls.TabItem])
        $style.Setters.Add((New-Object System.Windows.Setter ([System.Windows.Controls.TabItem]::ForegroundProperty, (New-Brush $t.TextSecondary))))
        $style.Setters.Add((New-Object System.Windows.Setter ([System.Windows.Controls.TabItem]::FontSizeProperty, 12.0)))
        $style.Setters.Add((New-Object System.Windows.Setter ([System.Windows.Controls.TabItem]::FontWeightProperty, [System.Windows.FontWeights]::SemiBold)))

        $tmpl = New-Object System.Windows.Controls.ControlTemplate ([System.Windows.Controls.TabItem])
        $bf = New-Object System.Windows.FrameworkElementFactory ([System.Windows.Controls.Border])
        $bf.Name = 'tb'; $bf.SetValue([System.Windows.Controls.Border]::BackgroundProperty, [System.Windows.Media.Brushes]::Transparent)
        $bf.SetValue([System.Windows.Controls.Border]::PaddingProperty, [System.Windows.Thickness]::new(12,7,12,7))
        $bf.SetValue([System.Windows.Controls.Border]::CornerRadiusProperty, [System.Windows.CornerRadius]::new(5,5,0,0))
        $bf.SetValue([System.Windows.Controls.Border]::CursorProperty, [System.Windows.Input.Cursors]::Hand)
        $cp = New-Object System.Windows.FrameworkElementFactory ([System.Windows.Controls.ContentPresenter])
        $cp.SetValue([System.Windows.Controls.ContentPresenter]::ContentSourceProperty, 'Header')
        $bf.AppendChild($cp); $tmpl.VisualTree = $bf

        $sel = New-Object System.Windows.Trigger; $sel.Property = [System.Windows.Controls.TabItem]::IsSelectedProperty; $sel.Value = $true
        $sel.Setters.Add((New-Object System.Windows.Setter ([System.Windows.Controls.Border]::BackgroundProperty, (New-Brush $t.PanelBg), 'tb')))
        $sel.Setters.Add((New-Object System.Windows.Setter ([System.Windows.Controls.TabItem]::ForegroundProperty, (New-Brush $t.Accent))))
        $tmpl.Triggers.Add($sel)
        $hov = New-Object System.Windows.Trigger; $hov.Property = [System.Windows.Controls.TabItem]::IsMouseOverProperty; $hov.Value = $true
        $hov.Setters.Add((New-Object System.Windows.Setter ([System.Windows.Controls.Border]::BackgroundProperty, (New-Brush $t.InputBg), 'tb')))
        $tmpl.Triggers.Add($hov)
        $style.Setters.Add((New-Object System.Windows.Setter ([System.Windows.Controls.TabItem]::TemplateProperty, $tmpl)))
        $tab.Style = $style
    }
}

# ── Scan Execution Engine (Async) ────────────────────────────────────────────
$script:ScanTimestamps = @{}  # ID -> last scan datetime string
$script:TabScanCounts  = @{}  # tabIndex -> @{Pass=0;Fail=0;Partial=0;Error=0}

function Write-Log([string]$msg, [string]$level = 'VERBOSE') {
    $ts = Get-Date -Format 'HH:mm:ss'
    $line = "[$ts] $level`: $msg"
    $el['txtConsole'].AppendText("$line`r`n")
    $el['txtConsole'].ScrollToEnd()
    $script:ConsoleLineCount++
    $el['lblConsoleCount'].Text = "$($script:ConsoleLineCount) lines"
}

function Flash-TabForCheck([string]$id, [string]$status) {
    # Find the tab index for this check
    if (-not $script:ItemTabIndex.Contains($id)) { return }
    $tabIdx = $script:ItemTabIndex[$id]
    if ($tabIdx -ge $el['MainTabs'].Items.Count) { return }

    $tab = $el['MainTabs'].Items[$tabIdx]

    # Track scan counts per tab
    if (-not $script:TabScanCounts.Contains($tabIdx)) {
        $script:TabScanCounts[$tabIdx] = @{Pass=0;Fail=0;Partial=0;Error=0;Total=0}
    }
    $counts = $script:TabScanCounts[$tabIdx]
    $counts.Total++
    switch ($status) { 'Pass'{$counts.Pass++} 'Fail'{$counts.Fail++} 'Partial'{$counts.Partial++} default{$counts.Error++} }

    # Get the original category name
    $catName = $tab.Header
    if ($catName -is [System.Windows.Controls.StackPanel]) {
        $catName = $catName.Tag
    }

    # Determine badge colors based on worst result
    $flashColor = switch ($status) { 'Pass' {'#22c55e'} 'Fail' {'#ef4444'} 'Partial' {'#eab308'} default {'#0ea5e9'} }
    if ($counts.Fail -gt 0) {
        $badgeBg = '#dc2626'; $badgeFg = '#ffffff'
        $badgeText = "$($counts.Pass)P $($counts.Fail)F"
    } elseif ($counts.Partial -gt 0) {
        $badgeBg = '#854d0e'; $badgeFg = '#fef08a'
        $badgeText = "$($counts.Pass)P $($counts.Partial)W"
    } else {
        $badgeBg = '#166534'; $badgeFg = '#bbf7d0'
        $badgeText = "$($counts.Pass)P"
    }

    # Build tab header with live badge
    $hp = New-Object System.Windows.Controls.StackPanel
    $hp.Orientation = [System.Windows.Controls.Orientation]::Horizontal
    $hp.Tag = $catName

    $txt = New-Object System.Windows.Controls.TextBlock
    $txt.Text = $catName
    $txt.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $txt.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($flashColor))
    $txt.FontWeight = [System.Windows.FontWeights]::Bold
    $hp.Children.Add($txt) | Out-Null

    $badge = New-Object System.Windows.Controls.Border
    $badge.CornerRadius = [System.Windows.CornerRadius]::new(8)
    $badge.Padding = [System.Windows.Thickness]::new(5,1,5,1)
    $badge.Margin = [System.Windows.Thickness]::new(6,0,0,0)
    $badge.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $badge.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($badgeBg))

    $badgeTxtBlock = New-Object System.Windows.Controls.TextBlock
    $badgeTxtBlock.FontSize = 9.5
    $badgeTxtBlock.FontWeight = [System.Windows.FontWeights]::Bold
    $badgeTxtBlock.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $badgeTxtBlock.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($badgeFg))
    $badgeTxtBlock.Text = $badgeText
    $badge.Child = $badgeTxtBlock
    $hp.Children.Add($badge) | Out-Null

    $tab.Header = $hp

    # Reset text color after 800ms (keep badge, dim the text back to theme secondary)
    $t = Get-T
    $resetColor = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($t.TextSecondary))
    $resetTimer = New-Object System.Windows.Threading.DispatcherTimer
    $resetTimer.Interval = [TimeSpan]::FromMilliseconds(800)
    $txtRef = $txt
    $brushRef = $resetColor
    $resetTimer.Add_Tick({
        $this.Stop()
        $txtRef.Foreground = $brushRef
        $txtRef.FontWeight = [System.Windows.FontWeights]::SemiBold
    }.GetNewClosure())
    $resetTimer.Start()
}

function Reset-TabScanBadges {
    # Reset tab headers back to plain text and clear counts
    $script:TabScanCounts = @{}
    foreach ($tabIdx in $script:TabItemIDs.Keys) {
        if ($tabIdx -ge $el['MainTabs'].Items.Count) { continue }
        $tab = $el['MainTabs'].Items[$tabIdx]
        $catName = $tab.Header
        if ($catName -is [System.Windows.Controls.StackPanel]) {
            $tab.Header = $catName.Tag
        }
    }
    Update-TabStyles
}

function Apply-ScanResult([string]$id, [hashtable]$result) {
    $check = $script:AutoChecks[$id]
    # Status values match combo exactly: Pass/Fail/Partial
    $statusText = if ($result.Status -eq 'Pass' -or $result.Status -eq 'Fail' -or $result.Status -eq 'Partial') { $result.Status } else { 'Not Assessed' }

    if ($script:StatusCombos.Contains($id)) {
        $combo = $script:StatusCombos[$id]
        for ($i=0; $i -lt $combo.Items.Count; $i++) {
            if ($combo.Items[$i] -eq $statusText) { $combo.SelectedIndex = $i; break }
        }
    }
    if ($result.Findings -and $script:FindingsBoxes.Contains($id)) { $script:FindingsBoxes[$id].Text = $result.Findings }
    if ($result.Evidence -and $script:EvidenceBoxes.Contains($id)) { $script:EvidenceBoxes[$id].Text = $result.Evidence }

    $script:ScanTimestamps[$id] = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # Auto-check the checkbox so progress updates and item shows as reviewed
    if ($script:CheckBoxes.Contains($id)) {
        $script:SuppressAdvance = $true  # Don't auto-advance during batch scans
        $script:CheckBoxes[$id].IsChecked = $true
        $script:SuppressAdvance = $false
    }
    $script:CheckStates[$id] = $true
    Update-Progress

    # Flash the tab header for this check's category
    Flash-TabForCheck $id $result.Status

    if ($script:ScanButtons.Contains($id)) {
        $btn = $script:ScanButtons[$id]
        $resultIcon = switch ($result.Status) { 'Pass' { 'OK' } 'Fail' { 'FAIL' } 'Partial' { '~' } default { '?' } }
        $btn.Content = "$resultIcon"
        $btn.ToolTip = "Last: $($script:ScanTimestamps[$id]) | $statusText - Click to re-scan"
        switch ($result.Status) {
            'Pass'    { Apply-ButtonTheme $btn '#16a34a' '#22c55e' }
            'Fail'    { Apply-ButtonTheme $btn '#dc2626' '#ef4444' }
            'Partial' { Apply-ButtonTheme $btn '#eab308' '#facc15' }
        }
    }

    # Flash the item card border to show data was populated
    if ($script:ItemCards.Contains($id)) {
        $card = $script:ItemCards[$id]
        $flashColor = switch ($result.Status) { 'Pass' {'#22c55e'} 'Fail' {'#ef4444'} 'Partial' {'#eab308'} default {'#0ea5e9'} }
        $card.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($flashColor))
        $card.BorderThickness = [System.Windows.Thickness]::new(2)
        # Pre-compute reset brush (avoid Get-T/New-Brush in closure)
        $t2 = Get-T
        $resetBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($t2.BorderDim))
        $cardRef = $card
        $brushRef = $resetBrush
        $resetTimer = New-Object System.Windows.Threading.DispatcherTimer
        $resetTimer.Interval = [TimeSpan]::FromMilliseconds(1500)
        $resetTimer.Add_Tick({
            $this.Stop()
            $cardRef.BorderBrush = $brushRef
            $cardRef.BorderThickness = [System.Windows.Thickness]::new(1)
        }.GetNewClosure())
        $resetTimer.Start()
    }

    $levelTag = switch ($result.Status) { 'Pass' {'PASS'} 'Fail' {'FAIL'} 'Partial' {'WARN'} default {'INFO'} }
    $elapsed = ''
    if ($script:CurrentScanStopwatch) { $elapsed = " ($([math]::Round($script:CurrentScanStopwatch.Elapsed.TotalSeconds, 1))s)" }
    $findingsPreview = ''
    if ($result.Findings) {
        $firstLine = ($result.Findings -split "`n")[0].Trim()
        if ($firstLine.Length -gt 80) { $firstLine = $firstLine.Substring(0, 77) + '...' }
        $findingsPreview = " | $firstLine"
    }
    Write-Log "[$id] $($result.Status): $($check.Label)${elapsed}${findingsPreview}" $levelTag
}

function Apply-ScanError([string]$id, [string]$errMsg) {
    if ($script:FindingsBoxes.Contains($id)) { $script:FindingsBoxes[$id].Text = "SCAN ERROR: $errMsg" }
    if ($script:EvidenceBoxes.Contains($id)) { $script:EvidenceBoxes[$id].Text = "Error during auto-check @ $(Get-Date -f 'yyyy-MM-dd HH:mm')" }
    $script:ScanTimestamps[$id] = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    if ($script:ScanButtons.Contains($id)) {
        $script:ScanButtons[$id].Content = "ERR"
        $script:ScanButtons[$id].ToolTip = "Error: $errMsg - Click to retry"
        Apply-ButtonTheme $script:ScanButtons[$id] '#dc2626' '#ef4444'
    }
    # Flash tab badge with error
    Flash-TabForCheck $id 'Error'
    $elapsed = ''
    if ($script:CurrentScanStopwatch) { $elapsed = " ($([math]::Round($script:CurrentScanStopwatch.Elapsed.TotalSeconds, 1))s)" }
    Write-Log "[$id] ERROR: $errMsg${elapsed}" 'ERROR'
}

function Start-AsyncCheck([string]$id) {
    if (-not $script:AutoChecks.Contains($id)) { return }
    $check = $script:AutoChecks[$id]
    $target = $el['txtScanTarget'].Text
    $isLocal = ($target -eq 'localhost' -or $target -eq '127.0.0.1' -or $target -eq $env:COMPUTERNAME)

    $script:CurrentScanId = $id
    $script:CurrentScanStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $script:CurrentScanHeartbeat = 0  # tracks last heartbeat second

    $progressPrefix = if ($script:ScanBatchMode -eq 'Batch') { "[$($script:ScanBatchDone)/$($script:ScanBatchTotal)] " } else { "" }
    $el['StatusText'].Text = "${progressPrefix}Scanning [$id] $($check.Label)..."
    Write-Log "${progressPrefix}[$id] Starting: $($check.Label) (Type=$($check.Type), Target=$target)"

    # Build the wrapper scriptblock that runs in a FRESH runspace per check.
    # A shared runspace stalls because it stays "Busy" between sequential invocations.
    $ps = [PowerShell]::Create()
    if ($script:ScanISS) {
        $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($script:ScanISS)
        $rs.Open()
        $ps.Runspace = $rs
    }
    # CRITICAL: Pass scriptblock as STRING to break runspace affinity.
    # Scriptblocks carry a reference to their creation runspace (the UI thread).
    # Invoking them in another runspace via & $sb deadlocks because they try
    # to marshal back to the UI dispatcher. Converting to string and recreating
    # with [scriptblock]::Create() produces a runspace-neutral block.
    $checkScriptText = $check.Script.ToString()
    $ps.AddScript({
        param($CheckScriptText, $CheckType, $Target, $IsLocal, $Credential)
        try {
            $CheckScript = [scriptblock]::Create($CheckScriptText)
            $result = $null
            if ($CheckType -eq 'Local' -and $IsLocal) {
                $result = & $CheckScript
            }
            elseif ($CheckType -eq 'AD') {
                if (-not (Get-Module ActiveDirectory -ListAvailable -EA SilentlyContinue)) {
                    $result = @{ Status='Fail'; Findings="ActiveDirectory module not available.`nInstall RSAT or run from a domain controller."; Evidence="Module check @ $(Get-Date -f 'yyyy-MM-dd HH:mm')" }
                } else {
                    $result = & $CheckScript
                }
            }
            elseif ($CheckType -eq 'Local' -and -not $IsLocal) {
                $params = @{ ComputerName = $Target; ScriptBlock = $CheckScript; ErrorAction = 'Stop' }
                if ($Credential) { $params.Credential = $Credential }
                $result = Invoke-Command @params
            }
            else { $result = & $CheckScript }
            return @{ Success=$true; Result=$result }
        }
        catch {
            return @{ Success=$false; ErrorMessage=$_.Exception.Message }
        }
    }).AddArgument($checkScriptText).AddArgument($check.Type).AddArgument($target).AddArgument($isLocal).AddArgument($script:ScanCredential) | Out-Null

    $script:CurrentPS = $ps
    $script:CurrentAsyncResult = $ps.BeginInvoke()
}

function Complete-CurrentScan {
    if (-not $script:CurrentPS -or -not $script:CurrentAsyncResult) { return }

    $id = $script:CurrentScanId
    try {
        $output = $script:CurrentPS.EndInvoke($script:CurrentAsyncResult)
        if ($output -and $output.Count -gt 0) {
            $data = $output[0]
            if ($data.Success -and $data.Result) {
                Apply-ScanResult $id $data.Result
                # Update running tally
                if ($script:ScanBatchTally) {
                    $st = $data.Result.Status
                    if ($script:ScanBatchTally.Contains($st)) { $script:ScanBatchTally[$st]++ }
                }
                $progressPrefix = if ($script:ScanBatchMode -eq 'Batch') { "[$($script:ScanBatchDone)/$($script:ScanBatchTotal)] " } else { "" }
                $el['StatusText'].Text = "${progressPrefix}[$id] $($data.Result.Status): $($script:AutoChecks[$id].Label)"
            } elseif (-not $data.Success) {
                Apply-ScanError $id $data.ErrorMessage
                if ($script:ScanBatchTally) { $script:ScanBatchTally.Error++ }
                $el['StatusText'].Text = "[$id] Error: $($data.ErrorMessage)"
            }
        }
    }
    catch {
        Apply-ScanError $id $_.Exception.Message
        if ($script:ScanBatchTally) { $script:ScanBatchTally.Error++ }
    }
    finally {
        if ($script:CurrentScanStopwatch) { $script:CurrentScanStopwatch.Stop() }
        # Close per-check runspace before disposing the PS instance
        try {
            $rs = $script:CurrentPS.Runspace
            if ($rs -and $rs.RunspaceStateInfo.State -eq 'Opened') { $rs.Close() }
            $rs.Dispose()
        } catch {}
        $script:CurrentPS.Dispose()
        $script:CurrentPS = $null
        $script:CurrentAsyncResult = $null
        $script:CurrentScanId = $null
    }
}

function Process-ScanQueue {
    # Called by timer - process next item if queue has items
    if ($script:ScanQueue.Count -gt 0) {
        $nextId = $script:ScanQueue.Dequeue()
        $script:ScanBatchDone++
        $el['lblScanProgress'].Text = "$($script:ScanBatchDone) / $($script:ScanBatchTotal)"
        Start-AsyncCheck $nextId
    }
    else {
        # Queue empty - batch complete
        $script:ScanRunning = $false
        $el['btnFullAudit'].IsEnabled = $true
        $el['btnScanAll'].IsEnabled = $true; $el['btnScanAD'].IsEnabled = $true; $el['btnScanLocal'].IsEnabled = $true
        $el['btnPreflight'].IsEnabled = $true
        foreach ($sbtn in $script:ScanButtons.Values) { $sbtn.IsEnabled = $true }

        if ($script:ScanBatchMode -eq 'Batch') {
            $batchElapsed = ''
            if ($script:ScanBatchStopwatch) {
                $script:ScanBatchStopwatch.Stop()
                $totalSecs = [math]::Round($script:ScanBatchStopwatch.Elapsed.TotalSeconds, 1)
                $batchElapsed = if ($totalSecs -ge 60) { " in $([math]::Floor($totalSecs / 60))m $([math]::Round($totalSecs % 60))s" } else { " in ${totalSecs}s" }
            }
            $t = $script:ScanBatchTally
            $tally = "Pass:$($t.Pass) Fail:$($t.Fail) Warn:$($t.Partial) Err:$($t.Error)"
            Write-Log "=== SCAN COMPLETE: $($script:ScanBatchTotal) checks${batchElapsed} | $tally ===" 'INFO'
            $el['StatusText'].Text = "Scan complete: $($script:ScanBatchTotal) checks${batchElapsed} | $tally"
        }
        elseif ($script:ScanBatchMode -eq 'Single') {
            # Single scan done - no extra messaging needed
        }
        $el['lblScanProgress'].Text = "Done"
        $script:ScanBatchMode = $null

        # Auto-export HTML report after every batch scan
        if ($script:ScanBatchTotal -gt 1) {
            Update-Progress
            if ($script:FullAuditMode) {
                # Full Audit: auto-export + auto-save, no prompt
                Write-Log "Full Audit: auto-exporting results..." 'INFO'
                $exportPath = Invoke-AutoExport
                Invoke-AutoSave
                $script:FullAuditMode = $false
                $script:TurnkeyAutoScan = $false
                Write-Log "=== FULL AUDIT COMPLETE ===" 'INFO'
            }
            else {
                Write-Log "Auto-exporting HTML report..." 'INFO'
                Invoke-AutoExport
                $script:TurnkeyAutoScan = $false
            }
        }
    }
}

function Start-ScanBatch([string]$filterType) {
    $ids = $script:AutoChecks.Keys | Sort-Object

    # Reset tab scan badges from prior runs
    Reset-TabScanBadges

    # Apply profile-based filtering
    if ($filterType -eq 'AD') {
        $ids = $ids | Where-Object { $script:AutoChecks[$_].Type -eq 'AD' }
    }
    elseif ($filterType -eq 'Local') {
        $ids = $ids | Where-Object { $script:AutoChecks[$_].Type -eq 'Local' }
    }
    elseif ($filterType -eq 'Profile') {
        # Get selected profile from ComboBox
        $profileOrder = @('Quick','Standard','Full','ADOnly','LocalOnly','HIPAA','PCI','CMMC','SOC2','ISO27001')
        $selIdx = $el['cboProfile'].SelectedIndex
        if ($selIdx -lt 0) { $selIdx = 2 }
        $profName = $profileOrder[$selIdx]
        $prof = $script:ScanProfiles[$profName]

        if ($profName -eq 'ADOnly') {
            $ids = $ids | Where-Object { $script:AutoChecks[$_].Type -eq 'AD' }
        }
        elseif ($profName -eq 'LocalOnly') {
            $ids = $ids | Where-Object { $script:AutoChecks[$_].Type -eq 'Local' }
        }
        elseif ($prof.IDs.Count -gt 0) {
            $profileSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($pid in $prof.IDs) { $profileSet.Add($pid) | Out-Null }
            $ids = $ids | Where-Object { $profileSet.Contains($_) -and $script:AutoCheckIDs.Contains($_) }
        }
        # Full profile = all checks (no filter)
        Write-Log "Scan profile: $profName ($($prof.Label))" 'INFO'
    }

    # Risk tier filtering in read-only mode
    if ($script:ReadOnlyMode) {
        $preCount = @($ids).Count
        $ids = $ids | Where-Object {
            $tier = if ($script:RiskTiers.Contains($_)) { $script:RiskTiers[$_] } else { 0 }
            $tier -le 2  # Skip Tier 3 (modifying) checks in read-only mode
        }
        $postCount = @($ids).Count
        if ($preCount -ne $postCount) {
            Write-Log "Read-only mode: skipped $($preCount - $postCount) modifying checks (Tier 3)" 'WARN'
        }
    }

    $idList = @($ids)
    if ($idList.Count -eq 0) {
        Write-Log "No checks available for this profile/filter combination" 'WARN'
        $el['StatusText'].Text = "No checks available for selected profile"
        return
    }

    Write-Log "Starting scan batch: $filterType ($($idList.Count) checks)" 'INFO'

    $script:ScanRunning = $true
    $script:ScanBatchMode = 'Batch'
    $script:ScanBatchTotal = $idList.Count
    $script:ScanBatchDone = 0
    $script:ScanBatchStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $script:ScanBatchTally = @{ Pass=0; Fail=0; Partial=0; Error=0 }
    $el['btnFullAudit'].IsEnabled = $false
    $el['btnScanAll'].IsEnabled = $false; $el['btnScanAD'].IsEnabled = $false; $el['btnScanLocal'].IsEnabled = $false
    $el['btnPreflight'].IsEnabled = $false
    foreach ($sbtn in $script:ScanButtons.Values) { $sbtn.IsEnabled = $false }

    $script:ScanQueue.Clear()
    foreach ($id in $idList) { $script:ScanQueue.Enqueue($id) }

    # Start first check
    Process-ScanQueue
}

function Start-SingleCheck([string]$id) {
    if ($script:ScanRunning) { return }
    $script:ScanRunning = $true
    $script:ScanBatchMode = 'Single'
    $script:ScanBatchTotal = 1
    $script:ScanBatchDone = 0

    $script:ScanQueue.Clear()
    $script:ScanQueue.Enqueue($id)
    Process-ScanQueue
    $script:ScanTimer.Start()
}

# ── Theme Selector ───────────────────────────────────────────────────────────
$themeNames = @('Auto (System)') + ($script:Themes.Keys | Sort-Object)
foreach ($n in $themeNames) { $el['ThemeSelector'].Items.Add($n) | Out-Null }
$el['ThemeSelector'].SelectedIndex = 0

$el['ThemeSelector'].Add_SelectionChanged({
    $s = $el['ThemeSelector'].SelectedItem
    if (-not $s) { return }
    if ($s -eq 'Auto (System)') { $script:CurrentThemeName = if ((Get-SystemTheme) -eq 'Light') { 'Light' } else { 'Midnight' } }
    else { $script:CurrentThemeName = $s }
    Apply-Theme; Update-Progress
    Write-Log "Theme changed: $script:CurrentThemeName"
})

# ── Checkbox Style ───────────────────────────────────────────────────────────
function New-CBStyle {
    $t = Get-T
    $st = New-Object System.Windows.Style ([System.Windows.Controls.CheckBox])
    $st.Setters.Add((New-Object System.Windows.Setter ([System.Windows.Controls.CheckBox]::ForegroundProperty, (New-Brush $t.TextPrimary))))
    $st.Setters.Add((New-Object System.Windows.Setter ([System.Windows.Controls.CheckBox]::FontSizeProperty, 12.5)))
    $st.Setters.Add((New-Object System.Windows.Setter ([System.Windows.Controls.CheckBox]::CursorProperty, [System.Windows.Input.Cursors]::Hand)))

    $tmpl = New-Object System.Windows.Controls.ControlTemplate ([System.Windows.Controls.CheckBox])
    $sp = New-Object System.Windows.FrameworkElementFactory ([System.Windows.Controls.StackPanel])
    $sp.SetValue([System.Windows.Controls.StackPanel]::OrientationProperty, [System.Windows.Controls.Orientation]::Horizontal)

    $bx = New-Object System.Windows.FrameworkElementFactory ([System.Windows.Controls.Border])
    $bx.Name = 'box'; $bx.SetValue([System.Windows.FrameworkElement]::WidthProperty, 18.0)
    $bx.SetValue([System.Windows.FrameworkElement]::HeightProperty, 18.0)
    $bx.SetValue([System.Windows.Controls.Border]::BackgroundProperty, (New-Brush $t.InputBg))
    $bx.SetValue([System.Windows.Controls.Border]::BorderBrushProperty, (New-Brush $t.ThumbBg))
    $bx.SetValue([System.Windows.Controls.Border]::BorderThicknessProperty, [System.Windows.Thickness]::new(1.5))
    $bx.SetValue([System.Windows.Controls.Border]::CornerRadiusProperty, [System.Windows.CornerRadius]::new(3))
    $bx.SetValue([System.Windows.FrameworkElement]::MarginProperty, [System.Windows.Thickness]::new(0,0,8,0))

    $ck = New-Object System.Windows.FrameworkElementFactory ([System.Windows.Shapes.Path])
    $ck.Name = 'ck'; $ck.SetValue([System.Windows.Shapes.Path]::DataProperty, [System.Windows.Media.Geometry]::Parse('M3,7 L7,11 L13,3'))
    $ck.SetValue([System.Windows.Shapes.Shape]::StrokeProperty, (New-Brush $t.CheckedBorder))
    $ck.SetValue([System.Windows.Shapes.Shape]::StrokeThicknessProperty, 2.0)
    $ck.SetValue([System.Windows.UIElement]::VisibilityProperty, [System.Windows.Visibility]::Collapsed)
    $ck.SetValue([System.Windows.FrameworkElement]::HorizontalAlignmentProperty, [System.Windows.HorizontalAlignment]::Center)
    $ck.SetValue([System.Windows.FrameworkElement]::VerticalAlignmentProperty, [System.Windows.VerticalAlignment]::Center)
    $bx.AppendChild($ck); $sp.AppendChild($bx)
    $cpf = New-Object System.Windows.FrameworkElementFactory ([System.Windows.Controls.ContentPresenter])
    $cpf.SetValue([System.Windows.FrameworkElement]::VerticalAlignmentProperty, [System.Windows.VerticalAlignment]::Center)
    $sp.AppendChild($cpf); $tmpl.VisualTree = $sp

    $chk = New-Object System.Windows.Trigger; $chk.Property = [System.Windows.Controls.CheckBox]::IsCheckedProperty; $chk.Value = $true
    $chk.Setters.Add((New-Object System.Windows.Setter ([System.Windows.UIElement]::VisibilityProperty, [System.Windows.Visibility]::Visible, 'ck')))
    $chk.Setters.Add((New-Object System.Windows.Setter ([System.Windows.Controls.Border]::BorderBrushProperty, (New-Brush $t.CheckedBorder), 'box')))
    $chk.Setters.Add((New-Object System.Windows.Setter ([System.Windows.Controls.Border]::BackgroundProperty, (New-Brush $t.CheckedBg), 'box')))
    $tmpl.Triggers.Add($chk)
    $hv = New-Object System.Windows.Trigger; $hv.Property = [System.Windows.Controls.CheckBox]::IsMouseOverProperty; $hv.Value = $true
    $hv.Setters.Add((New-Object System.Windows.Setter ([System.Windows.Controls.Border]::BorderBrushProperty, (New-Brush $t.Accent), 'box')))
    $tmpl.Triggers.Add($hv)
    $st.Setters.Add((New-Object System.Windows.Setter ([System.Windows.Controls.CheckBox]::TemplateProperty, $tmpl)))
    return $st
}
$cbStyle = New-CBStyle

# ── Helper: Add themed label ─────────────────────────────────────────────────
function New-Label([string]$text, [string]$type='TextSec', [double]$size=11) {
    $tb = New-Object System.Windows.Controls.TextBlock
    $tb.Text = $text; $tb.FontSize = $size; $tb.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $script:ThemedElements.Add(@{Type=$type;Element=$tb}) | Out-Null
    return $tb
}

function New-InputBox([bool]$multi=$false, [double]$minH=0) {
    $tb = New-Object System.Windows.Controls.TextBox
    $tb.Padding = [System.Windows.Thickness]::new(6,4,6,4); $tb.FontSize = 11.5
    $tb.AcceptsReturn = $multi; $tb.AcceptsTab = $true
    $tb.TextWrapping = [System.Windows.TextWrapping]::Wrap
    if ($multi) {
        $tb.MinHeight = if ($minH -gt 0) { $minH } else { 48 }
        $tb.MaxHeight = 200; $tb.VerticalScrollBarVisibility = 'Auto'
        $tb.ToolTip = 'Multi-line text. HTML tags are preserved in export.'
    }
    $tb.SpellCheck.IsEnabled = $true
    $script:ThemedElements.Add(@{Type='Input';Element=$tb}) | Out-Null
    return $tb
}

# ── Build Tabs ───────────────────────────────────────────────────────────────

# Collapse/expand/advance helpers
function Collapse-ItemCard([string]$id) {
    $panel = $script:ItemPanels[$id]
    if (-not $panel) { return }
    # Hide everything after the first child (checkbox+badges row)
    for ($i = 1; $i -lt $panel.Children.Count; $i++) {
        $panel.Children[$i].Visibility = [System.Windows.Visibility]::Collapsed
    }
    $card = $script:ItemCards[$id]
    $card.Padding = [System.Windows.Thickness]::new(12,5,12,5)
    $card.Opacity = 0.6
}

function Expand-ItemCard([string]$id) {
    $panel = $script:ItemPanels[$id]
    if (-not $panel) { return }
    for ($i = 1; $i -lt $panel.Children.Count; $i++) {
        $child = $panel.Children[$i]
        # Restore visibility, but keep hint blocks collapsed if they were hidden
        if ($child -eq $script:HintBlocks[$id]) { continue }
        $child.Visibility = [System.Windows.Visibility]::Visible
    }
    $card = $script:ItemCards[$id]
    $card.Padding = [System.Windows.Thickness]::new(12,8,12,8)
    $card.Opacity = 1.0
}

function Highlight-ItemCard([string]$id) {
    $t = Get-T
    # Clear previous highlight
    if ($script:HighlightedCard -and $script:ItemCards.Contains($script:HighlightedCard)) {
        $script:ItemCards[$script:HighlightedCard].BorderBrush = New-Brush $t.BorderDim
        $script:ItemCards[$script:HighlightedCard].BorderThickness = [System.Windows.Thickness]::new(1)
    }
    $card = $script:ItemCards[$id]
    if ($card) {
        $card.BorderBrush = New-Brush $t.Accent
        $card.BorderThickness = [System.Windows.Thickness]::new(2)
        $script:HighlightedCard = $id
        # Scroll into view
        $card.BringIntoView()
    }
}

function Advance-ToNext([string]$currentId) {
    $tabIdx = $script:ItemTabIndex[$currentId]
    $ids = $script:TabItemIDs[$tabIdx]
    $curPos = $ids.IndexOf($currentId)
    $totalTabs = $script:TabIndex  # total number of category tabs

    # Search forward in current tab
    for ($i = $curPos + 1; $i -lt $ids.Count; $i++) {
        $nid = $ids[$i]
        if (-not $script:CheckStates[$nid]) {
            Highlight-ItemCard $nid
            return
        }
    }

    # Current tab complete - find next tab with unchecked items
    for ($t2 = 1; $t2 -lt $totalTabs; $t2++) {
        $nextTab = ($tabIdx + $t2) % $totalTabs
        $nextIds = $script:TabItemIDs[$nextTab]
        foreach ($nid in $nextIds) {
            if (-not $script:CheckStates[$nid]) {
                # Switch to that tab
                $el['MainTabs'].SelectedIndex = $nextTab
                # Use a DispatcherTimer to highlight after tab renders
                $capturedId = $nid
                $timer = New-Object System.Windows.Threading.DispatcherTimer
                $timer.Interval = [TimeSpan]::FromMilliseconds(80)
                $timer.Tag = $capturedId
                $timer.Add_Tick({
                    $this.Stop()
                    Highlight-ItemCard $this.Tag
                })
                $timer.Start()
                return
            }
        }
    }
    # All items in all tabs checked
    $el['StatusText'].Text = "All items completed!"
}

foreach ($catName in $script:AuditCategories.Keys) {
    $cat = $script:AuditCategories[$catName]
    $catColor = $script:CategoryAccents[$catName]

    $tab = New-Object System.Windows.Controls.TabItem; $tab.Header = $catName
    $sv = New-Object System.Windows.Controls.ScrollViewer; $sv.VerticalScrollBarVisibility = 'Auto'; $sv.Padding = [System.Windows.Thickness]::new(6)
    $stack = New-Object System.Windows.Controls.StackPanel
    $script:TabScrollViews[$script:TabIndex] = $sv
    $script:TabItemIDs[$script:TabIndex] = [System.Collections.ArrayList]@()

    # Category header
    $hdr = New-Object System.Windows.Controls.Border
    $hdr.CornerRadius=[System.Windows.CornerRadius]::new(6); $hdr.Padding=[System.Windows.Thickness]::new(14,10,14,10)
    $hdr.Margin=[System.Windows.Thickness]::new(0,2,0,10); $hdr.BorderBrush=New-Brush $catColor; $hdr.BorderThickness=[System.Windows.Thickness]::new(1)
    $script:ThemedElements.Add(@{Type='CatHeader';Element=$hdr}) | Out-Null

    $hdrG = New-Object System.Windows.Controls.Grid
    $c1 = New-Object System.Windows.Controls.ColumnDefinition; $c1.Width=[System.Windows.GridLength]::new(1,[System.Windows.GridUnitType]::Star)
    $c2 = New-Object System.Windows.Controls.ColumnDefinition; $c2.Width=[System.Windows.GridLength]::new(0,[System.Windows.GridUnitType]::Auto)
    $hdrG.ColumnDefinitions.Add($c1); $hdrG.ColumnDefinitions.Add($c2)

    $ls = New-Object System.Windows.Controls.StackPanel; [System.Windows.Controls.Grid]::SetColumn($ls,0)
    $ct = New-Object System.Windows.Controls.TextBlock; $ct.Text=$catName; $ct.FontSize=15; $ct.FontWeight=[System.Windows.FontWeights]::Bold; $ct.Foreground=New-Brush $catColor
    $ls.Children.Add($ct)|Out-Null
    $cd = New-Object System.Windows.Controls.TextBlock; $cd.Text=$cat.Desc; $cd.FontSize=11.5; $cd.Margin=[System.Windows.Thickness]::new(0,2,0,0)
    $script:ThemedElements.Add(@{Type='TextSec';Element=$cd})|Out-Null; $ls.Children.Add($cd)|Out-Null

    $rs = New-Object System.Windows.Controls.StackPanel; $rs.VerticalAlignment=[System.Windows.VerticalAlignment]::Center; [System.Windows.Controls.Grid]::SetColumn($rs,1)
    $bg = New-Object System.Windows.Controls.Grid; $bg.Height=8; $bg.Width=140
    $bgb = New-Object System.Windows.Controls.Border; $bgb.CornerRadius=[System.Windows.CornerRadius]::new(3); $script:ThemedElements.Add(@{Type='BarBg';Element=$bgb})|Out-Null
    $bfb = New-Object System.Windows.Controls.Border; $bfb.Background=New-Brush $catColor; $bfb.CornerRadius=[System.Windows.CornerRadius]::new(3); $bfb.HorizontalAlignment=[System.Windows.HorizontalAlignment]::Left; $bfb.Width=0
    $bg.Children.Add($bgb)|Out-Null; $bg.Children.Add($bfb)|Out-Null; $rs.Children.Add($bg)|Out-Null
    $cpt = New-Object System.Windows.Controls.TextBlock; $cpt.Text="0/$($cat.Items.Count)"; $cpt.FontSize=11; $cpt.FontWeight=[System.Windows.FontWeights]::SemiBold
    $cpt.Foreground=New-Brush $catColor; $cpt.Margin=[System.Windows.Thickness]::new(0,3,0,0); $cpt.HorizontalAlignment=[System.Windows.HorizontalAlignment]::Right
    $rs.Children.Add($cpt)|Out-Null
    $hdrG.Children.Add($ls)|Out-Null; $hdrG.Children.Add($rs)|Out-Null; $hdr.Child=$hdrG; $stack.Children.Add($hdr)|Out-Null
    $script:CategoryProgress[$catName] = @{Total=$cat.Items.Count;TextBlock=$cpt;Bar=$bfb;BarMax=140}

    # Items
    foreach ($item in $cat.Items) {
        $script:TotalItems++; $script:CheckStates[$item.ID] = $false

        $ib = New-Object System.Windows.Controls.Border; $ib.CornerRadius=[System.Windows.CornerRadius]::new(5)
        $ib.Padding=[System.Windows.Thickness]::new(12,8,12,8); $ib.Margin=[System.Windows.Thickness]::new(0,0,0,5)
        $ib.BorderThickness=[System.Windows.Thickness]::new(1)
        $script:ThemedElements.Add(@{Type='Card';Element=$ib})|Out-Null

        $is = New-Object System.Windows.Controls.StackPanel

        # Track for collapse/advance
        $script:ItemCards[$item.ID] = $ib
        $script:ItemPanels[$item.ID] = $is
        $script:ItemTabIndex[$item.ID] = $script:TabIndex
        $script:TabItemIDs[$script:TabIndex].Add($item.ID) | Out-Null

        # Row 1: Checkbox + badges
        $r1 = New-Object System.Windows.Controls.Grid
        $r1c1 = New-Object System.Windows.Controls.ColumnDefinition; $r1c1.Width=[System.Windows.GridLength]::new(1,[System.Windows.GridUnitType]::Star)
        $r1c2 = New-Object System.Windows.Controls.ColumnDefinition; $r1c2.Width=[System.Windows.GridLength]::new(0,[System.Windows.GridUnitType]::Auto)
        $r1.ColumnDefinitions.Add($r1c1); $r1.ColumnDefinitions.Add($r1c2)

        $cb = New-Object System.Windows.Controls.CheckBox; $cb.Content="[$($item.ID)] $($item.Text)"; $cb.Style=$cbStyle; $cb.Tag=$item.ID
        [System.Windows.Controls.Grid]::SetColumn($cb,0); $r1.Children.Add($cb)|Out-Null; $script:CheckBoxes[$item.ID]=$cb
        $cb.Add_Checked({
            $id = $this.Tag
            $script:CheckStates[$id] = $true
            Update-Progress
            if (-not $script:ScanRunning) { Collapse-ItemCard $id }
            if (-not $script:SuppressAdvance) { Advance-ToNext $id }
        })
        $cb.Add_Unchecked({
            $id = $this.Tag
            $script:CheckStates[$id] = $false
            Update-Progress
            Expand-ItemCard $id
            Highlight-ItemCard $id
        })

        # Badge panel
        $bp = New-Object System.Windows.Controls.StackPanel; $bp.Orientation=[System.Windows.Controls.Orientation]::Horizontal
        [System.Windows.Controls.Grid]::SetColumn($bp,1)

        $wb = New-Object System.Windows.Controls.Border; $wb.Background=New-Brush '#334155'; $wb.CornerRadius=[System.Windows.CornerRadius]::new(8)
        $wb.Padding=[System.Windows.Thickness]::new(6,1,6,1); $wb.Margin=[System.Windows.Thickness]::new(4,0,4,0)
        $wt = New-Object System.Windows.Controls.TextBlock; $wt.Text="W:$($item.Weight)"; $wt.FontSize=10; $wt.Foreground=New-Brush '#94a3b8'; $wb.Child=$wt
        $bp.Children.Add($wb)|Out-Null

        $sevClr = $script:SeverityColors[$item.Severity]
        $sb = New-Object System.Windows.Controls.Border; $sb.Background=New-Brush $sevClr; $sb.CornerRadius=[System.Windows.CornerRadius]::new(8)
        $sb.Padding=[System.Windows.Thickness]::new(8,1,8,1); $sb.Opacity=0.9
        $stx = New-Object System.Windows.Controls.TextBlock; $stx.Text=$item.Severity; $stx.FontSize=10.5; $stx.FontWeight=[System.Windows.FontWeights]::Bold; $stx.Foreground=[System.Windows.Media.Brushes]::White
        $sb.Child=$stx; $bp.Children.Add($sb)|Out-Null

        # Per-item scan button (only for items with auto-checks)
        if ($script:AutoCheckIDs.Contains($item.ID)) {
            $scanBtn = New-Object System.Windows.Controls.Button
            $scanBtn.Content = "Scan"
            $scanBtn.FontSize = 9.5; $scanBtn.FontWeight = [System.Windows.FontWeights]::SemiBold
            $scanBtn.Padding = [System.Windows.Thickness]::new(8,1,8,1)
            $scanBtn.Margin = [System.Windows.Thickness]::new(6,0,0,0)
            $scanBtn.Cursor = [System.Windows.Input.Cursors]::Hand
            $scanBtn.Tag = $item.ID
            $scanBtn.ToolTip = "$($script:AutoChecks[$item.ID].Label) ($($script:AutoChecks[$item.ID].Type))"
            Apply-ButtonTheme $scanBtn '#0ea5e9' '#38bdf8'
            $scanBtn.Add_Click({
                $sid = $this.Tag
                if (-not $script:ScanRunning) { Start-SingleCheck $sid }
            })
            $bp.Children.Add($scanBtn) | Out-Null
            $script:ScanButtons[$item.ID] = $scanBtn
        }

        $r1.Children.Add($bp)|Out-Null
        $is.Children.Add($r1)|Out-Null

        # Compliance tags
        if ($item.Compliance) {
            $compTb = New-Object System.Windows.Controls.TextBlock; $compTb.Text=$item.Compliance; $compTb.FontSize=10; $compTb.FontStyle=[System.Windows.FontStyles]::Italic
            $compTb.Margin=[System.Windows.Thickness]::new(26,2,0,2); $compTb.TextWrapping=[System.Windows.TextWrapping]::Wrap
            $script:ThemedElements.Add(@{Type='TextSec';Element=$compTb})|Out-Null; $is.Children.Add($compTb)|Out-Null
        }

        # Hint/Guidance (collapsible)
        $hintBorder = New-Object System.Windows.Controls.Border; $hintBorder.CornerRadius=[System.Windows.CornerRadius]::new(4)
        $hintBorder.Padding=[System.Windows.Thickness]::new(10,6,10,6); $hintBorder.Margin=[System.Windows.Thickness]::new(26,4,0,4)
        $hintBorder.BorderThickness=[System.Windows.Thickness]::new(1); $hintBorder.Visibility=[System.Windows.Visibility]::Collapsed
        $script:ThemedElements.Add(@{Type='Hint';Element=$hintBorder})|Out-Null

        $hintTb = New-Object System.Windows.Controls.TextBlock; $hintTb.Text=$item.Hint; $hintTb.FontSize=11; $hintTb.TextWrapping=[System.Windows.TextWrapping]::Wrap
        $script:ThemedElements.Add(@{Type='HintText';Element=$hintTb})|Out-Null
        $hintBorder.Child = $hintTb; $is.Children.Add($hintBorder)|Out-Null
        $script:HintBlocks[$item.ID] = $hintBorder

        # Toggle hint button
        $hintBtn = New-Object System.Windows.Controls.TextBlock; $hintBtn.Text="[?] Show Guidance"; $hintBtn.FontSize=10.5; $hintBtn.Cursor=[System.Windows.Input.Cursors]::Hand
        $hintBtn.Margin=[System.Windows.Thickness]::new(26,0,0,2); $hintBtn.Foreground=New-Brush '#0ea5e9'
        $hintBtn.Tag = $item.ID
        $hintBtn.Add_MouseLeftButtonDown({
            $id = $this.Tag
            $hb = $script:HintBlocks[$id]
            if ($hb.Visibility -eq [System.Windows.Visibility]::Collapsed) {
                $hb.Visibility = [System.Windows.Visibility]::Visible; $this.Text = "[-] Hide Guidance"
            } else {
                $hb.Visibility = [System.Windows.Visibility]::Collapsed; $this.Text = "[?] Show Guidance"
            }
        })
        $is.Children.Add($hintBtn)|Out-Null

        # Fields: stacked full-width layout for usability
        $fg = New-Object System.Windows.Controls.StackPanel; $fg.Margin=[System.Windows.Thickness]::new(26,6,0,0)

        # Row 0: Status + Rem Status combos side by side, left-aligned
        $comboRow = New-Object System.Windows.Controls.StackPanel; $comboRow.Orientation=[System.Windows.Controls.Orientation]::Horizontal
        $comboRow.Margin=[System.Windows.Thickness]::new(0,0,0,6)

        $slbl = New-Label 'Status:'; $slbl.Margin=[System.Windows.Thickness]::new(0,0,6,0); $comboRow.Children.Add($slbl)|Out-Null
        $scb = New-Object System.Windows.Controls.ComboBox; $scb.Width=130; $scb.Height=26; $scb.FontSize=11
        $scb.HorizontalAlignment=[System.Windows.HorizontalAlignment]::Left
        foreach ($sOpt in @('Not Assessed','Pass','Fail','Partial','N/A')) { $scb.Items.Add($sOpt)|Out-Null }; $scb.SelectedIndex=0
        $comboRow.Children.Add($scb)|Out-Null
        $script:StatusCombos[$item.ID] = $scb
        $script:AllCombos.Add($scb) | Out-Null

        $rsLbl = New-Label 'Rem Status:'; $rsLbl.Margin=[System.Windows.Thickness]::new(18,0,6,0); $comboRow.Children.Add($rsLbl)|Out-Null
        $rsCb = New-Object System.Windows.Controls.ComboBox; $rsCb.Width=150; $rsCb.Height=26; $rsCb.FontSize=11
        $rsCb.HorizontalAlignment=[System.Windows.HorizontalAlignment]::Left
        foreach ($rs2 in @('Open','In Progress','Remediated','Accepted Risk','Deferred')) { $rsCb.Items.Add($rs2)|Out-Null }; $rsCb.SelectedIndex=0
        $comboRow.Children.Add($rsCb)|Out-Null
        $script:RemStatusCombos[$item.ID] = $rsCb
        $script:AllCombos.Add($rsCb) | Out-Null

        # Remediation: Assign + Due on same row as combos
        $raLbl = New-Label 'Assign:' 'TextSec' 10.5; $raLbl.Margin=[System.Windows.Thickness]::new(18,0,4,0); $comboRow.Children.Add($raLbl)|Out-Null
        $raBox = New-InputBox; $raBox.Width=120; $raBox.Height=26; $comboRow.Children.Add($raBox)|Out-Null; $script:RemAssignBoxes[$item.ID]=$raBox
        $rdLbl = New-Label 'Due:' 'TextSec' 10.5; $rdLbl.Margin=[System.Windows.Thickness]::new(10,0,4,0); $comboRow.Children.Add($rdLbl)|Out-Null
        $rdBox = New-InputBox; $rdBox.Width=100; $rdBox.Height=26; $comboRow.Children.Add($rdBox)|Out-Null; $script:RemDueBoxes[$item.ID]=$rdBox

        $fg.Children.Add($comboRow)|Out-Null

        # Notes: full-width multi-line
        $nlbl = New-Label 'Notes:' 'TextSec' 10.5; $nlbl.Margin=[System.Windows.Thickness]::new(0,0,0,2)
        $fg.Children.Add($nlbl)|Out-Null
        $nbox = New-InputBox $true 40; $nbox.Margin=[System.Windows.Thickness]::new(0,0,10,4)
        $fg.Children.Add($nbox)|Out-Null
        $script:NotesBoxes[$item.ID] = $nbox

        # Findings: full-width multi-line
        $flbl = New-Label 'Findings:' 'TextSec' 10.5; $flbl.Margin=[System.Windows.Thickness]::new(0,0,0,2)
        $fg.Children.Add($flbl)|Out-Null
        $fbox = New-InputBox $true 48; $fbox.Margin=[System.Windows.Thickness]::new(0,0,10,4)
        $fg.Children.Add($fbox)|Out-Null
        $script:FindingsBoxes[$item.ID] = $fbox

        # Evidence: full-width multi-line
        $elbl = New-Label 'Evidence:' 'TextSec' 10.5; $elbl.Margin=[System.Windows.Thickness]::new(0,0,0,2)
        $fg.Children.Add($elbl)|Out-Null
        $ebox = New-InputBox $true 48; $ebox.Margin=[System.Windows.Thickness]::new(0,0,10,0)
        $fg.Children.Add($ebox)|Out-Null
        $script:EvidenceBoxes[$item.ID] = $ebox

        $is.Children.Add($fg)|Out-Null; $ib.Child=$is; $stack.Children.Add($ib)|Out-Null
    }

    $sv.Content=$stack; $tab.Content=$sv; $el['MainTabs'].Items.Add($tab)|Out-Null
    $script:TabIndex++
}

# ── Executive Summary Tab ────────────────────────────────────────────────────
$exTab = New-Object System.Windows.Controls.TabItem; $exTab.Header = "Executive Summary"
$exSv = New-Object System.Windows.Controls.ScrollViewer; $exSv.VerticalScrollBarVisibility = 'Auto'; $exSv.Padding = [System.Windows.Thickness]::new(12)
$exStack = New-Object System.Windows.Controls.StackPanel
$script:ExSummaryText = New-Object System.Windows.Controls.TextBlock
$script:ExSummaryText.TextWrapping = [System.Windows.TextWrapping]::Wrap; $script:ExSummaryText.FontSize = 13
$script:ThemedElements.Add(@{Type='TextPri';Element=$script:ExSummaryText})|Out-Null
$script:exRefreshBtn = New-Object System.Windows.Controls.Button; $script:exRefreshBtn.Content = "Refresh Summary"; $script:exRefreshBtn.Margin=[System.Windows.Thickness]::new(0,0,0,12)
$script:exRefreshBtn.Padding = [System.Windows.Thickness]::new(14,6,14,6); $script:exRefreshBtn.FontSize=12; $script:exRefreshBtn.FontWeight=[System.Windows.FontWeights]::SemiBold; $script:exRefreshBtn.Cursor=[System.Windows.Input.Cursors]::Hand
$exStack.Children.Add($script:exRefreshBtn)|Out-Null; $exStack.Children.Add($script:ExSummaryText)|Out-Null
$exSv.Content=$exStack; $exTab.Content=$exSv; $el['MainTabs'].Items.Add($exTab)|Out-Null

# ── Risk Score + Progress ────────────────────────────────────────────────────
function Get-RiskScore {
    $maxS=0; $earn=0
    foreach ($cn in $script:AuditCategories.Keys) {
        foreach ($it in $script:AuditCategories[$cn].Items) {
            $maxS += $it.Weight
            $st = if ($script:StatusCombos[$it.ID].SelectedItem) { $script:StatusCombos[$it.ID].SelectedItem.ToString() } else { 'Not Assessed' }
            switch ($st) { 'Pass'{$earn+=$it.Weight} 'Partial'{$earn+=[math]::Floor($it.Weight*0.5)} 'N/A'{$maxS-=$it.Weight} }
        }
    }
    if ($maxS -le 0) { return @{Score=0;Max=0;Pct=0;Grade='N/A'} }
    $p=[math]::Round(($earn/$maxS)*100)
    $g = switch($true) { ($p -ge 90){'A'} ($p -ge 80){'B'} ($p -ge 70){'C'} ($p -ge 60){'D'} default{'F'} }
    @{Score=$earn;Max=$maxS;Pct=$p;Grade=$g}
}

function Update-Progress {
    $t = Get-T; $ck=($script:CheckStates.Values|Where-Object{$_}).Count; $tot=$script:TotalItems
    if ($tot -gt 0) {
        $p=[math]::Round(($ck/$tot)*100); $el['ProgBarFill'].Width=[math]::Round(($ck/$tot)*180)
        $el['ProgText'].Text="$ck/$tot ($p%)"
        $c=if($p -ge 75){$t.ProgressGood}elseif($p -ge 40){$t.ProgressMid}else{'#ef4444'}
        $el['ProgText'].Foreground=New-Brush $c; $el['ProgBarFill'].Background=New-Brush $c
    }
    foreach ($cn in $script:CategoryProgress.Keys) {
        $inf=$script:CategoryProgress[$cn]; $cc=0
        foreach ($it in $script:AuditCategories[$cn].Items) { if ($script:CheckStates[$it.ID]) { $cc++ } }
        $cp2=if($inf.Total -gt 0){[math]::Round(($cc/$inf.Total)*100)}else{0}
        $inf.TextBlock.Text="$cc/$($inf.Total) ($cp2%)"
        if ($inf.Total -gt 0) { $inf.Bar.Width=[math]::Round(($cc/$inf.Total)*$inf.BarMax) }
    }
    $r=Get-RiskScore; $el['ScoreText'].Text="Score: $($r.Score)/$($r.Max) ($($r.Pct)%) Grade: $($r.Grade)"
}

# ── Executive Summary Generator ──────────────────────────────────────────────
function Update-ExecSummary {
    $risk = Get-RiskScore
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("EXECUTIVE SUMMARY")
    [void]$sb.AppendLine("=" * 60)
    [void]$sb.AppendLine("Client: $($el['txtClient'].Text)     Auditor: $($el['txtAuditor'].Text)     Date: $($el['txtDate'].Text)")
    [void]$sb.AppendLine("Overall Risk Score: $($risk.Score)/$($risk.Max) ($($risk.Pct)%) - Grade: $($risk.Grade)")
    [void]$sb.AppendLine("")

    # Count by status
    $pass=0;$fail=0;$partial=0;$na=0;$notA=0
    foreach ($id in $script:CheckStates.Keys) {
        $sv = if ($script:StatusCombos[$id].SelectedItem) { $script:StatusCombos[$id].SelectedItem.ToString() } else { 'Not Assessed' }
        switch ($sv) { 'Pass'{$pass++} 'Fail'{$fail++} 'Partial'{$partial++} 'N/A'{$na++} default{$notA++} }
    }
    [void]$sb.AppendLine("STATUS BREAKDOWN: Pass=$pass | Fail=$fail | Partial=$partial | N/A=$na | Not Assessed=$notA")
    [void]$sb.AppendLine("")

    # Critical/High failures
    [void]$sb.AppendLine("CRITICAL & HIGH FINDINGS:")
    [void]$sb.AppendLine("-" * 40)
    $hasFindings = $false
    foreach ($cn in $script:AuditCategories.Keys) {
        foreach ($it in $script:AuditCategories[$cn].Items) {
            $sv = if ($script:StatusCombos[$it.ID].SelectedItem) { $script:StatusCombos[$it.ID].SelectedItem.ToString() } else { 'Not Assessed' }
            if ($sv -eq 'Fail' -and ($it.Severity -eq 'Critical' -or $it.Severity -eq 'High')) {
                $hasFindings = $true
                $finding = $script:FindingsBoxes[$it.ID].Text
                [void]$sb.AppendLine("[$($it.Severity.ToUpper())] [$($it.ID)] $($it.Text)")
                if ($finding) { [void]$sb.AppendLine("   Finding: $finding") }
                $remSt = if ($script:RemStatusCombos[$it.ID].SelectedItem) { $script:RemStatusCombos[$it.ID].SelectedItem.ToString() } else { 'Open' }
                $assign = $script:RemAssignBoxes[$it.ID].Text
                $due = $script:RemDueBoxes[$it.ID].Text
                if ($assign -or $due) { [void]$sb.AppendLine("   Remediation: $remSt | Assigned: $assign | Due: $due") }
                [void]$sb.AppendLine("")
            }
        }
    }
    if (-not $hasFindings) { [void]$sb.AppendLine("No critical or high items currently marked as Fail."); [void]$sb.AppendLine("") }

    # Per-category summary
    [void]$sb.AppendLine("CATEGORY SCORES:")
    [void]$sb.AppendLine("-" * 40)
    foreach ($cn in $script:AuditCategories.Keys) {
        $catMax=0;$catEarn=0
        foreach ($it in $script:AuditCategories[$cn].Items) {
            $catMax+=$it.Weight
            $sv=if($script:StatusCombos[$it.ID].SelectedItem){$script:StatusCombos[$it.ID].SelectedItem.ToString()}else{'Not Assessed'}
            switch($sv){'Pass'{$catEarn+=$it.Weight}'Partial'{$catEarn+=[math]::Floor($it.Weight*0.5)}'N/A'{$catMax-=$it.Weight}}
        }
        $catPct=if($catMax -gt 0){[math]::Round(($catEarn/$catMax)*100)}else{0}
        [void]$sb.AppendLine("  $cn : $catEarn/$catMax ($catPct%)")
    }

    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("REMEDIATION TRACKING:")
    [void]$sb.AppendLine("-" * 40)
    $openCount=0; $ipCount=0; $remCount=0; $arCount=0; $defCount=0
    foreach ($id in $script:CheckStates.Keys) {
        $rs3=if($script:RemStatusCombos[$id].SelectedItem){$script:RemStatusCombos[$id].SelectedItem.ToString()}else{'Open'}
        switch($rs3){'Open'{$openCount++}'In Progress'{$ipCount++}'Remediated'{$remCount++}'Accepted Risk'{$arCount++}'Deferred'{$defCount++}}
    }
    [void]$sb.AppendLine("  Open=$openCount | In Progress=$ipCount | Remediated=$remCount | Accepted=$arCount | Deferred=$defCount")

    $script:ExSummaryText.Text = $sb.ToString()
}

$script:exRefreshBtn.Add_Click({ Update-ExecSummary })

# ── Apply Initial Theme ──────────────────────────────────────────────────────
Apply-Theme; Update-Progress

# ── Scan Bar Setup ──────────────────────────────────────────────────────────
# Show scan bar if any auto-checks are defined
if ($script:AutoChecks.Count -gt 0) {
    $el['ScanBar'].Visibility = [System.Windows.Visibility]::Visible
    $autoCount = $script:AutoChecks.Count
    $adCount = ($script:AutoChecks.Values | Where-Object { $_.Type -eq 'AD' }).Count
    $localCount = ($script:AutoChecks.Values | Where-Object { $_.Type -eq 'Local' }).Count
    $el['lblScanIcon'].Text = "[SCAN] $autoCount auto-checks available ($adCount AD, $localCount Local)"
}

# ── Async Scan Timer ────────────────────────────────────────────────────────
$script:ScanTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:ScanTimer.Interval = [TimeSpan]::FromMilliseconds(200)
$script:ScanTimer.Add_Tick({
    # ── Turnkey async setup ──
    if ($script:TurnkeyPS -and $script:TurnkeyAsync) {
        # Flush any new log entries from background to console
        while ($script:TurnkeyStatus.Log.Count -gt 0) {
            try {
                $entry = $script:TurnkeyStatus.Log[0]
                $script:TurnkeyStatus.Log.RemoveAt(0)
                if ($entry -is [hashtable]) {
                    Write-Log $entry.Msg $entry.Level
                } elseif ($entry -is [string]) {
                    Write-Log $entry 'INFO'
                }
            } catch { break }
        }
        # Update status bar from shared status
        if ($script:TurnkeyStatus.Status) {
            $el['StatusText'].Text = "Setup: $($script:TurnkeyStatus.Status)"
        }
        if ($script:TurnkeyAsync.IsCompleted) {
            Complete-AsyncTurnkey
            if (-not $script:PreflightPS) {
                $script:ScanTimer.Stop()
            }
        }
        return
    }

    # ── Preflight async ──
    if (-not $script:CurrentAsyncResult) {
        if ($script:PreflightPS -and $script:PreflightAsync) {
            if ($script:PreflightAsync.IsCompleted) {
                Complete-AsyncPreflight
                # Only stop timer if no scan was started during preflight completion
                if (-not $script:CurrentAsyncResult) {
                    $script:ScanTimer.Stop()
                }
            }
        } else {
            $script:ScanTimer.Stop()
        }
        return
    }

    # ── Scan async ──
    if ($script:CurrentAsyncResult.IsCompleted) {
        Complete-CurrentScan
        Process-ScanQueue

        # If no more items in queue and no active scan, stop timer
        if ($script:ScanQueue.Count -eq 0 -and -not $script:CurrentAsyncResult) {
            $script:ScanTimer.Stop()
        }
    }
    elseif ($script:CurrentScanStopwatch -and $script:CurrentScanId) {
        # Heartbeat: show elapsed time for long-running checks
        $secs = [int]$script:CurrentScanStopwatch.Elapsed.TotalSeconds

        # Timeout: force-stop checks running longer than 60 seconds
        if ($secs -ge 60 -and $script:CurrentPS) {
            $id = $script:CurrentScanId
            Write-Log "[$id] TIMEOUT after ${secs}s - force stopping" 'ERROR'
            try { $script:CurrentPS.Stop() } catch {}
            Apply-ScanError $id "Timed out after ${secs}s"
            if ($script:ScanBatchTally) { $script:ScanBatchTally.Error++ }
            if ($script:CurrentScanStopwatch) { $script:CurrentScanStopwatch.Stop() }
            # Dispose the PS instance (does NOT close the shared runspace)
            try { $script:CurrentPS.Dispose() } catch {}
            $script:CurrentPS = $null
            $script:CurrentAsyncResult = $null
            $script:CurrentScanId = $null
            # If shared runspace is broken after timeout, recreate it
            if ($script:ScanRunspace -and $script:ScanRunspace.RunspaceStateInfo.State -ne 'Opened') {
                Write-Log "Scan runspace broken after timeout - recreating" 'WARN'
                try { $script:ScanRunspace.Dispose() } catch {}
                try {
                    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
                    $script:ScanRunspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($iss)
                    $script:ScanRunspace.Open()
                } catch { $script:ScanRunspace = $null }
            }
            Process-ScanQueue
            if ($script:ScanQueue.Count -eq 0 -and -not $script:CurrentAsyncResult) {
                $script:ScanTimer.Stop()
            }
        }
        elseif ($secs -ge 3 -and $secs -ne $script:CurrentScanHeartbeat -and ($secs % 3 -eq 0)) {
            $script:CurrentScanHeartbeat = $secs
            $id = $script:CurrentScanId
            $label = if ($script:AutoChecks.Contains($id)) { $script:AutoChecks[$id].Label } else { $id }
            $progressPrefix = if ($script:ScanBatchMode -eq 'Batch') { "[$($script:ScanBatchDone)/$($script:ScanBatchTotal)] " } else { "" }
            $el['StatusText'].Text = "${progressPrefix}[$id] $label... (${secs}s)"
            Write-Log "[$id] Still running... (${secs}s elapsed)" 'VERBOSE'
        }
    }
})

# ── Console Panel Setup ────────────────────────────────────────────────────
$script:ConsoleVisible = $true
$el['btnConsoleClear'].Add_Click({
    $el['txtConsole'].Clear()
    $script:ConsoleLineCount = 0
    $el['lblConsoleCount'].Text = ''
})
$el['btnConsoleToggle'].Add_Click({
    if ($script:ConsoleVisible) {
        $el['txtConsole'].Visibility = [System.Windows.Visibility]::Collapsed
        $el['ConsolePanel'].MaxHeight = 30
        $el['btnConsoleToggle'].Content = 'Show'
        $script:ConsoleVisible = $false
    } else {
        $el['txtConsole'].Visibility = [System.Windows.Visibility]::Visible
        $el['ConsolePanel'].MaxHeight = 220
        $el['btnConsoleToggle'].Content = 'Hide'
        $script:ConsoleVisible = $true
    }
})

Write-Log "Network Security Audit v4.0 initialized" 'INFO'
Write-Log "$($script:TotalItems) audit items | $($script:AutoChecks.Count) auto-checks available" 'INFO'

$el['btnSetCreds'].Add_Click({
    try {
        $cred = Get-Credential -Message "Enter domain credentials for remote scans"
        if ($cred) {
            $script:ScanCredential = $cred
            $el['lblCredStatus'].Text = "[$($cred.UserName)]"
            $el['StatusText'].Text = "Credentials set for $($cred.UserName)"
            Write-Log "Credentials set: $($cred.UserName)" 'INFO'
        }
    } catch {
        $el['StatusText'].Text = "Credential prompt cancelled"
    }
})

# ── Async Turnkey Setup ────────────────────────────────────────────────────
$script:RunnerPopup = $null

function Show-RunnerPopup {
    $t = Get-T
    $pop = New-Object System.Windows.Window
    $pop.WindowStyle = 'None'
    $pop.AllowsTransparency = $true
    $pop.Background = 'Transparent'
    $pop.ResizeMode = 'NoResize'
    $pop.Width = 340; $pop.Height = 130
    $pop.WindowStartupLocation = 'CenterScreen'
    $pop.Topmost = $true
    try { $pop.Owner = $window } catch {}

    # Outer border with rounded corners + shadow
    $border = New-Object System.Windows.Controls.Border
    $border.CornerRadius = [System.Windows.CornerRadius]::new(12)
    $border.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($t.PanelBg))
    $border.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($t.Accent))
    $border.BorderThickness = [System.Windows.Thickness]::new(1)
    $border.Padding = [System.Windows.Thickness]::new(24,18,24,18)
    $border.Effect = New-Object System.Windows.Media.Effects.DropShadowEffect -Property @{
        BlurRadius=20; ShadowDepth=4; Opacity=0.5
        Color=[System.Windows.Media.ColorConverter]::ConvertFromString('#000000')
    }

    $stack = New-Object System.Windows.Controls.StackPanel
    $stack.HorizontalAlignment = 'Center'

    # Title
    $title = New-Object System.Windows.Controls.TextBlock
    $title.Text = 'Network Security Audit v4.0'
    $title.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($t.TextPrimary))
    $title.FontSize = 15; $title.FontWeight = 'SemiBold'
    $title.HorizontalAlignment = 'Center'
    $title.Margin = [System.Windows.Thickness]::new(0,0,0,6)
    $stack.Children.Add($title) | Out-Null

    # Status text
    $status = New-Object System.Windows.Controls.TextBlock
    $status.Text = 'Detecting environment...'
    $status.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($t.TextSecondary))
    $status.FontSize = 12
    $status.HorizontalAlignment = 'Center'
    $status.Margin = [System.Windows.Thickness]::new(0,0,0,12)
    $stack.Children.Add($status) | Out-Null

    # Indeterminate progress bar
    $bar = New-Object System.Windows.Controls.ProgressBar
    $bar.IsIndeterminate = $true
    $bar.Height = 4; $bar.Width = 260
    $bar.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($t.BarBg))
    $bar.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($t.Accent))
    $bar.BorderThickness = [System.Windows.Thickness]::new(0)
    $stack.Children.Add($bar) | Out-Null

    $border.Child = $stack
    $pop.Content = $border
    $pop.Show()

    # Force a render frame so the popup is visible before dialog building blocks the UI thread
    # WPF's indeterminate progress bar animation runs on the composition thread, so it will
    # continue animating even while the UI thread is busy building the turnkey dialog.
    $pop.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Render)

    $script:RunnerPopup = $pop
}

function Close-RunnerPopup {
    if ($script:RunnerPopup) {
        try { $script:RunnerPopup.Close() } catch {}
        $script:RunnerPopup = $null
    }
}

function Show-TurnkeyDialog {
    $t = Get-T

    # ── Build the WPF Window ──
    $dlg = New-Object System.Windows.Window
    $dlg.Title = 'Environment Setup'
    $dlg.Width = 620; $dlg.Height = 660
    $dlg.WindowStartupLocation = 'CenterOwner'
    $dlg.ResizeMode = 'NoResize'
    $dlg.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($t.WindowBg))
    $dlg.WindowStyle = 'SingleBorderWindow'
    try { $dlg.Owner = $window } catch {}

    $root = New-Object System.Windows.Controls.Grid
    $root.Margin = [System.Windows.Thickness]::new(0)
    $r0 = New-Object System.Windows.Controls.RowDefinition; $r0.Height = [System.Windows.GridLength]::new(0, [System.Windows.GridUnitType]::Auto)
    $r1 = New-Object System.Windows.Controls.RowDefinition; $r1.Height = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
    $r2 = New-Object System.Windows.Controls.RowDefinition; $r2.Height = [System.Windows.GridLength]::new(0, [System.Windows.GridUnitType]::Auto)
    $root.RowDefinitions.Add($r0); $root.RowDefinitions.Add($r1); $root.RowDefinitions.Add($r2)

    # ── Header Bar ──
    $hdrBorder = New-Object System.Windows.Controls.Border
    $hdrBorder.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($t.PanelBg))
    $hdrBorder.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($t.Accent))
    $hdrBorder.BorderThickness = [System.Windows.Thickness]::new(0,0,0,2)
    $hdrBorder.Padding = [System.Windows.Thickness]::new(20,14,20,14)
    [System.Windows.Controls.Grid]::SetRow($hdrBorder, 0)

    $hdrStack = New-Object System.Windows.Controls.StackPanel
    $hdrTitle = New-Object System.Windows.Controls.TextBlock
    $hdrTitle.Text = 'Environment Setup'
    $hdrTitle.FontSize = 18; $hdrTitle.FontWeight = [System.Windows.FontWeights]::Bold
    $hdrTitle.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($t.TextPrimary))
    $hdrStack.Children.Add($hdrTitle) | Out-Null

    $hdrSub = New-Object System.Windows.Controls.TextBlock
    $hdrSub.FontSize = 11.5; $hdrSub.Margin = [System.Windows.Thickness]::new(0,4,0,0)
    $hdrSub.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($t.TextSecondary))
    $hdrSub.TextWrapping = [System.Windows.TextWrapping]::Wrap
    $envLine = "$($script:Env.OSCaption)  |  $($script:Env.ComputerName)"
    if ($script:Env.IsDomainJoined) { $envLine += "  |  Domain: $($script:Env.DomainName)" } else { $envLine += "  |  Workgroup" }
    $envLine += "  |  $(if($script:Env.IsAdmin){'Admin'}else{'Standard User'})"
    $hdrSub.Text = $envLine
    $hdrStack.Children.Add($hdrSub) | Out-Null
    $hdrBorder.Child = $hdrStack
    $root.Children.Add($hdrBorder) | Out-Null

    # ── Scrollable Content ──
    $sv = New-Object System.Windows.Controls.ScrollViewer
    $sv.VerticalScrollBarVisibility = 'Auto'; $sv.Padding = [System.Windows.Thickness]::new(20,12,20,8)
    [System.Windows.Controls.Grid]::SetRow($sv, 1)

    $content = New-Object System.Windows.Controls.StackPanel

    # Helper: section label
    $sectionLabel = {
        param([string]$text)
        $lbl = New-Object System.Windows.Controls.TextBlock
        $lbl.Text = $text; $lbl.FontSize = 13; $lbl.FontWeight = [System.Windows.FontWeights]::SemiBold
        $lbl.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($t.Accent))
        $lbl.Margin = [System.Windows.Thickness]::new(0,10,0,6)
        return $lbl
    }

    # Helper: option row with checkbox, label, status badge, description
    $optionRow = {
        param([string]$key, [string]$label, [string]$desc, [string]$status, [bool]$enabled, [bool]$defaultChecked)

        $border = New-Object System.Windows.Controls.Border
        $border.CornerRadius = [System.Windows.CornerRadius]::new(5)
        $border.Padding = [System.Windows.Thickness]::new(12,8,12,8)
        $border.Margin = [System.Windows.Thickness]::new(0,0,0,4)
        $border.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($t.CardBg))
        $border.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($t.BorderDim))
        $border.BorderThickness = [System.Windows.Thickness]::new(1)

        $grid = New-Object System.Windows.Controls.Grid
        $gc1 = New-Object System.Windows.Controls.ColumnDefinition; $gc1.Width = [System.Windows.GridLength]::new(0, [System.Windows.GridUnitType]::Auto)
        $gc2 = New-Object System.Windows.Controls.ColumnDefinition; $gc2.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
        $gc3 = New-Object System.Windows.Controls.ColumnDefinition; $gc3.Width = [System.Windows.GridLength]::new(0, [System.Windows.GridUnitType]::Auto)
        $grid.ColumnDefinitions.Add($gc1); $grid.ColumnDefinitions.Add($gc2); $grid.ColumnDefinitions.Add($gc3)

        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.IsChecked = $defaultChecked; $cb.IsEnabled = $enabled
        $cb.VerticalAlignment = [System.Windows.VerticalAlignment]::Top
        $cb.Margin = [System.Windows.Thickness]::new(0,2,10,0)
        $cb.Tag = $key
        # Checkbox styling
        $cbStyle = New-Object System.Windows.Style ([System.Windows.Controls.CheckBox])
        $fgColor = if ($enabled) { $t.TextPrimary } else { $t.TextSecondary }
        $cbStyle.Setters.Add((New-Object System.Windows.Setter ([System.Windows.Controls.CheckBox]::ForegroundProperty, (New-Brush $fgColor))))
        $cb.Style = $cbStyle
        [System.Windows.Controls.Grid]::SetColumn($cb, 0)
        $grid.Children.Add($cb) | Out-Null

        $txtStack = New-Object System.Windows.Controls.StackPanel
        [System.Windows.Controls.Grid]::SetColumn($txtStack, 1)
        $lblText = New-Object System.Windows.Controls.TextBlock
        $lblText.Text = $label; $lblText.FontSize = 12; $lblText.FontWeight = [System.Windows.FontWeights]::SemiBold
        $lblFg = if ($enabled) { $t.TextPrimary } else { $t.TextSecondary }
        $lblText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($lblFg))
        $txtStack.Children.Add($lblText) | Out-Null
        $descText = New-Object System.Windows.Controls.TextBlock
        $descText.Text = $desc; $descText.FontSize = 10.5; $descText.TextWrapping = [System.Windows.TextWrapping]::Wrap
        $descText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($t.TextSecondary))
        $descText.Margin = [System.Windows.Thickness]::new(0,2,0,0)
        $txtStack.Children.Add($descText) | Out-Null
        $grid.Children.Add($txtStack) | Out-Null

        # Status badge
        $badge = New-Object System.Windows.Controls.Border
        $badge.CornerRadius = [System.Windows.CornerRadius]::new(8)
        $badge.Padding = [System.Windows.Thickness]::new(8,2,8,2)
        $badge.VerticalAlignment = [System.Windows.VerticalAlignment]::Top
        $badge.Margin = [System.Windows.Thickness]::new(8,2,0,0)
        $badgeTxt = New-Object System.Windows.Controls.TextBlock
        $badgeTxt.FontSize = 9.5; $badgeTxt.FontWeight = [System.Windows.FontWeights]::SemiBold
        switch ($status) {
            'OK'      { $badge.Background = New-Brush '#14532d'; $badgeTxt.Foreground = New-Brush '#86efac'; $badgeTxt.Text = 'OK' }
            'Needed'  { $badge.Background = New-Brush '#7c2d12'; $badgeTxt.Foreground = New-Brush '#fdba74'; $badgeTxt.Text = 'NEEDED' }
            'No Admin' { $badge.Background = New-Brush '#44403c'; $badgeTxt.Foreground = New-Brush '#a8a29e'; $badgeTxt.Text = 'NO ADMIN' }
            'N/A'     { $badge.Background = New-Brush '#1e293b'; $badgeTxt.Foreground = New-Brush '#64748b'; $badgeTxt.Text = 'N/A' }
            default   { $badge.Background = New-Brush '#1e293b'; $badgeTxt.Foreground = New-Brush '#94a3b8'; $badgeTxt.Text = $status }
        }
        $badge.Child = $badgeTxt
        [System.Windows.Controls.Grid]::SetColumn($badge, 2)
        $grid.Children.Add($badge) | Out-Null

        $border.Child = $grid
        return @{ Border=$border; CheckBox=$cb }
    }

    # ── Build Options ──
    $checkboxes = @{}
    $isAdmin = $script:Env.IsAdmin

    # --- Package Management ---
    $content.Children.Add((& $sectionLabel 'Package Management')) | Out-Null

    $psGalStatus = 'Needed'; $psGalDefault = $true
    try {
        $repo = Get-PSRepository -Name PSGallery -EA SilentlyContinue
        if ($repo -and $repo.InstallationPolicy -eq 'Trusted') { $psGalStatus = 'OK'; $psGalDefault = $false }
    } catch {}
    $row = & $optionRow 'PSGallery' 'Trust PSGallery Repository' 'Sets PowerShell Gallery as a trusted source for module installation.' $psGalStatus $isAdmin $psGalDefault
    $content.Children.Add($row.Border) | Out-Null; $checkboxes['PSGallery'] = $row.CheckBox

    $nugetStatus = 'Needed'; $nugetDefault = $true
    try {
        $nuget = Get-PackageProvider -Name NuGet -ListAvailable -EA SilentlyContinue
        if ($nuget -and $nuget.Version -ge [Version]'2.8.5.201') { $nugetStatus = 'OK'; $nugetDefault = $false }
    } catch {}
    $row = & $optionRow 'NuGet' 'Install NuGet Package Provider' 'Required for installing PowerShell modules from the gallery.' $nugetStatus $isAdmin $nugetDefault
    $content.Children.Add($row.Border) | Out-Null; $checkboxes['NuGet'] = $row.CheckBox

    # --- RSAT Modules ---
    $content.Children.Add((& $sectionLabel 'RSAT Modules')) | Out-Null

    if ($script:Env.MissingModules.Count -gt 0) {
        foreach ($mod in $script:Env.MissingModules) {
            $modKey = "Module_$($mod.Name)"
            $modDesc = switch ($mod.Name) {
                'ActiveDirectory' { 'Required for domain account, group, and GPO auditing (AD checks).' }
                'DnsServer'       { 'Required for DNS server configuration auditing.' }
                'GroupPolicy'     { 'Required for Group Policy analysis and compliance checks.' }
                default           { "Required for $($mod.Name) related audit checks." }
            }
            $modStatus = if ($isAdmin) { 'Needed' } else { 'No Admin' }
            $row = & $optionRow $modKey "Install $($mod.Name)" $modDesc $modStatus $isAdmin $isAdmin
            $content.Children.Add($row.Border) | Out-Null; $checkboxes[$modKey] = $row.CheckBox
        }
    } else {
        $allOk = New-Object System.Windows.Controls.TextBlock
        $allOk.Text = 'All required modules are already installed.'
        $allOk.FontSize = 11; $allOk.FontStyle = [System.Windows.FontStyles]::Italic
        $allOk.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString('#22c55e'))
        $allOk.Margin = [System.Windows.Thickness]::new(4,0,0,4)
        $content.Children.Add($allOk) | Out-Null
    }

    # --- Remote Access & Services ---
    $content.Children.Add((& $sectionLabel 'Remote Access and Services')) | Out-Null

    $winrmStatus = if ($script:Env.WinRMRunning) { 'OK' } elseif ($isAdmin) { 'Needed' } else { 'No Admin' }
    $winrmDefault = (-not $script:Env.WinRMRunning) -and $isAdmin
    $row = & $optionRow 'WinRM' 'Enable WinRM (PS Remoting)' 'Enables PowerShell Remoting and sets TrustedHosts. Required for remote scans.' $winrmStatus ($isAdmin -and -not $script:Env.WinRMRunning) $winrmDefault
    $content.Children.Add($row.Border) | Out-Null; $checkboxes['WinRM'] = $row.CheckBox

    $rrStatus = 'Needed'; $rrDefault = $false
    try {
        $svc = Get-Service RemoteRegistry -EA SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') { $rrStatus = 'OK'; $rrDefault = $false }
        else { $rrDefault = $isAdmin }
    } catch { $rrStatus = 'N/A'; $rrDefault = $false }
    if (-not $isAdmin -and $rrStatus -eq 'Needed') { $rrStatus = 'No Admin' }
    $row = & $optionRow 'RemoteRegistry' 'Start Remote Registry Service' 'Sets Remote Registry to Manual startup and starts the service.' $rrStatus ($isAdmin -and $rrStatus -ne 'OK') $rrDefault
    $content.Children.Add($row.Border) | Out-Null; $checkboxes['RemoteRegistry'] = $row.CheckBox

    # --- Firewall ---
    $content.Children.Add((& $sectionLabel 'Firewall Rules')) | Out-Null

    $fwGroups = @(
        @{ Key='FW_WinRM'; Label='WinRM Rules'; Group='Windows Remote Management'; Desc='Allows inbound WinRM connections for remote PowerShell.' }
        @{ Key='FW_WMI'; Label='WMI Rules'; Group='Windows Management Instrumentation (WMI)'; Desc='Allows WMI queries to remote machines.' }
        @{ Key='FW_EventLog'; Label='Remote Event Log Rules'; Group='Remote Event Log Management'; Desc='Allows reading event logs on remote machines.' }
        @{ Key='FW_FilePrinter'; Label='File and Printer Sharing'; Group='File and Printer Sharing'; Desc='Allows SMB file sharing enumeration.' }
    )
    foreach ($fg in $fwGroups) {
        $fwStatus = 'Needed'; $fwDefault = $isAdmin; $fwEnabled = $isAdmin
        try {
            $rules = Get-NetFirewallRule -DisplayGroup $fg.Group -EA SilentlyContinue
            $disabled = $rules | Where-Object { $_.Enabled -ne 'True' }
            if (-not $disabled -or $disabled.Count -eq 0) { $fwStatus = 'OK'; $fwDefault = $false; $fwEnabled = $false }
        } catch {}
        if (-not $isAdmin -and $fwStatus -eq 'Needed') { $fwStatus = 'No Admin'; $fwEnabled = $false; $fwDefault = $false }
        $row = & $optionRow $fg.Key $fg.Label $fg.Desc $fwStatus $fwEnabled $fwDefault
        $content.Children.Add($row.Border) | Out-Null; $checkboxes[$fg.Key] = $row.CheckBox
    }

    # --- Audit Policies ---
    $content.Children.Add((& $sectionLabel 'Audit Configuration')) | Out-Null

    $apStatus = if ($isAdmin) { 'Needed' } else { 'No Admin' }
    $row = & $optionRow 'AuditPolicies' 'Configure Windows Audit Policies' 'Enables success/failure auditing for Logon, Account Logon, Account Management, Policy Change, Object Access, Privilege Use, System.' $apStatus $isAdmin $isAdmin
    $content.Children.Add($row.Border) | Out-Null; $checkboxes['AuditPolicies'] = $row.CheckBox

    # --- Discovery (always read-only, always runs) ---
    $content.Children.Add((& $sectionLabel 'Discovery (Read-Only)')) | Out-Null

    $dcStatus = if ($script:Env.IsDomainJoined) { 'Needed' } else { 'N/A' }
    $dcEnabled = $script:Env.IsDomainJoined
    $row = & $optionRow 'DiscoverDCs' 'Discover Domain Controllers' 'Queries DNS SRV records and Active Directory to locate DCs. No system changes.' $dcStatus $dcEnabled $dcEnabled
    $content.Children.Add($row.Border) | Out-Null; $checkboxes['DiscoverDCs'] = $row.CheckBox

    $sv.Content = $content
    $root.Children.Add($sv) | Out-Null

    # ── Footer Buttons ──
    $footer = New-Object System.Windows.Controls.Border
    $footer.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($t.PanelBg))
    $footer.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($t.BorderDim))
    $footer.BorderThickness = [System.Windows.Thickness]::new(0,1,0,0)
    $footer.Padding = [System.Windows.Thickness]::new(20,10,20,10)
    [System.Windows.Controls.Grid]::SetRow($footer, 2)

    $btnGrid = New-Object System.Windows.Controls.Grid
    $bc1 = New-Object System.Windows.Controls.ColumnDefinition; $bc1.Width = [System.Windows.GridLength]::new(0, [System.Windows.GridUnitType]::Auto)
    $bc2 = New-Object System.Windows.Controls.ColumnDefinition; $bc2.Width = [System.Windows.GridLength]::new(0, [System.Windows.GridUnitType]::Auto)
    $bc3 = New-Object System.Windows.Controls.ColumnDefinition; $bc3.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
    $bc4 = New-Object System.Windows.Controls.ColumnDefinition; $bc4.Width = [System.Windows.GridLength]::new(0, [System.Windows.GridUnitType]::Auto)
    $bc5 = New-Object System.Windows.Controls.ColumnDefinition; $bc5.Width = [System.Windows.GridLength]::new(0, [System.Windows.GridUnitType]::Auto)
    $btnGrid.ColumnDefinitions.Add($bc1); $btnGrid.ColumnDefinitions.Add($bc2); $btnGrid.ColumnDefinitions.Add($bc3); $btnGrid.ColumnDefinitions.Add($bc4); $btnGrid.ColumnDefinitions.Add($bc5)

    $btnSelAll = New-Object System.Windows.Controls.Button; $btnSelAll.Content = 'Select All'; $btnSelAll.Padding = [System.Windows.Thickness]::new(12,6,12,6)
    $btnSelAll.FontSize = 11; $btnSelAll.Cursor = [System.Windows.Input.Cursors]::Hand; $btnSelAll.Margin = [System.Windows.Thickness]::new(0,0,6,0)
    Apply-ButtonTheme $btnSelAll '#475569' '#64748b'
    [System.Windows.Controls.Grid]::SetColumn($btnSelAll, 0)
    $btnGrid.Children.Add($btnSelAll) | Out-Null

    $btnSelNone = New-Object System.Windows.Controls.Button; $btnSelNone.Content = 'Select None'; $btnSelNone.Padding = [System.Windows.Thickness]::new(12,6,12,6)
    $btnSelNone.FontSize = 11; $btnSelNone.Cursor = [System.Windows.Input.Cursors]::Hand
    Apply-ButtonTheme $btnSelNone '#475569' '#64748b'
    [System.Windows.Controls.Grid]::SetColumn($btnSelNone, 1)
    $btnGrid.Children.Add($btnSelNone) | Out-Null

    $btnSkip = New-Object System.Windows.Controls.Button; $btnSkip.Content = 'Skip Setup'; $btnSkip.Padding = [System.Windows.Thickness]::new(16,8,16,8)
    $btnSkip.FontSize = 12; $btnSkip.FontWeight = [System.Windows.FontWeights]::SemiBold; $btnSkip.Cursor = [System.Windows.Input.Cursors]::Hand
    $btnSkip.Margin = [System.Windows.Thickness]::new(0,0,8,0)
    Apply-ButtonTheme $btnSkip '#475569' '#64748b'
    [System.Windows.Controls.Grid]::SetColumn($btnSkip, 3)
    $btnGrid.Children.Add($btnSkip) | Out-Null

    $btnRun = New-Object System.Windows.Controls.Button; $btnRun.Content = 'Run Selected'; $btnRun.Padding = [System.Windows.Thickness]::new(16,8,16,8)
    $btnRun.FontSize = 12; $btnRun.FontWeight = [System.Windows.FontWeights]::Bold; $btnRun.Cursor = [System.Windows.Input.Cursors]::Hand
    Apply-ButtonTheme $btnRun $t.Accent $t.AccentHover
    [System.Windows.Controls.Grid]::SetColumn($btnRun, 4)
    $btnGrid.Children.Add($btnRun) | Out-Null

    $footer.Child = $btnGrid
    $root.Children.Add($footer) | Out-Null

    $dlg.Content = $root

    # ── Result tracking ──
    $dlgResult = @{ Action = 'Skip'; Selections = @{} }

    $btnSelAll.Add_Click({
        foreach ($cb in $checkboxes.Values) { if ($cb.IsEnabled) { $cb.IsChecked = $true } }
    }.GetNewClosure())
    $btnSelNone.Add_Click({
        foreach ($cb in $checkboxes.Values) { if ($cb.IsEnabled) { $cb.IsChecked = $false } }
    }.GetNewClosure())
    $btnSkip.Add_Click({
        $dlgResult.Action = 'Skip'
        $dlg.Close()
    }.GetNewClosure())
    $btnRun.Add_Click({
        $dlgResult.Action = 'Run'
        foreach ($key in $checkboxes.Keys) {
            $dlgResult.Selections[$key] = ($checkboxes[$key].IsChecked -eq $true)
        }
        $dlg.Close()
    }.GetNewClosure())

    # Close the runner popup before showing this modal dialog
    Close-RunnerPopup

    $dlg.ShowDialog() | Out-Null
    return $dlgResult
}

function Start-AsyncTurnkey {
    # Show loading runner while environment is being detected
    Show-RunnerPopup

    # Show configuration dialog first - user chooses what to run
    $dlgResult = Show-TurnkeyDialog
    Close-RunnerPopup  # Safety: ensure runner is closed if dialog errored early
    $sel = $dlgResult.Selections

    Write-Log "=== TURNKEY SETUP STARTING ===" 'INFO'
    Write-Log "OS: $($script:Env.OSCaption) | Computer: $($script:Env.ComputerName)" 'INFO'
    Write-Log "Admin: $($script:Env.IsAdmin) | PS: $($script:Env.PSVersion)" 'INFO'
    Write-Log "Domain: $(if($script:Env.IsDomainJoined){$script:Env.DomainName}else{'Workgroup (standalone)'})" 'INFO'
    Write-Log "Server OS: $($script:Env.IsServer) | WinRM: $($script:Env.WinRMRunning)" 'INFO'

    $caps = @()
    if ($script:Env.HasDefender)  { $caps += 'Defender' }
    if ($script:Env.HasSMB)       { $caps += 'SMB' }
    if ($script:Env.HasBitLocker) { $caps += 'BitLocker' }
    if ($script:Env.HasAppLocker) { $caps += 'AppLocker' }
    if ($script:Env.HasAD)        { $caps += 'ActiveDirectory' }
    if ($script:Env.HasDNS)       { $caps += 'DnsServer' }
    if ($script:Env.HasGPO)       { $caps += 'GroupPolicy' }
    Write-Log "Initial capabilities: $(if($caps.Count -gt 0){$caps -join ', '}else{'(none detected)'})" 'INFO'

    if ($script:Env.InstalledModules.Count -gt 0) {
        Write-Log "Modules available: $($script:Env.InstalledModules -join ', ')" 'INFO'
    }

    # Auto-populate fields immediately
    if (-not $el['txtClient'].Text) {
        $clientName = if ($script:Env.IsDomainJoined) { $script:Env.DomainName.Split('.')[0].ToUpper() } else { $script:Env.ComputerName }
        $el['txtClient'].Text = $clientName
        Write-Log "Auto-populated client: $clientName" 'INFO'
    }
    if (-not $el['txtAuditor'].Text) {
        $el['txtAuditor'].Text = "$env:USERNAME"
        Write-Log "Auto-populated auditor: $env:USERNAME" 'INFO'
    }

    # If user skipped, go straight to preflight
    if ($dlgResult.Action -eq 'Skip') {
        Write-Log "User skipped environment setup" 'INFO'
        $el['StatusText'].Text = "Setup skipped - starting pre-flight..."
        Start-AsyncPreflight
        return
    }

    # Log what the user selected
    $selected = @($sel.Keys | Where-Object { $sel[$_] -eq $true })
    $skipped  = @($sel.Keys | Where-Object { $sel[$_] -ne $true })
    if ($selected.Count -gt 0) { Write-Log "User selected: $($selected -join ', ')" 'INFO' }
    if ($skipped.Count -gt 0)  { Write-Log "User skipped: $($skipped -join ', ')" 'INFO' }

    # If nothing was selected, skip to preflight
    if ($selected.Count -eq 0) {
        Write-Log "No setup items selected - proceeding to pre-flight" 'INFO'
        $el['StatusText'].Text = "No setup selected - starting pre-flight..."
        Start-AsyncPreflight
        return
    }

    # Build module install list from selections
    $installModules = @()
    foreach ($mod in $script:Env.MissingModules) {
        $modKey = "Module_$($mod.Name)"
        if ($sel.Contains($modKey) -and $sel[$modKey]) { $installModules += $mod }
    }

    $envData = @{
        IsAdmin        = $script:Env.IsAdmin
        IsServer       = $script:Env.IsServer
        IsDomainJoined = $script:Env.IsDomainJoined
        DomainName     = $script:Env.DomainName
        WinRMRunning   = $script:Env.WinRMRunning
        MissingModules = @($installModules)
        ComputerName   = $script:Env.ComputerName
        InstallApproved = ($installModules.Count -gt 0)
        # Pass user selections to background worker
        Sel_PSGallery       = ($sel.Contains('PSGallery') -and $sel['PSGallery'])
        Sel_NuGet           = ($sel.Contains('NuGet') -and $sel['NuGet'])
        Sel_WinRM           = ($sel.Contains('WinRM') -and $sel['WinRM'])
        Sel_RemoteRegistry  = ($sel.Contains('RemoteRegistry') -and $sel['RemoteRegistry'])
        Sel_FW_WinRM        = ($sel.Contains('FW_WinRM') -and $sel['FW_WinRM'])
        Sel_FW_WMI          = ($sel.Contains('FW_WMI') -and $sel['FW_WMI'])
        Sel_FW_EventLog     = ($sel.Contains('FW_EventLog') -and $sel['FW_EventLog'])
        Sel_FW_FilePrinter  = ($sel.Contains('FW_FilePrinter') -and $sel['FW_FilePrinter'])
        Sel_AuditPolicies   = ($sel.Contains('AuditPolicies') -and $sel['AuditPolicies'])
        Sel_DiscoverDCs     = ($sel.Contains('DiscoverDCs') -and $sel['DiscoverDCs'])
    }
    $sharedStatus = $script:TurnkeyStatus
    $sharedStatus.Status = ''
    $sharedStatus.Phase = 'starting'
    $sharedStatus.Done = $false
    $sharedStatus.Log.Clear()

    $el['StatusText'].Text = "Turnkey setup: initializing..."

    $ps = [PowerShell]::Create()
    $ps.AddScript({
        param($Env, $Shared)

        function Log([string]$msg, [string]$lvl = 'INFO') {
            $Shared.Status = $msg
            $Shared.Log.Add(@{ Msg=$msg; Level=$lvl }) | Out-Null
        }

        $results = @{
            ModulesInstalled = [System.Collections.ArrayList]@()
            ModulesFailed    = [System.Collections.ArrayList]@()
            WinRM            = @{ Success=$false; Message='' }
            AuditPolicies    = @{ Configured=0; Failed=0 }
            Firewall         = [System.Collections.ArrayList]@()
            DCs              = @()
            PrimaryDC        = $null
            BestTarget       = $null
            RemoteRegistry   = @{ Success=$false; Message='' }
            PSGallery        = @{ Success=$false; Message='' }
            NuGet            = @{ Success=$false; Message='' }
        }

        # ── Step 1: PSGallery Trust ──
        $Shared.Phase = 'psgallery'
        if ($Env.Sel_PSGallery) {
            Log "Trusting PSGallery repository..."
            try {
                $repo = Get-PSRepository -Name PSGallery -EA SilentlyContinue
                if ($repo -and $repo.InstallationPolicy -ne 'Trusted') {
                    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -EA Stop
                    $results.PSGallery = @{ Success=$true; Message='PSGallery set to Trusted' }
                    Log "PSGallery trusted" 'INFO'
                } else {
                    $results.PSGallery = @{ Success=$true; Message='PSGallery already trusted' }
                    Log "PSGallery already trusted" 'INFO'
                }
            }
            catch {
                $results.PSGallery = @{ Success=$false; Message="PSGallery: $_" }
                Log "PSGallery trust failed: $_" 'WARN'
            }
        } else { Log "PSGallery: skipped by user" 'INFO' }

        # ── Step 2: NuGet Provider ──
        $Shared.Phase = 'nuget'
        if ($Env.Sel_NuGet) {
            Log "Checking NuGet provider..."
            try {
                $nuget = Get-PackageProvider -Name NuGet -ListAvailable -EA SilentlyContinue
                if (-not $nuget -or $nuget.Version -lt [Version]'2.8.5.201') {
                    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -EA Stop | Out-Null
                    $results.NuGet = @{ Success=$true; Message='NuGet provider installed' }
                    Log "NuGet provider installed" 'INFO'
                } else {
                    $results.NuGet = @{ Success=$true; Message='NuGet already available' }
                    Log "NuGet provider OK" 'INFO'
                }
            }
            catch {
                $results.NuGet = @{ Success=$false; Message="NuGet: $_" }
                Log "NuGet install failed: $_" 'WARN'
            }
        } else { Log "NuGet: skipped by user" 'INFO' }

        # ── Step 3: Install Missing RSAT Modules ──
        $Shared.Phase = 'modules'
        if ($Env.MissingModules.Count -gt 0 -and $Env.IsAdmin -and $Env.InstallApproved) {
            foreach ($mod in $Env.MissingModules) {
                Log "Installing module: $($mod.Name)..." 'INFO'
                $installed = $false
                try {
                    if ($Env.IsServer) {
                        $feat = Install-WindowsFeature -Name $mod.Feature -EA Stop
                        if ($feat.Success) {
                            $installed = $true
                            Log "$($mod.Name) installed (server feature: $($mod.Feature))" 'INFO'
                        } else {
                            Log "$($mod.Name) install returned failure" 'ERROR'
                        }
                    }
                    else {
                        $cap = Get-WindowsCapability -Online -Name "$($mod.RSATName)~~~~*" -EA Stop | Where-Object { $_.State -ne 'Installed' }
                        if ($cap) {
                            foreach ($c in $cap) {
                                Add-WindowsCapability -Online -Name $c.Name -EA Stop | Out-Null
                            }
                            $installed = $true
                            Log "$($mod.Name) installed (RSAT capability)" 'INFO'
                        } else {
                            $installed = $true
                            Log "$($mod.Name) already present" 'INFO'
                        }
                    }
                }
                catch {
                    Log "$($mod.Name) install failed: $($_.Exception.Message)" 'ERROR'
                }
                if ($installed) { $results.ModulesInstalled.Add($mod.Name) | Out-Null }
                else { $results.ModulesFailed.Add($mod.Name) | Out-Null }
            }
        }
        elseif ($Env.MissingModules.Count -gt 0 -and -not $Env.InstallApproved) {
            Log "Module installation declined by user - skipping" 'INFO'
            foreach ($mod in $Env.MissingModules) { $results.ModulesFailed.Add($mod.Name) | Out-Null }
        }
        elseif ($Env.MissingModules.Count -gt 0) {
            Log "Cannot install modules without admin privileges" 'WARN'
            foreach ($mod in $Env.MissingModules) { $results.ModulesFailed.Add($mod.Name) | Out-Null }
        }
        else {
            Log "All required modules present" 'INFO'
        }

        # ── Step 4: WinRM Configuration ──
        $Shared.Phase = 'winrm'
        if ($Env.Sel_WinRM) {
            if (-not $Env.WinRMRunning -and $Env.IsAdmin) {
                Log "Configuring WinRM (Enable-PSRemoting)..." 'INFO'
                try {
                    Enable-PSRemoting -Force -SkipNetworkProfileCheck -EA Stop | Out-Null
                    Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force -EA SilentlyContinue
                    $results.WinRM = @{ Success=$true; Message='WinRM enabled and configured' }
                    Log "WinRM enabled successfully" 'INFO'
                }
                catch {
                    $results.WinRM = @{ Success=$false; Message="WinRM: $($_.Exception.Message)" }
                    Log "WinRM configuration failed: $($_.Exception.Message)" 'ERROR'
                }
            }
            elseif ($Env.WinRMRunning) {
                $results.WinRM = @{ Success=$true; Message='WinRM already running' }
                Log "WinRM already running" 'INFO'
                try { Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force -EA SilentlyContinue } catch {}
            }
            else {
                $results.WinRM = @{ Success=$false; Message='WinRM not running, admin required' }
                Log "WinRM: admin required to configure" 'WARN'
            }
        } else { Log "WinRM: skipped by user" 'INFO' }

        # ── Step 5: Firewall Rules ──
        $Shared.Phase = 'firewall'
        if ($Env.IsAdmin) {
            # WinRM
            if ($Env.Sel_FW_WinRM) {
                try {
                    $rules = Get-NetFirewallRule -DisplayGroup 'Windows Remote Management' -EA SilentlyContinue
                    $disabled = $rules | Where-Object { $_.Enabled -ne 'True' }
                    if ($disabled) {
                        Enable-NetFirewallRule -DisplayGroup 'Windows Remote Management' -EA Stop
                        $results.Firewall.Add("WinRM: Enabled $($disabled.Count) rules") | Out-Null
                        Log "WinRM firewall rules enabled ($($disabled.Count))" 'INFO'
                    } else { Log "WinRM firewall rules OK" 'INFO' }
                } catch { Log "WinRM firewall: $($_.Exception.Message)" 'WARN' }
            } else { Log "WinRM firewall: skipped by user" 'INFO' }
            # WMI
            if ($Env.Sel_FW_WMI) {
                try {
                    $rules = Get-NetFirewallRule -DisplayGroup 'Windows Management Instrumentation (WMI)' -EA SilentlyContinue
                    $disabled = $rules | Where-Object { $_.Enabled -ne 'True' }
                    if ($disabled) {
                        Enable-NetFirewallRule -DisplayGroup 'Windows Management Instrumentation (WMI)' -EA Stop
                        $results.Firewall.Add("WMI: Enabled $($disabled.Count) rules") | Out-Null
                        Log "WMI firewall rules enabled ($($disabled.Count))" 'INFO'
                    } else { Log "WMI firewall rules OK" 'INFO' }
                } catch { Log "WMI firewall: $($_.Exception.Message)" 'WARN' }
            } else { Log "WMI firewall: skipped by user" 'INFO' }
            # Remote Event Log
            if ($Env.Sel_FW_EventLog) {
                try {
                    $rules = Get-NetFirewallRule -DisplayGroup 'Remote Event Log Management' -EA SilentlyContinue
                    $disabled = $rules | Where-Object { $_.Enabled -ne 'True' }
                    if ($disabled) {
                        Enable-NetFirewallRule -DisplayGroup 'Remote Event Log Management' -EA Stop
                        $results.Firewall.Add("EventLog: Enabled $($disabled.Count) rules") | Out-Null
                        Log "Event Log firewall rules enabled ($($disabled.Count))" 'INFO'
                    } else { Log "Event Log firewall rules OK" 'INFO' }
                } catch { Log "Event Log firewall: $($_.Exception.Message)" 'WARN' }
            } else { Log "Event Log firewall: skipped by user" 'INFO' }
            # File and Printer Sharing
            if ($Env.Sel_FW_FilePrinter) {
                try {
                    $rules = Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -EA SilentlyContinue
                    $disabled = $rules | Where-Object { $_.Enabled -ne 'True' }
                    if ($disabled) {
                        Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -EA Stop
                        $results.Firewall.Add("File/Printer: Enabled $($disabled.Count) rules") | Out-Null
                        Log "File/Printer sharing firewall rules enabled ($($disabled.Count))" 'INFO'
                    } else { Log "File/Printer sharing firewall rules OK" 'INFO' }
                } catch { Log "File/Printer firewall: $($_.Exception.Message)" 'WARN' }
            } else { Log "File/Printer firewall: skipped by user" 'INFO' }
        }

        # ── Step 6: Audit Policies ──
        $Shared.Phase = 'auditpol'
        if ($Env.Sel_AuditPolicies -and $Env.IsAdmin) {
            Log "Configuring Windows audit policies..." 'INFO'
            $configured = 0; $failed = 0
            $policies = @(
                @{ Sub='Logon'; Setting='/success:enable /failure:enable' }
                @{ Sub='Account Logon'; Setting='/success:enable /failure:enable' }
                @{ Sub='Account Management'; Setting='/success:enable /failure:enable' }
                @{ Sub='Policy Change'; Setting='/success:enable /failure:enable' }
                @{ Sub='Object Access'; Setting='/success:enable /failure:enable' }
                @{ Sub='Privilege Use'; Setting='/success:enable /failure:enable' }
                @{ Sub='System'; Setting='/success:enable /failure:enable' }
            )
            foreach ($p in $policies) {
                try {
                    $cmd = "auditpol /set /subcategory:`"$($p.Sub)`" $($p.Setting)"
                    $out = cmd.exe /c $cmd 2>&1
                    if ($LASTEXITCODE -eq 0) { $configured++ }
                    else { $failed++; Log "Audit policy failed: $($p.Sub)" 'WARN' }
                } catch { $failed++ }
            }
            $results.AuditPolicies = @{ Configured=$configured; Failed=$failed }
            Log "Audit policies: $configured configured, $failed failed" $(if($failed -eq 0){'INFO'}else{'WARN'})
        } else {
            if (-not $Env.Sel_AuditPolicies) { Log "Audit policies: skipped by user" 'INFO' }
            else { Log "Skipping audit policies (admin required)" 'WARN' }
        }

        # ── Step 7: Remote Registry (local) ──
        $Shared.Phase = 'remoteregistry'
        if ($Env.Sel_RemoteRegistry -and $Env.IsAdmin) {
            Log "Checking Remote Registry service..." 'INFO'
            try {
                $svc = Get-Service RemoteRegistry -EA Stop
                if ($svc.Status -ne 'Running') {
                    Set-Service RemoteRegistry -StartupType Manual -EA Stop
                    Start-Service RemoteRegistry -EA Stop
                    $results.RemoteRegistry = @{ Success=$true; Message='Remote Registry started' }
                    Log "Remote Registry service started" 'INFO'
                } else {
                    $results.RemoteRegistry = @{ Success=$true; Message='Remote Registry already running' }
                    Log "Remote Registry already running" 'INFO'
                }
            } catch {
                $results.RemoteRegistry = @{ Success=$false; Message="$($_.Exception.Message)" }
                Log "Remote Registry: $($_.Exception.Message)" 'WARN'
            }
        } else {
            if (-not $Env.Sel_RemoteRegistry) { Log "Remote Registry: skipped by user" 'INFO' }
        }

        # ── Step 8: Discover Domain Controllers ──
        $Shared.Phase = 'discovery'
        if ($Env.Sel_DiscoverDCs -and $Env.IsDomainJoined) {
            Log "Discovering domain controllers for $($Env.DomainName)..." 'INFO'
            $dcs = [System.Collections.ArrayList]@()
            $primary = $null

            # DNS SRV
            try {
                $srv = Resolve-DnsName "_ldap._tcp.dc._msdcs.$($Env.DomainName)" -Type SRV -EA Stop
                foreach ($r in ($srv | Where-Object { $_.Type -eq 'SRV' } | Sort-Object Priority, Weight)) {
                    $name = $r.NameTarget -replace '\.$',''
                    if ($name -and $dcs -notcontains $name) { $dcs.Add($name) | Out-Null }
                }
                if ($dcs.Count -gt 0) { Log "DNS SRV found $($dcs.Count) DC(s)" 'INFO' }
            } catch { Log "DNS SRV lookup failed: $($_.Exception.Message)" 'WARN' }

            # nltest fallback
            if ($dcs.Count -eq 0) {
                try {
                    $nl = nltest /dsgetdc:$($Env.DomainName) 2>&1
                    $dcLine = ($nl | Select-String 'DC: \\\\(.+)' | Select-Object -First 1)
                    if ($dcLine -and $dcLine.Matches) {
                        $name = $dcLine.Matches[0].Groups[1].Value.Trim()
                        if ($name) { $dcs.Add($name) | Out-Null; Log "nltest found DC: $name" 'INFO' }
                    }
                } catch { }
            }

            # DirectoryServices fallback
            if ($dcs.Count -eq 0) {
                try {
                    $ctx = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new('Domain', $Env.DomainName)
                    $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)
                    foreach ($dc in $dom.DomainControllers) {
                        $name = $dc.Name
                        if ($name -and $dcs -notcontains $name) { $dcs.Add($name) | Out-Null }
                    }
                    if ($dcs.Count -gt 0) { Log "DirectoryServices found $($dcs.Count) DC(s)" 'INFO' }
                } catch { Log "DirectoryServices lookup: $($_.Exception.Message)" 'WARN' }
            }

            # Determine PDC
            try {
                $nl2 = nltest /dsgetdc:$($Env.DomainName) /pdc 2>&1
                $pdcLine = ($nl2 | Select-String 'DC: \\\\(.+)' | Select-Object -First 1)
                if ($pdcLine -and $pdcLine.Matches) { $primary = $pdcLine.Matches[0].Groups[1].Value.Trim() }
            } catch { }
            if (-not $primary -and $dcs.Count -gt 0) { $primary = $dcs[0] }

            $results.DCs = @($dcs)
            $results.PrimaryDC = $primary
            $results.BestTarget = $primary

            if ($dcs.Count -gt 0) {
                Log "Domain Controllers: $($dcs -join ', ')" 'INFO'
                Log "Primary DC: $primary" 'INFO'
            } else {
                Log "No domain controllers discovered - using localhost" 'WARN'
                $results.BestTarget = 'localhost'
            }
        }
        else {
            if (-not $Env.Sel_DiscoverDCs) { Log "DC discovery: skipped by user" 'INFO' }
            else { Log "Workgroup machine - scan target: localhost" 'INFO' }
            $results.BestTarget = 'localhost'
        }

        # ── Step 9: Verify installed modules post-install ──
        $Shared.Phase = 'verify'
        if ($results.ModulesInstalled.Count -gt 0) {
            Log "Verifying newly installed modules..." 'INFO'
            $verified = @()
            foreach ($modName in $results.ModulesInstalled) {
                if (Get-Module $modName -ListAvailable -EA SilentlyContinue) {
                    $verified += $modName
                    Log "Verified: $modName" 'INFO'
                } else {
                    Log "$modName installed but not yet available (may need restart)" 'WARN'
                }
            }
            $results.VerifiedModules = $verified
        }

        $Shared.Phase = 'complete'
        $Shared.Status = 'Setup complete'
        $Shared.Done = $true
        Log "=== TURNKEY SETUP COMPLETE ===" 'INFO'

        return $results
    }).AddArgument($envData).AddArgument($sharedStatus) | Out-Null

    $script:TurnkeyPS = $ps
    $script:TurnkeyAsync = $ps.BeginInvoke()
    $script:ScanTimer.Start()
}

function Complete-AsyncTurnkey {
    try {
        $output = $script:TurnkeyPS.EndInvoke($script:TurnkeyAsync)
        $data = if ($output -and $output.Count -gt 0) { $output[0] } else { $null }

        # Flush remaining log entries
        while ($script:TurnkeyStatus.Log.Count -gt 0) {
            try {
                $entry = $script:TurnkeyStatus.Log[0]
                $script:TurnkeyStatus.Log.RemoveAt(0)
                if ($entry -is [hashtable]) { Write-Log $entry.Msg $entry.Level }
                elseif ($entry -is [string]) { Write-Log $entry 'INFO' }
            } catch { break }
        }

        if ($data) {
            # Update environment with newly installed modules
            foreach ($modName in $data.VerifiedModules) {
                $mc = $script:Env.MissingModules | Where-Object { $_.Name -eq $modName }
                if ($mc) {
                    $script:Env[$mc.EnvKey] = $true
                    $script:Env.InstalledModules.Add($mc.Name) | Out-Null
                    $script:Env.MissingModules.Remove($mc) | Out-Null
                }
            }
            # Re-check capabilities
            try { if (Get-Module ActiveDirectory -ListAvailable -EA SilentlyContinue) { $script:Env.HasAD = $true } } catch {}
            try { if (Get-Module DnsServer -ListAvailable -EA SilentlyContinue) { $script:Env.HasDNS = $true } } catch {}
            try { if (Get-Module GroupPolicy -ListAvailable -EA SilentlyContinue) { $script:Env.HasGPO = $true } } catch {}

            # Update WinRM status
            if ($data.WinRM.Success) { $script:Env.WinRMRunning = $true }

            # Store discovered DCs
            $script:DiscoveredDCs = @($data.DCs)

            # Auto-set scan target to best target (DC or localhost)
            if ($data.BestTarget) {
                $el['txtScanTarget'].Text = $data.BestTarget
                Write-Log "Scan target set to: $($data.BestTarget)" 'INFO'
            }

            # Log final capability summary
            $caps = @()
            if ($script:Env.HasDefender)  { $caps += 'Defender' }
            if ($script:Env.HasSMB)       { $caps += 'SMB' }
            if ($script:Env.HasBitLocker) { $caps += 'BitLocker' }
            if ($script:Env.HasAppLocker) { $caps += 'AppLocker' }
            if ($script:Env.HasAD)        { $caps += 'AD' }
            if ($script:Env.HasDNS)       { $caps += 'DNS' }
            if ($script:Env.HasGPO)       { $caps += 'GPO' }
            Write-Log "Final capabilities: $(if($caps.Count -gt 0){$caps -join ', '}else{'(none)'})" 'INFO'

            if ($script:DiscoveredDCs.Count -gt 0) {
                Write-Log "Available DCs: $($script:DiscoveredDCs -join ', ')" 'INFO'
            }
        }

        $el['StatusText'].Text = "Setup complete - starting pre-flight..."
    }
    catch {
        Write-Log "Turnkey setup error: $($_.Exception.Message)" 'ERROR'
        $el['StatusText'].Text = "Setup error - starting pre-flight anyway..."
    }
    finally {
        if ($script:TurnkeyPS) {
            $script:TurnkeyPS.Dispose()
            $script:TurnkeyPS = $null
        }
        $script:TurnkeyAsync = $null
    }

    # Chain into preflight
    Write-Log "Starting automatic pre-flight check..." 'INFO'
    Start-AsyncPreflight
}

# ── Pre-flight Connectivity Check (Async) ───────────────────────────────────
$script:PreflightResults = @{}
$script:PreflightPS = $null
$script:PreflightAsync = $null

function Start-AsyncPreflight {
    $target = $el['txtScanTarget'].Text
    $cred = $script:ScanCredential
    $script:ScanRunning = $true
    $el['btnPreflight'].IsEnabled = $false
    $el['btnScanAll'].IsEnabled = $false; $el['btnScanAD'].IsEnabled = $false; $el['btnScanLocal'].IsEnabled = $false
    $el['StatusText'].Text = "Pre-flight: checking connectivity..."
    Write-Log "Pre-flight started for target: $target" 'INFO'

    $ps = [PowerShell]::Create()
    $ps.AddScript({
        param($Target, $Credential)
        $isLocal = ($Target -eq 'localhost' -or $Target -eq '127.0.0.1' -or $Target -eq $env:COMPUTERNAME)
        $results = [ordered]@{}
        $log = [System.Collections.ArrayList]@()

        # 1. Ping
        if ($isLocal) { $results['Ping'] = 'OK'; $log.Add("[OK]  Ping: localhost (skipped)") | Out-Null }
        else {
            try {
                $p = Test-Connection -ComputerName $Target -Count 1 -Quiet -EA Stop
                if ($p) { $results['Ping'] = 'OK'; $log.Add("[OK]  Ping: $Target responded") | Out-Null }
                else { $results['Ping'] = 'FAIL'; $log.Add("[FAIL] Ping: $Target not responding") | Out-Null }
            } catch { $results['Ping'] = 'FAIL'; $log.Add("[FAIL] Ping: $_") | Out-Null }
        }
        # 2. WinRM
        if (-not $isLocal) {
            try {
                $params = @{ ComputerName = $Target; ErrorAction = 'Stop' }
                if ($Credential) { $params.Credential = $Credential }
                $ws = Test-WSMan @params
                $results['WinRM'] = 'OK'; $log.Add("[OK]  WinRM: Connected ($($ws.ProductVersion))") | Out-Null
            } catch {
                $results['WinRM'] = 'FAIL'
                $log.Add("[FAIL] WinRM: $($_.Exception.Message)") | Out-Null
                $log.Add("       Fix: Enable-PSRemoting -Force on target, check port 5985/5986") | Out-Null
            }
        } else { $results['WinRM'] = 'OK'; $log.Add("[OK]  WinRM: local (not required)") | Out-Null }
        # 3. AD Module
        if (Get-Module ActiveDirectory -ListAvailable -EA SilentlyContinue) {
            try {
                Import-Module ActiveDirectory -EA Stop
                $domain = (Get-ADDomain -EA Stop).DNSRoot
                $results['AD'] = 'OK'; $log.Add("[OK]  AD: Module loaded, domain '$domain'") | Out-Null
            } catch { $results['AD'] = 'WARN'; $log.Add("[WARN] AD: Module available but domain unreachable: $_") | Out-Null }
        } else { $results['AD'] = 'FAIL'; $log.Add("[FAIL] AD: RSAT module not installed") | Out-Null }
        # 4. SMB
        try {
            $smbCfg = Get-SmbServerConfiguration -EA Stop
            $results['SMB'] = 'OK'; $log.Add("[OK]  SMB: Accessible | SMB1=$($smbCfg.EnableSMB1Protocol) | Encrypt=$($smbCfg.EncryptData)") | Out-Null
        } catch { $results['SMB'] = 'WARN'; $log.Add("[WARN] SMB: $($_.Exception.Message)") | Out-Null }
        # 5. DNS
        try {
            $dns = Resolve-DnsName 'microsoft.com' -EA Stop -DnsOnly | Select-Object -First 1
            $results['DNS'] = 'OK'; $log.Add("[OK]  DNS: microsoft.com -> $($dns.IPAddress)") | Out-Null
        } catch { $results['DNS'] = 'FAIL'; $log.Add("[FAIL] DNS: $_") | Out-Null }
        # 6. Elevation
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if ($isAdmin) { $results['Elevation'] = 'OK'; $log.Add("[OK]  Elevation: Administrator") | Out-Null }
        else { $results['Elevation'] = 'WARN'; $log.Add("[WARN] Elevation: NOT Administrator") | Out-Null }
        # 7. Defender
        try {
            $mp = Get-MpComputerStatus -EA Stop
            $results['Defender'] = 'OK'; $log.Add("[OK]  Defender: RealTime=$($mp.RealTimeProtectionEnabled)") | Out-Null
        } catch { $results['Defender'] = 'WARN'; $log.Add("[WARN] Defender: Not available") | Out-Null }

        return @{ Results=$results; Log=$log; IsLocal=$isLocal }
    }).AddArgument($target).AddArgument($cred) | Out-Null

    $script:PreflightPS = $ps
    $script:PreflightAsync = $ps.BeginInvoke()
    $script:ScanTimer.Start()
}

function Complete-AsyncPreflight {
    try {
        $output = $script:PreflightPS.EndInvoke($script:PreflightAsync)
        if ($output -and $output.Count -gt 0) {
            $data = $output[0]
            $script:PreflightResults = $data.Results

            # Write all log entries to console
            foreach ($line in $data.Log) { Write-Log $line 'PREFLIGHT' }

            $okCount = ($data.Results.Values | Where-Object { $_ -eq 'OK' }).Count
            $warnCount = ($data.Results.Values | Where-Object { $_ -eq 'WARN' }).Count
            $failCount = ($data.Results.Values | Where-Object { $_ -eq 'FAIL' }).Count
            Write-Log "Pre-flight result: $okCount OK, $warnCount Warn, $failCount Fail" 'INFO'

            # Scan availability
            $canAD = $data.Results['AD'] -eq 'OK'
            $canLocal = $data.IsLocal -or $data.Results['WinRM'] -eq 'OK'
            $adChecks = ($script:AutoChecks.Values | Where-Object { $_.Type -eq 'AD' }).Count
            $localChecks = ($script:AutoChecks.Values | Where-Object { $_.Type -eq 'Local' }).Count
            $availTotal = 0
            if ($canAD) { $availTotal += $adChecks }
            if ($canLocal) { $availTotal += $localChecks }
            Write-Log "Scannable: $availTotal of $($script:AutoChecks.Count) (AD:$(if($canAD){'ready'}else{'unavail'}) Local:$(if($canLocal){'ready'}else{'unavail'}))" 'INFO'

            $el['StatusText'].Text = "Pre-flight complete: $okCount OK, $warnCount Warn, $failCount Fail"

            # Turnkey: prompt for scan after preflight
            if (($script:TurnkeyLaunched -or $script:FullAuditMode) -and -not $script:TurnkeyAutoScan) {
                $scannable = $availTotal
                if ($scannable -gt 0) {
                    if ($script:FullAuditMode) {
                        # Full Audit mode: no prompt, just go
                        Write-Log "Full Audit: auto-starting scan ($scannable checks)" 'INFO'
                        $script:TurnkeyAutoScan = $true
                        Start-ScanBatch 'All'
                        $script:ScanTimer.Start()
                    }
                    else {
                        $r = [System.Windows.MessageBox]::Show(
                            "Pre-flight complete. $scannable auto-checks are available.`n`nRun all scans now?`n`nTarget: $($el['txtScanTarget'].Text)",
                            'Run Auto-Scan', 'YesNo', 'Question')
                        if ($r -eq 'Yes') {
                            $script:TurnkeyAutoScan = $true
                            Start-ScanBatch 'All'
                            $script:ScanTimer.Start()
                        }
                    }
                }
                elseif ($script:FullAuditMode) {
                    Write-Log "Full Audit: no scannable checks available after preflight" 'WARN'
                    $script:FullAuditMode = $false
                }
            }
        }
    }
    catch {
        Write-Log "Pre-flight error: $($_.Exception.Message)" 'ERROR'
        $el['StatusText'].Text = "Pre-flight failed"
    }
    finally {
        $script:PreflightPS.Dispose()
        $script:PreflightPS = $null
        $script:PreflightAsync = $null
        $script:ScanRunning = $false
        $el['btnFullAudit'].IsEnabled = $true
        $el['btnPreflight'].IsEnabled = $true
        $el['btnScanAll'].IsEnabled = $true; $el['btnScanAD'].IsEnabled = $true; $el['btnScanLocal'].IsEnabled = $true
    }
}

$el['btnPreflight'].Add_Click({
    if ($script:ScanRunning) { return }
    Start-AsyncPreflight
})

$el['btnScanAll'].Add_Click({
    if ($script:ScanRunning) { return }
    $profileOrder = @('Quick','Standard','Full','ADOnly','LocalOnly','HIPAA','PCI','CMMC','SOC2','ISO27001')
    $selIdx = $el['cboProfile'].SelectedIndex
    if ($selIdx -lt 0) { $selIdx = 2 }
    $profName = $profileOrder[$selIdx]
    $prof = $script:ScanProfiles[$profName]
    $checkCount = if ($prof.IDs.Count -gt 0) { $prof.IDs.Count } else { $script:AutoChecks.Count }
    $roTag = if ($script:ReadOnlyMode) { "`n[Read-Only Mode: safe, non-modifying checks only]" } else { '' }
    $r = [System.Windows.MessageBox]::Show("Run $profName scan (~$checkCount checks)?$roTag`n`nProfile: $($prof.Label)`nTarget: $($el['txtScanTarget'].Text)`n`nThis will overwrite existing Findings/Evidence fields for scanned items.", 'Confirm Scan', 'YesNo', 'Question')
    if ($r -eq 'Yes') {
        Start-ScanBatch 'Profile'
        $script:ScanTimer.Start()
    }
})

$el['btnScanAD'].Add_Click({
    if ($script:ScanRunning) { return }
    Start-ScanBatch 'AD'
    $script:ScanTimer.Start()
})

$el['btnScanLocal'].Add_Click({
    if ($script:ScanRunning) { return }
    Start-ScanBatch 'Local'
    $script:ScanTimer.Start()
})

# ── Filter View Modes ───────────────────────────────────────────────────────
function Apply-ItemFilter([string]$mode) {
    $script:ActiveFilter = $mode
    $t = Get-T
    $shown = 0; $hidden = 0

    foreach ($id in $script:CheckStates.Keys) {
        $card = $script:ItemCards[$id]
        if (-not $card) { continue }

        $visible = $true
        switch ($mode) {
            'All' { $visible = $true }
            'Incomplete' {
                $visible = -not $script:CheckStates[$id]
            }
            'Fail' {
                $combo = $script:StatusCombos[$id]
                $statusVal = if ($combo.SelectedItem) { $combo.SelectedItem.ToString() } else { 'Not Assessed' }
                $visible = $statusVal -eq 'Fail'
            }
            'Scanned' {
                $visible = $script:ScanTimestamps.Contains($id)
            }
        }

        if ($visible) {
            $card.Visibility = [System.Windows.Visibility]::Visible
            $shown++
        } else {
            $card.Visibility = [System.Windows.Visibility]::Collapsed
            $hidden++
        }
    }

    # Update filter button highlighting
    foreach ($fb in @('btnFilterAll','btnFilterIncomplete','btnFilterFail','btnFilterScanned')) {
        $btnMode = $fb -replace 'btnFilter',''
        if ($btnMode -eq $mode) {
            Apply-ButtonTheme $el[$fb] $t.Accent $t.AccentHover
        } else {
            Apply-ButtonTheme $el[$fb] $t.SurfaceBg $t.HoverBg
            $el[$fb].Foreground = New-Brush $t.TextPrimary
        }
    }

    $el['StatusText'].Text = "Filter: $mode | Showing $shown items, $hidden hidden"
    Write-Log "Filter applied: $mode (showing $shown, hidden $hidden)"
}

$el['btnFilterAll'].Add_Click({ Apply-ItemFilter 'All' })
$el['btnFilterIncomplete'].Add_Click({ Apply-ItemFilter 'Incomplete' })
$el['btnFilterFail'].Add_Click({ Apply-ItemFilter 'Fail' })
$el['btnFilterScanned'].Add_Click({ Apply-ItemFilter 'Scanned' })

# ── Zoom / DPI Scaling (Ctrl+MouseWheel) ────────────────────────────────────
$script:ZoomLevel = 1.0
$script:ZoomTransform = New-Object System.Windows.Media.ScaleTransform(1.0, 1.0)
$el['RootGrid'].LayoutTransform = $script:ZoomTransform

$window.Add_PreviewMouseWheel({
    if ([System.Windows.Input.Keyboard]::Modifiers -eq [System.Windows.Input.ModifierKeys]::Control) {
        $_.Handled = $true
        $delta = if ($_.Delta -gt 0) { 0.05 } else { -0.05 }
        $script:ZoomLevel = [math]::Max(0.5, [math]::Min(2.5, $script:ZoomLevel + $delta))
        $script:ZoomTransform.ScaleX = $script:ZoomLevel
        $script:ZoomTransform.ScaleY = $script:ZoomLevel
        $zPct = [math]::Round($script:ZoomLevel * 100)
        $el['StatusText'].Text = "Zoom: ${zPct}% (Ctrl+Wheel to adjust, Ctrl+0 to reset)"
    }
})
$window.Add_PreviewKeyDown({
    $key = $_.Key
    $mods = [System.Windows.Input.Keyboard]::Modifiers
    $ctrl = $mods -band [System.Windows.Input.ModifierKeys]::Control
    $shift = $mods -band [System.Windows.Input.ModifierKeys]::Shift

    # Ctrl+0: Zoom reset
    if ($ctrl -and ($key -eq [System.Windows.Input.Key]::D0 -or $key -eq [System.Windows.Input.Key]::NumPad0)) {
        $script:ZoomLevel = 1.0; $script:ZoomTransform.ScaleX = 1.0; $script:ZoomTransform.ScaleY = 1.0
        $el['StatusText'].Text = "Zoom reset to 100%"; $_.Handled = $true; return
    }

    # Don't intercept keyboard when a text input is focused
    $focused = [System.Windows.Input.Keyboard]::FocusedElement
    if ($focused -is [System.Windows.Controls.TextBox] -or $focused -is [System.Windows.Controls.ComboBox]) {
        # Allow Escape to defocus text inputs
        if ($key -eq [System.Windows.Input.Key]::Escape) {
            [System.Windows.Input.Keyboard]::ClearFocus()
            $_.Handled = $true
        }
        return
    }

    # Helper: get ordered IDs for current tab
    $tabIdx = $el['MainTabs'].SelectedIndex
    if ($tabIdx -lt 0 -or -not $script:TabItemIDs.Contains($tabIdx)) { return }
    $ids = $script:TabItemIDs[$tabIdx]
    if ($ids.Count -eq 0) { return }

    # Helper: find current position
    $curPos = -1
    if ($script:HighlightedCard) {
        $curPos = $ids.IndexOf($script:HighlightedCard)
    }

    switch ($key) {

        # ── Arrow Down / J: Next item ───────────────────────────────
        { $_ -eq [System.Windows.Input.Key]::Down -or $_ -eq [System.Windows.Input.Key]::J } {
            $_.Handled = $true
            if ($ctrl) {
                # Ctrl+Down: next tab
                $nextTab = ($tabIdx + 1) % $script:TabIndex
                $el['MainTabs'].SelectedIndex = $nextTab
                $nIds = $script:TabItemIDs[$nextTab]
                if ($nIds -and $nIds.Count -gt 0) {
                    $timer = New-Object System.Windows.Threading.DispatcherTimer
                    $timer.Interval = [TimeSpan]::FromMilliseconds(80)
                    $timer.Tag = $nIds[0]
                    $timer.Add_Tick({ $this.Stop(); Highlight-ItemCard $this.Tag; Expand-ItemCard $this.Tag })
                    $timer.Start()
                }
                $el['StatusText'].Text = "Tab: $($el['MainTabs'].Items[$nextTab].Header)"
            } else {
                # Find next visible item
                $found = $false
                for ($i = $curPos + 1; $i -lt $ids.Count; $i++) {
                    $nid = $ids[$i]
                    $nCard = $script:ItemCards[$nid]
                    if ($nCard -and $nCard.Visibility -eq [System.Windows.Visibility]::Visible) {
                        Highlight-ItemCard $nid; Expand-ItemCard $nid; $found = $true; break
                    }
                }
                if (-not $found -and $curPos -ne 0) {
                    # Wrap to first visible
                    for ($i = 0; $i -lt $ids.Count; $i++) {
                        $nid = $ids[$i]
                        $nCard = $script:ItemCards[$nid]
                        if ($nCard -and $nCard.Visibility -eq [System.Windows.Visibility]::Visible) {
                            Highlight-ItemCard $nid; Expand-ItemCard $nid; break
                        }
                    }
                }
            }
        }

        # ── Arrow Up / K: Previous item ─────────────────────────────
        { $_ -eq [System.Windows.Input.Key]::Up -or $_ -eq [System.Windows.Input.Key]::K } {
            $_.Handled = $true
            if ($ctrl) {
                # Ctrl+Up: previous tab
                $prevTab = ($tabIdx - 1 + $script:TabIndex) % $script:TabIndex
                $el['MainTabs'].SelectedIndex = $prevTab
                $pIds = $script:TabItemIDs[$prevTab]
                if ($pIds -and $pIds.Count -gt 0) {
                    $timer = New-Object System.Windows.Threading.DispatcherTimer
                    $timer.Interval = [TimeSpan]::FromMilliseconds(80)
                    $timer.Tag = $pIds[$pIds.Count - 1]
                    $timer.Add_Tick({ $this.Stop(); Highlight-ItemCard $this.Tag; Expand-ItemCard $this.Tag })
                    $timer.Start()
                }
                $el['StatusText'].Text = "Tab: $($el['MainTabs'].Items[$prevTab].Header)"
            } else {
                # Find previous visible item
                $found = $false
                $start = if ($curPos -gt 0) { $curPos - 1 } else { $ids.Count - 1 }
                for ($i = $start; $i -ge 0; $i--) {
                    $nid = $ids[$i]
                    $nCard = $script:ItemCards[$nid]
                    if ($nCard -and $nCard.Visibility -eq [System.Windows.Visibility]::Visible) {
                        Highlight-ItemCard $nid; Expand-ItemCard $nid; $found = $true; break
                    }
                }
                if (-not $found) {
                    # Wrap to last visible
                    for ($i = $ids.Count - 1; $i -ge 0; $i--) {
                        $nid = $ids[$i]
                        $nCard = $script:ItemCards[$nid]
                        if ($nCard -and $nCard.Visibility -eq [System.Windows.Visibility]::Visible) {
                            Highlight-ItemCard $nid; Expand-ItemCard $nid; break
                        }
                    }
                }
            }
        }

        # ── Space: Toggle checkbox ──────────────────────────────────
        ([System.Windows.Input.Key]::Space) {
            if ($script:HighlightedCard -and $script:CheckBoxes.Contains($script:HighlightedCard)) {
                $_.Handled = $true
                $cb = $script:CheckBoxes[$script:HighlightedCard]
                $cb.IsChecked = -not $cb.IsChecked
            }
        }

        # ── Enter: Expand/Collapse ──────────────────────────────────
        ([System.Windows.Input.Key]::Return) {
            if ($script:HighlightedCard) {
                $_.Handled = $true
                $panel = $script:ItemPanels[$script:HighlightedCard]
                if ($panel -and $panel.Children.Count -gt 1) {
                    $isCollapsed = $panel.Children[1].Visibility -eq [System.Windows.Visibility]::Collapsed
                    if ($isCollapsed) { Expand-ItemCard $script:HighlightedCard }
                    else { Collapse-ItemCard $script:HighlightedCard }
                }
            }
        }

        # ── Tab: Jump to next unchecked / Shift+Tab: previous unchecked
        ([System.Windows.Input.Key]::Tab) {
            $_.Handled = $true
            if ($shift) {
                # Previous unchecked
                $start = if ($curPos -gt 0) { $curPos - 1 } else { $ids.Count - 1 }
                $found = $false
                for ($i = $start; $i -ge 0; $i--) {
                    $nid = $ids[$i]
                    $nCard = $script:ItemCards[$nid]
                    if (-not $script:CheckStates[$nid] -and $nCard -and $nCard.Visibility -eq [System.Windows.Visibility]::Visible) {
                        Highlight-ItemCard $nid; Expand-ItemCard $nid; $found = $true; break
                    }
                }
                if (-not $found) {
                    # Wrap search from end
                    for ($i = $ids.Count - 1; $i -gt $curPos; $i--) {
                        $nid = $ids[$i]
                        $nCard = $script:ItemCards[$nid]
                        if (-not $script:CheckStates[$nid] -and $nCard -and $nCard.Visibility -eq [System.Windows.Visibility]::Visible) {
                            Highlight-ItemCard $nid; Expand-ItemCard $nid; $found = $true; break
                        }
                    }
                }
                if (-not $found) { $el['StatusText'].Text = "All items in this tab are checked" }
            } else {
                # Forward: next unchecked in current tab, then cross-tab
                $found = $false
                $start = if ($curPos -ge 0) { $curPos + 1 } else { 0 }
                for ($i = $start; $i -lt $ids.Count; $i++) {
                    $nid = $ids[$i]
                    $nCard = $script:ItemCards[$nid]
                    if (-not $script:CheckStates[$nid] -and $nCard -and $nCard.Visibility -eq [System.Windows.Visibility]::Visible) {
                        Highlight-ItemCard $nid; Expand-ItemCard $nid; $found = $true; break
                    }
                }
                if (-not $found) {
                    # Cross-tab advance
                    Advance-ToNext $(if($script:HighlightedCard){$script:HighlightedCard}else{$ids[$ids.Count-1]})
                }
            }
        }

        # ── Escape: Clear selection ─────────────────────────────────
        ([System.Windows.Input.Key]::Escape) {
            if ($script:HighlightedCard) {
                $_.Handled = $true
                $t = Get-T
                $script:ItemCards[$script:HighlightedCard].BorderBrush = New-Brush $t.BorderDim
                $script:ItemCards[$script:HighlightedCard].BorderThickness = [System.Windows.Thickness]::new(1)
                $script:HighlightedCard = $null
                $el['StatusText'].Text = "Selection cleared"
            }
        }

        # ── 1-4: Set status combo ───────────────────────────────────
        { $_ -in @([System.Windows.Input.Key]::D1,[System.Windows.Input.Key]::D2,[System.Windows.Input.Key]::D3,[System.Windows.Input.Key]::D4) } {
            if ($script:HighlightedCard -and -not $ctrl -and $script:StatusCombos.Contains($script:HighlightedCard)) {
                $_.Handled = $true
                $idx = switch ($_) {
                    ([System.Windows.Input.Key]::D1) { 1 }  # Compliant
                    ([System.Windows.Input.Key]::D2) { 2 }  # Non-Compliant
                    ([System.Windows.Input.Key]::D3) { 3 }  # Partial
                    ([System.Windows.Input.Key]::D4) { 4 }  # N/A
                }
                $combo = $script:StatusCombos[$script:HighlightedCard]
                if ($idx -lt $combo.Items.Count) {
                    $combo.SelectedIndex = $idx
                    $el['StatusText'].Text = "$script:HighlightedCard -> $($combo.SelectedItem)"
                }
            }
        }

        # ── S: Run scan on highlighted item ─────────────────────────
        ([System.Windows.Input.Key]::S) {
            if ($script:HighlightedCard -and $script:AutoCheckIDs.Contains($script:HighlightedCard) -and -not $script:ScanRunning) {
                $_.Handled = $true
                Start-SingleCheck $script:HighlightedCard
            }
        }

        # ── H: Toggle hint ─────────────────────────────────────────
        ([System.Windows.Input.Key]::H) {
            if ($script:HighlightedCard -and $script:HintBlocks.Contains($script:HighlightedCard)) {
                $_.Handled = $true
                $hb = $script:HintBlocks[$script:HighlightedCard]
                if ($hb.Visibility -eq [System.Windows.Visibility]::Visible) {
                    $hb.Visibility = [System.Windows.Visibility]::Collapsed
                } else {
                    $hb.Visibility = [System.Windows.Visibility]::Visible
                }
            }
        }

        # ── F: Focus findings box ──────────────────────────────────
        ([System.Windows.Input.Key]::F) {
            if ($script:HighlightedCard -and $script:FindingsBoxes.Contains($script:HighlightedCard)) {
                $_.Handled = $true
                Expand-ItemCard $script:HighlightedCard
                $script:FindingsBoxes[$script:HighlightedCard].Focus() | Out-Null
            }
        }

        # ── N: Focus notes box ─────────────────────────────────────
        ([System.Windows.Input.Key]::N) {
            if ($script:HighlightedCard -and $script:NotesBoxes.Contains($script:HighlightedCard)) {
                $_.Handled = $true
                Expand-ItemCard $script:HighlightedCard
                $script:NotesBoxes[$script:HighlightedCard].Focus() | Out-Null
            }
        }

        # ── ?: Show keyboard shortcuts ──────────────────────────────
        ([System.Windows.Input.Key]::OemQuestion) {
            if ($shift) {
                $_.Handled = $true
                $helpText = @"
KEYBOARD SHORTCUTS

Navigation:
  Up / K          Previous item
  Down / J        Next item
  Ctrl+Up         Previous tab
  Ctrl+Down       Next tab
  Tab             Next unchecked item (cross-tab)
  Shift+Tab       Previous unchecked item

Actions:
  Space           Toggle checkbox
  Enter           Expand / collapse item
  1               Set Compliant
  2               Set Non-Compliant
  3               Set Partial
  4               Set N/A
  S               Run auto-scan (if available)
  H               Toggle hint text
  F               Focus findings field
  N               Focus notes field
  Escape          Clear selection / defocus text
  Ctrl+0          Reset zoom to 100%
  Ctrl+Wheel      Zoom in/out
  ?               Show this help
"@
                [System.Windows.MessageBox]::Show($helpText, 'Keyboard Shortcuts', 'OK', 'Information')
            }
        }
    }
})

# ── Save / Load ──────────────────────────────────────────────────────────────
function Get-AuditState {
    $state = @{ Client=$el['txtClient'].Text; Auditor=$el['txtAuditor'].Text; Date=$el['txtDate'].Text; Theme=$script:CurrentThemeName; Version='4.0'; ScanTarget=$el['txtScanTarget'].Text; Items=@{} }
    foreach ($id in $script:CheckStates.Keys) {
        $sv=if($script:StatusCombos[$id].SelectedItem){$script:StatusCombos[$id].SelectedItem.ToString()}else{'Not Assessed'}
        $rs4=if($script:RemStatusCombos[$id].SelectedItem){$script:RemStatusCombos[$id].SelectedItem.ToString()}else{'Open'}
        $state.Items[$id] = @{
            Checked=$script:CheckStates[$id]; Status=$sv; Notes=$script:NotesBoxes[$id].Text
            Findings=$script:FindingsBoxes[$id].Text; Evidence=$script:EvidenceBoxes[$id].Text
            RemAssign=$script:RemAssignBoxes[$id].Text; RemDue=$script:RemDueBoxes[$id].Text; RemStatus=$rs4
            ScanTime=if($script:ScanTimestamps.Contains($id)){$script:ScanTimestamps[$id]}else{$null}
        }
    }
    return $state
}

function Set-AuditState($state) {
    $script:SuppressAdvance = $true
    $el['txtClient'].Text=$state.Client; $el['txtAuditor'].Text=$state.Auditor; $el['txtDate'].Text=$state.Date
    if ($state.ScanTarget) { $el['txtScanTarget'].Text = $state.ScanTarget }
    if ($state.Theme -and $script:Themes.Contains($state.Theme)) {
        $script:CurrentThemeName=$state.Theme
        for($i=0;$i -lt $el['ThemeSelector'].Items.Count;$i++){if($el['ThemeSelector'].Items[$i] -eq $state.Theme){$el['ThemeSelector'].SelectedIndex=$i;break}}
        Apply-Theme
    }
    foreach ($id in $state.Items.Keys) {
        $it=$state.Items[$id]
        if($script:CheckBoxes.Contains($id)){$script:CheckBoxes[$id].IsChecked=$it.Checked}
        if($script:StatusCombos.Contains($id)){$c=$script:StatusCombos[$id];for($i=0;$i -lt $c.Items.Count;$i++){if($c.Items[$i] -eq $it.Status){$c.SelectedIndex=$i;break}}}
        if($script:NotesBoxes.Contains($id)){$script:NotesBoxes[$id].Text=$it.Notes}
        if($script:FindingsBoxes.Contains($id)){$script:FindingsBoxes[$id].Text=$it.Findings}
        if($script:EvidenceBoxes.Contains($id)){$script:EvidenceBoxes[$id].Text=$it.Evidence}
        if($script:RemAssignBoxes.Contains($id)){$script:RemAssignBoxes[$id].Text=$it.RemAssign}
        if($script:RemDueBoxes.Contains($id)){$script:RemDueBoxes[$id].Text=$it.RemDue}
        if($script:RemStatusCombos.Contains($id)){$c2=$script:RemStatusCombos[$id];for($i=0;$i -lt $c2.Items.Count;$i++){if($c2.Items[$i] -eq $it.RemStatus){$c2.SelectedIndex=$i;break}}}
        # Restore scan timestamp and button state
        if ($it.ScanTime) {
            $script:ScanTimestamps[$id] = $it.ScanTime
            if ($script:ScanButtons.Contains($id)) {
                $script:ScanButtons[$id].ToolTip = "Last: $($it.ScanTime) - Click to re-scan"
            }
        }
        # Sync card visual state
        if ($it.Checked) { Collapse-ItemCard $id } else { Expand-ItemCard $id }
    }
    $script:SuppressAdvance = $false
    Update-Progress
}

$el['btnSave'].Add_Click({
    $dlg=New-Object Microsoft.Win32.SaveFileDialog; $dlg.Filter='JSON|*.json'; $dlg.FileName="Audit_$($el['txtClient'].Text -replace '\s','_')_$(Get-Date -Format 'yyyyMMdd').json"
    if($dlg.ShowDialog()){(Get-AuditState)|ConvertTo-Json -Depth 5|Set-Content $dlg.FileName -Encoding UTF8; $el['StatusText'].Text="Saved: $($dlg.FileName)"; Write-Log "Audit saved: $($dlg.FileName)" 'INFO'}
})

$el['btnLoad'].Add_Click({
    $dlg=New-Object Microsoft.Win32.OpenFileDialog; $dlg.Filter='JSON|*.json'
    if($dlg.ShowDialog()){
        try{
            $j=Get-Content $dlg.FileName -Raw|ConvertFrom-Json
            $st=@{Client=$j.Client;Auditor=$j.Auditor;Date=$j.Date;Theme=$j.Theme;ScanTarget=$j.ScanTarget;Items=@{}}
            foreach($p in $j.Items.PSObject.Properties){
                $st.Items[$p.Name]=@{
                    Checked=[bool]$p.Value.Checked;Status=$p.Value.Status;Notes=$p.Value.Notes
                    Findings=$p.Value.Findings;Evidence=$p.Value.Evidence
                    RemAssign=$p.Value.RemAssign;RemDue=$p.Value.RemDue;RemStatus=$p.Value.RemStatus
                    ScanTime=$p.Value.ScanTime
                }
            }
            Set-AuditState $st; $el['StatusText'].Text="Loaded: $($dlg.FileName)"; Write-Log "Audit loaded: $($dlg.FileName) ($($st.Items.Count) items)" 'INFO'
        } catch { [System.Windows.MessageBox]::Show("Failed: $_",'Error','OK','Error'); Write-Log "Load failed: $_" 'ERROR' }
    }
})

# ── Diff Comparison ──────────────────────────────────────────────────────────
$el['btnDiff'].Add_Click({
    $dlg1=New-Object Microsoft.Win32.OpenFileDialog; $dlg1.Filter='JSON|*.json'; $dlg1.Title='Select FIRST (older) audit'
    if(-not $dlg1.ShowDialog()){return}
    $dlg2=New-Object Microsoft.Win32.OpenFileDialog; $dlg2.Filter='JSON|*.json'; $dlg2.Title='Select SECOND (newer) audit'
    if(-not $dlg2.ShowDialog()){return}

    try {
        $j1=Get-Content $dlg1.FileName -Raw|ConvertFrom-Json; $j2=Get-Content $dlg2.FileName -Raw|ConvertFrom-Json
        $sb=[System.Text.StringBuilder]::new()
        [void]$sb.AppendLine("AUDIT COMPARISON REPORT")
        [void]$sb.AppendLine("=" * 60)
        [void]$sb.AppendLine("Audit 1: $($j1.Client) - $($j1.Date) (Auditor: $($j1.Auditor))")
        [void]$sb.AppendLine("Audit 2: $($j2.Client) - $($j2.Date) (Auditor: $($j2.Auditor))")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("CHANGES:")
        [void]$sb.AppendLine("-" * 40)

        $changes = 0
        foreach ($cn in $script:AuditCategories.Keys) {
            foreach ($it in $script:AuditCategories[$cn].Items) {
                $id=$it.ID
                $s1=if($j1.Items.PSObject.Properties[$id]){$j1.Items.$id.Status}else{'N/A'}
                $s2=if($j2.Items.PSObject.Properties[$id]){$j2.Items.$id.Status}else{'N/A'}
                $r1=if($j1.Items.PSObject.Properties[$id]){$j1.Items.$id.RemStatus}else{''}
                $r2=if($j2.Items.PSObject.Properties[$id]){$j2.Items.$id.RemStatus}else{''}
                if ($s1 -ne $s2 -or $r1 -ne $r2) {
                    $changes++
                    [void]$sb.AppendLine("[$id] $($it.Text)")
                    if ($s1 -ne $s2) { [void]$sb.AppendLine("  Status: $s1 -> $s2") }
                    if ($r1 -ne $r2) { [void]$sb.AppendLine("  Remediation: $r1 -> $r2") }
                    [void]$sb.AppendLine("")
                }
            }
        }
        if ($changes -eq 0) { [void]$sb.AppendLine("No changes detected between audits.") }
        else { [void]$sb.AppendLine("Total changes: $changes") }

        [System.Windows.MessageBox]::Show($sb.ToString(), "Audit Diff - $changes changes", 'OK', 'Information')
    } catch { [System.Windows.MessageBox]::Show("Diff failed: $_",'Error','OK','Error') }
})

# ── Reset ────────────────────────────────────────────────────────────────────
$el['btnReset'].Add_Click({
    if([System.Windows.MessageBox]::Show("Clear ALL data?`nThis cannot be undone.",'Reset','YesNo','Warning') -eq 'Yes'){
        $script:SuppressAdvance = $true
        foreach($id in $script:CheckStates.Keys){
            $script:CheckBoxes[$id].IsChecked=$false; $script:StatusCombos[$id].SelectedIndex=0
            $script:NotesBoxes[$id].Text=''; $script:FindingsBoxes[$id].Text=''; $script:EvidenceBoxes[$id].Text=''
            $script:RemAssignBoxes[$id].Text=''; $script:RemDueBoxes[$id].Text=''; $script:RemStatusCombos[$id].SelectedIndex=0
            Expand-ItemCard $id
        }
        $script:SuppressAdvance = $false
        $script:HighlightedCard = $null
        $el['txtClient'].Text=''; $el['txtAuditor'].Text=''; $el['txtDate'].Text=Get-Date -Format 'yyyy-MM-dd'
        Update-Progress; $el['StatusText'].Text='Reset complete'; Write-Log "Audit reset: all data cleared" 'INFO'
    }
})

# ── HTML Export (Enhanced) ───────────────────────────────────────────────────
function Export-HTMLReport([string]$outPath, [switch]$OpenAfter, [string]$Tier = '') {
    if (-not $Tier) { $Tier = $script:CliReport }
    if (-not $Tier) { $Tier = 'All' }
    $state=Get-AuditState; $risk=Get-RiskScore
    $ck2=($script:CheckStates.Values|Where-Object{$_}).Count; $tot2=$script:TotalItems
    $pct2=if($tot2 -gt 0){[math]::Round(($ck2/$tot2)*100)}else{0}
    $gc=switch($risk.Grade){'A'{'#22c55e'}'B'{'#84cc16'}'C'{'#eab308'}'D'{'#f97316'}default{'#ef4444'}}

    # Status counts
    $pass2=0;$fail2=0;$part2=0;$na2=0;$not2=0
    foreach($id in $script:CheckStates.Keys){
        $sv5=if($script:StatusCombos[$id].SelectedItem){$script:StatusCombos[$id].SelectedItem.ToString()}else{'Not Assessed'}
        switch($sv5){'Pass'{$pass2++}'Fail'{$fail2++}'Partial'{$part2++}'N/A'{$na2++}default{$not2++}}
    }

    # Scan metadata
    $scanTarget = $el['txtScanTarget'].Text
    $scannedCount = ($script:ScanTimestamps.Keys | Measure-Object).Count
    $autoAvail = $script:AutoChecks.Count

    # Category scoring
    $catScores = @{}
    foreach($cn in $script:AuditCategories.Keys){
        $cat=$script:AuditCategories[$cn]
        $catPass=0; $catFail=0; $catPart=0; $catNA=0; $catTotal=$cat.Items.Count
        foreach($it in $cat.Items){
            $sv=if($script:StatusCombos[$it.ID].SelectedItem){$script:StatusCombos[$it.ID].SelectedItem.ToString()}else{'Not Assessed'}
            switch($sv){'Pass'{$catPass++}'Fail'{$catFail++}'Partial'{$catPart++}'N/A'{$catNA++}}
        }
        $assessed = $catPass + $catFail + $catPart
        $score = if($assessed -gt 0){ [math]::Round(($catPass + $catPart * 0.5) / $assessed * 100) } else { 0 }
        $weight = if ($script:CategoryWeights.Contains($cn)) { $script:CategoryWeights[$cn] } else { 1.0 }
        $catScores[$cn] = @{ Pass=$catPass; Fail=$catFail; Partial=$catPart; NA=$catNA; Total=$catTotal; Score=$score; Weight=$weight }
    }

    # Weighted overall score
    $weightedSum = 0; $weightTotal = 0
    foreach ($cn in $catScores.Keys) {
        $cs = $catScores[$cn]
        if (($cs.Pass + $cs.Fail + $cs.Partial) -gt 0) {
            $weightedSum += $cs.Score * $cs.Weight
            $weightTotal += $cs.Weight
        }
    }
    $overallScore = if ($weightTotal -gt 0) { [math]::Round($weightedSum / $weightTotal) } else { 0 }
    $overallGrade = switch($true) { ($overallScore -ge 90){'A'} ($overallScore -ge 80){'B'} ($overallScore -ge 70){'C'} ($overallScore -ge 60){'D'} default{'F'} }
    $overallColor = switch($overallGrade){'A'{'#22c55e'}'B'{'#84cc16'}'C'{'#eab308'}'D'{'#f97316'}default{'#ef4444'}}

    # Collect all findings by severity for executive summary
    $critFindings = [System.Collections.ArrayList]@()
    $highFindings = [System.Collections.ArrayList]@()
    $medFindings = [System.Collections.ArrayList]@()
    foreach($cn in $script:AuditCategories.Keys){
        foreach($it in $script:AuditCategories[$cn].Items){
            $id=$it.ID
            $sv=if($script:StatusCombos[$id].SelectedItem){$script:StatusCombos[$id].SelectedItem.ToString()}else{'Not Assessed'}
            if ($sv -eq 'Fail') {
                $entry = @{ID=$id;Text=$it.Text;Severity=$it.Severity;Category=$cn;Findings=$script:FindingsBoxes[$id].Text}
                if ($it.Severity -eq 'Critical') { $critFindings.Add($entry) | Out-Null }
                elseif ($it.Severity -eq 'High') { $highFindings.Add($entry) | Out-Null }
                elseif ($it.Severity -eq 'Medium') { $medFindings.Add($entry) | Out-Null }
            }
        }
    }
    $totalFindings = $critFindings.Count + $highFindings.Count + $medFindings.Count

    # Profile info
    $profileOrder = @('Quick','Standard','Full','ADOnly','LocalOnly','HIPAA','PCI','CMMC','SOC2','ISO27001')
    $selIdx = $el['cboProfile'].SelectedIndex; if ($selIdx -lt 0) { $selIdx = 2 }
    $profName = $profileOrder[$selIdx]
    $roMode = if ($script:ReadOnlyMode) { 'Yes (safe mode)' } else { 'No' }

    # ── HTML Head + CSS ──────────────────────────────────────────────────────
    $html = @"
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Security Audit - $([System.Net.WebUtility]::HtmlEncode($state.Client))</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:30px;max-width:1200px;margin:0 auto;line-height:1.5}
a{color:#38bdf8;text-decoration:none}

/* Header */
.hdr{background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);border-radius:12px;padding:28px;margin-bottom:20px;border:1px solid #334155;position:relative;overflow:hidden}
.hdr::before{content:'';position:absolute;top:0;left:0;right:0;height:4px;background:linear-gradient(90deg,$overallColor,#0ea5e9)}
.hdr h1{font-size:24px;color:#f1f5f9;margin-bottom:4px;letter-spacing:-0.5px}
.hdr .sub{color:#94a3b8;font-size:13px;margin-bottom:16px}
.meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px 20px;font-size:12.5px;color:#94a3b8}
.meta-grid strong{color:#e2e8f0}

/* Score Dashboard */
.dash{display:grid;grid-template-columns:200px 1fr;gap:20px;margin:20px 0}
.score-ring{text-align:center;padding:16px}
.score-ring svg{width:140px;height:140px}
.score-stats{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}
.stat-card{background:#1e293b;border-radius:8px;padding:12px;text-align:center;border:1px solid #334155}
.stat-card .num{font-size:26px;font-weight:800;line-height:1}
.stat-card .lbl{font-size:10px;text-transform:uppercase;color:#94a3b8;margin-top:4px;letter-spacing:0.5px}

/* Category Bars */
.cat-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:16px 0}
.cat-bar{background:#1e293b;border-radius:8px;padding:14px 16px;border:1px solid #334155}
.cat-bar .top{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
.cat-bar .name{font-size:12px;font-weight:600}
.cat-bar .pct{font-size:18px;font-weight:800}
.bar-track{background:#334155;border-radius:4px;height:8px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width 0.3s}
.cat-bar .detail{font-size:10px;color:#94a3b8;margin-top:4px}

/* Sections */
.sec{background:#1e293b;border-radius:10px;padding:22px;margin-bottom:14px;border:1px solid #334155}
.sec h2{font-size:17px;margin-bottom:4px;display:flex;align-items:center;gap:8px}
.sec .d{color:#94a3b8;font-size:12px;margin-bottom:14px}
.tier-label{display:inline-block;padding:2px 10px;border-radius:12px;font-size:10px;font-weight:700;letter-spacing:0.5px;text-transform:uppercase}

/* Executive Summary */
.exec{background:linear-gradient(135deg,#1e293b,#1a1a2e);border-radius:10px;padding:22px;margin-bottom:14px;border:1px solid #334155;border-left:4px solid #f97316}
.exec h2{font-size:17px;color:#f97316;margin-bottom:12px}
.finding-list{margin:8px 0 12px 0}
.finding-item{display:flex;align-items:flex-start;gap:8px;padding:6px 0;border-bottom:1px solid #1e293b;font-size:12px}
.finding-item:last-child{border:none}

/* Remediation Roadmap */
.roadmap{margin:16px 0}
.road-phase{background:#0f172a;border-radius:8px;padding:14px;margin-bottom:8px;border-left:3px solid #a855f7}
.road-phase h4{color:#a855f7;font-size:13px;margin-bottom:6px}
.road-item{font-size:11.5px;padding:3px 0;display:flex;gap:8px}

/* Compliance Matrix */
.comp-matrix{margin:12px 0}
.comp-matrix table{width:100%;font-size:11px}
.comp-matrix th{background:#0f172a;padding:6px 8px;text-align:center;border:1px solid #334155;font-weight:600;color:#94a3b8}
.comp-matrix td{padding:5px 8px;border:1px solid #1e293b;text-align:center;font-size:10px}

/* Framework Scorecard */
.fw-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin:12px 0}
.fw-card{background:#0f172a;border-radius:8px;padding:12px;text-align:center;border:1px solid #334155;border-top:3px solid}
.fw-card .fw-name{font-size:10px;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px}
.fw-card .fw-score{font-size:24px;font-weight:800;line-height:1}
.fw-card .fw-detail{font-size:9px;color:#94a3b8;margin-top:4px}

/* Gap Analysis */
.gap-section{margin:12px 0}
.gap-ctrl{background:#0f172a;border-radius:6px;padding:10px 14px;margin-bottom:6px;border-left:3px solid #ef4444;font-size:12px}
.gap-ctrl .gap-id{font-weight:700;color:#ef4444;margin-right:8px}
.gap-ctrl .gap-refs{font-size:10px;color:#94a3b8;margin-top:2px}

/* MITRE ATT&CK Heatmap */
.mitre-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(80px,1fr));gap:4px;margin:12px 0}
.mitre-cell{border-radius:6px;padding:8px 4px;text-align:center;border:1px solid #334155;position:relative}
.mitre-cell .m-name{font-size:8px;text-transform:uppercase;letter-spacing:0.3px;margin-bottom:2px}
.mitre-cell .m-pct{font-size:18px;font-weight:800;line-height:1}
.mitre-cell .m-det{font-size:8px;color:#94a3b8;margin-top:2px}

/* Attack Paths */
.atk-path{background:#0f172a;border-radius:8px;padding:14px;margin-bottom:10px;border-left:3px solid #ef4444}
.atk-path h4{font-size:13px;margin-bottom:8px;display:flex;align-items:center;gap:8px}
.atk-step{display:flex;align-items:flex-start;gap:8px;padding:4px 0;font-size:11.5px;border-bottom:1px solid #1e293b}
.atk-step:last-child{border:none}
.atk-arrow{color:#ef4444;font-weight:700;min-width:16px}

/* Ransomware Score */
.rw-header{display:flex;align-items:center;gap:20px;margin-bottom:16px}
.rw-ring{text-align:center}
.rw-ring svg{width:110px;height:110px}
.rw-domains{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:12px 0}
.rw-domain{background:#0f172a;border-radius:8px;padding:12px;text-align:center;border:1px solid #334155;border-top:3px solid}
.rw-domain .rw-d-name{font-size:10px;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px}
.rw-domain .rw-d-score{font-size:22px;font-weight:800;line-height:1}
.rw-domain .rw-d-detail{font-size:9px;color:#94a3b8;margin-top:3px}
.rw-checklist{margin:12px 0}
.rw-item{display:flex;align-items:center;gap:8px;padding:4px 0;font-size:11.5px;border-bottom:1px solid #1e293b}
.rw-item:last-child{border:none}
.rw-icon{width:16px;text-align:center;font-weight:700}

/* Risk Tier Badge */
.tier-badge{display:inline-block;padding:1px 6px;border-radius:4px;font-size:9px;font-weight:700}
.t0{background:#16a34a22;color:#4ade80;border:1px solid #22c55e44}
.t1{background:#0ea5e922;color:#38bdf8;border:1px solid #0ea5e944}
.t2{background:#eab30822;color:#facc15;border:1px solid #eab30844}
.t3{background:#ef444422;color:#f87171;border:1px solid #ef444444}

/* Tables */
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:8px;background:#0f172a;color:#94a3b8;font-weight:600;border-bottom:2px solid #334155}
td{padding:8px;border-bottom:1px solid #1e293b;vertical-align:top}
tr:nth-child(even) td{background:rgba(15,23,42,0.3)}

/* Badges & Status */
.badge{display:inline-block;padding:1px 8px;border-radius:8px;font-size:10px;font-weight:700;color:#fff}
.b-critical{background:#ef4444}.b-high{background:#f97316}.b-medium{background:#eab308;color:#000}.b-low{background:#22c55e}
.s-pass{color:#22c55e;font-weight:600}.s-fail{color:#ef4444;font-weight:600}.s-partial{color:#eab308;font-weight:600}.s-na{color:#94a3b8}.s-not{color:#64748b}
.ck-y{color:#22c55e}.ck-n{color:#475569}
.find{background:#1a1307;border:1px solid #78350f;border-radius:6px;padding:8px;margin-top:6px;font-size:11px;color:#fbbf24;white-space:pre-wrap;font-family:'Cascadia Code',Consolas,monospace;max-height:200px;overflow:auto;line-height:1.4}
.ev{color:#60a5fa;font-size:11px;margin-top:4px}.rem{color:#a78bfa;font-size:11px;margin-top:2px}
.comp{color:#94a3b8;font-size:10px;font-style:italic;margin-top:3px}
.scan-ts{display:inline-block;background:#0c4a6e;color:#38bdf8;padding:0 6px;border-radius:4px;font-size:9px;font-weight:600;margin-left:4px}
.scan-auto{display:inline-block;background:#14532d;color:#4ade80;padding:0 6px;border-radius:4px;font-size:9px;font-weight:600;margin-left:2px}

/* Preflight */
.pfs{background:#1e293b;border-radius:8px;padding:16px;margin-bottom:14px;border-left:4px solid #a855f7}
.pfs h3{font-size:14px;color:#a855f7;margin-bottom:8px}
.pf-ok{color:#22c55e}.pf-warn{color:#eab308}.pf-fail{color:#ef4444}
.scan-info{background:#0f172a;border-radius:6px;padding:10px 12px;margin:8px 0;border:1px solid #334155;font-size:12px;color:#94a3b8}
.scan-info strong{color:#0ea5e9}

/* Footer */
.ftr{text-align:center;color:#475569;font-size:11px;margin-top:24px;padding-top:16px;border-top:1px solid #334155}

/* Print */
@media print{
body{background:#fff;color:#111;padding:16px;font-size:11px}
.hdr,.sec,.stat-card,.cat-bar,.exec,.road-phase,.pfs{background:#f8fafc;border:1px solid #d1d5db;color:#111}
.hdr::before{display:none}
.hdr h1,.sec h2{color:#111}th{background:#f1f5f9;color:#374151}td{border-color:#e5e7eb}
.find{background:#fffbeb;border-color:#f59e0b;color:#92400e}
.bar-track{background:#e5e7eb}.ftr{color:#9ca3af}
.score-ring svg text{fill:#111!important}
}
</style></head><body>
"@

    # ── HEADER ───────────────────────────────────────────────────────────────
    $html += @"
<div class="hdr">
<h1>Network Security Audit Report</h1>
<div class="sub">Confidential - Prepared for $([System.Net.WebUtility]::HtmlEncode($state.Client))</div>
<div class="meta-grid">
<div>Client: <strong>$([System.Net.WebUtility]::HtmlEncode($state.Client))</strong></div>
<div>Auditor: <strong>$([System.Net.WebUtility]::HtmlEncode($state.Auditor))</strong></div>
<div>Date: <strong>$([System.Net.WebUtility]::HtmlEncode($state.Date))</strong></div>
<div>Target: <strong>$([System.Net.WebUtility]::HtmlEncode($scanTarget))</strong></div>
<div>Profile: <strong>$profName</strong></div>
<div>Read-Only: <strong>$roMode</strong></div>
<div>Report Tier: <strong>$Tier</strong></div>
<div>Version: <strong>v4.0.0</strong></div>
</div>
</div>
"@

    # ── SCORE DASHBOARD (all tiers) ──────────────────────────────────────────
    $dashPct = [math]::Min($overallScore, 100)
    $circumference = 2 * [math]::PI * 52
    $dashOffset = $circumference * (1 - $dashPct / 100)
    $html += @"
<div class="dash">
<div class="score-ring">
<svg viewBox="0 0 120 120">
<circle cx="60" cy="60" r="52" fill="none" stroke="#334155" stroke-width="10"/>
<circle cx="60" cy="60" r="52" fill="none" stroke="$overallColor" stroke-width="10" stroke-linecap="round"
  stroke-dasharray="$([math]::Round($circumference,1))" stroke-dashoffset="$([math]::Round($dashOffset,1))"
  transform="rotate(-90 60 60)"/>
<text x="60" y="52" text-anchor="middle" fill="$overallColor" font-size="28" font-weight="800">$overallGrade</text>
<text x="60" y="70" text-anchor="middle" fill="#94a3b8" font-size="11">${overallScore}%</text>
<text x="60" y="84" text-anchor="middle" fill="#64748b" font-size="9">WEIGHTED SCORE</text>
</svg>
</div>
<div>
<div class="score-stats">
<div class="stat-card"><div class="num" style="color:#22c55e">$pass2</div><div class="lbl">Compliant</div></div>
<div class="stat-card"><div class="num" style="color:#ef4444">$fail2</div><div class="lbl">Non-Compliant</div></div>
<div class="stat-card"><div class="num" style="color:#eab308">$part2</div><div class="lbl">Partial</div></div>
<div class="stat-card"><div class="num" style="color:#94a3b8">$na2</div><div class="lbl">N/A</div></div>
<div class="stat-card"><div class="num" style="color:#475569">$not2</div><div class="lbl">Not Assessed</div></div>
</div>
<div class="scan-info" style="margin-top:10px">
<strong>Scan Coverage:</strong> $scannedCount of $autoAvail auto-checks executed | <strong>$autoAvail of $tot2</strong> items have auto-discovery | Generated: <strong>$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</strong>
</div>
<div class="scan-info" style="border-left:3px solid #6366f1">
<strong style="color:#818cf8">Environment:</strong> $([System.Net.WebUtility]::HtmlEncode($script:Env.OSCaption)) | $(if($script:Env.IsDomainJoined){"Domain: $([System.Net.WebUtility]::HtmlEncode($script:Env.DomainName))"}else{'Workgroup'}) | $(if($script:Env.IsAdmin){'Administrator'}else{'Standard User'}) | PS $($script:Env.PSVersion) | Modules: $(if($script:Env.InstalledModules.Count -gt 0){$script:Env.InstalledModules -join ', '}else{'None'})
</div>
<div class="scan-info" style="border-left:3px solid #a855f7">
<strong style="color:#a855f7">Compliance:</strong> Target: <strong>$(if($script:ComplianceTarget -eq 'All'){'All Frameworks'}else{$script:FrameworkMeta[$script:ComplianceTarget].Name})</strong> | Frameworks: CIS v8.1, NIST 800-171, CMMC 2.0, HIPAA, PCI-DSS 4.0.1, SOC 2, ISO 27001$(if($script:Env.JoinType){" | Join: $($script:Env.JoinType)"})$(if($script:Env.IntuneManaged){' | Intune: Managed'})
</div>
</div>
</div>
"@

    # ── CATEGORY SCORE BARS (all tiers) ──────────────────────────────────────
    $html += "<div class='cat-grid'>`n"
    foreach($cn in ($catScores.Keys | Sort-Object)){
        $cs = $catScores[$cn]; $col = $script:CategoryAccents[$cn]
        $barColor = switch($true) { ($cs.Score -ge 80){$col} ($cs.Score -ge 60){'#eab308'} ($cs.Score -ge 40){'#f97316'} default{'#ef4444'} }
        $html += @"
<div class="cat-bar">
<div class="top"><span class="name" style="color:$col">$([System.Net.WebUtility]::HtmlEncode($cn))</span><span class="pct" style="color:$barColor">$($cs.Score)%</span></div>
<div class="bar-track"><div class="bar-fill" style="width:$($cs.Score)%;background:$barColor"></div></div>
<div class="detail">$($cs.Pass) pass | $($cs.Fail) fail | $($cs.Partial) partial | $($cs.NA) N/A | Weight: $($cs.Weight)x</div>
</div>
"@
    }
    $html += "</div>`n"

    # ── EXECUTIVE SUMMARY (Executive, Management, All) ───────────────────────
    if ($Tier -ne 'Technical') {
        $html += "<div class='exec'><h2>Executive Summary <span class='tier-label' style='background:#f9731622;color:#f97316;border:1px solid #f9731644'>EXECUTIVE</span></h2>`n"

        if ($totalFindings -eq 0) {
            $html += "<p style='color:#22c55e;font-weight:600'>No non-compliant findings detected. The environment meets baseline security requirements.</p>`n"
        } else {
            $html += "<p style='font-size:13px;margin-bottom:12px'>This assessment identified <strong style='color:#ef4444'>$totalFindings non-compliant findings</strong> across the environment: <strong style='color:#ef4444'>$($critFindings.Count) Critical</strong>, <strong style='color:#f97316'>$($highFindings.Count) High</strong>, and <strong style='color:#eab308'>$($medFindings.Count) Medium</strong> severity issues.</p>`n"

            if ($critFindings.Count -gt 0) {
                $html += "<div class='finding-list'><strong style='color:#ef4444;font-size:13px'>Critical Findings (Immediate Action Required):</strong>`n"
                foreach ($cf in $critFindings) {
                    $html += "<div class='finding-item'><span class='badge b-critical'>CRIT</span><div><strong>[$($cf.ID)]</strong> $([System.Net.WebUtility]::HtmlEncode($cf.Text))</div></div>`n"
                }
                $html += "</div>`n"
            }
            if ($highFindings.Count -gt 0) {
                $html += "<div class='finding-list'><strong style='color:#f97316;font-size:13px'>High Severity Findings (Action Within 30 Days):</strong>`n"
                foreach ($hf in ($highFindings | Select-Object -First 10)) {
                    $html += "<div class='finding-item'><span class='badge b-high'>HIGH</span><div><strong>[$($hf.ID)]</strong> $([System.Net.WebUtility]::HtmlEncode($hf.Text))</div></div>`n"
                }
                if ($highFindings.Count -gt 10) { $html += "<div style='font-size:11px;color:#94a3b8;padding:4px 0'>... and $($highFindings.Count - 10) more high findings (see Technical section)</div>`n" }
                $html += "</div>`n"
            }
        }
        # Framework Scorecard
        $fwScores = Get-FrameworkScores -Framework 'All'
        $html += "<div style='margin-top:16px'><strong style='font-size:13px;color:#e2e8f0'>Compliance Framework Scores</strong>`n"
        $html += "<div class='fw-grid'>`n"
        foreach ($fw in $script:FrameworkMeta.Keys) {
            $meta = $script:FrameworkMeta[$fw]
            $sc = if ($fwScores.Contains($fw)) { $fwScores[$fw] } else { @{Score=0;Assessed=0;Pass=0;Fail=0;Partial=0;Total=0} }
            $scColor = switch($true) { ($sc.Score -ge 80){$meta.Color} ($sc.Score -ge 60){'#eab308'} ($sc.Score -ge 40){'#f97316'} default{'#ef4444'} }
            $html += "<div class='fw-card' style='border-top-color:$($meta.Color)'>"
            $html += "<div class='fw-name' style='color:$($meta.Color)'>$($meta.Short)</div>"
            $html += "<div class='fw-score' style='color:$scColor'>$($sc.Score)%</div>"
            $html += "<div class='fw-detail'>$($sc.Pass)P / $($sc.Fail)F / $($sc.Partial)Pt of $($sc.Total)</div>"
            $html += "</div>`n"
        }
        $html += "</div></div>`n"
        $html += "</div>`n"
    }

    # ── PRE-FLIGHT RESULTS (all tiers) ───────────────────────────────────────
    if ($script:PreflightResults.Count -gt 0) {
        $html += "<div class='pfs'><h3>Pre-flight Connectivity Results</h3><table style='font-size:12px'>`n"
        $html += "<tr><th style='width:140px'>Check</th><th style='width:80px'>Result</th><th>Details</th></tr>`n"
        $pfMap = @{
            'Ping'='Network reachability (ICMP)'; 'WinRM'='Remote management (PS Remoting port 5985/5986)'
            'AD'='Active Directory module + domain'; 'SMB'='SMB server configuration access'
            'DNS'='External DNS resolution'; 'Elevation'='Running as Administrator'; 'Defender'='Windows Defender access'
        }
        foreach ($k in @('Ping','WinRM','AD','SMB','DNS','Elevation','Defender')) {
            if ($script:PreflightResults.Contains($k)) {
                $v = $script:PreflightResults[$k]
                $cls = switch($v) { 'OK'{'pf-ok'} 'WARN'{'pf-warn'} default{'pf-fail'} }
                $desc = if ($pfMap.Contains($k)) { $pfMap[$k] } else { '' }
                $html += "<tr><td><strong>$k</strong></td><td><span class='$cls'>$v</span></td><td>$desc</td></tr>`n"
            }
        }
        $html += "</table></div>`n"
    }

    # ── REMEDIATION ROADMAP (Management, All) ────────────────────────────────
    if ($Tier -eq 'Management' -or $Tier -eq 'All') {
        $html += "<div class='sec'><h2 style='color:#a855f7'>Remediation Roadmap <span class='tier-label' style='background:#a855f722;color:#a855f7;border:1px solid #a855f744'>MANAGEMENT</span></h2>`n"
        $html += "<div class='d'>Prioritized remediation plan organized by urgency and impact</div>`n"
        $html += "<div class='roadmap'>`n"

        # Phase 1: Critical (Immediate)
        if ($critFindings.Count -gt 0) {
            $html += "<div class='road-phase' style='border-color:#ef4444'><h4 style='color:#ef4444'>Phase 1: Immediate (0-7 days) - $($critFindings.Count) items</h4>`n"
            foreach ($f in $critFindings) {
                $html += "<div class='road-item'><span class='badge b-critical'>CRIT</span><span><strong>[$($f.ID)]</strong> $([System.Net.WebUtility]::HtmlEncode($f.Text))</span></div>`n"
            }
            $html += "</div>`n"
        }
        # Phase 2: High (30 days)
        if ($highFindings.Count -gt 0) {
            $html += "<div class='road-phase' style='border-color:#f97316'><h4 style='color:#f97316'>Phase 2: Short-term (8-30 days) - $($highFindings.Count) items</h4>`n"
            foreach ($f in $highFindings) {
                $html += "<div class='road-item'><span class='badge b-high'>HIGH</span><span><strong>[$($f.ID)]</strong> $([System.Net.WebUtility]::HtmlEncode($f.Text))</span></div>`n"
            }
            $html += "</div>`n"
        }
        # Phase 3: Medium (60-90 days)
        if ($medFindings.Count -gt 0) {
            $html += "<div class='road-phase' style='border-color:#eab308'><h4 style='color:#eab308'>Phase 3: Medium-term (30-90 days) - $($medFindings.Count) items</h4>`n"
            foreach ($f in $medFindings) {
                $html += "<div class='road-item'><span class='badge b-medium'>MED</span><span><strong>[$($f.ID)]</strong> $([System.Net.WebUtility]::HtmlEncode($f.Text))</span></div>`n"
            }
            $html += "</div>`n"
        }

        # Open remediation items
        $remOpen = [System.Collections.ArrayList]@()
        foreach($id in $script:CheckStates.Keys) {
            $rs=if($script:RemStatusCombos[$id].SelectedItem){$script:RemStatusCombos[$id].SelectedItem.ToString()}else{'Open'}
            $assign=$script:RemAssignBoxes[$id].Text; $due=$script:RemDueBoxes[$id].Text
            if ($rs -ne 'Closed' -and ($assign -or $due)) { $remOpen.Add(@{ID=$id;Status=$rs;Assign=$assign;Due=$due}) | Out-Null }
        }
        if ($remOpen.Count -gt 0) {
            $html += "<div class='road-phase' style='border-color:#818cf8'><h4 style='color:#818cf8'>Tracked Remediation Items ($($remOpen.Count) open)</h4>`n"
            foreach ($ro in $remOpen) {
                $html += "<div class='road-item'><span style='color:#818cf8;font-weight:600'>[$($ro.ID)]</span> $($ro.Status)$(if($ro.Assign){" | Assigned: $([System.Net.WebUtility]::HtmlEncode($ro.Assign))"})$(if($ro.Due){" | Due: $([System.Net.WebUtility]::HtmlEncode($ro.Due))"})</div>`n"
            }
            $html += "</div>`n"
        }
        $html += "</div></div>`n"

        # ── COMPLIANCE MATRIX (Management, All) ─────────────────────────────
        $fwTarget = $script:ComplianceTarget
        $html += "<div class='sec'><h2>Compliance Framework Mapping</h2>`n"
        $html += "<div class='d'>Each finding maps to controls across 7 frameworks. Active target: <strong style='color:#38bdf8'>$(if($fwTarget -eq 'All'){'All Frameworks'}else{$script:FrameworkMeta[$fwTarget].Name})</strong></div>`n"
        # Determine which columns to show based on framework target
        $showFw = if ($fwTarget -eq 'All') { @('CIS','NIST','CMMC','HIPAA','PCI','SOC2','ISO27001') } else { @($fwTarget) }
        $html += "<div class='comp-matrix'><table><tr><th style='width:55px'>ID</th><th style='width:160px'>Check Item</th><th style='width:60px'>Status</th>"
        foreach ($fw in $showFw) {
            $meta = $script:FrameworkMeta[$fw]
            $html += "<th style='color:$($meta.Color)'>$($meta.Short)</th>"
        }
        $html += "</tr>`n"
        foreach($cn in $script:AuditCategories.Keys){
            foreach($it in $script:AuditCategories[$cn].Items){
                $sv=if($script:StatusCombos[$it.ID].SelectedItem){$script:StatusCombos[$it.ID].SelectedItem.ToString()}else{'Not Assessed'}
                if ($sv -eq 'Fail' -or $sv -eq 'Partial') {
                    $sc2=switch($sv){'Fail'{'s-fail'}'Partial'{'s-partial'}default{'s-not'}}
                    # Parse existing compliance string
                    $compStr = $it.Compliance
                    $builtInCIS=''; $builtInNIST=''; $builtInHIPAA=''
                    if ($compStr -match 'CIS Control ([^|]+)') { $builtInCIS = $Matches[1].Trim() }
                    if ($compStr -match 'NIST CSF ([^|]+)') { $builtInNIST = $Matches[1].Trim() }
                    if ($compStr -match 'HIPAA (.+)$') { $builtInHIPAA = $Matches[1].Trim() }
                    $fwData = if ($script:FrameworkMap.Contains($it.ID)) { $script:FrameworkMap[$it.ID] } else { @{} }
                    $html += "<tr><td><strong>$($it.ID)</strong></td><td style='text-align:left;font-size:10px'>$([System.Net.WebUtility]::HtmlEncode($it.Text.Substring(0,[math]::Min(80,$it.Text.Length))))$(if($it.Text.Length -gt 80){'...'})</td><td><span class='$sc2'>$sv</span></td>"
                    foreach ($fw in $showFw) {
                        $val = switch ($fw) {
                            'CIS'      { $builtInCIS }
                            'NIST'     { $n = $builtInNIST; if ($fwData.NIST) { $n += " / $($fwData.NIST)" }; $n }
                            'HIPAA'    { $builtInHIPAA }
                            'CMMC'     { $fwData.CMMC }
                            'PCI'      { $fwData.PCI }
                            'SOC2'     { $fwData.SOC2 }
                            'ISO27001' { $fwData.ISO27001 }
                            default    { '' }
                        }
                        $html += "<td style='font-size:9px'>$([System.Net.WebUtility]::HtmlEncode($val))</td>"
                    }
                    $html += "</tr>`n"
                }
            }
        }
        $html += "</table></div></div>`n"

        # ── GAP ANALYSIS (Management, All) ────────────────────────────────────
        if ($fwTarget -ne 'All') {
            $fwMeta = $script:FrameworkMeta[$fwTarget]
            $fwScore = (Get-FrameworkScores -Framework $fwTarget)[$fwTarget]
            $html += "<div class='sec'><h2 style='color:$($fwMeta.Color)'>$($fwMeta.Name) - Gap Analysis</h2>`n"
            $html += "<div class='d'>Failed and partially compliant controls for $($fwMeta.Name). Score: <strong style='color:$($fwMeta.Color)'>$($fwScore.Score)%</strong> ($($fwScore.Pass) pass, $($fwScore.Fail) fail, $($fwScore.Partial) partial of $($fwScore.Total) applicable checks)</div>`n"
            $html += "<div class='gap-section'>`n"
            $fwChecks = if ($script:FrameworkChecks.Contains($fwTarget)) { $script:FrameworkChecks[$fwTarget] } else { @() }
            $gapCount = 0
            foreach ($id in $fwChecks) {
                $sv = if ($script:StatusCombos[$id] -and $script:StatusCombos[$id].SelectedItem) { $script:StatusCombos[$id].SelectedItem.ToString() } else { 'Not Assessed' }
                if ($sv -eq 'Fail' -or $sv -eq 'Partial') {
                    $gapCount++
                    # Find check item
                    $item = $null
                    foreach ($cn in $script:AuditCategories.Keys) { $item = $script:AuditCategories[$cn].Items | Where-Object { $_.ID -eq $id }; if ($item) { break } }
                    if (-not $item) { continue }
                    $fwData = if ($script:FrameworkMap.Contains($id)) { $script:FrameworkMap[$id] } else { @{} }
                    $fwRef = switch ($fwTarget) {
                        'CIS'      { if ($item.Compliance -match 'CIS Control ([^|]+)') { $Matches[1].Trim() } else { '' } }
                        'NIST'     { $fwData.NIST }
                        'CMMC'     { $fwData.CMMC }
                        'HIPAA'    { if ($item.Compliance -match 'HIPAA (.+)$') { $Matches[1].Trim() } else { '' } }
                        'PCI'      { $fwData.PCI }
                        'SOC2'     { $fwData.SOC2 }
                        'ISO27001' { $fwData.ISO27001 }
                        default    { '' }
                    }
                    $borderColor = if ($sv -eq 'Fail') { '#ef4444' } else { '#eab308' }
                    $html += "<div class='gap-ctrl' style='border-left-color:$borderColor'>"
                    $html += "<span class='gap-id'>[$id]</span> <span class='badge $(if($sv -eq 'Fail'){'b-critical'}else{'b-medium'})'>$sv</span> "
                    $html += "$([System.Net.WebUtility]::HtmlEncode($item.Text))"
                    if ($fwRef) { $html += "<div class='gap-refs'>$($fwMeta.Short) Controls: $([System.Net.WebUtility]::HtmlEncode($fwRef))</div>" }
                    $findings = $script:FindingsBoxes[$id].Text
                    if ($findings) {
                        $shortFind = if ($findings.Length -gt 200) { $findings.Substring(0,200) + '...' } else { $findings }
                        $html += "<div style='font-size:10px;color:#cbd5e1;margin-top:4px'>$([System.Net.WebUtility]::HtmlEncode($shortFind))</div>"
                    }
                    $html += "</div>`n"
                }
            }
            if ($gapCount -eq 0) { $html += "<p style='color:#22c55e'>No gaps found - all applicable $($fwMeta.Name) controls are passing.</p>`n" }
            $html += "</div></div>`n"
        }
    }

    # ── MITRE ATT&CK COVERAGE (Management, Technical, All) ────────────────
    if ($Tier -ne 'Executive') {
        $mitreCov = Get-MitreCoverage
        $html += "<div class='sec'><h2 style='color:#ef4444'>MITRE ATT&CK Coverage <span class='tier-label' style='background:#ef444422;color:#ef4444;border:1px solid #ef444444'>THREAT INTEL</span></h2>`n"
        $html += "<div class='d'>Technique coverage mapped against MITRE ATT&CK Enterprise framework. Higher coverage = more adversary techniques are mitigated by passing checks.</div>`n"

        # Tactic Heatmap Grid
        $html += "<div class='mitre-grid'>`n"
        foreach ($ta in $script:MitreTactics.Keys) {
            $tmeta = $script:MitreTactics[$ta]
            $cov = $mitreCov[$ta]
            $covPct = if ($cov.Total -gt 0) { [math]::Round($cov.Covered / $cov.Total * 100) } else { 0 }
            $bgOpacity = [math]::Max(0.08, [math]::Min(0.4, $covPct / 250.0))
            $cellBg = if ($cov.Total -eq 0) { '#1e293b' }
                      elseif ($covPct -ge 80) { "rgba(34,197,94,$bgOpacity)" }
                      elseif ($covPct -ge 50) { "rgba(234,179,8,$bgOpacity)" }
                      else { "rgba(239,68,68,$bgOpacity)" }
            $pctColor = if ($cov.Total -eq 0) { '#64748b' } elseif ($covPct -ge 80) { '#22c55e' } elseif ($covPct -ge 50) { '#eab308' } else { '#ef4444' }
            $html += "<div class='mitre-cell' style='background:$cellBg'>"
            $html += "<div class='m-name' style='color:$($tmeta.Color)'>$($tmeta.Short)</div>"
            $html += "<div class='m-pct' style='color:$pctColor'>$covPct%</div>"
            $html += "<div class='m-det'>$([int]$cov.Covered)/$($cov.Total) checks</div>"
            $html += "</div>`n"
        }
        $html += "</div>`n"

        # Attack Path Narratives (only if failed checks form chains)
        $atkPaths = Get-AttackPaths
        if ($atkPaths.Count -gt 0) {
            $html += "<div style='margin-top:16px'><strong style='font-size:13px;color:#ef4444'>Attack Path Analysis</strong>"
            $html += "<div style='font-size:11px;color:#94a3b8;margin-bottom:8px'>Based on failed checks, the following attack chains are exploitable in this environment:</div>`n"
            foreach ($path in $atkPaths) {
                $borderColor = if ($path.Severity -eq 'CRITICAL') { '#ef4444' } else { '#f97316' }
                $html += "<div class='atk-path' style='border-left-color:$borderColor'>"
                $html += "<h4><span class='badge $(if($path.Severity -eq "CRITICAL"){"b-critical"}else{"b-high"})'>$($path.Severity)</span> $($path.Name)</h4>`n"
                $stepNum = 1
                foreach ($step in $path.Steps) {
                    $html += "<div class='atk-step'><span class='atk-arrow'>$stepNum.</span><strong>[$($step.ID)]</strong> $([System.Net.WebUtility]::HtmlEncode($step.Step))</div>`n"
                    $stepNum++
                }
                $html += "</div>`n"
            }
            $html += "</div>`n"
        }
        $html += "</div>`n"
    }

    # ── RANSOMWARE PREPAREDNESS (Management, All) ─────────────────────────
    if ($Tier -eq 'Management' -or $Tier -eq 'All') {
        $rwScore = Get-RansomwareScore
        $rwColor = switch($true) { ($rwScore.Overall -ge 80){'#22c55e'} ($rwScore.Overall -ge 60){'#eab308'} ($rwScore.Overall -ge 40){'#f97316'} default{'#ef4444'} }
        $gradeColor = switch($rwScore.Grade) { 'A'{'#22c55e'} 'B'{'#84cc16'} 'C'{'#eab308'} 'D'{'#f97316'} default{'#ef4444'} }

        $html += "<div class='sec' style='border-left:4px solid $rwColor'><h2 style='color:$rwColor'>Ransomware Preparedness <span class='tier-label' style='background:$($rwColor)22;color:$rwColor;border:1px solid $($rwColor)44'>RANSOMWARE</span></h2>`n"
        $html += "<div class='d'>Evaluates organizational readiness across four domains: Prevention, Protection, Detection, and Recovery. Score: 0-100 with letter grade.</div>`n"

        # Score Ring + Grade
        $dashOffset = 283 - (283 * $rwScore.Overall / 100)
        $html += "<div class='rw-header'>`n"
        $html += "<div class='rw-ring'><svg viewBox='0 0 100 100'>"
        $html += "<circle cx='50' cy='50' r='45' fill='none' stroke='#334155' stroke-width='8'/>"
        $html += "<circle cx='50' cy='50' r='45' fill='none' stroke='$rwColor' stroke-width='8' stroke-dasharray='283' stroke-dashoffset='$dashOffset' stroke-linecap='round' transform='rotate(-90 50 50)'/>"
        $html += "<text x='50' y='46' text-anchor='middle' fill='$rwColor' font-size='22' font-weight='800'>$($rwScore.Overall)</text>"
        $html += "<text x='50' y='60' text-anchor='middle' fill='$gradeColor' font-size='14' font-weight='700'>$($rwScore.Grade)</text>"
        $html += "</svg></div>`n"
        $html += "<div style='flex:1'>"
        $riskLevel = switch($true) { ($rwScore.Overall -ge 80){'LOW - Organization has strong ransomware defenses'} ($rwScore.Overall -ge 60){'MODERATE - Key gaps exist that should be addressed'} ($rwScore.Overall -ge 40){'HIGH - Significant ransomware exposure present'} default{'CRITICAL - Organization is highly vulnerable to ransomware'} }
        $html += "<div style='font-size:16px;font-weight:700;color:$rwColor;margin-bottom:4px'>Ransomware Risk: $riskLevel</div>"
        $html += "<div style='font-size:12px;color:#94a3b8'>This score reflects the organization's ability to prevent, withstand, detect, and recover from ransomware attacks based on the security controls assessed in this audit.</div>"
        $html += "</div></div>`n"

        # Domain Score Cards
        $domainColors = @{ Prevention='#3b82f6'; Protection='#22c55e'; Detection='#eab308'; Recovery='#a855f7' }
        $html += "<div class='rw-domains'>`n"
        foreach ($dName in $rwScore.Domains.Keys) {
            $d = $rwScore.Domains[$dName]; $dCol = $domainColors[$dName]
            $dScoreCol = if ($d.Score -ge 80) { '#22c55e' } elseif ($d.Score -ge 60) { '#eab308' } elseif ($d.Score -ge 40) { '#f97316' } else { '#ef4444' }
            $html += "<div class='rw-domain' style='border-top-color:$dCol'>"
            $html += "<div class='rw-d-name' style='color:$dCol'>$dName</div>"
            $html += "<div class='rw-d-score' style='color:$dScoreCol'>$($d.Score)%</div>"
            $html += "<div class='rw-d-detail'>$($d.Earned)/$($d.Max) pts (x$($d.Weight))</div>"
            $html += "</div>`n"
        }
        $html += "</div>`n"

        # Detailed Checklist per Domain
        foreach ($dName in $rwScore.Domains.Keys) {
            $d = $rwScore.Domains[$dName]; $dCol = $domainColors[$dName]
            $html += "<div style='margin-top:8px'><strong style='font-size:12px;color:$dCol'>$dName Controls</strong>`n"
            $html += "<div class='rw-checklist'>`n"
            foreach ($item in $d.Details) {
                $icon = switch ($item.Status) { 'Pass' { "<span class='rw-icon' style='color:#22c55e'>P</span>" } 'Partial' { "<span class='rw-icon' style='color:#eab308'>~</span>" } 'Fail' { "<span class='rw-icon' style='color:#ef4444'>X</span>" } default { "<span class='rw-icon' style='color:#64748b'>-</span>" } }
                $html += "<div class='rw-item'>$icon <strong style='min-width:35px'>[$($item.ID)]</strong> $([System.Net.WebUtility]::HtmlEncode($item.Factor)) <span style='margin-left:auto;font-size:10px;color:#94a3b8'>$($item.Earned)/$($item.MaxPoints) pts</span></div>`n"
            }
            $html += "</div></div>`n"
        }

        # Priority Remediation List (failed items sorted by points)
        $allFailed = @()
        foreach ($dName in $rwScore.Domains.Keys) {
            foreach ($item in $rwScore.Domains[$dName].Details) {
                if ($item.Status -eq 'Fail') { $allFailed += @{ ID=$item.ID; Factor=$item.Factor; Points=$item.MaxPoints; Domain=$dName } }
            }
        }
        if ($allFailed.Count -gt 0) {
            $allFailed = $allFailed | Sort-Object { $_.Points } -Descending
            $html += "<div style='margin-top:12px;background:#0f172a;border-radius:8px;padding:14px;border-left:3px solid #ef4444'>"
            $html += "<strong style='color:#ef4444;font-size:13px'>Priority Ransomware Remediation ($($allFailed.Count) items)</strong>`n"
            $html += "<div style='font-size:10px;color:#94a3b8;margin-bottom:8px'>Sorted by impact on ransomware preparedness score (highest first)</div>`n"
            foreach ($f in ($allFailed | Select-Object -First 15)) {
                $html += "<div class='rw-item'><span class='rw-icon' style='color:#ef4444'>!</span> <strong>[$($f.ID)]</strong> $([System.Net.WebUtility]::HtmlEncode($f.Factor)) <span style='margin-left:auto;font-size:10px;color:#ef4444'>+$($f.Points) pts if fixed</span></div>`n"
            }
            if ($allFailed.Count -gt 15) { $html += "<div style='font-size:10px;color:#94a3b8;padding:4px 0'>... and $($allFailed.Count - 15) more items</div>`n" }
            $html += "</div>`n"
        }
        $html += "</div>`n"
    }

    # ── TECHNICAL DETAIL (Technical, All) ────────────────────────────────────
    if ($Tier -eq 'Technical' -or $Tier -eq 'All') {
        foreach($cn in $script:AuditCategories.Keys){
            $cat=$script:AuditCategories[$cn]; $col=$script:CategoryAccents[$cn]
            $cs = $catScores[$cn]
            $html += "<div class='sec'><h2 style='color:$col'>$([System.Net.WebUtility]::HtmlEncode($cn)) "
            $html += "<span style='font-size:12px;color:#94a3b8;font-weight:400'>($($cs.Pass+$cs.Fail+$cs.Partial)/$($cs.Total) assessed, Score: $($cs.Score)%)</span> "
            $html += "<span class='tier-label' style='background:#0ea5e922;color:#38bdf8;border:1px solid #0ea5e944'>TECHNICAL</span></h2>`n"
            $html += "<div class='d'>$([System.Net.WebUtility]::HtmlEncode($cat.Desc))</div>`n"
            $html += "<table><tr><th style='width:28px'>OK</th><th style='width:70px'>ID</th><th>Item</th><th style='width:55px'>Sev</th><th style='width:50px'>Tier</th><th style='width:90px'>Status</th><th>Details</th><th style='width:120px'>Remediation</th></tr>`n"

            foreach($it in $cat.Items){
                $id=$it.ID; $cm=if($script:CheckStates[$id]){"<span class='ck-y'>[X]</span>"}else{"<span class='ck-n'>[ ]</span>"}
                $sv6=if($script:StatusCombos[$id].SelectedItem){$script:StatusCombos[$id].SelectedItem.ToString()}else{'Not Assessed'}
                $sc2=switch($sv6){'Pass'{'s-pass'}'Fail'{'s-fail'}'Partial'{'s-partial'}'N/A'{'s-na'}default{'s-not'}}
                $bc2="b-$($it.Severity.ToLower())"

                # Risk tier badge
                $riskTier = if ($script:RiskTiers.Contains($id)) { $script:RiskTiers[$id] } else { 0 }
                $tierCls = "t$riskTier"
                $tierLbl = $script:RiskTierLabels[$riskTier]
                $tierHtml = "<span class='tier-badge $tierCls'>T$riskTier $tierLbl</span>"

                # ID column with scan indicators
                $idHtml = "<strong>$id</strong>"
                $hasAuto = $script:AutoCheckIDs.Contains($id)
                $wasScanned = $script:ScanTimestamps.Contains($id)
                if ($hasAuto) { $idHtml += "<span class='scan-auto'>AUTO</span>" }
                if ($wasScanned) { $idHtml += "<span class='scan-ts'>$($script:ScanTimestamps[$id])</span>" }

                $notes=$script:NotesBoxes[$id].Text
                $finds=$script:FindingsBoxes[$id].Text
                $evid=$script:EvidenceBoxes[$id].Text
                $comp=[System.Net.WebUtility]::HtmlEncode($it.Compliance)

                $detHtml = ''
                if ($notes) { $detHtml += [System.Net.WebUtility]::HtmlEncode($notes) -replace "`r`n","<br>" -replace "`n","<br>" }
                if ($finds) {
                    $findsEnc = [System.Net.WebUtility]::HtmlEncode($finds)
                    $detHtml += "<div class='find'>$findsEnc</div>"
                }
                if ($evid) {
                    $evidEnc = [System.Net.WebUtility]::HtmlEncode($evid) -replace "`r`n","<br>" -replace "`n","<br>"
                    $detHtml += "<div class='ev'>Evidence: $evidEnc</div>"
                }
                # Enhanced compliance display: built-in + extended framework data
                if ($comp) { $detHtml += "<div class='comp'>$comp</div>" }
                $fwData = if ($script:FrameworkMap.Contains($id)) { $script:FrameworkMap[$id] } else { $null }
                if ($fwData) {
                    $extParts = @()
                    if ($fwData.NIST) { $extParts += "<span style='color:#818cf8'>800-171: $($fwData.NIST)</span>" }
                    if ($fwData.CMMC) { $extParts += "<span style='color:#a855f7'>CMMC: $($fwData.CMMC)</span>" }
                    if ($fwData.PCI) { $extParts += "<span style='color:#f97316'>PCI: $($fwData.PCI)</span>" }
                    if ($fwData.SOC2) { $extParts += "<span style='color:#eab308'>SOC2: $($fwData.SOC2)</span>" }
                    if ($fwData.ISO27001) { $extParts += "<span style='color:#ec4899'>ISO: $($fwData.ISO27001)</span>" }
                    if ($extParts.Count -gt 0) { $detHtml += "<div class='comp' style='margin-top:2px'>$($extParts -join ' | ')</div>" }
                }
                # MITRE ATT&CK technique display
                $mitreData = if ($script:MitreMap.Contains($id)) { $script:MitreMap[$id] } else { $null }
                if ($mitreData) {
                    $techStr = ($mitreData.Techniques -join ', ')
                    $tacStr = ($mitreData.Tactics | ForEach-Object { if ($script:MitreTactics[$_]) { $script:MitreTactics[$_].Short } else { $_ } }) -join ' > '
                    $detHtml += "<div class='comp' style='margin-top:2px'><span style='color:#ef4444'>ATT&CK:</span> <span style='color:#94a3b8'>$tacStr</span> | <span style='color:#f87171'>$techStr</span></div>"
                }

                $rs5=if($script:RemStatusCombos[$id].SelectedItem){$script:RemStatusCombos[$id].SelectedItem.ToString()}else{'Open'}
                $assign=[System.Net.WebUtility]::HtmlEncode($script:RemAssignBoxes[$id].Text)
                $due=[System.Net.WebUtility]::HtmlEncode($script:RemDueBoxes[$id].Text)
                $remHtml="<span class='rem'>$rs5</span>"
                if($assign){$remHtml+="<div class='rem'>Assigned: $assign</div>"}
                if($due){$remHtml+="<div class='rem'>Due: $due</div>"}

                $html += "<tr><td>$cm</td><td>$idHtml</td><td>$([System.Net.WebUtility]::HtmlEncode($it.Text))</td>"
                $html += "<td><span class='badge $bc2'>$($it.Severity)</span></td><td>$tierHtml</td><td><span class='$sc2'>$sv6</span></td>"
                $html += "<td>$detHtml</td><td>$remHtml</td></tr>`n"
            }
            $html += "</table></div>`n"
        }
    }

    $fwLabel = if ($script:ComplianceTarget -eq 'All') { 'All Frameworks' } else { $script:FrameworkMeta[$script:ComplianceTarget].Name }
    $html += "<div class='ftr'>Generated by Network Security Audit Checklist v4.0 | $(Get-Date -Format 'yyyy-MM-dd HH:mm') | Profile: $profName | Framework: $fwLabel | $scannedCount auto-checks on $([System.Net.WebUtility]::HtmlEncode($scanTarget)) | Read-Only: $roMode</div></body></html>"
    $html | Set-Content $outPath -Encoding UTF8
    $el['StatusText'].Text = "Exported: $outPath"; Write-Log "HTML exported: $outPath (Tier: $Tier)" 'INFO'
    if ($OpenAfter) { Start-Process $outPath }
}

function Invoke-AutoExport {
    $desktop = [Environment]::GetFolderPath('Desktop')
    $client = $el['txtClient'].Text -replace '[^\w\-]','_'
    if (-not $client) { $client = $env:COMPUTERNAME }
    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
    $basePath = Join-Path $desktop "SecurityAudit_${client}_$ts"
    $outFile = "${basePath}.html"
    try { Export-HTMLReport $outFile -OpenAfter; Write-Log "Auto-export HTML: $outFile" 'INFO' }
    catch { Write-Log "Auto-export HTML failed: $_" 'ERROR'; $el['StatusText'].Text = "HTML export failed: $($_.Exception.Message)" }
    # Also generate structured JSON and CSV
    try { Export-FindingsJSON -OutPath "${basePath}_findings.json"; Write-Log "Auto-export findings JSON" 'INFO' } catch {}
    try { Export-FindingsCSV -OutPath "${basePath}.csv"; Write-Log "Auto-export CSV" 'INFO' } catch {}
    try { Export-ComplianceSummary -OutPath "${basePath}_summary.json"; Write-Log "Auto-export compliance summary" 'INFO' } catch {}
    return $outFile
}

$el['btnExportHTML'].Add_Click({
    $dlg=New-Object Microsoft.Win32.SaveFileDialog; $dlg.Filter='HTML|*.html'; $dlg.FileName="Audit_$($el['txtClient'].Text -replace '\s','_')_$(Get-Date -Format 'yyyyMMdd').html"
    if($dlg.ShowDialog()){
        try { Export-HTMLReport $dlg.FileName -OpenAfter }
        catch { $el['StatusText'].Text = "HTML export failed: $($_.Exception.Message)"; Write-Log "HTML export failed: $_" 'ERROR' }
    }
})

$el['btnExportJSON'].Add_Click({
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'JSON Findings|*.json|JSONL (SIEM)|*.jsonl|Compliance Summary|*.json'
    $dlg.FilterIndex = 1
    $dlg.FileName = "Findings_$($el['txtClient'].Text -replace '\s','_')_$(Get-Date -Format 'yyyyMMdd').json"
    if ($dlg.ShowDialog()) {
        try {
            switch ($dlg.FilterIndex) {
                1 { Export-FindingsJSON -OutPath $dlg.FileName; $el['StatusText'].Text = "JSON findings exported: $($dlg.FileName)" }
                2 { Export-FindingsJSONL -OutPath $dlg.FileName; $el['StatusText'].Text = "JSONL (SIEM) exported: $($dlg.FileName)" }
                3 { Export-ComplianceSummary -OutPath $dlg.FileName; $el['StatusText'].Text = "Compliance summary exported: $($dlg.FileName)" }
            }
        } catch {
            $el['StatusText'].Text = "Export failed: $($_.Exception.Message)"
            Write-Log "JSON export failed: $_" 'ERROR'
        }
    }
})

$el['btnExportCSV'].Add_Click({
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'CSV|*.csv'
    $dlg.FileName = "Audit_$($el['txtClient'].Text -replace '\s','_')_$(Get-Date -Format 'yyyyMMdd').csv"
    if ($dlg.ShowDialog()) {
        try {
            Export-FindingsCSV -OutPath $dlg.FileName
            $el['StatusText'].Text = "CSV exported: $($dlg.FileName)"
        } catch {
            $el['StatusText'].Text = "CSV export failed: $($_.Exception.Message)"
            Write-Log "CSV export failed: $_" 'ERROR'
        }
    }
})

# ── Auto-Save JSON ───────────────────────────────────────────────────────────
function Invoke-AutoSave {
    $desktop = [Environment]::GetFolderPath('Desktop')
    $client = $el['txtClient'].Text -replace '[^\w\-]','_'
    if (-not $client) { $client = $env:COMPUTERNAME }
    $outFile = Join-Path $desktop "SecurityAudit_${client}_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    (Get-AuditState) | ConvertTo-Json -Depth 5 | Set-Content $outFile -Encoding UTF8
    Write-Log "Auto-saved audit state: $outFile" 'INFO'
    $el['StatusText'].Text = "Auto-saved: $outFile"
    return $outFile
}

# ── Phase 5A: Enhanced Structured JSON Export ─────────────────────────────────
# Per-finding JSON with full compliance, MITRE, remediation metadata
function Export-FindingsJSON {
    param([string]$OutPath, [string]$ClientName = '', [string]$AuditorName = '')
    if (-not $ClientName) { $ClientName = try { $el['txtClient'].Text } catch { $env:COMPUTERNAME } }
    if (-not $AuditorName) { $AuditorName = try { $el['txtAuditor'].Text } catch { 'System' } }
    $scanTs = Get-Date -Format 'o'
    $scanTarget = try { $el['txtScanTarget'].Text } catch { 'localhost' }
    $riskData = Get-RiskScore
    $rwData = Get-RansomwareScore

    $findings = @()
    foreach ($cn in $script:AuditCategories.Keys) {
        $cat = $script:AuditCategories[$cn]
        foreach ($item in $cat.Items) {
            $id = $item.ID
            $sv = if ($script:StatusCombos[$id] -and $script:StatusCombos[$id].SelectedItem) { $script:StatusCombos[$id].SelectedItem.ToString() } else { 'Not Assessed' }
            $rs = if ($script:RemStatusCombos[$id] -and $script:RemStatusCombos[$id].SelectedItem) { $script:RemStatusCombos[$id].SelectedItem.ToString() } else { 'Open' }

            # Compliance mappings
            $fwData = if ($script:FrameworkMap.Contains($id)) { $script:FrameworkMap[$id] } else { $null }
            $compObj = @{ BuiltIn = $item.Compliance }
            if ($fwData) {
                if ($fwData.NIST) { $compObj['NIST_800_171'] = $fwData.NIST }
                if ($fwData.CMMC) { $compObj['CMMC_2_0'] = $fwData.CMMC }
                if ($fwData.PCI) { $compObj['PCI_DSS_4'] = $fwData.PCI }
                if ($fwData.SOC2) { $compObj['SOC2'] = $fwData.SOC2 }
                if ($fwData.ISO27001) { $compObj['ISO_27001'] = $fwData.ISO27001 }
            }

            # MITRE mapping
            $mitreObj = $null
            if ($script:MitreMap.Contains($id)) {
                $m = $script:MitreMap[$id]
                $mitreObj = @{
                    Tactics = $m.Tactics
                    Techniques = $m.Techniques
                    Description = $m.Desc
                }
            }

            $finding = [ordered]@{
                id            = $id
                category      = $cn
                severity      = $item.Severity
                weight        = $item.Weight
                status        = $sv
                text          = $item.Text
                findings      = if ($script:FindingsBoxes[$id]) { $script:FindingsBoxes[$id].Text } else { '' }
                evidence      = if ($script:EvidenceBoxes[$id]) { $script:EvidenceBoxes[$id].Text } else { '' }
                notes         = if ($script:NotesBoxes[$id]) { $script:NotesBoxes[$id].Text } else { '' }
                remediation   = [ordered]@{
                    status   = $rs
                    assigned = if ($script:RemAssignBoxes[$id]) { $script:RemAssignBoxes[$id].Text } else { '' }
                    due      = if ($script:RemDueBoxes[$id]) { $script:RemDueBoxes[$id].Text } else { '' }
                }
                compliance    = $compObj
                mitre_attack  = $mitreObj
                scan_time     = if ($script:ScanTimestamps.Contains($id)) { $script:ScanTimestamps[$id] } else { $null }
            }
            $findings += $finding
        }
    }

    # Framework compliance status flags
    $fwStatus = @{}
    try {
        $fwScores = Get-FrameworkScores -Framework 'All'
        foreach ($fw in $fwScores.Keys) {
            $s = $fwScores[$fw]
            $fwStatus[$fw] = [ordered]@{
                score     = $s.Score
                compliant = ($s.Score -ge 80)
                pass      = $s.Pass; fail = $s.Fail; partial = $s.Partial
                total     = $s.Total; assessed = $s.Assessed
            }
        }
    } catch {}

    $scanTarget = if ($el -and $el['txtScanTarget']) { $el['txtScanTarget'].Text } else { 'localhost' }

    $export = [ordered]@{
        schema_version = '2.0'
        tool           = 'NetworkSecurityAudit'
        tool_version   = '4.0'
        export_type    = 'structured_findings'
        timestamp      = $scanTs
        client         = $ClientName
        auditor        = $AuditorName
        target         = $scanTarget
        environment    = [ordered]@{
            os          = $script:Env.OSCaption
            domain      = $script:Env.IsDomainJoined
            admin       = $script:Env.IsAdmin
            join_type   = $script:Env.JoinType
            intune      = $script:Env.IntuneMgmt
        }
        score          = [ordered]@{
            overall    = $riskData.Pct
            grade      = $riskData.Grade
            ransomware = [ordered]@{ score=$rwData.Overall; grade=$rwData.Grade }
        }
        compliance_frameworks = $fwStatus
        findings_count = [ordered]@{
            total    = $findings.Count
            pass     = ($findings | Where-Object { $_.status -eq 'Pass' }).Count
            fail     = ($findings | Where-Object { $_.status -eq 'Fail' }).Count
            partial  = ($findings | Where-Object { $_.status -eq 'Partial' }).Count
            na       = ($findings | Where-Object { $_.status -eq 'N/A' }).Count
            not_assessed = ($findings | Where-Object { $_.status -eq 'Not Assessed' }).Count
        }
        findings       = $findings
    }

    $export | ConvertTo-Json -Depth 8 | Set-Content $OutPath -Encoding UTF8
    Write-Log "Structured JSON exported: $OutPath" 'INFO'
    return $OutPath
}

# ── Phase 5A: SIEM-Compatible JSONL Export ────────────────────────────────────
# Flat JSON-lines format for Splunk/Elastic/Sentinel ingestion
function Export-FindingsJSONL {
    param([string]$OutPath, [string]$ClientName = '', [string]$AuditorName = '')
    if (-not $ClientName) { $ClientName = try { $el['txtClient'].Text } catch { $env:COMPUTERNAME } }
    if (-not $AuditorName) { $AuditorName = try { $el['txtAuditor'].Text } catch { 'System' } }
    $scanTs = Get-Date -Format 'o'
    $scanTarget = try { $el['txtScanTarget'].Text } catch { $env:COMPUTERNAME }
    $riskData = Get-RiskScore
    $lines = [System.Collections.Generic.List[string]]::new()

    foreach ($cn in $script:AuditCategories.Keys) {
        $cat = $script:AuditCategories[$cn]
        foreach ($item in $cat.Items) {
            $id = $item.ID
            $sv = if ($script:StatusCombos[$id] -and $script:StatusCombos[$id].SelectedItem) { $script:StatusCombos[$id].SelectedItem.ToString() } else { 'Not Assessed' }
            $rs = if ($script:RemStatusCombos[$id] -and $script:RemStatusCombos[$id].SelectedItem) { $script:RemStatusCombos[$id].SelectedItem.ToString() } else { 'Open' }
            $fwData = if ($script:FrameworkMap.Contains($id)) { $script:FrameworkMap[$id] } else { $null }
            $mitreData = if ($script:MitreMap.Contains($id)) { $script:MitreMap[$id] } else { $null }

            # Flat event record - one line per finding
            $evt = [ordered]@{
                timestamp       = if ($script:ScanTimestamps.Contains($id)) { $script:ScanTimestamps[$id] } else { $scanTs }
                event_type      = 'security_audit_finding'
                source          = 'NetworkSecurityAudit'
                source_version  = '4.0'
                client          = $ClientName
                auditor         = $AuditorName
                host            = $scanTarget
                os              = $script:Env.OSCaption
                domain_joined   = $script:Env.IsDomainJoined
                overall_grade   = $riskData.Grade
                overall_score   = $riskData.Pct
                check_id        = $id
                category        = $cn
                severity        = $item.Severity
                weight          = $item.Weight
                status          = $sv
                description     = $item.Text
                findings        = if ($script:FindingsBoxes[$id]) { $script:FindingsBoxes[$id].Text } else { '' }
                evidence        = if ($script:EvidenceBoxes[$id]) { $script:EvidenceBoxes[$id].Text } else { '' }
                remediation_status = $rs
                remediation_assigned = if ($script:RemAssignBoxes[$id]) { $script:RemAssignBoxes[$id].Text } else { '' }
                remediation_due = if ($script:RemDueBoxes[$id]) { $script:RemDueBoxes[$id].Text } else { '' }
                nist_csf        = ''
                cis_controls    = ''
                hipaa           = ''
                nist_800_171    = if ($fwData) { $fwData.NIST } else { '' }
                cmmc            = if ($fwData) { $fwData.CMMC } else { '' }
                pci_dss         = if ($fwData) { $fwData.PCI } else { '' }
                soc2            = if ($fwData) { $fwData.SOC2 } else { '' }
                iso_27001       = if ($fwData) { $fwData.ISO27001 } else { '' }
                mitre_tactics   = if ($mitreData) { $mitreData.Tactics -join ',' } else { '' }
                mitre_techniques = if ($mitreData) { $mitreData.Techniques -join ',' } else { '' }
                mitre_context   = if ($mitreData) { $mitreData.Desc } else { '' }
            }
            # Parse built-in compliance string for NIST CSF, CIS, HIPAA
            if ($item.Compliance) {
                $parts = $item.Compliance -split '\|'
                foreach ($p in $parts) {
                    $p = $p.Trim()
                    if ($p -match 'NIST CSF (.+)') { $evt.nist_csf = $Matches[1].Trim() }
                    elseif ($p -match 'CIS Control (.+)') { $evt.cis_controls = $Matches[1].Trim() }
                    elseif ($p -match 'HIPAA (.+)') { $evt.hipaa = $Matches[1].Trim() }
                }
            }
            $lines.Add(($evt | ConvertTo-Json -Depth 3 -Compress))
        }
    }

    $lines -join "`n" | Set-Content $OutPath -Encoding UTF8
    Write-Log "JSONL (SIEM) exported: $OutPath ($($lines.Count) events)" 'INFO'
    return $OutPath
}

# ── Phase 5B: CSV Export for MSP Analysis ─────────────────────────────────────
# Column layout optimized for pivot tables across multi-client audits
function Export-FindingsCSV {
    param([string]$OutPath, [string]$ClientName = '', [string]$AuditorName = '')
    if (-not $ClientName) { $ClientName = try { $el['txtClient'].Text } catch { $env:COMPUTERNAME } }
    if (-not $AuditorName) { $AuditorName = try { $el['txtAuditor'].Text } catch { 'System' } }
    $scanTs = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $scanTarget = try { $el['txtScanTarget'].Text } catch { $env:COMPUTERNAME }
    $riskData = Get-RiskScore

    $rows = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($cn in $script:AuditCategories.Keys) {
        $cat = $script:AuditCategories[$cn]
        foreach ($item in $cat.Items) {
            $id = $item.ID
            $sv = if ($script:StatusCombos[$id] -and $script:StatusCombos[$id].SelectedItem) { $script:StatusCombos[$id].SelectedItem.ToString() } else { 'Not Assessed' }
            $rs = if ($script:RemStatusCombos[$id] -and $script:RemStatusCombos[$id].SelectedItem) { $script:RemStatusCombos[$id].SelectedItem.ToString() } else { 'Open' }
            $fwData = if ($script:FrameworkMap.Contains($id)) { $script:FrameworkMap[$id] } else { $null }
            $mitreData = if ($script:MitreMap.Contains($id)) { $script:MitreMap[$id] } else { $null }

            # Risk priority = severity numeric * weight (for sorting/filtering)
            $sevNum = switch($item.Severity) { 'Critical'{4} 'High'{3} 'Medium'{2} 'Low'{1} default{0} }
            $riskPriority = $sevNum * $item.Weight
            # Parse built-in compliance
            $nistCsf = ''; $cisCtrl = ''; $hipaaRef = ''
            if ($item.Compliance) {
                $parts = $item.Compliance -split '\|'
                foreach ($p in $parts) {
                    $p = $p.Trim()
                    if ($p -match 'NIST CSF (.+)') { $nistCsf = $Matches[1].Trim() }
                    elseif ($p -match 'CIS Control (.+)') { $cisCtrl = $Matches[1].Trim() }
                    elseif ($p -match 'HIPAA (.+)') { $hipaaRef = $Matches[1].Trim() }
                }
            }

            $row = [PSCustomObject][ordered]@{
                ScanDate         = $scanTs
                Client           = $ClientName
                Auditor          = $AuditorName
                Target           = $scanTarget
                OverallGrade     = $riskData.Grade
                OverallScore     = $riskData.Pct
                CheckID          = $id
                Category         = $cn
                Severity         = $item.Severity
                Weight           = $item.Weight
                RiskPriority     = $riskPriority
                Status           = $sv
                Description      = $item.Text
                Findings         = if ($script:FindingsBoxes[$id]) { ($script:FindingsBoxes[$id].Text -replace "`r?`n",' | ') } else { '' }
                Evidence         = if ($script:EvidenceBoxes[$id]) { ($script:EvidenceBoxes[$id].Text -replace "`r?`n",' | ') } else { '' }
                Notes            = if ($script:NotesBoxes[$id]) { ($script:NotesBoxes[$id].Text -replace "`r?`n",' | ') } else { '' }
                RemStatus        = $rs
                RemAssigned      = if ($script:RemAssignBoxes[$id]) { $script:RemAssignBoxes[$id].Text } else { '' }
                RemDue           = if ($script:RemDueBoxes[$id]) { $script:RemDueBoxes[$id].Text } else { '' }
                NIST_CSF         = $nistCsf
                CIS_Controls     = $cisCtrl
                HIPAA            = $hipaaRef
                NIST_800_171     = if ($fwData) { $fwData.NIST } else { '' }
                CMMC_2_0         = if ($fwData) { $fwData.CMMC } else { '' }
                PCI_DSS_4        = if ($fwData) { $fwData.PCI } else { '' }
                SOC2             = if ($fwData) { $fwData.SOC2 } else { '' }
                ISO_27001        = if ($fwData) { $fwData.ISO27001 } else { '' }
                MITRE_Tactics    = if ($mitreData) { $mitreData.Tactics -join '; ' } else { '' }
                MITRE_Techniques = if ($mitreData) { $mitreData.Techniques -join '; ' } else { '' }
                ScanTimestamp    = if ($script:ScanTimestamps.Contains($id)) { $script:ScanTimestamps[$id] } else { '' }
            }
            $rows.Add($row)
        }
    }

    $rows | Export-Csv -Path $OutPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV exported: $OutPath ($($rows.Count) rows)" 'INFO'
    return $OutPath
}

# ── Phase 5C: Compliance Summary Export ───────────────────────────────────────
# Compact summary JSON optimized for RMM dashboards and multi-client aggregation
function Export-ComplianceSummary {
    param([string]$OutPath, [string]$ClientName = '', [string]$AuditorName = '')
    if (-not $ClientName) { $ClientName = try { $el['txtClient'].Text } catch { $env:COMPUTERNAME } }
    if (-not $AuditorName) { $AuditorName = try { $el['txtAuditor'].Text } catch { 'System' } }
    $scanTarget = try { $el['txtScanTarget'].Text } catch { $env:COMPUTERNAME }
    $riskData = Get-RiskScore
    $rwData = Get-RansomwareScore

    # Category scores
    $catScores = @{}
    foreach ($cn in $script:AuditCategories.Keys) {
        $items = $script:AuditCategories[$cn].Items
        $p=0; $f=0; $par=0; $na=0
        foreach ($item in $items) {
            $sv = if ($script:StatusCombos[$item.ID] -and $script:StatusCombos[$item.ID].SelectedItem) { $script:StatusCombos[$item.ID].SelectedItem.ToString() } else { 'Not Assessed' }
            switch ($sv) { 'Pass'{$p++} 'Fail'{$f++} 'Partial'{$par++} 'N/A'{$na++} }
        }
        $assessed = $p + $f + $par
        $catScores[$cn] = [ordered]@{ pass=$p; fail=$f; partial=$par; na=$na; total=$items.Count; score=if($assessed -gt 0){[math]::Round(($p + $par*0.5)/$assessed*100)}else{0} }
    }

    # Critical findings list (fail + critical/high severity)
    $critFindings = @()
    foreach ($cn in $script:AuditCategories.Keys) {
        foreach ($item in $script:AuditCategories[$cn].Items) {
            $sv = if ($script:StatusCombos[$item.ID] -and $script:StatusCombos[$item.ID].SelectedItem) { $script:StatusCombos[$item.ID].SelectedItem.ToString() } else { 'Not Assessed' }
            if ($sv -eq 'Fail' -and $item.Severity -in @('Critical','High')) {
                $critFindings += [ordered]@{ id=$item.ID; severity=$item.Severity; text=$item.Text; category=$cn }
            }
        }
    }

    # Framework compliance flags
    $fwFlags = @{}
    try {
        $fwScores = Get-FrameworkScores -Framework 'All'
        foreach ($fw in $fwScores.Keys) {
            $s = $fwScores[$fw]
            $fwFlags[$fw] = [ordered]@{
                compliant = ($s.Score -ge 80)
                score     = $s.Score
                grade     = switch($true) { ($s.Score -ge 90){'A'} ($s.Score -ge 80){'B'} ($s.Score -ge 70){'C'} ($s.Score -ge 60){'D'} default{'F'} }
                gap_count = $s.Fail + $s.Partial
            }
        }
    } catch {}

    $summary = [ordered]@{
        schema_version = '2.0'
        export_type    = 'compliance_summary'
        timestamp      = Get-Date -Format 'o'
        client         = $ClientName
        auditor        = $AuditorName
        target         = $scanTarget
        environment    = [ordered]@{
            os=$script:Env.OSCaption; domain=$script:Env.IsDomainJoined; admin=$script:Env.IsAdmin
            join_type=$script:Env.JoinType; intune=$script:Env.IntuneMgmt
        }
        overall_score  = $riskData.Pct
        overall_grade  = $riskData.Grade
        ransomware     = [ordered]@{ score=$rwData.Overall; grade=$rwData.Grade; prevention=$rwData.Domains['Prevention'].Score; protection=$rwData.Domains['Protection'].Score; detection=$rwData.Domains['Detection'].Score; recovery=$rwData.Domains['Recovery'].Score }
        category_scores = $catScores
        framework_compliance = $fwFlags
        critical_findings = $critFindings
        critical_count = $critFindings.Count
        total_checks   = ($script:AuditCategories.Values | ForEach-Object { $_.Items.Count } | Measure-Object -Sum).Sum
        pass_count     = ($script:StatusCombos.Values | Where-Object { $_.SelectedItem -eq 'Pass' }).Count
        fail_count     = ($script:StatusCombos.Values | Where-Object { $_.SelectedItem -eq 'Fail' }).Count
    }

    $summary | ConvertTo-Json -Depth 5 | Set-Content $OutPath -Encoding UTF8
    Write-Log "Compliance summary exported: $OutPath" 'INFO'
    return $OutPath
}

# ── Full Audit Button Handler ────────────────────────────────────────────────
$el['btnFullAudit'].Add_Click({
    if ($script:ScanRunning) { return }
    $target = $el['txtScanTarget'].Text
    Write-Log "=== FULL AUDIT INITIATED ===" 'INFO'
    Write-Log "Target: $target" 'INFO'
    $script:FullAuditMode = $true
    $script:TurnkeyAutoExport = $true
    $script:TurnkeyAutoScan = $false
    # Disable all scan buttons during full audit
    $el['btnFullAudit'].IsEnabled = $false
    $el['btnScanAll'].IsEnabled = $false; $el['btnScanAD'].IsEnabled = $false; $el['btnScanLocal'].IsEnabled = $false
    $el['btnPreflight'].IsEnabled = $false
    $el['StatusText'].Text = "Full Audit: running pre-flight..."
    Start-AsyncPreflight
})

# ── Configure WinRM Button Handler ──────────────────────────────────────────
$el['btnConfigWinRM'].Add_Click({
    $target = $el['txtScanTarget'].Text
    if (-not $target) { $target = 'localhost' }
    Write-Log "Configuring WinRM on $target..." 'INFO'
    $el['StatusText'].Text = "Configuring WinRM on $target..."
    $cred = $script:ScanCredential
    $result = Enable-AuditWinRM -Target $target -Credential $cred
    $lvl = if ($result.Success) { 'INFO' } else { 'ERROR' }
    Write-Log "WinRM: $($result.Message)" $lvl
    $el['StatusText'].Text = "WinRM: $($result.Message)"
    if ($result.Success) {
        [System.Windows.MessageBox]::Show($result.Message, 'WinRM Configured', 'OK', 'Information')
    } else {
        [System.Windows.MessageBox]::Show($result.Message, 'WinRM Configuration Failed', 'OK', 'Warning')
    }
})

# ── Enable Required Audit Policies (standalone - for manual button use) ────
function Enable-AuditPolicies {
    if (-not $script:Env.IsAdmin) {
        Write-Log "Cannot configure audit policies without admin privileges" 'WARN'
        return @{ Success=$false; Message='Admin privileges required' }
    }
    $configured = 0; $failed = 0
    $policies = @(
        @{ Sub='Logon'; Setting='/success:enable /failure:enable' }
        @{ Sub='Account Logon'; Setting='/success:enable /failure:enable' }
        @{ Sub='Account Management'; Setting='/success:enable /failure:enable' }
        @{ Sub='Policy Change'; Setting='/success:enable /failure:enable' }
        @{ Sub='Object Access'; Setting='/success:enable /failure:enable' }
        @{ Sub='Privilege Use'; Setting='/success:enable /failure:enable' }
        @{ Sub='System'; Setting='/success:enable /failure:enable' }
    )
    foreach ($p in $policies) {
        try {
            $cmd = "auditpol /set /subcategory:`"$($p.Sub)`" $($p.Setting)"
            $out = cmd.exe /c $cmd 2>&1
            if ($LASTEXITCODE -eq 0) { $configured++; Write-Log "Audit policy enabled: $($p.Sub)" 'INFO' }
            else { $failed++; Write-Log "Audit policy failed: $($p.Sub) - $out" 'WARN' }
        }
        catch { $failed++; Write-Log "Audit policy error: $($p.Sub) - $_" 'ERROR' }
    }
    return @{ Success=($failed -eq 0); Configured=$configured; Failed=$failed; Message="$configured policies configured, $failed failed" }
}

# ── Launch ───────────────────────────────────────────────────────────────────
$el['StatusText'].Text = "Initializing turnkey setup..."

$script:LaunchTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:LaunchTimer.Interval = [TimeSpan]::FromMilliseconds(500)
$script:LaunchTimer.Add_Tick({
    $script:LaunchTimer.Stop()
    if (-not $script:TurnkeyLaunched) {
        $script:TurnkeyLaunched = $true
        Start-AsyncTurnkey
    }
})
$script:LaunchTimer.Start()

# ── Headless / Silent Mode (RMM) ────────────────────────────────────────────
if ($script:SilentMode) {
    # In silent mode: skip GUI, run scans synchronously, export, exit
    Write-Host "[Silent Mode] Network Security Audit v4.0" -ForegroundColor Cyan
    Write-Host "[Silent Mode] Profile: $($script:CliProfile) | ReadOnly: $($script:ReadOnlyMode) | Report: $($script:CliReport)"

    # Auto-populate fields
    $clientName = if ($script:CliClient) { $script:CliClient }
                  elseif ($script:Env.IsDomainJoined) { $script:Env.DomainName.Split('.')[0].ToUpper() }
                  else { $script:Env.ComputerName }
    $auditorName = if ($script:CliAuditor) { $script:CliAuditor } else { $env:USERNAME }
    $el['txtClient'].Text = $clientName
    $el['txtAuditor'].Text = $auditorName

    # Set profile
    $profileOrder = @('Quick','Standard','Full','ADOnly','LocalOnly','HIPAA','PCI','CMMC','SOC2','ISO27001')
    $idx = $profileOrder.IndexOf($script:CliProfile)
    if ($idx -ge 0) { $el['cboProfile'].SelectedIndex = $idx }

    Write-Host "[Silent Mode] Client: $clientName | Auditor: $auditorName"
    Write-Host "[Silent Mode] Environment: $($script:Env.OSCaption) | Domain: $($script:Env.IsDomainJoined) | Admin: $($script:Env.IsAdmin)"
    Write-Host "[Silent Mode] Running scan..."

    # Run checks synchronously (no async, no GUI updates needed)
    $profName = $script:CliProfile
    $prof = $script:ScanProfiles[$profName]
    $ids = $script:AutoChecks.Keys | Sort-Object

    if ($profName -eq 'ADOnly') {
        $ids = $ids | Where-Object { $script:AutoChecks[$_].Type -eq 'AD' }
    }
    elseif ($profName -eq 'LocalOnly') {
        $ids = $ids | Where-Object { $script:AutoChecks[$_].Type -eq 'Local' }
    }
    elseif ($prof.IDs.Count -gt 0) {
        $profileSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($pid in $prof.IDs) { $profileSet.Add($pid) | Out-Null }
        $ids = $ids | Where-Object { $profileSet.Contains($_) -and $script:AutoCheckIDs.Contains($_) }
    }

    # Risk tier filtering
    if ($script:ReadOnlyMode) {
        $ids = $ids | Where-Object {
            $tier = if ($script:RiskTiers.Contains($_)) { $script:RiskTiers[$_] } else { 0 }
            $tier -le 2
        }
    }

    $idList = @($ids)
    Write-Host "[Silent Mode] Scanning $($idList.Count) checks..."

    $completed = 0; $failed = 0
    foreach ($id in $idList) {
        $check = $script:AutoChecks[$id]
        if (-not $check) { continue }
        try {
            $result = & $check.Script
            if ($result -and $result.Status) {
                # Apply result to UI state (for export) - values match combo: Pass/Fail/Partial
                $mappedStatus = if ($result.Status -eq 'Pass' -or $result.Status -eq 'Fail' -or $result.Status -eq 'Partial') { $result.Status } else { 'Not Assessed' }

                if ($script:StatusCombos.Contains($id)) {
                    $combo = $script:StatusCombos[$id]
                    for ($i=0; $i -lt $combo.Items.Count; $i++) {
                        if ($combo.Items[$i] -eq $mappedStatus) { $combo.SelectedIndex = $i; break }
                    }
                }
                if ($result.Findings -and $script:FindingsBoxes.Contains($id)) {
                    $script:FindingsBoxes[$id].Text = $result.Findings
                }
                if ($result.Evidence -and $script:EvidenceBoxes.Contains($id)) {
                    $script:EvidenceBoxes[$id].Text = $result.Evidence
                }
                if ($script:CheckStates.Contains($id)) { $script:CheckStates[$id] = $true }
                $script:ScanTimestamps[$id] = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                $completed++
                $statusIcon = switch ($result.Status) { 'Pass'{'+'} 'Fail'{'X'} default{'~'} }
                Write-Host "  [$statusIcon] $id - $($check.Label): $($result.Status)" -ForegroundColor $(switch($result.Status){'Pass'{'Green'}'Fail'{'Red'}default{'Yellow'}})
            }
        } catch {
            $failed++
            Write-Host "  [!] $id - $($check.Label): ERROR - $($_.Exception.Message)" -ForegroundColor Red
            if ($script:FindingsBoxes.Contains($id)) {
                $script:FindingsBoxes[$id].Text = "Auto-check error: $($_.Exception.Message)"
            }
        }
    }

    Write-Host "[Silent Mode] Completed: $completed | Failed: $failed | Total: $($idList.Count)"

    # Export report
    $outFile = $script:CliOutput
    if (-not $outFile) {
        $desktop = [Environment]::GetFolderPath('Desktop')
        $safeClient = $clientName -replace '[^\w\-]','_'
        $outFile = Join-Path $desktop "SecurityAudit_${safeClient}_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    }
    $basePath = $outFile -replace '\.[^.]+$',''

    # HTML Report (always generated)
    try {
        Export-HTMLReport -outPath $outFile -Tier $script:CliReport
        Write-Host "[Silent Mode] HTML report: $outFile" -ForegroundColor Green
    } catch {
        Write-Host "[Silent Mode] HTML report FAILED: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[Silent Mode] Continuing with other exports..." -ForegroundColor Yellow
    }

    # Structured findings JSON (always generated, or when -ExportJSON)
    $jsonFindingsOut = "${basePath}_findings.json"
    try {
        Export-FindingsJSON -OutPath $jsonFindingsOut -ClientName $clientName -AuditorName $auditorName
        Write-Host "[Silent Mode] Findings JSON: $jsonFindingsOut" -ForegroundColor Green
    } catch { Write-Host "[Silent Mode] Findings JSON export failed: $_" -ForegroundColor Yellow; $jsonFindingsOut = '' }

    # SIEM JSONL export (when -ExportJSONL or always in silent mode)
    $jsonlOut = ''
    if ($script:CliExportJSONL -or $script:SilentMode) {
        $jsonlOut = "${basePath}_siem.jsonl"
        try {
            Export-FindingsJSONL -OutPath $jsonlOut -ClientName $clientName -AuditorName $auditorName
            Write-Host "[Silent Mode] SIEM JSONL: $jsonlOut" -ForegroundColor Green
        } catch { Write-Host "[Silent Mode] JSONL export failed: $_" -ForegroundColor Yellow; $jsonlOut = '' }
    }

    # CSV export (when -ExportCSV or always in silent mode)
    $csvOut = ''
    if ($script:CliExportCSV -or $script:SilentMode) {
        $csvOut = "${basePath}.csv"
        try {
            Export-FindingsCSV -OutPath $csvOut -ClientName $clientName -AuditorName $auditorName
            Write-Host "[Silent Mode] CSV: $csvOut" -ForegroundColor Green
        } catch { Write-Host "[Silent Mode] CSV export failed: $_" -ForegroundColor Yellow; $csvOut = '' }
    }

    # Compliance summary JSON (compact RMM dashboard payload)
    $summaryOut = "${basePath}_summary.json"
    try {
        Export-ComplianceSummary -OutPath $summaryOut -ClientName $clientName -AuditorName $auditorName
        Write-Host "[Silent Mode] Compliance summary: $summaryOut" -ForegroundColor Green
    } catch { Write-Host "[Silent Mode] Compliance summary export failed: $_" -ForegroundColor Yellow; $summaryOut = '' }

    # ── RMM Platform Detection & Custom Field Writing ──
    $riskData = Get-RiskScore
    $rwData = Get-RansomwareScore
    $fwFlags = @{}
    try {
        $fwScores = Get-FrameworkScores -Framework 'All'
        foreach ($fw in $fwScores.Keys) { $fwFlags[$fw] = ($fwScores[$fw].Score -ge 80) }
    } catch {}
    $complianceStr = ($fwFlags.Keys | ForEach-Object { "$_`:$(if($fwFlags[$_]){'PASS'}else{'FAIL'})" }) -join '|'

    # NinjaRMM
    if (Get-Command 'Ninja-Property-Set' -EA SilentlyContinue) {
        try {
            Ninja-Property-Set 'securityAuditGrade' $riskData.Grade
            Ninja-Property-Set 'securityAuditScore' $riskData.Pct
            Ninja-Property-Set 'securityAuditDate' (Get-Date -Format 'yyyy-MM-dd')
            Ninja-Property-Set 'securityAuditFindings' ($script:StatusCombos.Values | Where-Object { $_.SelectedItem -eq 'Fail' }).Count
            Ninja-Property-Set 'ransomwareScore' $rwData.Overall
            Ninja-Property-Set 'ransomwareGrade' $rwData.Grade
            Ninja-Property-Set 'complianceStatus' $complianceStr
            Write-Host "[Silent Mode] NinjaRMM custom fields updated" -ForegroundColor Cyan
        } catch { Write-Host "[Silent Mode] NinjaRMM field write failed: $_" -ForegroundColor Yellow }
    }

    # Datto RMM (UDF)
    if (Test-Path 'HKLM:\SOFTWARE\CentraStage' -EA SilentlyContinue) {
        try {
            New-ItemProperty -Path 'HKLM:\SOFTWARE\CentraStage' -Name 'Custom1' -Value $riskData.Grade -Force -EA SilentlyContinue | Out-Null
            New-ItemProperty -Path 'HKLM:\SOFTWARE\CentraStage' -Name 'Custom2' -Value "$($riskData.Pct)%" -Force -EA SilentlyContinue | Out-Null
            New-ItemProperty -Path 'HKLM:\SOFTWARE\CentraStage' -Name 'Custom3' -Value (Get-Date -Format 'yyyy-MM-dd') -Force -EA SilentlyContinue | Out-Null
            New-ItemProperty -Path 'HKLM:\SOFTWARE\CentraStage' -Name 'Custom4' -Value "RW:$($rwData.Overall)% ($($rwData.Grade))" -Force -EA SilentlyContinue | Out-Null
            New-ItemProperty -Path 'HKLM:\SOFTWARE\CentraStage' -Name 'Custom5' -Value $complianceStr -Force -EA SilentlyContinue | Out-Null
            Write-Host "[Silent Mode] Datto RMM UDFs updated" -ForegroundColor Cyan
        } catch { Write-Host "[Silent Mode] Datto UDF write failed: $_" -ForegroundColor Yellow }
    }

    # ConnectWise Automate (LabTech) - write to registry EDFs
    if (Test-Path 'HKLM:\SOFTWARE\LabTech\Service' -EA SilentlyContinue) {
        try {
            $ltPath = 'HKLM:\SOFTWARE\LabTech\Service\SecurityAudit'
            if (-not (Test-Path $ltPath)) { New-Item -Path $ltPath -Force | Out-Null }
            Set-ItemProperty -Path $ltPath -Name 'Grade' -Value $riskData.Grade -Force
            Set-ItemProperty -Path $ltPath -Name 'Score' -Value $riskData.Pct -Force
            Set-ItemProperty -Path $ltPath -Name 'Date' -Value (Get-Date -Format 'yyyy-MM-dd') -Force
            Set-ItemProperty -Path $ltPath -Name 'RansomwareScore' -Value $rwData.Overall -Force
            Set-ItemProperty -Path $ltPath -Name 'Compliance' -Value $complianceStr -Force
            Set-ItemProperty -Path $ltPath -Name 'ReportPath' -Value $outFile -Force
            Write-Host "[Silent Mode] ConnectWise Automate EDFs updated" -ForegroundColor Cyan
        } catch { Write-Host "[Silent Mode] CW Automate EDF write failed: $_" -ForegroundColor Yellow }
    }

    # Syncro RMM - write via Syncro module if available
    if (Get-Command 'Set-SyncroCustomField' -EA SilentlyContinue) {
        try {
            Set-SyncroCustomField -Name 'SecurityAuditGrade' -Value $riskData.Grade
            Set-SyncroCustomField -Name 'SecurityAuditScore' -Value "$($riskData.Pct)%"
            Set-SyncroCustomField -Name 'RansomwareScore' -Value "$($rwData.Overall)% ($($rwData.Grade))"
            Set-SyncroCustomField -Name 'ComplianceStatus' -Value $complianceStr
            Write-Host "[Silent Mode] Syncro RMM custom fields updated" -ForegroundColor Cyan
        } catch { Write-Host "[Silent Mode] Syncro field write failed: $_" -ForegroundColor Yellow }
    }

    # HaloPSA - write custom asset fields via registry cache
    if (Test-Path 'HKLM:\SOFTWARE\HaloPSA' -EA SilentlyContinue) {
        try {
            $haloPath = 'HKLM:\SOFTWARE\HaloPSA\SecurityAudit'
            if (-not (Test-Path $haloPath)) { New-Item -Path $haloPath -Force | Out-Null }
            Set-ItemProperty -Path $haloPath -Name 'Grade' -Value $riskData.Grade -Force
            Set-ItemProperty -Path $haloPath -Name 'Score' -Value $riskData.Pct -Force
            Set-ItemProperty -Path $haloPath -Name 'RansomwareScore' -Value $rwData.Overall -Force
            Set-ItemProperty -Path $haloPath -Name 'Compliance' -Value $complianceStr -Force
            Write-Host "[Silent Mode] HaloPSA fields updated" -ForegroundColor Cyan
        } catch { Write-Host "[Silent Mode] HaloPSA field write failed: $_" -ForegroundColor Yellow }
    }

    # Generic RMM output: write summary to well-known registry path
    try {
        $rmmPath = 'HKLM:\SOFTWARE\NetworkSecurityAudit'
        if (-not (Test-Path $rmmPath)) { New-Item -Path $rmmPath -Force | Out-Null }
        Set-ItemProperty -Path $rmmPath -Name 'LastScanDate' -Value (Get-Date -Format 'o') -Force
        Set-ItemProperty -Path $rmmPath -Name 'Grade' -Value $riskData.Grade -Force
        Set-ItemProperty -Path $rmmPath -Name 'Score' -Value $riskData.Pct -Force
        Set-ItemProperty -Path $rmmPath -Name 'RansomwareScore' -Value $rwData.Overall -Force
        Set-ItemProperty -Path $rmmPath -Name 'RansomwareGrade' -Value $rwData.Grade -Force
        Set-ItemProperty -Path $rmmPath -Name 'ComplianceFlags' -Value $complianceStr -Force
        Set-ItemProperty -Path $rmmPath -Name 'FailCount' -Value ($script:StatusCombos.Values | Where-Object { $_.SelectedItem -eq 'Fail' }).Count -Force
        Set-ItemProperty -Path $rmmPath -Name 'ReportPath' -Value $outFile -Force
        Set-ItemProperty -Path $rmmPath -Name 'SummaryPath' -Value $summaryOut -Force
        Write-Host "[Silent Mode] Registry audit data updated (HKLM\SOFTWARE\NetworkSecurityAudit)" -ForegroundColor Cyan
    } catch { Write-Host "[Silent Mode] Registry write failed: $_" -ForegroundColor Yellow }

    # ── Exit Codes for RMM Alerting ──
    # 0 = Clean (A/B grade, no critical failures)
    # 1 = Critical (D/F grade OR ransomware score < 40)
    # 2 = Warning (findings present but grade C+)
    # 3 = Compliance failure (any framework below 60%)
    $failCount = ($script:StatusCombos.Values | Where-Object { $_.SelectedItem -eq 'Fail' }).Count
    $anyFwCritical = ($fwFlags.Values | Where-Object { $_ -eq $false }).Count -gt 0
    $exitCode = if ($riskData.Grade -in @('D','F') -or $rwData.Overall -lt 40) { 1 }
                elseif ($failCount -gt 0 -and $anyFwCritical) { 3 }
                elseif ($failCount -gt 0) { 2 }
                else { 0 }

    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  AUDIT COMPLETE" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  Grade: $($riskData.Grade) ($($riskData.Pct)%)" -ForegroundColor $(if($riskData.Pct -ge 80){'Green'}elseif($riskData.Pct -ge 60){'Yellow'}else{'Red'})
    Write-Host "  Ransomware: $($rwData.Grade) ($($rwData.Overall)%)" -ForegroundColor $(if($rwData.Overall -ge 80){'Green'}elseif($rwData.Overall -ge 60){'Yellow'}else{'Red'})
    Write-Host "  Compliance: $complianceStr"
    Write-Host "  Exit code: $exitCode (0=clean, 1=critical, 2=findings, 3=compliance-fail)" -ForegroundColor $(switch($exitCode){0{'Green'}1{'Red'}2{'Yellow'}3{'Magenta'}})
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "[Silent Mode] Output files:" -ForegroundColor Cyan
    Write-Host "  HTML:     $outFile"
    Write-Host "  JSON:     $jsonFindingsOut"
    if ($script:CliExportJSONL -or $script:SilentMode) { Write-Host "  JSONL:    $jsonlOut" }
    if ($script:CliExportCSV -or $script:SilentMode) { Write-Host "  CSV:      $csvOut" }
    Write-Host "  Summary:  $summaryOut"

    exit $exitCode
}

# ── Normal GUI Mode ──────────────────────────────────────────────────────────
$window.ShowDialog() | Out-Null
