#Requires -Version 5.1
<#
.SYNOPSIS
    Static validation gate for NetworkSecurityAudit.ps1.
.DESCRIPTION
    Runs parser, catalog, profile, framework, export-pass-through, and version
    consistency checks without executing audit checks or touching the host.
#>
[CmdletBinding()]
param(
    [string]$ScriptPath = '',
    [string]$ReadmePath = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$repoRoot = Split-Path -Parent $scriptDir
if (-not $ScriptPath) { $ScriptPath = Join-Path $repoRoot 'NetworkSecurityAudit.ps1' }
if (-not $ReadmePath) { $ReadmePath = Join-Path $repoRoot 'README.md' }
$resolvedScript = (Resolve-Path -LiteralPath $ScriptPath).Path
$resolvedReadme = (Resolve-Path -LiteralPath $ReadmePath).Path
$scriptText = Get-Content -Raw -LiteralPath $resolvedScript
$readmeText = Get-Content -Raw -LiteralPath $resolvedReadme
$failures = New-Object System.Collections.Generic.List[string]

function Add-Failure {
    param([string]$Message)
    [void]$failures.Add($Message)
}

function Get-UniqueMatches {
    param(
        [string]$Text,
        [string]$Pattern
    )
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($match in [regex]::Matches($Text, $Pattern)) {
        [void]$set.Add($match.Groups[1].Value)
    }
    return @($set)
}

function Get-TextBetween {
    param(
        [string]$Text,
        [string]$StartPattern,
        [string]$EndPattern
    )
    $start = [regex]::Match($Text, $StartPattern)
    if (-not $start.Success) { return '' }
    $remaining = $Text.Substring($start.Index)
    $end = [regex]::Match($remaining, $EndPattern)
    if (-not $end.Success) { return $remaining }
    return $remaining.Substring(0, $end.Index)
}

function Compare-Set {
    param(
        [string[]]$Expected,
        [string[]]$Actual,
        [string]$Name
    )
    $expectedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $actualSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($id in $Expected) { [void]$expectedSet.Add($id) }
    foreach ($id in $Actual) { [void]$actualSet.Add($id) }

    $missing = @($expectedSet | Where-Object { -not $actualSet.Contains($_) } | Sort-Object)
    $extra = @($actualSet | Where-Object { -not $expectedSet.Contains($_) } | Sort-Object)
    if (@($missing).Count -gt 0) { Add-Failure "$Name missing IDs: $($missing -join ', ')" }
    if (@($extra).Count -gt 0) { Add-Failure "$Name contains unknown IDs: $($extra -join ', ')" }
}

function Get-FrameworkCoverageCount {
    param(
        [string]$Framework,
        [string]$FrameworkChecksBlock,
        [int]$AllCheckCount
    )

    $pattern = "(?ms)'$([regex]::Escape($Framework))'\s*=\s*@\((.*?)\)"
    $match = [regex]::Match($FrameworkChecksBlock, $pattern)
    if (-not $match.Success) { return -1 }

    $expression = $match.Groups[1].Value
    if ($expression -match '\$script:FrameworkMap\.Keys') { return $AllCheckCount }

    return @(
        Get-UniqueMatches -Text $expression -Pattern "'([A-Z]{2}\d{2})'"
    ).Count
}

$tokens = $null
$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseInput($scriptText, [ref]$tokens, [ref]$parseErrors) | Out-Null
if (@($parseErrors).Count -gt 0) {
    Add-Failure "Parser errors: $(@($parseErrors).Count)"
    foreach ($err in $parseErrors) {
        Add-Failure "  line $($err.Extent.StartLineNumber): $($err.Message)"
    }
}

$catalogIds = @(Get-UniqueMatches -Text $scriptText -Pattern "ID='([A-Z]{2}\d{2})';\s*Severity=")
$autoCheckBlock = Get-TextBetween -Text $scriptText -StartPattern '\$script:AutoChecks\s*=\s*@\{' -EndPattern '# Items that have auto-checks available'
$autoCheckIds = @(Get-UniqueMatches -Text $autoCheckBlock -Pattern "(?m)^\s*'([A-Z]{2}\d{2})'\s*=\s*@\{\s*Type=")
$profileBlock = Get-TextBetween -Text $scriptText -StartPattern '\$script:ScanProfiles\s*=\s*@\{' -EndPattern '# . Risk Tier Classification'
$profileIds = @(Get-UniqueMatches -Text $profileBlock -Pattern "'([A-Z]{2}\d{2})'")
$frameworkBlock = Get-TextBetween -Text $scriptText -StartPattern '\$script:FrameworkMap\s*=\s*@\{' -EndPattern '# . DISA STIG Mapping'
$frameworkIds = @(Get-UniqueMatches -Text $frameworkBlock -Pattern "(?m)^\s*'([A-Z]{2}\d{2})'\s*=\s*@\{")
$riskBlock = Get-TextBetween -Text $scriptText -StartPattern '\$script:RiskTiers\s*=\s*@\{' -EndPattern '\$script:RiskTierLabels'
$riskIds = @(Get-UniqueMatches -Text $riskBlock -Pattern "'([A-Z]{2}\d{2})'\s*=\s*\d")
$frameworkChecksBlock = Get-TextBetween -Text $scriptText -StartPattern '\$script:FrameworkChecks\s*=\s*@\{' -EndPattern '# Helper: Get formatted compliance string'
$frameworkCheckIds = @(Get-UniqueMatches -Text $frameworkChecksBlock -Pattern "'([A-Z]{2}\d{2})'")
$d3fendBlock = Get-TextBetween -Text $scriptText -StartPattern '\$script:D3FendMap\s*=\s*@\{' -EndPattern '\$script:D3FendStages'
$d3fendIds = @(Get-UniqueMatches -Text $d3fendBlock -Pattern "(?m)^\s*'([A-Z]{2}\d{2})'\s*=\s*@\{")

if (@($catalogIds).Count -ne 68) { Add-Failure "Expected 68 audit catalog IDs, found $(@($catalogIds).Count)" }
if (@($autoCheckIds).Count -ne 68) { Add-Failure "Expected 68 auto-check IDs, found $(@($autoCheckIds).Count)" }
Compare-Set -Expected $catalogIds -Actual $autoCheckIds -Name 'AutoChecks'
Compare-Set -Expected $catalogIds -Actual $frameworkIds -Name 'FrameworkMap'
Compare-Set -Expected $catalogIds -Actual $riskIds -Name 'RiskTiers'
Compare-Set -Expected $catalogIds -Actual $d3fendIds -Name 'D3FendMap'

$profileUnknown = @($profileIds | Where-Object { $_ -notin $catalogIds } | Sort-Object)
if (@($profileUnknown).Count -gt 0) { Add-Failure "ScanProfiles reference unknown IDs: $($profileUnknown -join ', ')" }
$frameworkChecksUnknown = @($frameworkCheckIds | Where-Object { $_ -notin $catalogIds } | Sort-Object)
if (@($frameworkChecksUnknown).Count -gt 0) { Add-Failure "FrameworkChecks reference unknown IDs: $($frameworkChecksUnknown -join ', ')" }

$readmeFrameworkLabels = [ordered]@{
    CIS = 'CIS'
    NIST = 'NIST'
    CMMC = 'CMMC'
    HIPAA = 'HIPAA'
    PCI = 'PCI-DSS'
    E8 = 'ACSC Essential Eight'
    CyberEssentials = 'Cyber Essentials'
    SOC2 = 'SOC 2'
    ISO27001 = 'ISO 27001'
    STIG = 'DISA STIG'
}
foreach ($framework in $readmeFrameworkLabels.Keys) {
    $coverageCount = Get-FrameworkCoverageCount -Framework $framework -FrameworkChecksBlock $frameworkChecksBlock -AllCheckCount @($catalogIds).Count
    if ($coverageCount -lt 0) {
        Add-Failure "FrameworkChecks is missing framework: $framework"
        continue
    }

    $labelPattern = [regex]::Escape("**$($readmeFrameworkLabels[$framework])**")
    $coveragePattern = "\|\s*$labelPattern\s*\|[^|]+\|\s*$coverageCount checks\s*\|"
    if ($readmeText -notmatch $coveragePattern) {
        Add-Failure "README framework profile count for $framework must be $coverageCount checks."
    }
}

$headerVersion = [regex]::Match($scriptText, '(?ms)\.VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)').Groups[1].Value
$productVersion = [regex]::Match($scriptText, "\`$script:ProductVersion\s*=\s*'([0-9]+\.[0-9]+\.[0-9]+)'").Groups[1].Value
$readmeVersions = @(Get-UniqueMatches -Text $readmeText -Pattern '(?:Version|version)-([0-9]+\.[0-9]+\.[0-9]+)')
$allVersions = @($headerVersion, $productVersion) + $readmeVersions
if (@($allVersions | Where-Object { -not $_ }).Count -gt 0) {
    Add-Failure 'Could not read all version surfaces.'
}
if (@($allVersions | Select-Object -Unique).Count -ne 1) {
    Add-Failure "Version drift detected: $($allVersions -join ', ')"
}

$staleVersionPatterns = @(
    'Network Security Audit Checklist v4\.1',
    'SMB Security Assessment Tool v4\.1',
    "tool_version\s*=\s*'4\.1'",
    "source_version\s*=\s*'4\.1'",
    "Version='4\.1'"
)
foreach ($pattern in $staleVersionPatterns) {
    if ($scriptText -match $pattern) { Add-Failure "Stale version string matched pattern: $pattern" }
}
if ($scriptText -match 'switch\(\$true\)') {
    Add-Failure 'Threshold scoring must use scalar if/elseif logic instead of switch($true), which can emit multiple matches.'
}

if ($scriptText -notmatch "if\s*\(\`$ExportSARIF\)[^\r\n]*'-ExportSARIF'") {
    Add-Failure 'Auto-elevation does not preserve -ExportSARIF.'
}
if ($scriptText -notmatch "if\s*\(\`$ExportPDF\)[^\r\n]*'-ExportPDF'") {
    Add-Failure 'Auto-elevation does not preserve -ExportPDF.'
}
if ($scriptText -notmatch '\[switch\]\$NoRmmWrite' -or $scriptText -notmatch "if\s*\(\`$NoRmmWrite\)[^\r\n]*'-NoRmmWrite'" -or $scriptText -notmatch '\$script:CliNoRmmWrite' -or $scriptText -notmatch 'RMM and registry field writes skipped') {
    Add-Failure 'Silent mode must expose, preserve, and honor -NoRmmWrite.'
}
if ($scriptText -notmatch '\[switch\]\$NoRegistryWrite' -or $scriptText -notmatch "if\s*\(\`$NoRegistryWrite\)[^\r\n]*'-NoRegistryWrite'" -or $scriptText -notmatch '\$script:CliNoRegistryWrite' -or $scriptText -notmatch 'Registry-backed RMM/cache writes skipped') {
    Add-Failure 'Silent mode must expose, preserve, and honor -NoRegistryWrite.'
}
if ($scriptText -notmatch '\[switch\]\$NoInternet' -or $scriptText -notmatch "if\s*\(\`$NoInternet\)[^\r\n]*'-NoInternet'" -or $scriptText -notmatch '\$script:CliNoInternet' -or $scriptText -notmatch 'KEV lookup skipped \(-NoInternet\)' -or $scriptText -notmatch 'Egress port probe skipped \(-NoInternet\)' -or $scriptText -notmatch 'External DNS test skipped \(-NoInternet\)') {
    Add-Failure 'Internet-touching checks must expose, preserve, and honor -NoInternet.'
}
if ($scriptText -notmatch '\[switch\]\$NoElevate' -or $scriptText -notmatch '\$script:ElevationSkipped' -or $scriptText -notmatch 'Auto-elevation skipped \(-NoElevate\)' -or $scriptText -notmatch 'if \(-not \$script:IsAdmin -and -not \$NoElevate\)') {
    Add-Failure 'Auto-elevation must be suppressible with -NoElevate.'
}
if ($scriptText -notmatch "Framework -eq 'STIG'" -or $scriptText -notmatch 'STIG:') {
    Add-Failure 'Get-ComplianceString does not emit STIG mappings.'
}
if ($scriptText -notmatch "Framework -eq 'E8'" -or $scriptText -notmatch 'E8:' -or $scriptText -notmatch "'E8'\s*=\s*@\{" -or $scriptText -notmatch '\[ValidateSet\([^\)]*E8') {
    Add-Failure 'ACSC Essential Eight must be exposed as a framework, scan profile, and formatted compliance target.'
}
if ($scriptText -notmatch "Framework -eq 'CyberEssentials'" -or $scriptText -notmatch 'CE:' -or $scriptText -notmatch "'CyberEssentials'\s*=\s*@\{" -or $scriptText -notmatch '\[ValidateSet\([^\)]*CyberEssentials') {
    Add-Failure 'Cyber Essentials must be exposed as a framework, scan profile, and formatted compliance target.'
}
if ($scriptText -notmatch "\`$compObj\['STIG'\]" -or $scriptText -notmatch '(?m)^\s+stig\s+=' -or $scriptText -notmatch '(?m)^\s+STIG\s+=') {
    Add-Failure 'Structured JSON, JSONL, and CSV exports must include STIG detail fields.'
}
if ($scriptText -notmatch "\`$compObj\['ACSC_Essential_Eight'\]" -or $scriptText -notmatch '(?m)^\s+essential_eight\s+=' -or $scriptText -notmatch '(?m)^\s+Essential_Eight\s+=') {
    Add-Failure 'Structured JSON, JSONL, and CSV exports must include ACSC Essential Eight fields.'
}
if ($scriptText -notmatch "\`$compObj\['Cyber_Essentials'\]" -or $scriptText -notmatch '(?m)^\s+cyber_essentials\s+=' -or $scriptText -notmatch '(?m)^\s+Cyber_Essentials\s+=') {
    Add-Failure 'Structured JSON, JSONL, and CSV exports must include Cyber Essentials fields.'
}
if ($scriptText -notmatch 'function ConvertTo-CsvSafeText' -or $scriptText -notmatch 'Findings\s+=\s+ConvertTo-CsvSafeText' -or $scriptText -notmatch 'Evidence\s+=\s+ConvertTo-CsvSafeText' -or $scriptText -notmatch 'Notes\s+=\s+ConvertTo-CsvSafeText') {
    Add-Failure 'CSV export free-text fields must be formula-injection neutralized.'
}
if ($scriptText -notmatch 'findings_truncated' -or $scriptText -notmatch 'findings_original_length' -or $scriptText -notmatch 'evidence_truncated' -or $scriptText -notmatch 'evidence_original_length') {
    Add-Failure 'JSONL truncation must include flags and original lengths.'
}
if ($scriptText -notmatch '\$script:RunLog' -or $scriptText -notmatch 'function Export-RunLogJSONL' -or $scriptText -notmatch 'run_log_summary' -or $scriptText -notmatch 'duration_ms' -or $scriptText -notmatch 'timed_out' -or $scriptText -notmatch 'skip_reason' -or $scriptText -notmatch '_runlog\.jsonl') {
    Add-Failure 'Scans must export structured run-log timing, timeout, skip, and error metadata.'
}
if ($scriptText -notmatch 'logicalLocations' -or $scriptText -notmatch 'network-security-audit://check/') {
    Add-Failure 'SARIF results must include logical check locations.'
}
if ($scriptText -notmatch '\$script:D3FendMap' -or $scriptText -notmatch 'function Get-D3FendCoverage' -or $scriptText -notmatch 'D3FEND Coverage') {
    Add-Failure 'D3FEND map and HTML coverage summary must be present.'
}
if ($scriptText -notmatch 'd3fend_techniques' -or $scriptText -notmatch 'D3FEND_Techniques' -or $scriptText -notmatch 'd3fend\s*=') {
    Add-Failure 'JSON, JSONL, and CSV exports must include D3FEND technique fields.'
}
if ($scriptText -notmatch '(?s)function Export-FindingsCSV.*\$d3fendData\s*=.*D3FEND_Techniques') {
    Add-Failure 'CSV export must initialize D3FEND data before writing D3FEND columns.'
}
if ($scriptText -match 'ToolTip="[^"]*ATT&CK') {
    Add-Failure 'XAML tooltips must XML-escape ATT&CK as ATT&amp;CK.'
}
if ($scriptText -match 'foreach\s*\(\$pid\b') {
    Add-Failure 'Profile loops must not use $pid because it collides with read-only $PID.'
}
if ($scriptText -match '\$t\.TextSec\b') {
    Add-Failure 'Theme code must use the TextSecondary token, not the nonexistent TextSec alias.'
}
if ($scriptText -notmatch 'Defender provider unavailable' -or $scriptText -notmatch 'Defender status unavailable') {
    Add-Failure 'EP01 must degrade Defender provider failures into a partial finding instead of aborting the check.'
}
if ($scriptText -notmatch 'BitLocker status unavailable' -or $scriptText -notmatch 'Run as Administrator for full disk-encryption evidence') {
    Add-Failure 'EP02 must degrade BitLocker access/provider failures into a partial finding instead of aborting the check.'
}
if ($scriptText -match '(?m)^\s*(Set-Service|Start-Service|Stop-Service|Restart-Service)\b') {
    Add-Failure 'Automation paths must use sc.exe instead of service cmdlets that can show progress UI.'
}
if ($scriptText -notmatch "'IA11'\s*=\s*@\{\s*Type='AD'" -or $scriptText -notmatch 'msDS-SupportedEncryptionTypes' -or $scriptText -notmatch "Get-ADUser 'krbtgt'" -or $scriptText -notmatch 'Kdcsvc' -or $scriptText -notmatch 'RC4DefaultDisablementPhase') {
    Add-Failure 'IA11 Kerberos RC4/DES readiness check must inspect krbtgt, AD encryption flags, KDC events, and RC4 phase registry state.'
}

if ($failures.Count -gt 0) {
    Write-Host 'NetworkSecurityAudit validation FAILED' -ForegroundColor Red
    foreach ($failure in $failures) { Write-Host " - $failure" -ForegroundColor Red }
    exit 1
}

Write-Host "NetworkSecurityAudit validation passed ($(@($catalogIds).Count) checks, version $productVersion)." -ForegroundColor Green
