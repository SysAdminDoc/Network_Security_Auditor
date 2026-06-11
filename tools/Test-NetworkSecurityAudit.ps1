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

if (@($catalogIds).Count -ne 67) { Add-Failure "Expected 67 audit catalog IDs, found $(@($catalogIds).Count)" }
if (@($autoCheckIds).Count -ne 67) { Add-Failure "Expected 67 auto-check IDs, found $(@($autoCheckIds).Count)" }
Compare-Set -Expected $catalogIds -Actual $autoCheckIds -Name 'AutoChecks'
Compare-Set -Expected $catalogIds -Actual $frameworkIds -Name 'FrameworkMap'
Compare-Set -Expected $catalogIds -Actual $riskIds -Name 'RiskTiers'

$profileUnknown = @($profileIds | Where-Object { $_ -notin $catalogIds } | Sort-Object)
if (@($profileUnknown).Count -gt 0) { Add-Failure "ScanProfiles reference unknown IDs: $($profileUnknown -join ', ')" }
$frameworkChecksUnknown = @($frameworkCheckIds | Where-Object { $_ -notin $catalogIds } | Sort-Object)
if (@($frameworkChecksUnknown).Count -gt 0) { Add-Failure "FrameworkChecks reference unknown IDs: $($frameworkChecksUnknown -join ', ')" }

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
if ($scriptText -notmatch "\`$compObj\['STIG'\]" -or $scriptText -notmatch '(?m)^\s+stig\s+=' -or $scriptText -notmatch '(?m)^\s+STIG\s+=') {
    Add-Failure 'Structured JSON, JSONL, and CSV exports must include STIG detail fields.'
}
if ($scriptText -notmatch 'function ConvertTo-CsvSafeText' -or $scriptText -notmatch 'Findings\s+=\s+ConvertTo-CsvSafeText' -or $scriptText -notmatch 'Evidence\s+=\s+ConvertTo-CsvSafeText' -or $scriptText -notmatch 'Notes\s+=\s+ConvertTo-CsvSafeText') {
    Add-Failure 'CSV export free-text fields must be formula-injection neutralized.'
}
if ($scriptText -notmatch 'findings_truncated' -or $scriptText -notmatch 'findings_original_length' -or $scriptText -notmatch 'evidence_truncated' -or $scriptText -notmatch 'evidence_original_length') {
    Add-Failure 'JSONL truncation must include flags and original lengths.'
}
if ($scriptText -notmatch 'logicalLocations' -or $scriptText -notmatch 'network-security-audit://check/') {
    Add-Failure 'SARIF results must include logical check locations.'
}
if ($scriptText -match '(?m)^\s*(Set-Service|Start-Service|Stop-Service|Restart-Service)\b') {
    Add-Failure 'Automation paths must use sc.exe instead of service cmdlets that can show progress UI.'
}

if ($failures.Count -gt 0) {
    Write-Host 'NetworkSecurityAudit validation FAILED' -ForegroundColor Red
    foreach ($failure in $failures) { Write-Host " - $failure" -ForegroundColor Red }
    exit 1
}

Write-Host "NetworkSecurityAudit validation passed ($(@($catalogIds).Count) checks, version $productVersion)." -ForegroundColor Green
