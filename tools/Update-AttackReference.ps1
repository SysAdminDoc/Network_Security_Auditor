<#
.SYNOPSIS
    Pins the MITRE ATT&CK Enterprise release that the check mappings are tested against.
.DESCRIPTION
    Downloads an Enterprise ATT&CK STIX bundle from mitre-attack/attack-stix-data,
    reduces it to tactics, active techniques with their tactics, and the revoked and
    deprecated IDs, and writes that digest to the test fixtures. The mapping tests
    then fail if a mapped technique is unknown, revoked or deprecated in the pinned
    release, or if a mapped tactic doesn't match the technique's tactics.
    Bump ExternalVersions.AttackEnterprise (C#) and $script:ExternalVersions (PS1)
    to the same version after running it.
.PARAMETER Version
    ATT&CK version to pin, for example 19.2. Defaults to the newest in the index.
.NOTES
    Needs PowerShell 7.5 or later (ConvertFrom-Json -DateKind) and internet access.
    Run: pwsh -File tools/Update-AttackReference.ps1 [-Version 19.2]
#>
#Requires -Version 7.5
[CmdletBinding()]
param([string]$Version)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$indexUrl = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json'
$outPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\tests\NetworkSecurityAuditor.Tests\Fixtures\Attack\enterprise-attack.json'))

# -DateKind String keeps timestamps exactly as published instead of local DateTimes.
$index = (Invoke-WebRequest -Uri $indexUrl -UseBasicParsing).Content | ConvertFrom-Json -DateKind String
$collection = $index.collections | Where-Object { $_.name -eq 'Enterprise ATT&CK' } | Select-Object -First 1
if (-not $collection) { throw 'Enterprise ATT&CK is missing from the attack-stix-data index.' }
$entry = if ($Version) { $collection.versions | Where-Object { $_.version -eq $Version } | Select-Object -First 1 } else { $collection.versions[0] }
if (-not $entry) { throw "ATT&CK version $Version isn't in the attack-stix-data index." }

$bundlePath = Join-Path ([System.IO.Path]::GetTempPath()) "enterprise-attack-$($entry.version).json"
Invoke-WebRequest -Uri $entry.url -OutFile $bundlePath -UseBasicParsing
$sha256 = (Get-FileHash -Path $bundlePath -Algorithm SHA256).Hash.ToLowerInvariant()

function Get-AttackId($Object) {
    if (-not $Object -or -not $Object.ContainsKey('external_references')) { return $null }
    foreach ($ref in $Object['external_references']) {
        if ($ref['source_name'] -eq 'mitre-attack' -and $ref.ContainsKey('external_id')) { return [string]$ref['external_id'] }
    }
    return $null
}

function Test-Flag($Object, [string]$Name) {
    return $Object.ContainsKey($Name) -and $Object[$Name] -eq $true
}

try {
    $objects = (ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($bundlePath)) -AsHashtable -Depth 100)['objects']
} finally {
    Remove-Item -LiteralPath $bundlePath -ErrorAction SilentlyContinue
}

$byStixId = @{}
$tacticByShortName = @{}
$tacticNames = @{}
foreach ($o in $objects) {
    $byStixId[$o['id']] = $o
    if ($o['type'] -eq 'x-mitre-tactic') {
        $tid = Get-AttackId $o
        $tacticByShortName[$o['x_mitre_shortname']] = $tid
        $tacticNames[$tid] = $o['name']
    }
}
$matrix = $objects | Where-Object { $_['type'] -eq 'x-mitre-matrix' -and -not (Test-Flag $_ 'revoked') } | Select-Object -First 1
$matrixOrder = @($matrix['tactic_refs'] | ForEach-Object { Get-AttackId $byStixId[$_] })

$techniques = [System.Collections.Generic.SortedDictionary[string, object]]::new([System.StringComparer]::Ordinal)
$revoked = [System.Collections.Generic.SortedDictionary[string, object]]::new([System.StringComparer]::Ordinal)
$deprecated = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
foreach ($o in $objects) {
    if ($o['type'] -eq 'relationship' -and $o['relationship_type'] -eq 'revoked-by') {
        $source = $byStixId[$o['source_ref']]
        $target = $byStixId[$o['target_ref']]
        if ($source -and $target -and $source['type'] -eq 'attack-pattern') { $revoked[(Get-AttackId $source)] = (Get-AttackId $target) }
        continue
    }
    if ($o['type'] -ne 'attack-pattern') { continue }
    $tid = Get-AttackId $o
    if (-not $tid) { continue }
    if (Test-Flag $o 'revoked') { if (-not $revoked.ContainsKey($tid)) { $revoked[$tid] = $null }; continue }
    if (Test-Flag $o 'x_mitre_deprecated') { [void]$deprecated.Add($tid); continue }
    $tactics = @()
    if ($o.ContainsKey('kill_chain_phases')) {
        $tactics = @($o['kill_chain_phases'] | Where-Object { $_['kill_chain_name'] -eq 'mitre-attack' } | ForEach-Object { $tacticByShortName[$_['phase_name']] })
    }
    $techniques[$tid] = [ordered]@{ name = [string]$o['name']; tactics = $tactics }
}

$reference = [ordered]@{
    version    = [string]$entry.version
    modified   = [string]$entry.modified
    source     = [string]$entry.url
    sha256     = $sha256
    tactics    = @($matrixOrder | ForEach-Object { [ordered]@{ id = $_; name = $tacticNames[$_] } })
    techniques = $techniques
    revoked    = $revoked
    deprecated = @($deprecated)
}
New-Item -ItemType Directory -Force -Path (Split-Path $outPath) | Out-Null
$json = ($reference | ConvertTo-Json -Depth 6) -replace "`r`n", "`n"
[System.IO.File]::WriteAllText($outPath, $json + "`n", [System.Text.UTF8Encoding]::new($false))
Write-Host "Pinned ATT&CK Enterprise $($entry.version): $($techniques.Count) techniques, $($revoked.Count) revoked, $($deprecated.Count) deprecated -> $outPath"
