<#
.SYNOPSIS
    Pins the MITRE D3FEND release that the check mappings are tested against.
.DESCRIPTION
    Downloads a D3FEND ontology release (JSON-LD), reduces it to each defensive
    technique's ID, label and tactic (Model, Harden, Detect, Isolate, Deceive, Evict,
    Restore), and writes that digest to the test fixtures. The mapping tests then fail
    if a mapped ID isn't in the pinned release, carries a label D3FEND doesn't give it,
    or sits under a stage the check doesn't list.
    Bump $script:ExternalVersions.D3FEND in the PS1 to the same version after running it.
.PARAMETER Version
    D3FEND version to pin, for example 1.6.0. Defaults to the current release.
.NOTES
    Needs PowerShell 7.5 or later (ConvertFrom-Json -DateKind) and internet access.
    Run: pwsh -File tools/Update-D3fendReference.ps1 [-Version 1.6.0]
#>
#Requires -Version 7.5
[CmdletBinding()]
param([string]$Version)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$outPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\tests\NetworkSecurityAuditor.Tests\Fixtures\D3fend\d3fend.json'))
$stages = @('Model', 'Harden', 'Detect', 'Isolate', 'Deceive', 'Evict', 'Restore')

if (-not $Version) {
    $Version = [string]((Invoke-WebRequest -Uri 'https://d3fend.mitre.org/api/version.json' -UseBasicParsing).Content | ConvertFrom-Json -DateKind String).version
}
$sourceUrl = "https://d3fend.mitre.org/ontologies/d3fend/$Version/d3fend.json"
$ontologyPath = Join-Path ([System.IO.Path]::GetTempPath()) "d3fend-$Version.json"
Invoke-WebRequest -Uri $sourceUrl -OutFile $ontologyPath -UseBasicParsing
$sha256 = (Get-FileHash -Path $ontologyPath -Algorithm SHA256).Hash.ToLowerInvariant()
try {
    $graph = (ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($ontologyPath)) -AsHashtable -Depth 100 -DateKind String)['@graph']
} finally {
    Remove-Item -LiteralPath $ontologyPath -ErrorAction SilentlyContinue
}

function Get-List($Value) {
    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Collections.IList]) { return @($Value) }
    return @($Value)
}

function Get-Label($Node) {
    $label = $Node['rdfs:label']
    if ($label -is [System.Collections.IList]) { $label = $label[0] }
    if ($label -is [System.Collections.IDictionary]) { $label = $label['@value'] }
    return [string]$label
}

$byId = @{}
foreach ($node in $graph) { $byId[$node['@id']] = $node }

# A technique's tactic is the first "enables" link to a tactic found walking up rdfs:subClassOf.
function Get-Stage([string]$NodeId, [System.Collections.Generic.HashSet[string]]$Seen) {
    $node = $byId[$NodeId]
    if (-not $node -or -not $Seen.Add($NodeId)) { return $null }
    foreach ($link in (Get-List $node['d3f:enables'])) {
        $name = if ($link -is [System.Collections.IDictionary]) { ([string]$link['@id']).Split(':')[-1] } else { [string]$link }
        if ($stages -contains $name) { return $name }
    }
    foreach ($parent in (Get-List $node['rdfs:subClassOf'])) {
        if ($parent -is [System.Collections.IDictionary]) {
            $stage = Get-Stage ([string]$parent['@id']) $Seen
            if ($stage) { return $stage }
        }
    }
    return $null
}

$techniques = [System.Collections.Generic.SortedDictionary[string, object]]::new([System.StringComparer]::Ordinal)
foreach ($node in $graph) {
    $id = [string]$node['d3f:d3fend-id']
    if (-not $id) { continue }
    $stage = Get-Stage ([string]$node['@id']) ([System.Collections.Generic.HashSet[string]]::new())
    if (-not $stage) { continue }   # analytic techniques (D3A-*) have no defensive tactic
    $techniques[$id] = [ordered]@{ label = (Get-Label $node); stage = $stage }
}

$reference = [ordered]@{
    version    = $Version
    source     = $sourceUrl
    sha256     = $sha256
    stages     = $stages
    techniques = $techniques
}
New-Item -ItemType Directory -Force -Path (Split-Path $outPath) | Out-Null
$json = ($reference | ConvertTo-Json -Depth 5) -replace "`r`n", "`n"
[System.IO.File]::WriteAllText($outPath, $json + "`n", [System.Text.UTF8Encoding]::new($false))
Write-Host "Pinned D3FEND $Version`: $($techniques.Count) defensive techniques -> $outPath"
