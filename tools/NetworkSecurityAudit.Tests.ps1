#Requires -Version 5.1
<#
.SYNOPSIS
    Pester v5 quality gate for NetworkSecurityAudit.ps1.
.DESCRIPTION
    Static, non-executing tests that protect the single-file tool from
    regressions: parser health, catalog/profile/framework/risk/D3FEND ID
    consistency, version-surface drift, export serialization, lint cleanliness,
    and the legacy static gate. No test executes a real audit check or modifies
    the host.

    Run:  Invoke-Pester -Path .\tools\NetworkSecurityAudit.Tests.ps1
#>

BeforeAll {
    $script:RepoRoot   = Split-Path -Parent $PSScriptRoot
    $script:ScriptPath = Join-Path $script:RepoRoot 'NetworkSecurityAudit.ps1'
    $script:ReadmePath = Join-Path $script:RepoRoot 'README.md'
    $script:Text       = Get-Content -Raw -LiteralPath $script:ScriptPath
    $script:Readme     = Get-Content -Raw -LiteralPath $script:ReadmePath

    function Get-IdSet {
        param([string]$Text, [string]$Pattern)
        $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($m in [regex]::Matches($Text, $Pattern)) { [void]$set.Add($m.Groups[1].Value) }
        return @($set)
    }
    function Get-Block {
        param([string]$Text, [string]$Start, [string]$End)
        $s = [regex]::Match($Text, $Start)
        if (-not $s.Success) { return '' }
        $rest = $Text.Substring($s.Index)
        $e = [regex]::Match($rest, $End)
        if (-not $e.Success) { return $rest }
        return $rest.Substring(0, $e.Index)
    }

    $script:CatalogIds   = Get-IdSet $script:Text "ID='([A-Z]{2}\d{2})';\s*Severity="
    $script:AutoBlock    = Get-Block $script:Text '\$script:AutoChecks\s*=\s*@\{' '# Items that have auto-checks available'
    $script:AutoIds      = Get-IdSet $script:AutoBlock "(?m)^\s*'([A-Z]{2}\d{2})'\s*=\s*@\{\s*Type="
    $script:ProfileBlock = Get-Block $script:Text '\$script:ScanProfiles\s*=\s*@\{' '# . Risk Tier Classification'
    $script:ProfileIds   = Get-IdSet $script:ProfileBlock "'([A-Z]{2}\d{2})'"
    $script:FwBlock      = Get-Block $script:Text '\$script:FrameworkMap\s*=\s*@\{' '# . DISA STIG Mapping'
    $script:FwIds        = Get-IdSet $script:FwBlock "(?m)^\s*'([A-Z]{2}\d{2})'\s*=\s*@\{"
    $script:RiskBlock    = Get-Block $script:Text '\$script:RiskTiers\s*=\s*@\{' '\$script:RiskTierLabels'
    $script:RiskIds      = Get-IdSet $script:RiskBlock "'([A-Z]{2}\d{2})'\s*=\s*\d"
    $script:D3Block      = Get-Block $script:Text '\$script:D3FendMap\s*=\s*@\{' '\$script:D3FendStages'
    $script:D3Ids        = Get-IdSet $script:D3Block "(?m)^\s*'([A-Z]{2}\d{2})'\s*=\s*@\{"
    $script:FwChkBlock   = Get-Block $script:Text '\$script:FrameworkChecks\s*=\s*@\{' '# Helper: Get formatted compliance string'
    $script:FwChkIds     = Get-IdSet $script:FwChkBlock "'([A-Z]{2}\d{2})'"

    $script:ExpectedCheckCount = 69
}

Describe 'Parser health' {
    It 'parses with zero parser errors' {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$errors) | Out-Null
        @($errors).Count | Should -Be 0 -Because 'syntax errors must never ship'
    }
}

Describe 'Check catalog consistency' {
    It "defines exactly <ExpectedCheckCount> unique audit IDs" -TestCases @(@{ ExpectedCheckCount = 69 }) {
        @($script:CatalogIds).Count | Should -Be $ExpectedCheckCount
    }
    It 'has exactly one auto-check per catalog ID' {
        @($script:AutoIds).Count | Should -Be $script:ExpectedCheckCount
    }

    Context 'every catalog ID is covered by <_>' -ForEach @('AutoChecks','FrameworkMap','RiskTiers','D3FendMap') {
        It 'has no missing or unknown IDs' {
            $actual = switch ($_) {
                'AutoChecks'   { $script:AutoIds }
                'FrameworkMap' { $script:FwIds }
                'RiskTiers'    { $script:RiskIds }
                'D3FendMap'    { $script:D3Ids }
            }
            $cat = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($id in $script:CatalogIds) { [void]$cat.Add($id) }
            $act = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($id in $actual) { [void]$act.Add($id) }
            $missing = @($cat | Where-Object { -not $act.Contains($_) } | Sort-Object)
            $extra   = @($act | Where-Object { -not $cat.Contains($_) } | Sort-Object)
            $missing | Should -BeNullOrEmpty -Because "$_ is missing: $($missing -join ', ')"
            $extra   | Should -BeNullOrEmpty -Because "$_ has unknown IDs: $($extra -join ', ')"
        }
    }

    It 'scan profiles reference only known check IDs' {
        $unknown = @($script:ProfileIds | Where-Object { $_ -notin $script:CatalogIds } | Sort-Object)
        $unknown | Should -BeNullOrEmpty -Because "ScanProfiles reference unknown IDs: $($unknown -join ', ')"
    }
    It 'framework profiles reference only known check IDs' {
        $unknown = @($script:FwChkIds | Where-Object { $_ -notin $script:CatalogIds } | Sort-Object)
        $unknown | Should -BeNullOrEmpty -Because "FrameworkChecks reference unknown IDs: $($unknown -join ', ')"
    }
}

Describe 'Version surface consistency' {
    BeforeAll {
        $script:HeaderComment = [regex]::Match($script:Text, 'Network Security Auditor v([0-9]+\.[0-9]+\.[0-9]+)').Groups[1].Value
        $script:DotVersion    = [regex]::Match($script:Text, '(?ms)\.VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)').Groups[1].Value
        $script:ProductVer    = [regex]::Match($script:Text, "\`$script:ProductVersion\s*=\s*'([0-9]+\.[0-9]+\.[0-9]+)'").Groups[1].Value
        $script:ReadmeVers    = @([regex]::Matches($script:Readme, '(?:Version|version)-([0-9]+\.[0-9]+\.[0-9]+)') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    }
    It 'reads a non-empty centralized product version' {
        $script:ProductVer | Should -Match '^[0-9]+\.[0-9]+\.[0-9]+$'
    }
    It 'script header comment matches the product version' {
        $script:HeaderComment | Should -Be $script:ProductVer
    }
    It '.VERSION block matches the product version' {
        $script:DotVersion | Should -Be $script:ProductVer
    }
    It 'all README version badges match the product version' {
        $script:ReadmeVers | Should -Not -BeNullOrEmpty
        ($script:ReadmeVers | Where-Object { $_ -ne $script:ProductVer }) | Should -BeNullOrEmpty -Because "README badges drifted: $($script:ReadmeVers -join ', ')"
    }

    Context 'dynamic surfaces derive from $script:ProductVersion (cannot drift)' {
        It '<_> references the centralized version constant' -ForEach @(
            'WindowTitle','HTML report footer','save state','silent banner') {
            switch ($_) {
                'WindowTitle'         { $script:Text | Should -Match '\$script:WindowTitle\s*=\s*"[^"]*\$\(\$script:ProductVersion\)' }
                'HTML report footer'  { $script:Text | Should -Match 'Version:\s*<strong>v\$\(\$script:ProductVersion\)' }
                'save state'          { $script:Text | Should -Match 'Version\s*=\s*\$script:ProductVersion' }
                'silent banner'       { $script:Text | Should -Match '\$script:ProductSubtitle\s*=\s*"[^"]*\$\(\$script:ProductVersion\)' }
            }
        }
    }
}

Describe 'Export serialization' {
    It 'serializes a representative finding object to valid JSON' {
        $sample = [ordered]@{
            schema_version = '2.1'
            tool_version   = '4.9.0'
            findings = @(
                [ordered]@{
                    id = 'IA01'; label = 'Privileged group membership'; status = 'Fail'
                    score = 0; severity = 'Critical'; weight = 5
                    findings = 'Domain Admins contains 12 members.'
                    evidence = "Get-ADGroupMember 'Domain Admins'"
                    compliance = [ordered]@{ CIS='5.1'; STIG='V-1000'; FedRAMP='AC-2' }
                    mitre = @('T1078'); d3fend = @('D3-ANCI')
                }
            )
        }
        { $sample | ConvertTo-Json -Depth 8 | ConvertFrom-Json } | Should -Not -Throw
        $round = $sample | ConvertTo-Json -Depth 8 | ConvertFrom-Json
        $round.findings[0].id | Should -Be 'IA01'
        $round.findings[0].compliance.STIG | Should -Be 'V-1000'
    }
}

Describe 'Lint cleanliness (PSScriptAnalyzer)' {
    It 'has zero analyzer findings under the project settings' -Skip:(-not (Get-Module -ListAvailable PSScriptAnalyzer)) {
        $settings = Join-Path $script:RepoRoot 'PSScriptAnalyzerSettings.psd1'
        $results  = Invoke-ScriptAnalyzer -Path $script:ScriptPath -Settings $settings
        $summary  = ($results | ForEach-Object { "$($_.Severity) $($_.RuleName):$($_.Line)" }) -join '; '
        @($results).Count | Should -Be 0 -Because "analyzer findings: $summary"
    }
}

Describe 'Legacy static gate' {
    It 'passes tools/Test-NetworkSecurityAudit.ps1' {
        $gate = Join-Path $PSScriptRoot 'Test-NetworkSecurityAudit.ps1'
        # Run in a child process using the same PowerShell host as the test run
        # (the gate calls 'exit', which would otherwise terminate Pester).
        $hostExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $out  = & $hostExe -NoProfile -File $gate 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($out -join "`n")
    }
}
