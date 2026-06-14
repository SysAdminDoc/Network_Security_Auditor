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

    It 'serializes a representative write-manifest disclosure to valid JSON' {
        $writes = [ordered]@{
            read_only           = $true
            write_manifest_only = $false
            no_rmm_write        = $false
            no_registry_write   = $false
            intended_count      = 1
            any_attempted       = $true
            any_succeeded       = $true
            manifest = @(
                [ordered]@{
                    action_id = 'registry.generic'; provider = 'Generic registry'
                    destination = 'HKLM:\SOFTWARE\NetworkSecurityAudit'; risk_tier = 1
                    requires_admin = $true; allowed = $true; attempted = $true
                    succeeded = $true; skip_reason = ''; error = ''
                    rollback_hint = 'Remove the HKLM:\SOFTWARE\NetworkSecurityAudit key.'
                }
            )
        }
        { $writes | ConvertTo-Json -Depth 6 | ConvertFrom-Json } | Should -Not -Throw
        $round = $writes | ConvertTo-Json -Depth 6 | ConvertFrom-Json
        $round.any_attempted | Should -BeTrue
        $round.manifest[0].provider | Should -Be 'Generic registry'
    }
}

Describe 'Write gate behavior (real functions via AST)' {
    BeforeAll {
        # Extract the actual function bodies from the script and load them in
        # isolation so we exercise the real safety-critical code, not a copy,
        # without running the auto-elevating GUI/silent entry points.
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        foreach ($nm in 'Register-AuditWrite','Block-IfReadOnly') {
            $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $nm }, $true)[0]
            . ([scriptblock]::Create($fn.Extent.Text))
        }
    }
    BeforeEach {
        $script:WriteManifest = [System.Collections.Generic.List[object]]::new()
        $script:CliWriteManifestOnly = $false
        $script:ReadOnlyMode = $false
    }

    It 'executes an allowed write and records success' {
        $script:__ran1 = $false
        $e = Register-AuditWrite -ActionId 't' -Provider 'P' -Destination 'D' -Allowed $true -Action { $script:__ran1 = $true }
        $script:__ran1 | Should -BeTrue
        $e.attempted | Should -BeTrue
        $e.succeeded | Should -BeTrue
    }
    It 'previews (does not execute) under -WriteManifestOnly' {
        $script:CliWriteManifestOnly = $true
        $script:__ran2 = $false
        $e = Register-AuditWrite -ActionId 't' -Provider 'P' -Destination 'D' -Allowed $true -Action { $script:__ran2 = $true }
        $e.allowed   | Should -BeFalse
        $e.attempted | Should -BeFalse
        $script:__ran2 | Should -BeFalse
        $e.skip_reason | Should -Be 'WriteManifestOnly preview'
    }
    It 'records error text when the action throws' {
        $e = Register-AuditWrite -ActionId 't' -Provider 'P' -Destination 'D' -Allowed $true -Action { throw 'boom' }
        $e.attempted | Should -BeTrue
        $e.succeeded | Should -BeFalse
        $e.error | Should -Match 'boom'
    }
    It 'does not execute a gate-blocked (Allowed=$false) write' {
        $script:__ran4 = $false
        $e = Register-AuditWrite -ActionId 't' -Provider 'P' -Destination 'D' -Allowed $false -SkipReason '-NoRmmWrite' -Action { $script:__ran4 = $true }
        $e.attempted | Should -BeFalse
        $script:__ran4 | Should -BeFalse
        $e.skip_reason | Should -Be '-NoRmmWrite'
    }
    It 'blocks host-modifying setup in read-only mode' {
        $script:ReadOnlyMode = $true
        $b = Block-IfReadOnly -ActionId 'setup.winrm' -Provider 'WinRM setup' -Destination 'localhost' -ActionLabel 'WinRM configuration'
        $b.Success | Should -BeFalse
        $b.Blocked | Should -BeTrue
        @($script:WriteManifest).Count | Should -Be 1
        $script:WriteManifest[0].allowed | Should -BeFalse
    }
    It 'allows host-modifying setup to proceed when not read-only' {
        $script:ReadOnlyMode = $false
        $b = Block-IfReadOnly -ActionId 'setup.winrm' -Provider 'WinRM setup' -Destination 'localhost' -ActionLabel 'WinRM configuration'
        $b | Should -BeNullOrEmpty
    }
}

Describe 'Evidence-grade compliance helpers (real functions via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        foreach ($nm in 'Get-AuditExceptions','Get-FrameworkControlSummary') {
            $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $nm }, $true)[0]
            . ([scriptblock]::Create($fn.Extent.Text))
        }
        $script:FrameworkChecks = @{ HIPAA = @('IA01','EP02','PS01') }
        $script:SampleFindings = @(
            [pscustomobject]@{ id='IA01'; text='Priv groups'; severity='Critical'; status='Fail'; evidence='12 DAs'; findings='Too many admins'; notes='Accept until Q3'; compliance=[pscustomobject]@{ HIPAA='164.308'; CIS='5.1' }; remediation=[pscustomobject]@{ status='Accepted Risk'; assigned='Jane'; due='2026-09-30' } }
            [pscustomobject]@{ id='EP02'; text='BitLocker'; severity='Critical'; status='N/A'; evidence='No TPM'; findings='N/A'; notes=''; compliance=[pscustomobject]@{ HIPAA='164.312' }; remediation=[pscustomobject]@{ status='Open'; assigned=''; due='' } }
            [pscustomobject]@{ id='PS01'; text='Physical'; severity='Medium'; status='Pass'; evidence='Locked'; findings='OK'; notes=''; compliance=[pscustomobject]@{ HIPAA='164.310' }; remediation=[pscustomobject]@{ status='Deferred'; assigned='Bob'; due='2026-12-01' } }
        )
    }
    It 'extracts accepted-risk and deferred findings as exceptions with owner/expiration/rationale' {
        $ex = Get-AuditExceptions -Findings $script:SampleFindings
        @($ex).Count | Should -Be 2
        $ia = $ex | Where-Object { $_.id -eq 'IA01' }
        $ia.disposition | Should -Be 'Accepted Risk'
        $ia.owner | Should -Be 'Jane'
        $ia.expiration | Should -Be '2026-09-30'
        $ia.rationale | Should -Be 'Accept until Q3'
        $ia.controls.framework | Should -Contain 'HIPAA'
    }
    It 'builds a single-framework control summary that excludes N/A from the score' {
        $fc = Get-FrameworkControlSummary -Framework 'HIPAA' -Findings $script:SampleFindings
        $fc.framework | Should -Be 'HIPAA'
        @($fc.controls).Count | Should -Be 3
        $fc.na | Should -Be 1
        $fc.assessed | Should -Be 2
        $fc.score | Should -Be 50   # 1 pass of 2 assessed; N/A excluded
        $fc.score_excludes_na | Should -BeTrue
        ($fc.controls | Where-Object { $_.check_id -eq 'IA01' }).observed_fact | Should -Be '12 DAs'
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
