#Requires -Version 5.1
<#
.SYNOPSIS
    Pester v5 quality gate for NetworkSecurityAudit.ps1.
.DESCRIPTION
    Static, non-executing tests that protect the single-file tool from
    regressions: parser health, catalog/profile/framework/risk/evidence/D3FEND ID
    consistency, version-surface drift, export serialization, lint cleanliness,
    and the legacy static gate. No test executes a real audit check or modifies
    the host.

    Run:  Invoke-Pester -Path .\tools\NetworkSecurityAudit.Tests.ps1
#>

BeforeAll {
    $script:RepoRoot   = Split-Path -Parent $PSScriptRoot
    $script:ScriptPath = Join-Path $script:RepoRoot 'NetworkSecurityAudit.ps1'
    $script:ReadmePath = Join-Path $script:RepoRoot 'README.md'
    $script:ClaudePath = Join-Path $script:RepoRoot 'CLAUDE.md'
    $script:CSharpProjectPath = Join-Path $script:RepoRoot 'src\NetworkSecurityAuditor\NetworkSecurityAuditor.csproj'
    $script:Text       = Get-Content -Raw -LiteralPath $script:ScriptPath
    $script:Readme     = Get-Content -Raw -LiteralPath $script:ReadmePath
    $script:CSharpProject = Get-Content -Raw -LiteralPath $script:CSharpProjectPath
    $script:Claude     = if (Test-Path -LiteralPath $script:ClaudePath) { Get-Content -Raw -LiteralPath $script:ClaudePath } else { '' }

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
    $script:EvidenceBlock = Get-Block $script:Text '\$script:CheckEvidenceManifest\s*=\s*@\{' 'function Get-CheckEvidenceMetadata'
    $script:EvidenceIds   = Get-IdSet $script:EvidenceBlock "(?m)^\s*'([A-Z]{2}\d{2})'\s*=\s*@\{"
    $script:D3Block      = Get-Block $script:Text '\$script:D3FendMap\s*=\s*@\{' '\$script:D3FendStages'
    $script:D3Ids        = Get-IdSet $script:D3Block "(?m)^\s*'([A-Z]{2}\d{2})'\s*=\s*@\{"
    $script:FwChkBlock   = Get-Block $script:Text '\$script:FrameworkChecks\s*=\s*@\{' '# Helper: Get formatted compliance string'
    $script:FwChkIds     = Get-IdSet $script:FwChkBlock "'([A-Z]{2}\d{2})'"

    $script:ExpectedCheckCount = 70
}

Describe 'Parser health' {
    It 'parses with zero parser errors' {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$errors) | Out-Null
        @($errors).Count | Should -Be 0 -Because 'syntax errors must never ship'
    }
}

Describe 'Localization-neutral text resources' {
    It 'resolves named English resources and supports a provider switch' {
        $localizationBlock = [regex]::Match(
            $script:Text,
            '(?s)# Localization catalog start.*?# Localization catalog end').Value
        $localizationBlock | Should -Not -BeNullOrEmpty
        $localizationAst = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        $choiceFunction = $localizationAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'New-UiChoice'
        }, $true)[0].Extent.Text

        $probe = @'
$before = Get-UiText 'Gui.ScoreFormat' @(1, 2, 50, 'B')
$script:TextResourceProvider = { param($Key, $DefaultText) "[TEST:$Key]$DefaultText" }
$after = Get-UiText 'Gui.Ready'
$choice = New-UiChoice 'Pass' 'Gui.StatusPass'
@($before, $after, $choice.Display, $choice.ToString())
'@
        $result = & ([scriptblock]::Create("& { $localizationBlock`n$choiceFunction`n$probe }"))

        $result[0] | Should -Be 'Score: 1/2 (50%) Grade: B'
        $result[1] | Should -Be '[TEST:Gui.Ready]Ready'
        $result[2] | Should -Be '[TEST:Gui.StatusPass]Pass'
        $result[3] | Should -Be 'Pass'
    }

    It 'routes WPF labels and report headings through the catalog' {
        $xamlBlock = Get-Block $script:Text '\[xml\]\$xaml\s*=\s*@"' '"@\s*\r?\n\s*\$reader'
        $literalPattern = '(?:Text|Content|ToolTip|AutomationProperties\.Name)="(?!\$\(|\{|localhost"|0/0")([^"\r\n]+)"'
        @([regex]::Matches($xamlBlock, $literalPattern)).Count | Should -Be 0

        foreach ($key in @(
            'Dashboard.Title',
            'Dashboard.KpiDefinitions',
            'Report.ExecutiveSummary',
            'Report.RemediationRoadmap',
            'Report.ComplianceMapping',
            'Report.MitreCoverage',
            'Report.CloudAssessment',
            'Report.ImportedBenchmarks',
            'Report.RansomwarePreparedness')) {
            $script:Text | Should -Match "Get-UiText '$([regex]::Escape($key))'"
        }
    }

    It 'keeps structured export names and status values invariant' {
        $jsonBlock = Get-Block $script:Text 'function Export-FindingsJSON' 'function Export-FindingsJSONL'
        $csvBlock = Get-Block $script:Text 'function Export-FindingsCSV' 'function Export-ComplianceSummary'

        $jsonBlock | Should -Match '(?m)^\s*schema_version\s*='
        $jsonBlock | Should -Match '(?m)^\s*status\s*=\s*\$sv'
        $jsonBlock | Should -Not -Match 'Get-UiText'
        $csvBlock | Should -Match '(?m)^\s*CheckID\s*='
        $csvBlock | Should -Match '(?m)^\s*Status\s*='
        $csvBlock | Should -Not -Match 'Get-UiText'
        $script:Text | Should -Match "ToString\('o'\)"
    }
}

Describe 'Check catalog consistency' {
    It "defines exactly <ExpectedCheckCount> unique audit IDs" -TestCases @(@{ ExpectedCheckCount = 70 }) {
        @($script:CatalogIds).Count | Should -Be $ExpectedCheckCount
    }
    It 'has exactly one auto-check per catalog ID' {
        @($script:AutoIds).Count | Should -Be $script:ExpectedCheckCount
    }

    Context 'every catalog ID is covered by <_>' -ForEach @('AutoChecks','FrameworkMap','RiskTiers','CheckEvidenceManifest','D3FendMap') {
        It 'has no missing or unknown IDs' {
            $actual = switch ($_) {
                'AutoChecks'   { $script:AutoIds }
                'FrameworkMap' { $script:FwIds }
                'RiskTiers'    { $script:RiskIds }
                'CheckEvidenceManifest' { $script:EvidenceIds }
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
    It 'evidence manifest declares every required metadata field per check' {
        foreach ($field in 'EvidenceMode','AuthorityLevel','DataSources','InternetRequired','WritesPossible','DefaultRiskTier','ManualFollowUp') {
            [regex]::Matches($script:EvidenceBlock, "$field\s*=").Count | Should -Be $script:ExpectedCheckCount -Because "$field must be present for every catalog check"
        }
        $script:Text | Should -Match 'assessment_method = \$evidenceMeta\.EvidenceMode'
        $script:Text | Should -Match 'score_excluding_manual_evidence'
        $script:Text | Should -Match 'ManualValidationRequired'
    }
}

Describe 'Version surface consistency' {
    BeforeAll {
        $script:HeaderComment = [regex]::Match($script:Text, 'Network Security Auditor v([0-9]+\.[0-9]+\.[0-9]+)').Groups[1].Value
        $script:DotVersion    = [regex]::Match($script:Text, '(?ms)\.VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)').Groups[1].Value
        $script:ProductVer    = [regex]::Match($script:Text, "\`$script:ProductVersion\s*=\s*'([0-9]+\.[0-9]+\.[0-9]+)'").Groups[1].Value
        $script:CSharpVer    = [regex]::Match($script:CSharpProject, '<Version>([0-9]+\.[0-9]+\.[0-9]+)</Version>').Groups[1].Value
        $script:CSharpAssemblyVer = [regex]::Match($script:CSharpProject, '<AssemblyVersion>([0-9]+\.[0-9]+\.[0-9]+)\.0</AssemblyVersion>').Groups[1].Value
        $script:CSharpFileVer = [regex]::Match($script:CSharpProject, '<FileVersion>([0-9]+\.[0-9]+\.[0-9]+)\.0</FileVersion>').Groups[1].Value
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
    It 'C# assembly and file versions match the project version' {
        $script:CSharpVer | Should -Match '^[0-9]+\.[0-9]+\.[0-9]+$'
        $script:CSharpAssemblyVer | Should -Be $script:CSharpVer
        $script:CSharpFileVer | Should -Be $script:CSharpVer
    }
    It 'CLAUDE version guidance matches authoritative versions when the local guidance file is present' {
        if ([string]::IsNullOrWhiteSpace($script:Claude)) { return }
        $csharpPattern = [regex]::Escape($script:CSharpVer)
        $powershellPattern = [regex]::Escape($script:ProductVer)
        $script:Claude | Should -Match "(?m)^## Tech Stack \(v$csharpPattern .+ C# rewrite\)$"
        $script:Claude | Should -Match "(?m)^- \*\*C# rewrite v$csharpPattern\*\*"
        $script:Claude | Should -Match "(?m)^- \*\*PowerShell artifact v$powershellPattern\*\*"
    }

    Context 'dynamic surfaces derive from $script:ProductVersion (cannot drift)' {
        It '<_> references the centralized version constant' -ForEach @(
            'WindowTitle','HTML report footer','save state','silent banner') {
            switch ($_) {
                'WindowTitle'         { $script:Text | Should -Match '\$script:WindowTitle\s*=\s*"[^"]*\$\(\$script:ProductVersion\)' }
                'HTML report footer'  { $script:Text | Should -Match 'Version:\s*<strong>v\$\(\$script:ProductVersion\)' }
                'save state'          { $script:Text | Should -Match 'Version\s*=\s*\$script:ProductVersion' }
                'silent banner'       {
                    $script:Text | Should -Match "'Product\.SubtitleFormat'\s*=\s*'[^']*v\{0\}"
                    $script:Text | Should -Match '\$script:ProductSubtitle\s*=\s*Get-UiText ''Product\.SubtitleFormat'' @\(\$script:ProductVersion\)'
                }
            }
        }
    }
}

Describe 'External export version contracts' {
    It 'pins current external taxonomy and schema versions' {
        $expected = [ordered]@{
            AttackEnterprise = '19.2'
            AttackNavigator = '4.5'
            AttackNavigatorApp = '5.3.2'
            D3FEND = '1.6.0'
            OCSF = '1.8.0'
            OSCAL = '1.2.3'
        }
        foreach ($key in $expected.Keys) {
            $script:Text | Should -Match "(?m)^\s*$key\s*=\s*'$([regex]::Escape($expected[$key]))'" -Because "$key export contract drifted"
        }
    }

    It 'exports source-version metadata from the central manifest' {
        $script:Text | Should -Match '\$script:ExternalVersionSources\s*=\s*\[ordered\]@\{'
        $script:Text | Should -Match 'function Get-ExternalVersionManifest'
        $script:Text | Should -Match 'source_version'
        $script:Text | Should -Match 'source_url'
        $script:Text | Should -Match 'reviewed_on'
        $script:Text | Should -Match 'external_versions = Get-ExternalVersionManifest'
    }
}

Describe 'Diagnostics profile' {
    It 'exposes a non-invasive diagnostics switch and bounded outputs' {
        $script:Text | Should -Match '\[switch\]\$DiagnosticsOnly'
        $script:Text | Should -Match '\$script:CliDiagnosticsOnly\s*=\s*\$DiagnosticsOnly\.IsPresent'
        $script:Text | Should -Match 'function Export-DiagnosticsReport'
        $script:Text | Should -Match 'NetworkSecurityAudit_diagnostics\.json'
        $script:Text | Should -Match 'NetworkSecurityAudit_diagnostics\.txt'
        $script:Text | Should -Match 'exit 67'
        $script:Text | Should -Match 'Graph authentication readiness'
    }

    It 'does not include raw host, domain, or user identifiers in the diagnostics payload' {
        $diagnosticBlock = Get-Block $script:Text 'function Export-DiagnosticsReport' '# .* Launch'
        $diagnosticBlock | Should -Not -Match '\$env:COMPUTERNAME|\$env:USERNAME|DomainName|TenantName|ClientName|AuditorName'
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

Describe 'Cloud assessment import semantics' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        foreach ($nm in 'Convert-CloudAssessmentStatus','Get-CloudAssessmentStatusSummary','Import-CloudAssessment') {
            $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $nm }, $true)[0]
            . ([scriptblock]::Create($fn.Extent.Text))
        }
    }
    It 'keeps cloud unavailable states separate from true failures' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("nsa-maester-{0}.json" -f ([guid]::NewGuid().ToString('N')))
        try {
            $fixture = [ordered]@{
                TenantId = 'tenant-1'
                TenantName = 'Acme'
                ExecutedAt = '2026-06-16T12:00:00Z'
                Results = @(
                    [ordered]@{ TestId='CL01'; Name='Secure Score'; Result='Passed'; Category='Cloud'; Remediation='' }
                    [ordered]@{ TestId='CL02'; Name='Conditional Access'; Result='Failed'; Category='Identity'; Remediation='Enable baseline CA' }
                    [ordered]@{ TestId='CL03'; Name='MFA registration'; Result='NotLicensed'; Category='Identity'; Remediation='Requires Entra ID P1/P2' }
                    [ordered]@{ TestId='CL04'; Name='Risky users'; Result='NotPermitted'; Category='Identity'; Remediation='Grant read permission' }
                    [ordered]@{ TestId='CL05'; Name='Legacy auth'; Result='NotConfigured'; Category='Identity'; Remediation='No policy found' }
                    [ordered]@{ TestId='CL06'; Name='Guest lifecycle'; Result='Skipped'; Category='Identity'; Remediation='' }
                    [ordered]@{ TestId='CL07'; Name='Alerts'; Result='Error'; Category='Security'; Remediation='Retry later' }
                )
            }
            $fixture | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $tmp -Encoding UTF8
            $imp = @(Import-CloudAssessment -Paths @($tmp))[0]

            $imp.Passed | Should -Be 1
            $imp.Failed | Should -Be 1
            $imp.NotLicensed | Should -Be 1
            $imp.NotPermitted | Should -Be 1
            $imp.NotConfigured | Should -Be 1
            $imp.Errors | Should -Be 1
            $imp.Unavailable | Should -Be 4
            $imp.Score | Should -Be 50
            $imp.StatusBreakdown['Skipped'] | Should -Be 1
            $imp.Findings.Status | Should -Contain 'Fail'
            $imp.Findings.Status | Should -Contain 'NotLicensed'
            $imp.Findings.Status | Should -Contain 'NotPermitted'
            $imp.Findings.Status | Should -Contain 'NotConfigured'
            $imp.Findings.Status | Should -Contain 'Error'
        }
        finally {
            Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
        }
    }

    It 'returns explicit diagnostics for missing, malformed, unsupported, and unrecognized inputs' {
        $unknown = Join-Path ([System.IO.Path]::GetTempPath()) ("nsa-cloud-unknown-{0}.json" -f ([guid]::NewGuid().ToString('N')))
        $malformed = Join-Path ([System.IO.Path]::GetTempPath()) ("nsa-cloud-malformed-{0}.json" -f ([guid]::NewGuid().ToString('N')))
        $unsupported = Join-Path ([System.IO.Path]::GetTempPath()) ("nsa-cloud-unsupported-{0}.txt" -f ([guid]::NewGuid().ToString('N')))
        $missing = Join-Path ([System.IO.Path]::GetTempPath()) ("nsa-cloud-missing-{0}.json" -f ([guid]::NewGuid().ToString('N')))
        try {
            '{"provider":"unknown"}' | Set-Content -LiteralPath $unknown -Encoding UTF8
            '{"Results":' | Set-Content -LiteralPath $malformed -Encoding UTF8
            'not a cloud report' | Set-Content -LiteralPath $unsupported -Encoding UTF8
            $imports = @(Import-CloudAssessment -Paths @($unknown, $malformed, $unsupported, $missing))

            $imports.Count | Should -Be 4
            @($imports | Where-Object ImportStatus -eq 'Skipped').Count | Should -Be 3
            @($imports | Where-Object ImportStatus -eq 'Error').Count | Should -Be 1
            ($imports | Where-Object Path -eq $unknown).ImportError | Should -Match 'supported Maester or ScubaGear'
            ($imports | Where-Object Path -eq $malformed).ImportError | Should -Match 'malformed \.json cloud assessment'
            ($imports | Where-Object Path -eq $unsupported).ImportError | Should -Match 'unsupported cloud assessment extension'
            ($imports | Where-Object Path -eq $missing).ImportError | Should -Be 'file was not found'
        }
        finally {
            foreach ($path in $unknown, $malformed, $unsupported) {
                if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
            }
        }
    }
}

Describe 'Graph wrapper offline fixtures' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        foreach ($nm in 'Get-GraphObjectProperty','Convert-GraphAuditErrorStatus','Invoke-GraphAuditRequest') {
            $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $nm }, $true)[0]
            . ([scriptblock]::Create($fn.Extent.Text))
        }
    }
    It 'pages mock Graph responses without a tenant' {
        $res = Invoke-GraphAuditRequest -Uri '/users' -PermissionScopes @('User.Read.All') -MockResponses @(
            [ordered]@{ StatusCode=200; Body=[ordered]@{ value=@([ordered]@{ id='u1' }); '@odata.nextLink'='/users?page=2' } }
            [ordered]@{ StatusCode=200; Body=[ordered]@{ value=@([ordered]@{ id='u2' }) } }
        )

        $res.Status | Should -Be 'Pass'
        @($res.Data).Count | Should -Be 2
        $res.Pages | Should -Be 2
        $res.PermissionScopes | Should -Contain 'User.Read.All'
        $res.SourceTimestamp | Should -Match '^\d{4}-\d{2}-\d{2}T'
    }
    It 'retries a throttled mock response without sleeping when Retry-After is zero' {
        $res = Invoke-GraphAuditRequest -Uri '/security/secureScores' -PermissionScopes @('SecurityEvents.Read.All') -MockResponses @(
            [ordered]@{ StatusCode=429; Headers=@{'Retry-After'='0'}; Body=[ordered]@{ error='throttled' } }
            [ordered]@{ StatusCode=200; Body=[ordered]@{ value=@([ordered]@{ id='score1' }) } }
        )

        $res.Status | Should -Be 'Pass'
        $res.Retried | Should -Be 1
        @($res.Data).Count | Should -Be 1
    }
    It 'retries an exception-shaped live 429 and stops after the retry budget' {
        Set-Item -Path Function:\Invoke-MgGraphRequest -Value {
            $script:__graphCalls++
            if ($script:__graphCalls -eq 1) {
                $exception = [System.Exception]::new('HTTP 429 throttled; Retry-After: 0')
                $exception.Data['StatusCode'] = 429
                $exception.Data['Retry-After'] = '0'
                throw $exception
            }
            return [ordered]@{ value = @([ordered]@{ id = 'recovered' }) }
        } -Force
        $script:__graphCalls = 0
        try {
            $recovered = Invoke-GraphAuditRequest -Uri '/security/secureScores' -PermissionScopes @('SecurityEvents.Read.All') -MaxRetries 1
            $recovered.Status | Should -Be 'Pass'
            $recovered.Retried | Should -Be 1
            $script:__graphCalls | Should -Be 2
        }
        finally {
            Remove-Item Function:\Invoke-MgGraphRequest -Force -ErrorAction SilentlyContinue
        }

        Set-Item -Path Function:\Invoke-MgGraphRequest -Value {
            $exception = [System.Exception]::new('HTTP 429 throttled; Retry-After: 0')
            $exception.Data['StatusCode'] = 429
            throw $exception
        } -Force
        try {
            $terminal = Invoke-GraphAuditRequest -Uri '/security/secureScores' -PermissionScopes @('SecurityEvents.Read.All') -MaxRetries 1
            $terminal.Status | Should -Be 'Error'
            $terminal.Error.status_code | Should -Be 429
            $terminal.Retried | Should -Be 1
        }
        finally {
            Remove-Item Function:\Invoke-MgGraphRequest -Force -ErrorAction SilentlyContinue
        }
    }
    It 'classifies denied and unlicensed mock responses without tenant access' {
        $denied = Invoke-GraphAuditRequest -Uri '/identity/conditionalAccess/policies' -PermissionScopes @('Policy.Read.All') -MockResponses @(
            [ordered]@{ StatusCode=403; Body=[ordered]@{ error='permission denied' } }
        )
        $unlicensed = Invoke-GraphAuditRequest -Uri '/identityProtection/riskyUsers' -PermissionScopes @('IdentityRiskyUser.Read.All') -MockResponses @(
            [ordered]@{ StatusCode=402; Body=[ordered]@{ error='license required' } }
        )

        $denied.Status | Should -Be 'NotPermitted'
        $denied.Error.status_code | Should -Be 403
        $unlicensed.Status | Should -Be 'NotLicensed'
        $unlicensed.Error.status_code | Should -Be 402
    }
}

Describe 'Cloud Graph profile manifest' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        foreach ($nm in 'Convert-CloudAssessmentStatus','Get-CloudAssessmentStatusSummary','Get-GraphObjectProperty','Convert-GraphAuditErrorStatus','Invoke-GraphAuditRequest','Get-GraphStringArray','Get-CloudMockResponses','New-CloudAssessmentFinding','New-CloudUnavailableFinding','Invoke-CloudSecureScoreAssessment','Invoke-CloudConditionalAccessAssessment','Invoke-CloudGuestLifecycleAssessment','Invoke-CloudHardMatchAssessment','Invoke-CloudProfileAssessment') {
            $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $nm }, $true)[0]
            . ([scriptblock]::Create($fn.Extent.Text))
        }
    }
    BeforeEach {
        $script:ProductVersion = '4.10.9'
        $script:CloudCheckManifest = [ordered]@{
            'CL01' = [ordered]@{ Name='Microsoft Secure Score'; PermissionScopes=@('SecurityEvents.Read.All'); RoleHints=@('Security Reader'); LicensePrerequisites='Secure Score'; ApiVersion='v1.0'; Endpoint='/security/secureScores?$top=1'; OutputFields=@('currentScore'); SkipStates=@('NotConfigured'); PrivacyClassification='Tenant'; Implemented=$true }
            'CL02' = [ordered]@{ Name='Conditional Access policy baseline'; PermissionScopes=@('Policy.Read.All'); RoleHints=@('Conditional Access Reader'); LicensePrerequisites='Entra ID P1/P2'; ApiVersion='v1.0'; Endpoint='/identity/conditionalAccess/policies?$select=id,displayName,state,conditions,grantControls,sessionControls'; OutputFields=@('displayName'); SkipStates=@('NotConfigured'); PrivacyClassification='TenantPolicy'; Implemented=$true }
            'CL06' = [ordered]@{ Name='Stale users and guests'; PermissionScopes=@('User.Read.All','AuditLog.Read.All'); RoleHints=@('Global Reader'); LicensePrerequisites='signInActivity'; ApiVersion='v1.0'; Endpoint='/users?$select=displayName,userPrincipalName,userType,accountEnabled,createdDateTime,signInActivity'; OutputFields=@('displayName'); SkipStates=@('NotConfigured'); PrivacyClassification='UserPII'; Implemented=$true }
            'CL13' = [ordered]@{ Name='Entra Connect hard-match protection'; PermissionScopes=@('User.Read.All','Directory.Read.All'); RoleHints=@('Global Reader'); LicensePrerequisites='Entra ID'; ApiVersion='v1.0'; Endpoint='/users?$select=displayName,userPrincipalName,onPremisesSyncEnabled,onPremisesImmutableId,onPremisesSamAccountName,userType&$filter=onPremisesSyncEnabled eq true'; OutputFields=@('displayName','userPrincipalName','onPremisesImmutableId'); SkipStates=@('NotConfigured','NotPermitted','NotLicensed','Error'); PrivacyClassification='UserPII'; Implemented=$true }
        }
    }

    It 'declares CL01 through CL10 with required metadata fields' {
        foreach ($n in 1..10) {
            $id = 'CL{0:d2}' -f $n
            $script:Text | Should -Match "'$id'\s*=\s*\[ordered\]@\{"
        }
        foreach ($field in 'PermissionScopes','RoleHints','LicensePrerequisites','ApiVersion','Endpoint','OutputFields','SkipStates','PrivacyClassification') {
            $script:Text | Should -Match $field
        }
        $script:Text | Should -Match 'Cloud\s*=\s*@\{'
        $script:Text | Should -Match "Invoke-CloudProfileAssessment"
    }

    It 'preserves cloud provenance across machine-readable export surfaces' {
        $script:Text | Should -Match 'function Get-CloudAssessmentExportRecords'
        $script:Text | Should -Match 'cloud_assessment_finding'
        $script:Text | Should -Match 'CloudSource\s*='
        $script:Text | Should -Match 'cloud_assessments\s*=\s*\$cloudSummary'
        $script:Text | Should -Match 'CloudAssessments\s*=\s*@\(Get-CloudAssessmentExportRecords\)'
        $script:Text | Should -Match 'network-security-audit://cloud'
        $script:Text | Should -Match 'CloudUnavailable'
    }

    It 'builds secure score, Conditional Access, guest lifecycle, and hard-match findings from mock Graph responses' {
        $mock = @{
            CL01 = @(
                [ordered]@{ StatusCode=200; Body=[ordered]@{ value=@([ordered]@{ currentScore=62; maxScore=100; createdDateTime='2026-06-16T12:00:00Z'; azureTenantId='tenant-1' }) } }
            )
            CL02 = @(
                [ordered]@{ StatusCode=200; Body=[ordered]@{ value=@(
                    [ordered]@{
                        displayName='Require MFA all users'
                        state='enabled'
                        conditions=[ordered]@{ users=[ordered]@{ includeUsers=@('All'); excludeUsers=@('breakglass') }; clientAppTypes=@('all') }
                        grantControls=[ordered]@{ builtInControls=@('mfa') }
                    }
                ) } }
            )
            CL06 = @(
                [ordered]@{ StatusCode=200; Body=[ordered]@{ value=@(
                    [ordered]@{
                        displayName='Guest One'
                        userPrincipalName='guest_one#EXT#@example.com'
                        userType='Guest'
                        accountEnabled=$true
                        createdDateTime='2025-01-01T00:00:00Z'
                        signInActivity=[ordered]@{ lastSuccessfulSignInDateTime='2025-02-01T00:00:00Z' }
                        sponsor='Jane Sponsor'
                        owner='Ops Owner'
                    }
                ) } }
            )
            CL13 = @(
                [ordered]@{ StatusCode=200; Body=[ordered]@{ value=@(
                    [ordered]@{
                        displayName='Synced Standard User'
                        userPrincipalName='synced.user@example.com'
                        userType='Member'
                        onPremisesSyncEnabled=$true
                        onPremisesImmutableId='abcdef0123456789'
                        onPremisesSamAccountName='synced.user'
                        assignedRoles=@()
                    }
                ) } }
            )
        }

        $assessment = Invoke-CloudProfileAssessment -MockResponsesById $mock
        $assessment.Source | Should -Be 'MicrosoftGraph'
        $assessment.TenantId | Should -Be 'tenant-1'
        $assessment.SecureScore.percent | Should -Be 62
        $assessment.Findings.TestId | Should -Contain 'CL01'
        $assessment.Findings.TestId | Should -Contain 'CL02'
        $assessment.Findings.TestId | Should -Contain 'CL06'
        $assessment.Findings.TestId | Should -Contain 'CL13'
        ($assessment.Findings | Where-Object TestId -eq 'CL02').Evidence | Should -Match 'Missing required policies'
        ($assessment.Findings | Where-Object TestId -eq 'CL02').Evidence | Should -Match 'Dangerous exclusions'
        ($assessment.Findings | Where-Object TestId -eq 'CL06').Evidence | Should -Match 'age='
        ($assessment.Findings | Where-Object TestId -eq 'CL06').Evidence | Should -Match 'last_sign_in='
        ($assessment.Findings | Where-Object TestId -eq 'CL06').Evidence | Should -Match 'sponsor='
        ($assessment.Findings | Where-Object TestId -eq 'CL06').Evidence | Should -Match 'owner='
        @($assessment.Findings | Where-Object { -not $_.SourceTimestamp -or @($_.PermissionScopes).Count -eq 0 }).Count | Should -Be 0
    }
}

Describe 'Privacy redaction coverage' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        foreach ($nm in 'Get-PrivacyHash','Initialize-PrivacyReplacements','ConvertTo-RedactedText','Get-RedactedIdentity','ConvertTo-PrivacySafeObject','Get-PrivacySafeBranding') {
            $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $nm }, $true)[0]
            . ([scriptblock]::Create($fn.Extent.Text))
        }
    }
    BeforeEach {
        $script:CliPrivacyMode = $true
        $script:CliClient = ''
        $script:PrivacyMap = @{}
        $script:PrivacyReplacements = @()
        $script:CloudAssessmentImports = @(
            [ordered]@{
                TenantName = 'Acme Tenant'
                TenantId   = 'tenant-123'
                Path       = 'C:\Reports\Acme Tenant\maester.json'
            }
        )
    }

    It 'redacts imported cloud tenants, paths, token values, and IP addresses' {
        Initialize-PrivacyReplacements
        $redacted = ConvertTo-RedactedText 'Acme Tenant tenant-123 10.1.2.3 access_token=abc123 Bearer eyJhbGciOiJub25l'
        $pathRedacted = ConvertTo-RedactedText $script:CloudAssessmentImports[0].Path

        $redacted | Should -Not -Match 'Acme Tenant'
        $redacted | Should -Not -Match 'tenant-123'
        $redacted | Should -Not -Match 'abc123'
        $redacted | Should -Match '\[TENANT-[0-9a-f]{8}\]'
        $redacted | Should -Match '\[IP-[0-9a-f]{8}\]'
        $redacted | Should -Match 'access_token=\[SECRET-REDACTED\]'
        $redacted | Should -Match 'Bearer \[SECRET-REDACTED\]'
        $pathRedacted | Should -Match '^\[PATH-[0-9a-f]{8}\]$'
        (Get-RedactedIdentity $script:CloudAssessmentImports[0].TenantId 'TENANT') | Should -Match '^\[TENANT-[0-9a-f]{8}\]$'
    }

    It 'redacts structured secrets and recursively sanitizes imported objects' {
        Initialize-PrivacyReplacements
        $value = [ordered]@{
            owner = 'Acme Tenant'
            credentials = [ordered]@{ client_secret = 'json-secret'; nested = @('token: yaml-secret', 'safe text') }
        }
        $safe = ConvertTo-PrivacySafeObject $value
        $json = $safe | ConvertTo-Json -Depth 8 -Compress
        $json | Should -Not -Match 'json-secret|yaml-secret'
        $json | Should -Match '\[SECRET-REDACTED\]'
        $json | Should -Match '\[TENANT-[0-9a-f]{8}\]'
    }

    It 'removes identifying branding and contact values from privacy exports' {
        Initialize-PrivacyReplacements
        $branding = [ordered]@{
            CompanyName = 'Acme Secret Company'; Tagline = 'Confidential slogan'; LogoData = 'data:image/png;base64,secret'
            PrimaryColor = '#123456'; AccentColor = '#abcdef'; ContactName = 'Jane Secret'; ContactEmail = 'jane@secret.example'
            ContactPhone = '555-0100'; Website = 'https://secret.example'; FooterText = 'Acme footer'; CoverPage = $true
        }
        $safe = Get-PrivacySafeBranding $branding
        $safe.CompanyName | Should -Match '^\[COMPANY-[0-9a-f]{8}\]$'
        $safe.Tagline | Should -Be ''
        $safe.LogoData | Should -Be ''
        $safe.ContactName | Should -Be ''
        $safe.ContactEmail | Should -Be ''
        $safe.Website | Should -Be ''
        $safe.FooterText | Should -Be ''
        $safe.CoverPage | Should -BeFalse
    }

    It 'preserves branding details when privacy mode is disabled' {
        $script:CliPrivacyMode = $false
        $branding = [ordered]@{ CompanyName = 'Acme'; ContactEmail = 'jane@acme.example'; LogoData = 'logo'; CoverPage = $true }
        $safe = Get-PrivacySafeBranding $branding
        $safe.CompanyName | Should -Be 'Acme'
        $safe.ContactEmail | Should -Be 'jane@acme.example'
        $safe.LogoData | Should -Be 'logo'
        $safe.CoverPage | Should -BeTrue
    }
}

Describe 'Data-handling manifest coverage' {
    It 'emits a deterministic privacy disclosure sidecar for silent exports' {
        $script:Text | Should -Match 'function Export-DataHandlingManifest'
        $script:Text | Should -Match 'policy_version\s*=\s*''1\.0'''
        $script:Text | Should -Match 'field_classifications'
        $script:Text | Should -Match 'secret_fields_excluded'
        $script:Text | Should -Match 'identity_strategy'
        $script:Text | Should -Match 'source_path_policy'
        $script:Text | Should -Match 'fleet_kpis_and_denominators\s*=\s*''operational-aggregate'''
        $script:Text | Should -Match 'dashboard_input_diagnostics\s*=\s*''restricted'''
        $script:Text | Should -Match 'data-handling\.json'
        $script:Text | Should -Match 'GetFileName\(\$_\)'
    }

    It 'never writes raw tenant, user, or token values into the manifest payload' {
        $manifestBlock = Get-Block $script:Text 'function Export-DataHandlingManifest' '# .* Phase 5G'
        $manifestBlock | Should -Not -Match '\$script:Env\.TenantName|\$env:USERNAME|access_token\s*=|client_secret\s*='
        $manifestBlock | Should -Match 'credentials_and_tokens\s*=\s*''secret-excluded'''
    }
}

Describe 'Multi-client dashboard output safety' {
    BeforeAll {
        $localizationBlock = [regex]::Match(
            $script:Text,
            '(?s)# Localization catalog start.*?# Localization catalog end').Value
        . ([scriptblock]::Create($localizationBlock))
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        foreach ($functionName in 'Get-MspExecutiveKpis','Export-MultiClientDashboard') {
            $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $functionName }, $true)[0]
            . ([scriptblock]::Create($fn.Extent.Text))
        }
        $script:ProductName = 'Network Security Auditor'
        $script:ProductVersion = 'test'
    }

    It 'HTML-encodes untrusted client fields, grades, categories, and report hrefs' {
        $root = Join-Path ([IO.Path]::GetTempPath()) ('nsa-dashboard-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        try {
            $jsonName = "client' onmouseover='alert(1)_findings.json"
            $jsonPath = Join-Path $root $jsonName
            $htmlPath = $jsonPath -replace '_findings\.json$','.html'
            Set-Content -LiteralPath $htmlPath -Value '<html></html>' -Encoding UTF8
            $doc = [ordered]@{
                export_type = 'structured_findings'
                timestamp = (Get-Date).ToString('o')
                client = '<img src=x onerror=alert(1)>'
                target = '</div><script>alert(2)</script>'
                score = [ordered]@{ overall = 75; grade = '</td><script>alert(3)</script>'; ransomware = [ordered]@{ score = 65; grade = "bad' onmouseover='alert(4)" } }
                findings = @([ordered]@{ status = 'Fail'; severity = 'Critical'; category = '<svg onload=alert(5)>' })
                compliance_frameworks = [ordered]@{ NIST = [ordered]@{ compliant = $false } }
                tool_version = 'test'
            }
            $doc | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
            $outPath = Join-Path $root 'dashboard.html'

            Export-MultiClientDashboard -SourceDir $root -OutPath $outPath | Should -Be $outPath
            $html = Get-Content -LiteralPath $outPath -Raw
            $html | Should -Not -Match '<(?:img|svg|script)\b'
            $html | Should -Not -Match "href='[^']*'\s+onmouseover="
            $html | Should -Match '&#39;'
            $html | Should -Match '&lt;script&gt;'
        }
        finally {
            if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'bounds dashboard input and surfaces skipped-file reasons' {
        $root = Join-Path ([IO.Path]::GetTempPath()) ('nsa-dashboard-limits-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        try {
            $valid = [ordered]@{
                export_type = 'structured_findings'
                timestamp = (Get-Date).ToString('o')
                client = 'Bounded Client'
                target = 'HOST01'
                score = [ordered]@{ overall = 80; grade = 'B'; ransomware = [ordered]@{ score = 80; grade = 'B' } }
                findings = @([ordered]@{ status='Pass'; severity='Low' })
                compliance_frameworks = [ordered]@{}
                tool_version = 'test'
            }
            $valid | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root '01_valid_findings.json') -Encoding UTF8
            Set-Content -LiteralPath (Join-Path $root '02_oversized_findings.json') -Value ('{' + ('x' * 1200) + '}') -Encoding UTF8
            $outPath = Join-Path $root 'dashboard.html'

            Export-MultiClientDashboard -SourceDir $root -OutPath $outPath -MaxFiles 10 -MaxFileBytes 1024 -MaxTotalBytes 4096 | Should -Be $outPath
            $html = Get-Content -LiteralPath $outPath -Raw
            $html | Should -Match 'Skipped input files'
            $html | Should -Match '02_oversized_findings\.json'
            $html | Should -Match 'per-file limit'
        }
        finally {
            if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'applies the requested trend window while retaining the latest scan' {
        $root = Join-Path ([IO.Path]::GetTempPath()) ('nsa-dashboard-trend-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        try {
            $base = [ordered]@{
                export_type = 'structured_findings'
                client = 'Trend Client'
                target = 'HOST01'
                score = [ordered]@{ overall = 70; grade = 'C'; ransomware = [ordered]@{ score = 70; grade = 'C' } }
                findings = @([ordered]@{ status='Pass'; severity='Low' })
                compliance_frameworks = [ordered]@{}
                tool_version = 'test'
            }
            $old = [ordered]@{} + $base; $old.timestamp = (Get-Date).AddDays(-60).ToString('o'); $old.score = [ordered]@{ overall = 55; grade = 'D'; ransomware = [ordered]@{ score = 55; grade = 'D' } }
            $new = [ordered]@{} + $base; $new.timestamp = (Get-Date).AddDays(-2).ToString('o')
            $old | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root '01_old_findings.json') -Encoding UTF8
            $new | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root '02_new_findings.json') -Encoding UTF8
            $outPath = Join-Path $root 'dashboard.html'
            $csvPath = Join-Path $root 'dashboard.csv'
            $jsonPath = Join-Path $root 'dashboard.json'

            Export-MultiClientDashboard -SourceDir $root -OutPath $outPath -CsvPath $csvPath -JsonPath $jsonPath -TrendWindowDays 30 | Should -Be $outPath
            $html = Get-Content -LiteralPath $outPath -Raw
            $html | Should -Match '2 scans / 1 in 30d trend'
            $dashboard = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
            $dashboard.assets_discovered | Should -Be 1
            $dashboard.assets_scanned | Should -Be 1
            $dashboard.coverage.denominator | Should -Be 1
            (Get-Content -LiteralPath $csvPath -Raw) | Should -Match '"RecordType","AssetsDiscovered"'
        }
        finally {
            if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'computes denominator-safe mixed-fleet KPIs without zero-risk rows' {
        $now = [datetime]'2026-08-12T12:00:00Z'
        $rows = @(
            [pscustomobject]@{
                ScorePct=80; Stale=$false; Critical=1
                Findings=@(
                    [pscustomobject]@{status='Fail';severity='Critical';remediation=[pscustomobject]@{status='Open';due='2026-08-01'}},
                    [pscustomobject]@{status='Fail';severity='High';remediation=[pscustomobject]@{status='Accepted Risk';due='2026-09-01'}}
                )
                Exceptions=@([pscustomobject]@{disposition='Accepted Risk';expiration='2026-09-01'},[pscustomobject]@{disposition='Deferred';expiration='2026-08-01'})
                Continuous=[pscustomobject]@{delta=[pscustomobject]@{new_criticals=1;resolved_criticals=2};exposure=[ordered]@{A=[pscustomobject]@{severity='Critical';days=12};B=[pscustomobject]@{severity='High';days=40}}}
            },
            [pscustomobject]@{ScorePct=40;Stale=$true;Critical=0;Findings=@([pscustomobject]@{status='Fail';severity='High';remediation=[pscustomobject]@{status='Open';due=''}});Exceptions=@();Continuous=$null}
        )

        $kpis = Get-MspExecutiveKpis -Rows $rows -AssetsValid 3 -AssetsSkipped 1 -AssetsFailed 1 -Now $now

        $kpis.assets_discovered | Should -Be 4
        $kpis.assets_scanned | Should -Be 2
        $kpis.coverage.denominator | Should -Be 4
        $kpis.coverage.percentage | Should -Be 50
        $kpis.scores.average | Should -Be 60
        $kpis.scores.median | Should -Be 60
        $kpis.scores.population | Should -Be 2
        $kpis.freshness.stale | Should -Be 1
        $kpis.critical_findings.new | Should -Be 1
        $kpis.critical_findings.resolved | Should -Be 2
        $kpis.critical_findings.oldest_high_age_days | Should -Be 40
        $kpis.critical_findings.oldest_critical_age_days | Should -Be 12
        $kpis.exceptions.active | Should -Be 1
        $kpis.exceptions.expired | Should -Be 1
        $kpis.remediation_aging.denominator | Should -Be 2
        $kpis.remediation_aging.overdue_1_to_30_days | Should -Be 1
        $kpis.remediation_aging.no_due_date | Should -Be 1
    }
}

Describe 'Saved timestamp validation' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'ConvertTo-SafeScanTime' }, $true)[0]
        . ([scriptblock]::Create($fn.Extent.Text))
    }

    It 'normalizes valid invariant timestamps and rejects markup' {
        ConvertTo-SafeScanTime '2026-08-10T14:30:00' | Should -Be '2026-08-10 14:30:00'
        ConvertTo-SafeScanTime '<script>alert(1)</script>' | Should -Be ''
        $script:Text | Should -Match 'HtmlEncode\(\[string\]\$script:ScanTimestamps\[\$id\]\)'
    }
}

Describe 'Benchmark import bounds and diagnostics' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Import-BenchmarkResults' }, $true)[0]
        . ([scriptblock]::Create($fn.Extent.Text))
    }

    It 'imports valid benchmark rows and records the import contract' {
        $path = Join-Path ([IO.Path]::GetTempPath()) ('nsa-benchmark-' + [guid]::NewGuid().ToString('N') + '.csv')
        $provenancePath = "$path.provenance.json"
        try {
            @(
                'ID,Name,TestResult,Category,Recommended,CurrentValue'
                'HK01,Firewall,Passed,Endpoint,Enabled,Enabled'
                'HK02,SMB,Failed,Network,Required,Disabled'
            ) | Set-Content -LiteralPath $path -Encoding UTF8
            $import = Import-BenchmarkResults -Path $path -MaxFileBytes 4096 -MaxRows 10
            $import.status | Should -Be 'Imported'
            $import.source | Should -Be 'HardeningKitty'
            $import.findings.Count | Should -Be 2
            $import.limits.max_rows | Should -Be 10
            $import.summary.fail | Should -Be 1
            $import.provenance.verification_status | Should -Be 'unverified'
            $import.provenance.trust_status | Should -Be 'degraded'
        }
        finally {
            if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
            if (Test-Path -LiteralPath $provenancePath) { Remove-Item -LiteralPath $provenancePath -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'verifies a supplied provenance manifest and rejects tampered content' {
        $path = Join-Path ([IO.Path]::GetTempPath()) ('nsa-benchmark-provenance-' + [guid]::NewGuid().ToString('N') + '.csv')
        $provenancePath = "$path.provenance.json"
        try {
            @(
                'ID,Name,TestResult'
                'HK01,Firewall,Passed'
            ) | Set-Content -LiteralPath $path -Encoding UTF8
            $digest = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            [ordered]@{
                source_version = 'fixture-v1'
                format = 'HardeningKitty CSV'
                reviewed_on = '2026-08-10'
                supported_targets = @('Windows test fixture')
                license_status = 'approved'
                redistribution_status = 'permitted'
                content_sha256 = $digest
                stale_after_days = 180
            } | ConvertTo-Json | Set-Content -LiteralPath $provenancePath -Encoding UTF8

            $verified = Import-BenchmarkResults -Path $path -MaxFileBytes 4096 -MaxRows 10
            $verified.provenance.verification_status | Should -Be 'verified'
            $verified.provenance.trust_status | Should -Be 'verified'
            $verified.provenance.content_sha256 | Should -Be $digest

            Add-Content -LiteralPath $path -Value 'HK02,SMB,Failed' -Encoding UTF8
            $tampered = Import-BenchmarkResults -Path $path -MaxFileBytes 4096 -MaxRows 10
            $tampered.status | Should -Be 'Error'
            $tampered.provenance.verification_status | Should -Be 'mismatch'
            $tampered.import_error | Should -Match 'SHA-256 digest does not match'
        }
        finally {
            foreach ($candidate in $path, $provenancePath) {
                if (Test-Path -LiteralPath $candidate) { Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue }
            }
        }
    }

    It 'returns bounded diagnostics for oversized and malformed external files' {
        $oversized = Join-Path ([IO.Path]::GetTempPath()) ('nsa-benchmark-large-' + [guid]::NewGuid().ToString('N') + '.csv')
        $malformed = Join-Path ([IO.Path]::GetTempPath()) ('nsa-benchmark-bad-' + [guid]::NewGuid().ToString('N') + '.json')
        try {
            Set-Content -LiteralPath $oversized -Value ("ID,Name,TestResult`nHK01,Firewall," + ('x' * 1600)) -Encoding UTF8
            Set-Content -LiteralPath $malformed -Value '{"results":' -Encoding UTF8
            $sizeResult = Import-BenchmarkResults -Path $oversized -MaxFileBytes 1024 -MaxRows 10
            $badResult = Import-BenchmarkResults -Path $malformed -MaxFileBytes 4096 -MaxRows 10
            $sizeResult.status | Should -Be 'Skipped'
            $sizeResult.skipped_reason | Should -Match 'exceeds limit'
            $badResult.status | Should -Be 'Error'
            $badResult.import_error | Should -Match 'malformed \.json input'
        }
        finally {
            foreach ($path in $oversized, $malformed) {
                if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
            }
        }
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
        foreach ($nm in 'Get-CheckEvidenceMetadata','Test-ManualEvidenceRequired','ConvertTo-RedactedText','Get-AuditExceptions','Get-FrameworkControlSummary') {
            $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $nm }, $true)[0]
            . ([scriptblock]::Create($fn.Extent.Text))
        }
        $script:FrameworkChecks = @{ HIPAA = @('IA01','EP02','PS01') }
        $script:RiskTiers = @{ IA01=0; EP02=0; PS01=0 }
        $script:ManualEvidenceModes = @('Checklist','InterviewRequired','ExternalRequired')
        $script:CheckEvidenceManifest = @{
            IA01 = @{ EvidenceMode='Automated'; AuthorityLevel='Directory'; DataSources=@('AD'); InternetRequired=$false; WritesPossible=$false; DefaultRiskTier=0; ManualFollowUp='Validate owner.' }
            EP02 = @{ EvidenceMode='Automated'; AuthorityLevel='LocalHost'; DataSources=@('BitLocker'); InternetRequired=$false; WritesPossible=$false; DefaultRiskTier=0; ManualFollowUp='Validate escrow.' }
            PS01 = @{ EvidenceMode='Checklist'; AuthorityLevel='Documentation'; DataSources=@('Policy'); InternetRequired=$false; WritesPossible=$false; DefaultRiskTier=0; ManualFollowUp='Review policy.' }
        }
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
        $fc.manual_validation_required | Should -Be 1
        ($fc.controls | Where-Object { $_.check_id -eq 'PS01' }).manual_validation_required | Should -BeTrue
        ($fc.controls | Where-Object { $_.check_id -eq 'IA01' }).observed_fact | Should -Be '12 DAs'
    }
}

Describe 'Fleet orchestration safeguards' {
    BeforeAll {
        $script:FleetBlock = Get-Block $script:Text '# .*Remote Fleet Scan Mode' '# .*Remediation Engine'
        $script:ElevationBlock = Get-Block $script:Text '# .*Auto-Elevate to Administrator' '# .*Store CLI config'
    }

    It 'does not fall through to a local scan when TargetsCsv is missing' {
        $script:Text | Should -Match 'Targets CSV not found'
        $script:Text | Should -Match 'Test-Path -LiteralPath \$TargetsCsv'
    }

    It 'deduplicates target names before queuing jobs' {
        $script:FleetBlock | Should -Match '\$fleetRowsByHost\s*=\s*@\{\}'
        $script:FleetBlock | Should -Match 'ContainsKey\(\$targetName\)'
        $script:FleetBlock | Should -Match '\$fleetHosts\s*=\s*@\(\$fleetHostList\.ToArray\(\)\)'
    }

    It 'rejects quoted fleet CSV values before starting jobs' {
        $script:FleetBlock | Should -Match '\$fleetSafeColumns\s*='
        $script:FleetBlock | Should -Match 'Targets CSV column'
        $script:FleetBlock | Should -Match 'Quotes are not allowed in fleet CSV fields'
    }

    It 'uses a local HTML output path and parses the derived findings JSON' {
        $script:FleetBlock | Should -Match '\$hostOutFile\s*=\s*Join-Path \$fleetDir "\$\{artifactBase\}\.html"'
        $script:FleetBlock | Should -Match '\$localJsonPath\s*=\s*\$hostOutFile -replace ''\\\.html\$'', ''_findings\.json'''
        $script:FleetBlock | Should -Match '\$localJson\s*=\s*\$meta\.JsonPath'
    }

    It 'disambiguates sanitized fleet artifact names with a stable target token' {
        $script:FleetBlock | Should -Match 'function Get-FleetStableToken'
        $script:FleetBlock | Should -Match '\$fleetSafeNameGroups\s*=\s*@\{\}'
        $script:FleetBlock | Should -Match '\$fleetMembers\.Count -gt 1'
        $script:FleetBlock | Should -Match '\$fleetArtifactNames\[\$fleetMember\]'
        $script:FleetBlock | Should -Match 'artifact_base\s*=\s*\$meta\.ArtifactBase'
    }

    It 'rejects missing, malformed, and schema-incomplete child output' {
        $script:FleetBlock | Should -Match 'function Test-FleetFindingsContract'
        $script:FleetBlock | Should -Match "status = 'OutputInvalid'"
        $script:FleetBlock | Should -Match "error = 'No JSON output'"
        $script:FleetBlock | Should -Match "error = 'JSON parse failed'"
        $script:FleetBlock | Should -Match "error = 'JSON contract invalid'"
        $script:FleetBlock | Should -Match "status = 'Completed'"
    }

    It 'projects fleet aggregate identities and source paths through privacy helpers' {
        $script:FleetBlock | Should -Match 'function Get-FleetPrivacyIdentity'
        $script:FleetBlock | Should -Match 'function Convert-FleetPrivacyText'
        $script:FleetBlock | Should -Match 'targets_csv = if \(\$PrivacyMode\.IsPresent\) \{ ''\[PATH-REDACTED\]'' \}'
        $script:FleetBlock | Should -Match 'fleetExportResults'
        $script:FleetBlock | Should -Match 'Get-FleetPrivacyIdentity \$_.host ''HOST'''
    }

    It 'builds localhost child parameters as a typed splat' {
        $script:FleetBlock | Should -Not -Match '\$\(if\(\$NI\)'
        $script:FleetBlock | Should -Match '\$childParams\s*=\s*@\{'
        $script:FleetBlock | Should -Match 'ReadOnly\s*=\s*\[bool\]\$using:ReadOnly'
        $script:FleetBlock | Should -Match 'if \(\$using:fleetNoInternet\) \{ \$childParams\.NoInternet = \$true \}'
    }

    It 'validates fleet concurrency and timeout ranges at the parameter boundary' {
        $script:Text | Should -Match '\[ValidateRange\(1,64\)\]\s*\[int\]\$ThrottleLimit'
        $script:Text | Should -Match '\[ValidateRange\(1,86400\)\]\s*\[int\]\$PerHostTimeout'
    }

    It 'forwards fleet child scan options without using dead session options' {
        $script:FleetBlock | Should -Not -Match '\$sessionOpts'
        $script:FleetBlock | Should -Match '\$fleetChildOptions\s*=\s*\[ordered\]@\{'
        $script:FleetBlock | Should -Match '\$childParams\.Auditor\s*=\s*\$childOptions\.Auditor'
        $script:FleetBlock | Should -Match '\$childParams\.ReportTier\s*=\s*\$childOptions\.ReportTier'
        foreach ($switchName in 'PrivacyMode','ExportCSV','ExportJSONL','ExportSARIF','ExportPDF','ExportNavigator','ExportOCSF','ExportOSCAL','ExportSIEM') {
            $script:FleetBlock | Should -Match ([regex]::Escape("'$switchName'"))
        }
    }

    It 'uses unique remote temp artifacts and bounded timeout cleanup' {
        $script:FleetBlock | Should -Match 'NetworkSecurityAudit_fleet_\$runId'
        $script:FleetBlock | Should -Match 'function Invoke-FleetRemoteTempCleanup'
        $script:FleetBlock | Should -Match 'Invoke-FleetRemoteTempCleanup -ComputerName \$target -RunId \$meta\.RemoteRunId'
        $script:FleetBlock | Should -Match 'AsJob\s*=\s*\$true'
        $script:FleetBlock | Should -Match 'Wait-Job -Job \$cleanupJob -Timeout \$TimeoutSeconds'
        $script:FleetBlock | Should -Match 'cleanup_status'
        $script:FleetBlock | Should -Not -Match 'Invoke-FleetRemoteTempCleanup -ComputerName \$running\.Key'
        $script:FleetBlock | Should -Not -Match 'Join-Path \$env:TEMP ''NetworkSecurityAudit_fleet\.ps1'''
        $script:FleetBlock | Should -Not -Match 'Join-Path \$env:TEMP "SecurityAudit_fleet\.html"'
    }

    It 'classifies timeouts by stopped job state and preserves zero-score hosts in aggregates' {
        $script:FleetBlock | Should -Match '\$meta\.Job\.PSEndTime'
        $script:FleetBlock | Should -Match '\$timedOut\s*=\s*\$meta\.Job\.State -eq ''Stopped'''
        $script:FleetBlock | Should -Not -Match '\$timedOut\s*=\s*\$elapsed -ge \$PerHostTimeout'
        $script:FleetBlock | Should -Match 'has_score\s*=\s*\$false'
        $script:FleetBlock | Should -Match '\$scoredFleetResults'
        $script:FleetBlock | Should -Match 'hosts_scored'
        $script:FleetBlock | Should -Not -Match '\.score -gt 0'
    }

    It 'forwards fleet and v4.11 switches during elevation or fails clearly for credentials' {
        $script:ElevationBlock | Should -Match 'Credential cannot be forwarded through a UAC relaunch'
        foreach ($token in '-ExportSIEM','-BrandingConfig','-TargetsCsv','-ThrottleLimit','-PerHostTimeout','-Remediate','-RemediateDryRun','-RemediateChecks','-BenchmarkImportPath','-BenchmarkMaxFileBytes','-BenchmarkMaxRows') {
            $script:ElevationBlock | Should -Match ([regex]::Escape($token))
        }
    }
}

Describe 'Continuous delta engine (real functions via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        foreach ($nm in 'Test-AuditSnapshotIdentity','Compare-AuditSnapshot','Update-ExposureWindows','Get-ResolvedExposureWindows','Get-AuditAlertPayload') {
            $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $nm }, $true)[0]
            . ([scriptblock]::Create($fn.Extent.Text))
        }
        function script:F { param($s,$sev,$fp) [ordered]@{ status=$s; severity=$sev; fingerprint=$fp } }
    }
    It 'classifies every transition type and counts criticals' {
        # current snapshot is an OrderedDictionary (as in production); baseline is JSON-roundtripped
        $prev = @{ schema_version='2.1'; run_id='R1'; score=@{overall=60;ransomware=50}; findings=@{
            IA01=(F 'Pass' 'Critical' 'a'); IA02=(F 'Fail' 'Critical' 'b'); IA03=(F 'Pass' 'High' 'c')
            IA04=(F 'Fail' 'High' 'd'); IA05=(F 'Fail' 'Medium' 'e'); IA06=(F 'Pass' 'Low' 'f'); EP01=(F 'Pass' 'High' 'h') } } | ConvertTo-Json -Depth 6 | ConvertFrom-Json
        $curr = [ordered]@{ schema_version='2.1'; run_id='R2'; score=[ordered]@{overall=72;ransomware=58}; findings=[ordered]@{
            IA01=(F 'Fail' 'Critical' 'a2'); IA02=(F 'Pass' 'Critical' 'b2'); IA03=(F 'Partial' 'High' 'c2')
            IA04=(F 'Partial' 'High' 'd2'); IA05=(F 'Fail' 'Medium' 'e2'); IA06=(F 'Pass' 'Low' 'f'); EP09=(F 'Fail' 'High' 'z') } }
        $d = Compare-AuditSnapshot -Previous $prev -Current $curr
        $d.states.NewFailure | Should -Contain 'IA01'
        $d.states.NewFailure | Should -Contain 'EP09'
        $d.states.Resolved   | Should -Be @('IA02')
        $d.states.Worsened   | Should -Be @('IA03')
        $d.states.Improved   | Should -Be @('IA04')
        $d.states.UpdatedEvidence | Should -Be @('IA05')
        $d.states.UnchangedPass   | Should -Be @('IA06')
        $d.states.AbsentFromCurrentRun | Should -Be @('EP01')
        $d.new_criticals      | Should -Be 1
        $d.resolved_criticals | Should -Be 1
        $d.score_delta.overall | Should -Be 12
    }
    It 'flags a schema-version mismatch as incompatible' {
        $prev = [ordered]@{ schema_version='2.0'; findings=[ordered]@{} }
        $curr = [ordered]@{ schema_version='2.1'; findings=[ordered]@{} }
        (Compare-AuditSnapshot -Previous $prev -Current $curr).schema_compatible | Should -BeFalse
    }
    It 'refuses to compare snapshots from different clients or targets' {
        $prev = [ordered]@{ schema_version='2.1'; client='Acme'; target='DC01'; score=@{ overall=50; ransomware=40 }; findings=[ordered]@{ IA01=(F 'Fail' 'Critical' 'old') } }
        $curr = [ordered]@{ schema_version='2.1'; client='Acme'; target='DC02'; score=@{ overall=80; ransomware=70 }; findings=[ordered]@{ IA01=(F 'Pass' 'Critical' 'new') } }
        $d = Compare-AuditSnapshot -Previous $prev -Current $curr
        $d.schema_compatible | Should -BeTrue
        $d.identity_compatible | Should -BeFalse
        $d.identity_error | Should -Match 'target differs'
        @($d.states.NewFailure).Count | Should -Be 0
        $d.score_delta.overall | Should -BeNullOrEmpty
    }
    It 'carries the exposure first-seen timestamp forward for still-failing findings' {
        $prevExp = @{ IA01 = @{ first_seen='2026-06-01T00:00:00.0000000'; days=0; severity='Critical' } }
        $snap = [ordered]@{ findings=[ordered]@{ IA01=(F 'Fail' 'Critical' 'x'); IA02=(F 'Pass' 'High' 'y') } }
        $now = [datetime]'2026-06-11T00:00:00'
        $exp = Update-ExposureWindows -PrevExposure $prevExp -CurrentSnapshot $snap -Now $now -NowIso $now.ToString('o')
        $exp.Keys | Should -Be @('IA01')                    # IA02 passing -> no exposure
        $exp.IA01.first_seen | Should -Be '2026-06-01T00:00:00.0000000'
        $exp.IA01.days | Should -Be 10                       # 10 days of exposure carried forward
    }
    It 'keeps first_seen and cumulative days across a run that could not assess the finding' {
        # Fail, Unavailable, Fail. Each baseline goes through JSON the way Invoke-AuditHistory reads it back.
        $roundTrip = { param($value) $value | ConvertTo-Json -Depth 6 | ConvertFrom-Json }
        $day1 = [datetime]'2026-06-01T00:00:00'; $day5 = [datetime]'2026-06-05T00:00:00'; $day11 = [datetime]'2026-06-11T00:00:00'
        $run1 = Update-ExposureWindows -PrevExposure $null -CurrentSnapshot ([ordered]@{ findings=[ordered]@{ IA01=(F 'Fail' 'Critical' 'x') } }) -Now $day1 -NowIso $day1.ToString('o')
        $run2 = Update-ExposureWindows -PrevExposure (& $roundTrip $run1) -CurrentSnapshot ([ordered]@{ findings=[ordered]@{ IA01=(F 'Error' 'Critical' '') } }) -Now $day5 -NowIso $day5.ToString('o')
        $run2.IA01.first_seen | Should -Be $day1.ToString('o')
        $run2.IA01.last_seen | Should -Be $day1.ToString('o')
        $run2.IA01.evidence_stale | Should -BeTrue
        foreach ($status in 'Skipped','NotPermitted','Not Assessed') {
            (Update-ExposureWindows -PrevExposure (& $roundTrip $run1) -CurrentSnapshot ([ordered]@{ findings=[ordered]@{ IA01=(F $status 'Critical' '') } }) -Now $day5 -NowIso $day5.ToString('o')).Keys | Should -Contain 'IA01'
        }
        $run3 = Update-ExposureWindows -PrevExposure (& $roundTrip $run2) -CurrentSnapshot ([ordered]@{ findings=[ordered]@{ IA01=(F 'Fail' 'Critical' 'x') } }) -Now $day11 -NowIso $day11.ToString('o')
        $run3.IA01.first_seen | Should -Be $day1.ToString('o')
        $run3.IA01.days | Should -Be 10
        $run3.IA01.evidence_stale | Should -BeFalse
        # Pass ends the open window.
        (Update-ExposureWindows -PrevExposure (& $roundTrip $run1) -CurrentSnapshot ([ordered]@{ findings=[ordered]@{ IA01=(F 'Pass' 'Critical' 'y') } }) -Now $day5 -NowIso $day5.ToString('o')).Keys | Should -Not -Contain 'IA01'
    }
    It 'keeps the window open when a failing finding improves to Partial, until it passes' {
        $roundTrip = { param($value) $value | ConvertTo-Json -Depth 6 | ConvertFrom-Json }
        $day1 = [datetime]'2026-06-01T00:00:00'; $day5 = [datetime]'2026-06-05T00:00:00'; $day11 = [datetime]'2026-06-11T00:00:00'
        $run1 = Update-ExposureWindows -PrevExposure $null -CurrentSnapshot ([ordered]@{ findings=[ordered]@{ IA01=(F 'Fail' 'Critical' 'x') } }) -Now $day1 -NowIso $day1.ToString('o')
        $partial = Update-ExposureWindows -PrevExposure (& $roundTrip $run1) -CurrentSnapshot ([ordered]@{ findings=[ordered]@{ IA01=(F 'Partial' 'Critical' 'p') } }) -Now $day5 -NowIso $day5.ToString('o')
        $partial.IA01.first_seen | Should -Be $day1.ToString('o')
        $partial.IA01.days | Should -Be 4
        $partial.IA01.status | Should -Be 'Partial'
        $partial.IA01.evidence_stale | Should -BeFalse
        $again = Update-ExposureWindows -PrevExposure (& $roundTrip $partial) -CurrentSnapshot ([ordered]@{ findings=[ordered]@{ IA01=(F 'Fail' 'Critical' 'x') } }) -Now $day11 -NowIso $day11.ToString('o')
        $again.IA01.first_seen | Should -Be $day1.ToString('o')
        $again.IA01.days | Should -Be 10
        $resolved = Get-ResolvedExposureWindows -PrevExposure (& $roundTrip $partial) -CurrentSnapshot ([ordered]@{ findings=[ordered]@{ IA01=(F 'Pass' 'Critical' 'y') } }) -Now $day11 -NowIso $day11.ToString('o')
        $resolved.IA01.first_seen | Should -Be $day1.ToString('o')
        $resolved.IA01.days | Should -Be 10
        # A Partial with no open window doesn't start one.
        (Update-ExposureWindows -PrevExposure $null -CurrentSnapshot ([ordered]@{ findings=[ordered]@{ IA01=(F 'Partial' 'Critical' 'p') } }) -Now $day5 -NowIso $day5.ToString('o')).Keys | Should -Not -Contain 'IA01'
    }
    It 'records resolved_at and the final exposure window when a failing finding passes' {
        $prevExp = @{ IA01 = @{ first_seen='2026-06-01T00:00:00.0000000'; last_seen='2026-06-08T00:00:00.0000000'; days=7; severity='Critical' }; IA02 = @{ first_seen='2026-06-01T00:00:00.0000000'; days=7; severity='High' } } | ConvertTo-Json -Depth 4 | ConvertFrom-Json
        $snap = [ordered]@{ findings=[ordered]@{ IA01=(F 'Pass' 'Critical' 'x'); IA02=(F 'Fail' 'High' 'y') } }
        $now = [datetime]'2026-06-11T00:00:00'
        $resolved = Get-ResolvedExposureWindows -PrevExposure $prevExp -CurrentSnapshot $snap -Now $now -NowIso $now.ToString('o')
        $resolved.Keys | Should -Be @('IA01')
        $resolved.IA01.resolved_at | Should -Be $now.ToString('o')
        $resolved.IA01.first_seen | Should -Be '2026-06-01T00:00:00.0000000'
        $resolved.IA01.last_seen | Should -Be '2026-06-08T00:00:00.0000000'
        $resolved.IA01.days | Should -Be 10
        $resolved.IA01.severity | Should -Be 'Critical'
        (Get-ResolvedExposureWindows -PrevExposure $null -CurrentSnapshot $snap -Now $now -NowIso 'n').Count | Should -Be 0
    }
    It 'builds an alert payload with worst critical exposure (never sent)' {
        $exp = @{ IA01=@{days=10;severity='Critical'}; IA02=@{days=40;severity='High'} }
        $p = Get-AuditAlertPayload -Delta (@{score_delta=@{overall=5};new_criticals=1;resolved_criticals=0;counts=@{new_failure=1;resolved=0}}) -CurrentSnapshot (@{client='Acme';target='DC';run_id='R';score=@{overall=70;grade='C'}}) -Exposure $exp -NowIso 'now'
        $p.worst_exposure_days | Should -Be 40
        $p.worst_critical_exposure_days | Should -Be 10
        $p.new_criticals | Should -Be 1
    }

    It 'converts two save files and diffs them through the shared engine' {
        # Load the catalog-dependent converter + fingerprint helper with a minimal catalog
        $ast2 = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        foreach ($nm in 'Convert-SaveStateToSnapshot','Get-StringSha256','Get-FindingFingerprint') {
            $fn = $ast2.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $nm }, $true)[0]
            . ([scriptblock]::Create($fn.Extent.Text))
        }
        $script:AuditCategories = @{ 'Identity' = @{ Items = @(
            @{ ID='IA01'; Text='Priv groups'; Severity='Critical' }
            @{ ID='IA02'; Text='MFA'; Severity='High' }) } }
        $script:SchemaVersion = '2.1'; $script:ProductVersion = '4.10.9'
        $save1 = @{ SchemaVersion='2.1'; Client='Acme'; Date='2026-06-01'; ScanTarget='DC'; Items=@{ IA01=@{Status='Fail';Findings='x';Evidence='y'}; IA02=@{Status='Pass'} } } | ConvertTo-Json -Depth 5 | ConvertFrom-Json
        $save2 = @{ SchemaVersion='2.1'; Client='Acme'; Date='2026-06-14'; ScanTarget='DC'; Items=@{ IA01=@{Status='Pass'}; IA02=@{Status='Fail'} } } | ConvertTo-Json -Depth 5 | ConvertFrom-Json
        $s1 = Convert-SaveStateToSnapshot $save1
        $s2 = Convert-SaveStateToSnapshot $save2
        @($s1.findings.Keys) | Should -Contain 'IA01'
        $d = Compare-AuditSnapshot -Previous $s1 -Current $s2
        $d.states.Resolved   | Should -Be @('IA01')   # IA01 Fail -> Pass
        $d.states.NewFailure | Should -Be @('IA02')   # IA02 Pass -> Fail
        $d.resolved_criticals | Should -Be 1          # IA01 is Critical
    }
}

Describe 'History persistence helpers (real functions via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        foreach ($nm in 'Write-HistoryJsonFile','Append-HistoryLine') {
            $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $nm }, $true)[0]
            . ([scriptblock]::Create($fn.Extent.Text))
        }
    }

    It 'replaces JSON atomically and appends complete JSONL records' {
        $root = Join-Path ([IO.Path]::GetTempPath()) ('nsa-history-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        try {
            $jsonPath = Join-Path $root 'latest.snapshot.json'
            Write-HistoryJsonFile -Path $jsonPath -Value ([ordered]@{ version = 1 }) | Should -BeTrue
            Write-HistoryJsonFile -Path $jsonPath -Value ([ordered]@{ version = 2 }) | Should -BeTrue
            (Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json).version | Should -Be 2
            @(Get-ChildItem -LiteralPath $root -Filter '*.tmp' -File) | Should -BeNullOrEmpty

            $historyPath = Join-Path $root 'history.jsonl'
            Append-HistoryLine -Path $historyPath -Line '{"run":1}'
            Append-HistoryLine -Path $historyPath -Line '{"run":2}'
            $lines = @(Get-Content -LiteralPath $historyPath)
            $lines.Count | Should -Be 2
            ($lines | ForEach-Object { ($_ | ConvertFrom-Json).run }) | Should -Be @(1,2)
        }
        finally {
            if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe 'Exposure windows through Invoke-AuditHistory (real functions via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        foreach ($nm in 'Invoke-AuditHistory','Test-AuditSnapshotIdentity','Compare-AuditSnapshot','Update-ExposureWindows','Get-ResolvedExposureWindows',
                        'Get-AuditAlertPayload','Get-MspExecutiveKpis','Write-HistoryJsonFile','Append-HistoryLine','Get-StringSha256') {
            $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $nm }, $true)[0]
            . ([scriptblock]::Create($fn.Extent.Text))
        }
        # Stands in for the GUI-state converter; each run reports the status in $script:NextStatus.
        function script:Convert-AuditStateToSnapshot {
            param($RunId, $SnapshotId, $TimestampIso, $Client, $Target)
            [ordered]@{ schema_version='2.1'; run_id=$RunId; timestamp=$TimestampIso; client=$Client; target=$Target; catalog_hash='c'; policy_hash='p'
                score=[ordered]@{ overall=70; grade='C'; ransomware=60 }
                findings=[ordered]@{ IA01=[ordered]@{ status=$script:NextStatus; severity='Critical'; fingerprint=$script:NextStatus } } }
        }
    }

    It 'keeps the window through an errored run and writes resolved_at to the delta and history record' {
        $root = Join-Path ([IO.Path]::GetTempPath()) ('nsa-exposure-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        $saved = @{ NoHistory=$script:CliNoHistory; HistoryPath=$script:CliHistoryPath; BaselinePath=$script:CliBaselinePath; Retention=$script:CliHistoryRetentionDays }
        try {
            $script:CliNoHistory = $false; $script:CliHistoryPath = $root; $script:CliBaselinePath = $null; $script:CliHistoryRetentionDays = 0
            $firstSeen = (Get-Date).AddDays(-10).ToString('o')
            $baselineDir = Join-Path $root 'baselines'
            New-Item -ItemType Directory -Path $baselineDir -Force | Out-Null
            [ordered]@{ schema_version='2.1'; run_id='R0'; timestamp=$firstSeen; client='Acme'; target='DC'; score=@{ overall=60; grade='D'; ransomware=50 }
                findings=@{ IA01=@{ status='Fail'; severity='Critical'; fingerprint='Fail' } }
                exposure=@{ IA01=@{ first_seen=$firstSeen; last_seen=$firstSeen; days=0; severity='Critical'; evidence_stale=$false } } } |
                ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $baselineDir 'latest.snapshot.json') -Encoding UTF8

            $script:NextStatus = 'Error'
            $errored = Invoke-AuditHistory -Client 'Acme' -Target 'DC' -OutputDir $root -RunId 'R1'
            $errored.exposure.IA01.first_seen | Should -Be $firstSeen
            $errored.exposure.IA01.evidence_stale | Should -BeTrue

            $script:NextStatus = 'Fail'
            $failing = Invoke-AuditHistory -Client 'Acme' -Target 'DC' -OutputDir $root -RunId 'R2'
            $failing.exposure.IA01.first_seen | Should -Be $firstSeen
            $failing.exposure.IA01.days | Should -Be 10

            $script:NextStatus = 'Pass'
            $passing = Invoke-AuditHistory -Client 'Acme' -Target 'DC' -OutputDir $root -RunId 'R3'
            $passing.exposure.Keys | Should -Not -Contain 'IA01'
            $passing.delta.resolved_exposure.IA01.first_seen | Should -Be $firstSeen
            $passing.delta.resolved_exposure.IA01.days | Should -Be 10
            $passing.delta.resolved_exposure.IA01.resolved_at | Should -Not -BeNullOrEmpty
            $record = Get-Content -LiteralPath (Join-Path $root 'history.jsonl') | Select-Object -Last 1 | ConvertFrom-Json
            $record.run_id | Should -Be 'R3'
            $iso = { param($value) if ($value -is [datetime]) { $value.ToString('o') } else { [string]$value } }   # pwsh 7 reads ISO strings back as DateTime
            & $iso $record.resolved_exposure.IA01.first_seen | Should -Be $firstSeen
            & $iso $record.resolved_exposure.IA01.resolved_at | Should -Be $passing.delta.resolved_exposure.IA01.resolved_at
            $record.resolved_exposure.IA01.days | Should -Be 10
        }
        finally {
            $script:CliNoHistory = $saved.NoHistory; $script:CliHistoryPath = $saved.HistoryPath; $script:CliBaselinePath = $saved.BaselinePath; $script:CliHistoryRetentionDays = $saved.Retention
            if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe 'Unattended audit run locking (real functions via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        foreach ($nm in 'Get-AuditRunLockIdentity','Get-AuditRunLockPath','Test-AuditRunLockRecoverable','Enter-AuditRunLock','Exit-AuditRunLock') {
            $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $nm }, $true)[0]
            . ([scriptblock]::Create($fn.Extent.Text))
        }
    }
    BeforeEach {
        $script:ProductVersion = '4.12.0'
    }

    It 'records owner metadata, normalizes identity, and permits unrelated targets' {
        $root = Join-Path ([IO.Path]::GetTempPath()) ('nsa-run-lock-' + [guid]::NewGuid().ToString('N'))
        $first = $null
        $other = $null
        try {
            $now = [DateTimeOffset]::UtcNow
            $first = Enter-AuditRunLock -OutputDirectory $root -Client 'Client A' -Target 'Host A' -HistoryIdentity 'history\client-a' -NowUtc $now
            $first | Should -Not -BeNullOrEmpty

            $metadataStream = [IO.FileStream]::new($first.LockPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
            $reader = [IO.StreamReader]::new($metadataStream)
            try { $metadata = $reader.ReadToEnd() | ConvertFrom-Json }
            finally { $reader.Dispose() }
            $metadata.schema_version | Should -Be 1
            $metadata.run_id | Should -Be $first.RunId
            $metadata.tool_version | Should -Be $script:ProductVersion
            $metadata.process_id | Should -Be $PID

            $duplicate = Enter-AuditRunLock -OutputDirectory $root -Client ' client a ' -Target 'host a' -HistoryIdentity 'history/client-a' -NowUtc $now.AddMinutes(1)
            $duplicate | Should -BeNullOrEmpty

            $other = Enter-AuditRunLock -OutputDirectory $root -Client 'Client A' -Target 'Host B' -HistoryIdentity 'history\client-a' -NowUtc $now.AddMinutes(1)
            $other | Should -Not -BeNullOrEmpty
        }
        finally {
            Exit-AuditRunLock -Lock $other
            Exit-AuditRunLock -Lock $first
            if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'removes the lock after a completed or canceled run' {
        $root = Join-Path ([IO.Path]::GetTempPath()) ('nsa-run-lock-' + [guid]::NewGuid().ToString('N'))
        try {
            $lock = Enter-AuditRunLock -OutputDirectory $root -Client 'Client' -Target 'Host'
            $lock | Should -Not -BeNullOrEmpty
            $lockPath = $lock.LockPath
            Exit-AuditRunLock -Lock $lock
            Test-Path -LiteralPath $lockPath | Should -BeFalse

            $next = Enter-AuditRunLock -OutputDirectory $root -Client 'Client' -Target 'Host'
            $next | Should -Not -BeNullOrEmpty
            Exit-AuditRunLock -Lock $next
        }
        finally {
            if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'recovers a stale crashed owner but never evicts a verified live owner' {
        $root = Join-Path ([IO.Path]::GetTempPath()) ('nsa-run-lock-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        $recovered = $null
        try {
            $now = [DateTimeOffset]::UtcNow
            $crashedIdentity = Get-AuditRunLockIdentity -OutputDirectory $root -Client 'Crashed' -Target 'Host A'
            $crashedPath = Get-AuditRunLockPath -OutputDirectory $root -Identity $crashedIdentity
            [ordered]@{
                schema_version = 1; run_id = 'crashed'; tool_version = $script:ProductVersion
                process_id = [int]::MaxValue; started_at_utc = $now.AddHours(-1).ToString('o')
            } | ConvertTo-Json | Set-Content -LiteralPath $crashedPath -Encoding UTF8
            [IO.File]::SetLastWriteTimeUtc($crashedPath, $now.AddHours(-1).UtcDateTime)

            $recovered = Enter-AuditRunLock -OutputDirectory $root -Client 'Crashed' -Target 'Host A' -NowUtc $now
            $recovered | Should -Not -BeNullOrEmpty

            $liveIdentity = Get-AuditRunLockIdentity -OutputDirectory $root -Client 'Live' -Target 'Host B'
            $livePath = Get-AuditRunLockPath -OutputDirectory $root -Identity $liveIdentity
            $ownerStarted = (Get-Process -Id $PID).StartTime.ToUniversalTime()
            [ordered]@{
                schema_version = 1; run_id = 'live'; tool_version = $script:ProductVersion
                process_id = $PID; started_at_utc = $ownerStarted.ToString('o')
            } | ConvertTo-Json | Set-Content -LiteralPath $livePath -Encoding UTF8
            [IO.File]::SetLastWriteTimeUtc($livePath, $now.AddHours(-1).UtcDateTime)

            Enter-AuditRunLock -OutputDirectory $root -Client 'Live' -Target 'Host B' -NowUtc $now | Should -BeNullOrEmpty
        }
        finally {
            Exit-AuditRunLock -Lock $recovered
            if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'acquires before history persistence and releases before normal exit' {
        $acquire = $script:Text.IndexOf('$script:ActiveAuditRunLock = Enter-AuditRunLock')
        $history = $script:Text.IndexOf('$histResult = Invoke-AuditHistory')
        $release = $script:Text.LastIndexOf('Exit-AuditRunLock -Lock $script:ActiveAuditRunLock')
        $normalExit = $script:Text.LastIndexOf('exit $exitCode')
        $acquire | Should -BeGreaterThan -1
        $history | Should -BeGreaterThan $acquire
        $release | Should -BeGreaterThan $history
        $normalExit | Should -BeGreaterThan $release
        $script:Text | Should -Match 'Invoke-AuditHistory[^\r\n]+-RunId \$script:ActiveAuditRunLock\.RunId'
    }
}

Describe 'LM02 log forwarding decision (nested check helper via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-Lm02ForwardingAssessment' }, $true)[0]
        . ([scriptblock]::Create($fn.Extent.Text))
        function New-CleanHostServices { @{ EventLog='Running'; Wecsvc='Stopped'; Sense='Stopped'; WinDefend='Running' } }
    }

    It 'counts nothing on a clean Windows host with EventLog, Wecsvc and Sense present' {
        $result = Get-Lm02ForwardingAssessment -Services (New-CleanHostServices)
        @($result.Counted).Count | Should -Be 0
        ($result.Lines -join "`n") | Should -Match 'local logging only'
    }
    It 'never counts inbox services even when all of them run' {
        $services = New-CleanHostServices; $services.Wecsvc = 'Running'; $services.Sense = 'Running'
        $result = Get-Lm02ForwardingAssessment -Services $services -MdeOnboardingState 0
        @($result.Counted).Count | Should -Be 0
    }
    It 'counts a running Splunk Universal Forwarder' {
        $services = New-CleanHostServices; $services.SplunkForwarder = 'Running'
        $result = Get-Lm02ForwardingAssessment -Services $services
        $result.Counted | Should -Be @('Splunk Universal Forwarder')
    }
    It 'counts Defender for Endpoint only when Sense runs and OnboardingState is 1' {
        $services = New-CleanHostServices; $services.Sense = 'Running'
        (Get-Lm02ForwardingAssessment -Services $services -MdeOnboardingState 1).Counted | Should -Be @('Microsoft Defender for Endpoint (onboarded)')
        $stopped = Get-Lm02ForwardingAssessment -Services (New-CleanHostServices) -MdeOnboardingState 1
        @($stopped.Counted).Count | Should -Be 0
        $stopped.NotCounted | Should -Be @('Microsoft Defender for Endpoint (Stopped)')
    }
    It 'reports a stopped agent without counting it' {
        $services = New-CleanHostServices; $services.ossecsvc = 'Stopped'
        $result = Get-Lm02ForwardingAssessment -Services $services
        @($result.Counted).Count | Should -Be 0
        $result.NotCounted | Should -Be @('Wazuh/OSSEC Agent (Stopped)')
    }
    It 'counts the event collector only with subscriptions and a running service' {
        $running = New-CleanHostServices; $running.Wecsvc = 'Running'
        @((Get-Lm02ForwardingAssessment -Services $running).Counted).Count | Should -Be 0
        (Get-Lm02ForwardingAssessment -Services $running -CollectorSubscriptions @('DC-Security')).Counted | Should -Be @('Windows Event Collector')
        $idle = Get-Lm02ForwardingAssessment -Services (New-CleanHostServices) -CollectorSubscriptions @('DC-Security')
        @($idle.Counted).Count | Should -Be 0
        $idle.NotCounted | Should -Be @('Windows Event Collector (Stopped)')
    }
    It 'counts a source-initiated forwarding policy' {
        $result = Get-Lm02ForwardingAssessment -Services (New-CleanHostServices) -ForwardingTargets @('1 = Server=http://wec01:5985/wsman/SubscriptionManager/WEC')
        $result.Counted | Should -Be @('Windows Event Forwarding (source)')
    }
    It 'scores on forwarding alone: a Splunk host without Sysmon or script block logging passes' {
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-Lm02Status' }, $true)[0]
        . ([scriptblock]::Create($fn.Extent.Text))
        $services = New-CleanHostServices; $services.SplunkForwarder = 'Running'
        $forwarding = Get-Lm02ForwardingAssessment -Services $services
        Get-Lm02Status -Counted $forwarding.Counted | Should -Be 'Pass'
        Get-Lm02Status -Counted (Get-Lm02ForwardingAssessment -Services (New-CleanHostServices)).Counted | Should -Be 'Fail'
        Get-Lm02Status -Counted @() -ServicesReadable $false | Should -Be 'Not Assessed'
        # Same as the app: an install trace with no matching service is Partial, unless a stopped agent explains it.
        Get-Lm02Status -Counted @() -TracesWithoutService @('Splunk') | Should -Be 'Partial'
        Get-Lm02Status -Counted @() -TracesWithoutService @('Splunk') -NotCounted @('Elastic Winlogbeat (Stopped)') | Should -Be 'Fail'
        $block = Get-Block -Text $script:Text -Start "'LM02' = @\{ Type='Local'" -End "'LM06' = @\{"
        $block | Should -Match "Key='HKLM:\\SOFTWARE\\Splunk'"
        $block | Should -Match '\$status = Get-Lm02Status -Counted \$forwarding\.Counted -ServicesReadable \$servicesReadable'
        $block | Should -Not -Match '\$issues'
    }
    It 'reads collector subscriptions from the registry instead of launching wecutil' {
        $block = Get-Block -Text $script:Text -Start "'LM02' = @\{ Type='Local'" -End "'LM06' = @\{"
        $block | Should -Not -Match 'wecutil'
        $block | Should -Match 'EventCollector\\Subscriptions'
        $block | Should -Not -Match "Name='MsSense'"
    }
}

Describe 'Audit policy setup (real function via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Set-AuditPolicyBaseline' }, $true)[0]
        . ([scriptblock]::Create($fn.Extent.Text))
        $script:AuditBaselineRows = @([regex]::Matches($fn.Extent.Text, "@\{ Name='(?<name>[^']+)'; Guid='(?<guid>[^']+)'; Setting='(?<setting>[^']+)' \}") |
            ForEach-Object { [pscustomobject]@{ Name=$_.Groups['name'].Value; Guid=$_.Groups['guid'].Value; Setting=$_.Groups['setting'].Value } })
    }
    It 'passes subcategory GUIDs and only the directions LM03 requires' {
        $calls = [System.Collections.Generic.List[object]]::new()
        $result = Set-AuditPolicyBaseline -Invoker { param([string[]]$Arguments) $calls.Add($Arguments); [pscustomobject]@{ ExitCode=0; Output='' } }
        $result.Total | Should -Be 18
        $result.Configured | Should -Be 18
        $result.Failed | Should -Be 0
        $calls.Count | Should -Be 18
        ($calls[0] -join ' ') | Should -Be '/set /subcategory:{0CCE923F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'
        ($calls | Where-Object { $_[1] -eq '/subcategory:{0CCE9217-69AE-11D9-BED3-505054503030}' }) -join ' ' | Should -Be '/set /subcategory:{0CCE9217-69AE-11D9-BED3-505054503030} /failure:enable'
        ($calls | Where-Object { $_[1] -eq '/subcategory:{0CCE9216-69AE-11D9-BED3-505054503030}' }) -join ' ' | Should -Be '/set /subcategory:{0CCE9216-69AE-11D9-BED3-505054503030} /success:enable'
        foreach ($call in $calls) {
            $call[0] | Should -Be '/set'
            $call[1] | Should -Match '^/subcategory:\{[0-9A-F]{8}-69AE-11D9-BED3-505054503030\}$'
            @($call | Where-Object { $_ -match 'disable' }).Count | Should -Be 0
        }
    }
    It 'reports each failed subcategory with its exit code and output' {
        $result = Set-AuditPolicyBaseline -Invoker {
            param([string[]]$Arguments)
            if ($Arguments[1] -eq '/subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}') { [pscustomobject]@{ ExitCode=87; Output='The parameter is incorrect.' } }
            elseif ($Arguments[1] -eq '/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}') { throw 'auditpol.exe not found' }
            else { [pscustomobject]@{ ExitCode=0; Output='' } }
        }
        $result.Configured | Should -Be 16
        $result.Failed | Should -Be 2
        $result.Failures | Should -Contain 'Logon (exit 87): The parameter is incorrect.'
        $result.Failures | Should -Contain 'Process Creation: auditpol.exe not found'
    }
    It 'sets exactly the subcategories and settings LM03 checks' {
        $lm03 = Get-Block -Text $script:Text -Start "'LM03' = @\{ Type='Local'" -End "foreach \(\`$sub in \`$cisRequired\.Keys\)"
        $required = @([regex]::Matches($lm03, "'(?<name>[^']+)' = '(?<setting>Success and Failure|Success|Failure)'") | ForEach-Object { "$($_.Groups['name'].Value)=$($_.Groups['setting'].Value)" } | Sort-Object)
        $required.Count | Should -Be 18
        @($script:AuditBaselineRows | ForEach-Object { "$($_.Name)=$($_.Setting)" } | Sort-Object) | Should -Be $required
    }
    It 'uses GUIDs that auditpol lists for those subcategories' {
        $listing = (& auditpol.exe /list /subcategory:* /v 2>&1 | Out-String)
        foreach ($row in $script:AuditBaselineRows) {
            $listing | Should -Match ([regex]::Escape($row.Guid))
            if ($listing -match "(?m)^\s+$([regex]::Escape($row.Name))\s+\{") { $listing | Should -Match "(?m)^\s+$([regex]::Escape($row.Name))\s+$([regex]::Escape($row.Guid))" }
        }
    }
    It 'runs the same function in the turnkey setup runspace and no longer uses category names' {
        $definition = "function Set-AuditPolicyBaseline {${function:Set-AuditPolicyBaseline}}"
        $count = & { . ([scriptblock]::Create($definition)); (Set-AuditPolicyBaseline -Invoker { param([string[]]$Arguments) [pscustomobject]@{ ExitCode=0; Output='' } }).Configured }
        $count | Should -Be 18
        $script:Text | Should -Match 'AuditPolicyFunction = "function Set-AuditPolicyBaseline \{\$\{function:Set-AuditPolicyBaseline\}\}"'
        $step = Get-Block -Text $script:Text -Start 'Step 6: Audit Policies' -End 'Step 7: Remote Registry'
        $step | Should -Match '\. \(\[scriptblock\]::Create\(\$Env\.AuditPolicyFunction\)\)'
        $step | Should -Not -Match "Sub='Account Logon'"
        $enable = Get-Block -Text $script:Text -Start 'function Enable-AuditPolicies \{' -End 'function Export-DiagnosticsReport'
        $enable | Should -Match 'Set-AuditPolicyBaseline'
        $script:Text | Should -Not -Match 'auditpol /set /subcategory:`"\$\(\$p\.Sub\)`"'
    }
}

Describe 'NP07 and LM06 agent service names' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-Np07AgentLine' }, $true)[0]
        . ([scriptblock]::Create($fn.Extent.Text))
    }
    It 'counts an agent only when it runs, and Defender for Endpoint only when onboarded' {
        # The Sense service exists, stopped, on every Windows 10/11 host that isn't onboarded.
        $stock = Get-Np07AgentLine -Desc 'Defender for Endpoint' -DisplayName 'Windows Defender Advanced Threat Protection Service' -Status 'Stopped' -IsMde $true -MdeOnboardingState $null
        $stock.Counted | Should -BeFalse
        $stock.Line | Should -Match 'not running, not counted'
        $runningNotOnboarded = Get-Np07AgentLine -Desc 'Defender for Endpoint' -DisplayName 'Sense' -Status 'Running' -IsMde $true -MdeOnboardingState 0
        $runningNotOnboarded.Counted | Should -BeFalse
        $runningNotOnboarded.Line | Should -Match 'not onboarded \(OnboardingState 0\)'
        (Get-Np07AgentLine -Desc 'Defender for Endpoint' -DisplayName 'Sense' -Status 'Running' -IsMde $true -MdeOnboardingState 1).Counted | Should -BeTrue
        (Get-Np07AgentLine -Desc 'CrowdStrike Falcon' -DisplayName 'CrowdStrike Falcon Sensor Service' -Status 'Stopped' -IsMde $false -MdeOnboardingState $null).Counted | Should -BeFalse
        (Get-Np07AgentLine -Desc 'CrowdStrike Falcon' -DisplayName 'CrowdStrike Falcon Sensor Service' -Status 'Running' -IsMde $false -MdeOnboardingState $null).Counted | Should -BeTrue
        $np07 = Get-Block -Text $script:Text -Start "'NP07' = @\{ Type='Local'" -End "'NP08' = @\{"
        $np07 | Should -Match 'if \(\$agent\.Counted\) \{ \$found = \$true \}'
        $np07 | Should -Match "-IsMde \(\`$svc\.Name -eq 'Sense'\)"
        @([regex]::Matches($np07, '\$found = \$true')).Count | Should -Be 1
    }
    It 'looks agents up by exact service name, not a wildcard that matches built-in services' {
        $np07 = Get-Block -Text $script:Text -Start "'NP07' = @\{ Type='Local'" -End "'NP08' = @\{"
        $np07 | Should -Match "Name='Sense'"
        $np07 | Should -Match "Name='CbDefense'"
        $np07 | Should -Match "Name='CSFalconService'"
        $np07 | Should -Not -Match "Name='cb\*'"
        $np07 | Should -Not -Match "Name='MsSense'"
        $lm06 = Get-Block -Text $script:Text -Start "'LM06' = @\{ Type='Local'" -End "'LM08' = @\{ Type='Local'"
        $lm06 | Should -Match "Get-Service -Name \`$f "
        $lm06 | Should -Not -Match "MsSense"
        $lm06 | Should -Not -Match 'Get-Service "\*\$f\*"'
    }
}

Describe 'NP02 listener classification (nested check helper via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-Np02PortAssessment' }, $true)[0]
        . ([scriptblock]::Create($fn.Extent.Text))
        function New-DefaultWorkstationListeners {
            @(
                @{ Protocol='TCP'; Address='0.0.0.0'; Port=135 }, @{ Protocol='TCP'; Address='::'; Port=135 },
                @{ Protocol='TCP'; Address='192.168.1.20'; Port=139 },
                @{ Protocol='TCP'; Address='0.0.0.0'; Port=445 }, @{ Protocol='TCP'; Address='::'; Port=445 },
                @{ Protocol='TCP'; Address='0.0.0.0'; Port=5985 }, @{ Protocol='TCP'; Address='0.0.0.0'; Port=49664 },
                @{ Protocol='TCP'; Address='127.0.0.1'; Port=5939 }
            )
        }
    }

    It 'never fails a default workstation on a private network' {
        $result = Get-Np02PortAssessment -Listeners (New-DefaultWorkstationListeners)
        $result.Status | Should -Be 'Pass'
        ($result.Info -join "`n") | Should -Match 'TCP 445 \(SMB\).*default Windows role port'
    }
    It 'never fails a default workstation on a public network with stock rules' {
        $rules = @(
            @{ Name='File and Printer Sharing (SMB-In)'; Profiles=3; Protocol='TCP'; LocalPorts=@('445'); Program='System' },
            @{ Name='Microsoft Teams'; Profiles=4; Protocol='TCP'; LocalPorts=@(); Program='C:\Program Files\Teams\ms-teams.exe' }
        )
        $result = Get-Np02PortAssessment -Listeners (New-DefaultWorkstationListeners) -PublicAddresses @('192.168.1.20') -PublicFirewallEnabled $true -Rules $rules
        $result.Status | Should -Not -Be 'Fail'
    }
    It 'fails a Telnet listener' {
        $listeners = @(New-DefaultWorkstationListeners) + @(@{ Protocol='TCP'; Address='0.0.0.0'; Port=23 })
        $result = Get-Np02PortAssessment -Listeners $listeners
        $result.Status | Should -Be 'Fail'
        ($result.Failures -join "`n") | Should -Match 'TCP 23 \(Telnet\)'
    }
    It 'fails SMB allowed inbound on the Public profile' {
        $rules = @(@{ Name='File and Printer Sharing (SMB-In)'; Profiles=4; Protocol='TCP'; LocalPorts=@('445'); Program='System' })
        $result = Get-Np02PortAssessment -Listeners (New-DefaultWorkstationListeners) -PublicAddresses @('192.168.1.20') -PublicFirewallEnabled $true -Rules $rules
        $result.Status | Should -Be 'Fail'
        ($result.Failures -join "`n") | Should -Match "TCP 445 \(SMB\) reachable from a Public-profile network via inbound rule 'File and Printer Sharing \(SMB-In\)'"
    }
    It 'maps the RPC-EPMap keyword to port 135 and fails when the Public firewall is off' {
        $rules = @(@{ Name='RPC Endpoint Mapper'; Profiles=0; Protocol='TCP'; LocalPorts=@('RPC-EPMap'); Program='' })
        $viaRule = Get-Np02PortAssessment -Listeners @(@{ Protocol='TCP'; Address='0.0.0.0'; Port=135 }) -PublicAddresses @('203.0.113.8') -PublicFirewallEnabled $true -Rules $rules
        $viaRule.Status | Should -Be 'Fail'
        (Get-Np02PortAssessment -Listeners (New-DefaultWorkstationListeners) -PublicAddresses @('192.168.1.20') -PublicFirewallEnabled $false).Status | Should -Be 'Fail'
    }
    It 'treats loopback-only insecure listeners as informational and RDP as review' {
        (Get-Np02PortAssessment -Listeners @(@{ Protocol='TCP'; Address='127.0.0.1'; Port=6379 })).Status | Should -Be 'Pass'
        (Get-Np02PortAssessment -Listeners @(@{ Protocol='TCP'; Address='0.0.0.0'; Port=3389 })).Status | Should -Be 'Partial'
    }
    It 'reports Partial when a public-bound role port cannot be checked against the firewall' {
        $result = Get-Np02PortAssessment -Listeners (New-DefaultWorkstationListeners) -PublicAddresses @('192.168.1.20') -FirewallError 'Access denied'
        $result.Status | Should -Be 'Partial'
        $known = Get-Np02PortAssessment -Listeners (New-DefaultWorkstationListeners) -PublicAddresses @('192.168.1.20') -PublicFirewallEnabled $true -FirewallError 'Access denied'
        $known.Status | Should -Be 'Partial'
        ($known.Reviews -join "`n") | Should -Match "firewall rules couldn't be read to confirm it's blocked"
    }
    It 'treats package, service and owner scoped any-port rules as closed to other programs' {
        $rules = @(
            @{ Name='Xbox Game Bar'; Action='Allow'; Profiles=0; Protocol='Any'; LocalPorts=@(); Program='Any'; Package='S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742' },
            @{ Name='Delivery Optimization (TCP-In)'; Action='Allow'; Profiles=0; Protocol='TCP'; LocalPorts=@(); Program='%SystemRoot%\system32\svchost.exe'; Service='DoSvc' },
            @{ Name='Per-user app'; Action='Allow'; Profiles=4; Protocol='TCP'; LocalPorts=@(); Owner='S-1-5-21-1-2-3-1001' }
        )
        $result = Get-Np02PortAssessment -Listeners (New-DefaultWorkstationListeners) -PublicAddresses @('192.168.1.20') -PublicFirewallEnabled $true -Rules $rules
        $result.Status | Should -Be 'Pass'
        $open = Get-Np02PortAssessment -Listeners (New-DefaultWorkstationListeners) -PublicAddresses @('192.168.1.20') -PublicFirewallEnabled $true -Rules @(@{ Name='Allow everything'; Action='Allow'; Profiles=4; Protocol='Any'; LocalPorts=@() })
        ($open.Failures -join "`n") | Should -Match "via inbound rule 'Allow everything'"
    }
    It 'lets an unscoped Block rule win over an Allow rule and default inbound Allow' {
        $smb = @(@{ Protocol='TCP'; Address='0.0.0.0'; Port=445 })
        $block = @{ Name='Block SMB on Public'; Action='Block'; Profiles=4; Protocol='TCP'; LocalPorts=@('445') }
        $allow = @{ Name='File and Printer Sharing (SMB-In)'; Action='Allow'; Profiles=4; Protocol='TCP'; LocalPorts=@('445'); Program='System' }
        (Get-Np02PortAssessment -Listeners $smb -PublicAddresses @('192.168.1.20') -PublicFirewallEnabled $true -Rules @($allow, $block)).Status | Should -Be 'Pass'
        (Get-Np02PortAssessment -Listeners $smb -PublicAddresses @('192.168.1.20') -PublicFirewallEnabled $true -PublicDefaultAllow $true -Rules @($block)).Status | Should -Be 'Pass'
    }
    It 'ignores Block rules scoped to one program, address range or interface' {
        $smb = @(@{ Protocol='TCP'; Address='0.0.0.0'; Port=445 })
        $allow = @{ Name='File and Printer Sharing (SMB-In)'; Action='Allow'; Profiles=4; Protocol='TCP'; LocalPorts=@('445'); Program='System' }
        foreach ($block in @(
            @{ Name='Block agent'; Action='Block'; Profiles=4; Protocol='TCP'; LocalPorts=@('445'); Program='C:\Tools\agent.exe' },
            @{ Name='Block 10/8'; Action='Block'; Profiles=4; Protocol='TCP'; LocalPorts=@('445'); RemoteAddresses=@('10.0.0.0/8') },
            @{ Name='Block on one address'; Action='Block'; Profiles=4; Protocol='TCP'; LocalPorts=@('445'); LocalAddresses=@('10.1.1.5') },
            @{ Name='Block on Wi-Fi'; Action='Block'; Profiles=4; Protocol='TCP'; LocalPorts=@('445'); InterfaceScoped=$true }
        )) {
            (Get-Np02PortAssessment -Listeners $smb -PublicAddresses @('192.168.1.20') -PublicFirewallEnabled $true -Rules @($allow, $block)).Status | Should -Be 'Fail'
        }
    }
    It 'fails when the Public profile is off or defaults to Allow even though rules are unreadable' {
        $off = Get-Np02PortAssessment -Listeners (New-DefaultWorkstationListeners) -PublicAddresses @('192.168.1.20') -PublicFirewallEnabled $false -FirewallError 'Access is denied.'
        $off.Status | Should -Be 'Fail'
        ($off.Failures -join "`n") | Should -Match 'the Public firewall profile being off'
        (Get-Np02PortAssessment -Listeners @(@{ Protocol='TCP'; Address='0.0.0.0'; Port=445 }) -PublicAddresses @('192.168.1.20') -PublicFirewallEnabled $true -PublicDefaultAllow $true -FirewallError 'Access is denied.').Status | Should -Be 'Fail'
    }
    It 'reports Partial when network categories cannot be read' {
        $result = Get-Np02PortAssessment -Listeners (New-DefaultWorkstationListeners) -NetworkProfileError 'Invalid class'
        $result.Status | Should -Be 'Partial'
        ($result.Reviews -join "`n") | Should -Match "network categories couldn't be read"
    }
    It 'reads the firewall from the active store with each read failing on its own' {
        $block = Get-Block -Text $script:Text -Start "'NP02' = @\{ Type='Local'" -End "'NP03' = @\{"
        $block | Should -Match 'Get-NetFirewallProfile -Name Public -PolicyStore ActiveStore'
        $block | Should -Match 'Get-NetFirewallRule -Enabled True -Direction Inbound -PolicyStore ActiveStore'
        $block | Should -Match 'Get-NetFirewallServiceFilter -All -PolicyStore ActiveStore'
        $block | Should -Match '\$fwProfileError = '
        $block | Should -Match '\$netProfileError = '
    }
}

Describe 'NP01, NP05 and NP06 read the active store (nested check helper via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-Np01AnyAnyRules' }, $true)[0]
        . ([scriptblock]::Create($fn.Extent.Text))
    }

    It 'counts an unscoped inbound allow as any/any, but not one tied to a program, package, service or user' {
        $rules = @(
            @{ Name='Wide open'; Direction='Inbound'; Action='Allow'; LocalPorts=@('Any'); RemoteAddresses=@('Any'); Program='Any' },
            @{ Name='Google Chrome (mDNS-In)'; Direction='Inbound'; Action='Allow'; LocalPorts=@('Any'); RemoteAddresses=@('Any'); Program='C:\Program Files\Google\Chrome\Application\chrome.exe' },
            @{ Name='Xbox Game Bar'; Direction='Inbound'; Action='Allow'; LocalPorts=@(); RemoteAddresses=@(); Program='Any'; Package='S-1-15-2-1861897761' },
            @{ Name='Delivery Optimization (TCP-In)'; Direction='Inbound'; Action='Allow'; LocalPorts=@(); RemoteAddresses=@(); Service='DoSvc' },
            @{ Name='Per-user app'; Direction='Inbound'; Action='Allow'; LocalPorts=@(); RemoteAddresses=@(); Owner='S-1-5-21-1-2-3-1001' },
            @{ Name='RDP'; Direction='Inbound'; Action='Allow'; LocalPorts=@('3389'); RemoteAddresses=@('Any') },
            @{ Name='LAN only'; Direction='Inbound'; Action='Allow'; LocalPorts=@('Any'); RemoteAddresses=@('LocalSubnet') },
            @{ Name='Block all'; Direction='Inbound'; Action='Block'; LocalPorts=@('Any'); RemoteAddresses=@('Any') }
        )
        @((Get-Np01AnyAnyRules -Rules $rules).Name) | Should -Be @('Wide open')
    }
    It 'reads rules and profiles from ActiveStore in all three checks' {
        $np01 = Get-Block -Text $script:Text -Start "'NP01' = @\{ Type='Local'" -End "'IA07' = @\{ Type='AD'"
        $np01 | Should -Match 'Get-NetFirewallRule -Enabled True -PolicyStore ActiveStore -EA Stop'
        $np01 | Should -Match 'Get-NetFirewallPortFilter -All -PolicyStore ActiveStore'
        $np01 | Should -Match 'Get-NetFirewallApplicationFilter -All -PolicyStore ActiveStore'
        $np01 | Should -Not -Match '\$r \| Get-NetFirewallPortFilter'
        # A standard user can't read filters; that's Partial, not a silent pass.
        $np01 | Should -Match "if \(\`$filterError\) \{\s+\`$issues\+\+"
        $np05 = Get-Block -Text $script:Text -Start "'NP05' = @\{ Type='Local'" -End "'NP06' = @\{ Type='Local'"
        $np05 | Should -Match 'Get-NetFirewallProfile -PolicyStore ActiveStore -EA Stop'
        $np05 | Should -Match 'Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True -PolicyStore ActiveStore'
        $np06 = Get-Block -Text $script:Text -Start "'NP06' = @\{ Type='Local'" -End "'NP07' = @\{ Type='Local'"
        $np06 | Should -Match 'Get-NetFirewallRule -Enabled True -PolicyStore ActiveStore -EA Stop'
    }
}

Describe 'IA03 MFA agents (nested check helper via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-Ia03MfaAgent' }, $true)[0]
        . ([scriptblock]::Create($fn.Extent.Text))
    }
    It 'ignores programs whose names only contain an agent name' {
        foreach ($name in 'Microsoft Visual C++ 2015-2022 Universal CRT','Microsoft Visual C++ Universal CRT','Snipping Tool','Duolingo','Thales Display Driver') {
            Get-Ia03MfaAgent $name | Should -BeNullOrEmpty -Because "$name isn't an MFA agent"
        }
    }
    It 'names the agent for whole product names' {
        Get-Ia03MfaAgent 'Duo Authentication for Windows Logon x64' | Should -Be 'Duo Security'
        Get-Ia03MfaAgent 'Okta Verify' | Should -Be 'Okta Verify'
        Get-Ia03MfaAgent 'YubiKey Manager' | Should -Be 'YubiKey'
        Get-Ia03MfaAgent 'NPS Extension For Azure MFA' | Should -Be 'Azure AD MFA'
    }
    It 'runs as a Local check so a workgroup host gets it' {
        $script:Text | Should -Match "'IA03' = @\{ Type='Local'"
        $script:Text | Should -Match "'IA09' = @\{ Type='Local'"
    }
}

Describe 'NP06 stale-rule indicators (nested check helpers via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        foreach ($nm in 'Get-Np06StaleIndicator','Test-Np06DatePattern') {
            $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $nm }, $true)[0]
            . ([scriptblock]::Create($fn.Extent.Text))
        }
    }
    It 'matches indicators on whole words, not inside other words' {
        foreach ($name in 'Droplet Template','Google Chrome for Testing','Folder Sync','Hold Music Server','Contoso Backup Agent','Vendor Portal') {
            Get-Np06StaleIndicator $name | Should -BeNullOrEmpty -Because "$name isn't stale"
        }
        Get-Np06StaleIndicator 'TEMP vendor access' | Should -Be 'temp'
        Get-Np06StaleIndicator 'tmp_rdp_rule' | Should -Be 'tmp'
        Get-Np06StaleIndicator 'Copy of Remote Desktop' | Should -Be 'copy of'
        Get-Np06StaleIndicator 'Old SQL port' | Should -Be 'old'
        Get-Np06StaleIndicator 'Remove after go-live' | Should -Be 'remove'
    }
    It 'flags a dated rule name the way the app does' {
        Test-Np06DatePattern 'Allow vendor 2024-03-01' | Should -BeTrue
        Test-Np06DatePattern 'Build 20240301' | Should -BeFalse
        Test-Np06DatePattern 'Port 1999-2000 range' | Should -BeFalse
    }
    It 'caps stale rules at Partial and leaves the rule count unscored, as the app does' {
        $np06 = Get-Block -Text $script:Text -Start "'NP06' = @\{ Type='Local'" -End "'NP07' = @\{ Type='Local'"
        $np06 | Should -Match "\`$status = if \(\`$staleRules.Count -eq 0\) \{'Pass'\} else \{'Partial'\}"
        $np06 | Should -Not -Match "'Fail'"
    }
}

Describe 'EP06 listener findings (nested check helpers via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        $script:Ep06Block = Get-Block -Text $script:Text -Start "'EP06' = @\{ Type='Local'" -End "'EP09' = @\{ Type='Local'"
        $script:HelperDefs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in @('Get-Np02PortAssessment','Get-Np02ExposureInputs') }, $true))
        . ([scriptblock]::Create(@($script:HelperDefs | Where-Object Name -eq 'Get-Np02PortAssessment')[0].Extent.Text))
        $script:StockListeners = @(
            @{ Protocol='TCP'; Address='0.0.0.0'; Port=135 }, @{ Protocol='TCP'; Address='::'; Port=135 },
            @{ Protocol='TCP'; Address='192.168.1.20'; Port=139 },
            @{ Protocol='TCP'; Address='0.0.0.0'; Port=445 }, @{ Protocol='TCP'; Address='::'; Port=445 },
            @{ Protocol='TCP'; Address='0.0.0.0'; Port=5985 }, @{ Protocol='TCP'; Address='0.0.0.0'; Port=49664 },
            @{ Protocol='TCP'; Address='127.0.0.1'; Port=5939 }
        )
    }

    It 'carries verbatim copies of both NP02 helpers' {
        foreach ($name in @('Get-Np02PortAssessment','Get-Np02ExposureInputs')) {
            $defs = @($script:HelperDefs | Where-Object Name -eq $name)
            $defs.Count | Should -Be 2
            $defs[0].Extent.Text | Should -BeExactly $defs[1].Extent.Text
            $script:Ep06Block | Should -Match "function $name \{"
        }
    }
    It 'lists default role ports on a stock workstation without raising anything' {
        $result = Get-Np02PortAssessment -Listeners $script:StockListeners
        @($result.Failures).Count | Should -Be 0
        @($result.Reviews).Count | Should -Be 0
        ($result.Info -join "`n") | Should -Match 'TCP 445 \(SMB\) on 0\.0\.0\.0 \(all interfaces\), :: \(all interfaces\); default Windows role port, not exposed'
    }
    It 'fails an insecure listener and reviews a sensitive one, but not on loopback' {
        $listeners = $script:StockListeners + @(
            @{ Protocol='TCP'; Address='0.0.0.0'; Port=23 },
            @{ Protocol='TCP'; Address='10.0.0.5'; Port=3389 },
            @{ Protocol='TCP'; Address='127.0.0.1'; Port=6379 }
        )
        $result = Get-Np02PortAssessment -Listeners $listeners
        @($result.Failures) | Should -Be @('TCP 23 (Telnet) listening on 0.0.0.0 (all interfaces)')
        @($result.Reviews) | Should -Be @('TCP 3389 (RDP) listening on 10.0.0.5')
        ($result.Info -join "`n") | Should -Match 'TCP 6379 \(Redis \(no auth by default\)\) on loopback only'
    }
    It 'fails SMB that a Public-profile network can reach, the same as the app' {
        $result = Get-Np02PortAssessment -Listeners $script:StockListeners -PublicAddresses @('203.0.113.7') -PublicFirewallEnabled $false
        ($result.Failures -join "`n") | Should -Match 'TCP 445 \(SMB\) reachable from a Public-profile network via the Public firewall profile being off'
    }
    It 'reads listeners through Get-NetTCPConnection and exposure through the shared helpers' {
        $script:Ep06Block | Should -Match 'Get-NetTCPConnection -State Listen'
        $script:Ep06Block | Should -Not -Match 'netstat'
        $script:Ep06Block | Should -Not -Match 'Get-Ep06ListenerFindings'
        $script:Ep06Block | Should -Match '\$x = Get-Np02ExposureInputs'
        $script:Ep06Block | Should -Match '\$ports = Get-Np02PortAssessment -Listeners \$endpoints @x'
        $script:Ep06Block | Should -Match "if \(\`$ports -and \`$ports.Failures.Count\) \{'Fail'\}"
    }
    It "doesn't pass when the listeners can't be read" {
        $script:Ep06Block | Should -Match "\`$listenerError = \`$_.Exception.Message.Trim\(\)"
        $script:Ep06Block | Should -Match "elseif \(\`$issues -eq 0 -and -not \`$listenerError -and"
    }
}

Describe 'Privileged groups by SID with nested membership (IA01, IA02, CF04 nested helpers via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        $script:SidHelperNames = @('Get-NsaWellKnownGroupSid', 'Expand-NsaGroupMember')
        $script:SidHelperDefs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in @('Get-NsaWellKnownGroupSid', 'Expand-NsaGroupMember') }, $true))
        foreach ($name in $script:SidHelperNames) {
            . ([scriptblock]::Create(@($script:SidHelperDefs | Where-Object Name -eq $name)[0].Extent.Text))
        }
        $script:Ia01Block = Get-Block -Text $script:Text -Start "'IA01' = @\{ Type='AD'" -End "'IA02' = @\{ Type='AD'"
        $script:Ia02Block = Get-Block -Text $script:Text -Start "'IA02' = @\{ Type='AD'" -End "'IA04' = @\{ Type='AD'"
        $script:Cf04Block = Get-Block -Text $script:Text -Start "'CF04' = @\{ Type='AD'" -End "'CF06' = @\{ Type='Local'"
        $script:DomainSid = 'S-1-5-21-1004336348-1177238915-682003330'
        # A German domain names Domain Admins "Domaenen-Admins" (with an a-umlaut); the test file stays ASCII.
        $script:German = "Dom$([char]0x00E4)nen-Admins"
        function New-Member([string]$Dn, [string]$Sam, [string]$Class = 'user') {
            @{ DistinguishedName = $Dn; SamAccountName = $Sam; objectClass = $Class }
        }
    }

    It 'carries identical copies of the shared helpers in IA01, IA02 and CF04' {
        foreach ($name in $script:SidHelperNames) {
            $defs = @($script:SidHelperDefs | Where-Object Name -eq $name)
            $defs.Count | Should -Be 3
            foreach ($def in $defs) { $def.Extent.Text | Should -BeExactly $defs[0].Extent.Text }
            foreach ($block in @($script:Ia01Block, $script:Ia02Block, $script:Cf04Block)) { $block | Should -Match "function $name \{" }
        }
    }
    It 'builds domain, forest root and builtin group SIDs from the RID' {
        $root = 'S-1-5-21-111-222-333'
        (Get-NsaWellKnownGroupSid -Key 'DomainAdmins' -DomainSid $script:DomainSid).Sid | Should -Be "$($script:DomainSid)-512"
        $ea = Get-NsaWellKnownGroupSid -Key 'EnterpriseAdmins' -DomainSid $script:DomainSid -RootSid $root
        $ea.Sid | Should -Be "$root-519"
        $ea.InRoot | Should -BeTrue
        (Get-NsaWellKnownGroupSid -Key 'SchemaAdmins' -DomainSid $script:DomainSid).Sid | Should -Be "$($script:DomainSid)-518"
        (Get-NsaWellKnownGroupSid -Key 'Administrators' -DomainSid $script:DomainSid).Sid | Should -Be 'S-1-5-32-544'
        (Get-NsaWellKnownGroupSid -Key 'BackupOperators' -DomainSid $script:DomainSid).Sid | Should -Be 'S-1-5-32-551'
        (Get-NsaWellKnownGroupSid -Key 'ProtectedUsers' -DomainSid $script:DomainSid).Sid | Should -Be "$($script:DomainSid)-525"
        { Get-NsaWellKnownGroupSid -Key 'NoSuchGroup' -DomainSid $script:DomainSid } | Should -Throw
    }
    It 'walks nested groups once each and gives every member the path it came through' {
        $tree = @{
            'CN=DA'  = @((New-Member 'CN=Administrator' 'Administrator'), (New-Member 'CN=Ops' 'Tier0-Ops' 'group'))
            'CN=Ops' = @((New-Member 'CN=Alice' 'alice'), (New-Member 'CN=DA' $script:German 'group'), (New-Member 'CN=Administrator' 'Administrator'))
        }
        $get = { param($dn) $tree[$dn] }.GetNewClosure()
        $members = @(Expand-NsaGroupMember -GroupDn 'CN=DA' -GroupName $script:German -GetMember $get)
        $members.Count | Should -Be 3
        $members[0].Path | Should -Be "$($script:German) > Administrator"
        $members[0].Nested | Should -BeFalse
        $members[1].IsGroup | Should -BeTrue
        $members[2].Path | Should -Be "$($script:German) > Tier0-Ops > alice"
        $members[2].Nested | Should -BeTrue
        @(Expand-NsaGroupMember -GroupDn 'CN=Empty' -GroupName 'Schema Admins' -GetMember $get).Count | Should -Be 0
    }
    It 'notes a nested group it cannot read, but fails when the privileged group itself cannot be read' {
        $ops = New-Member 'CN=Ops' 'Tier0-Ops' 'group'
        $get = { param($dn) if ($dn -eq 'CN=Ops') { throw 'Access is denied.' } else { $ops } }.GetNewClosure()
        $members = @(Expand-NsaGroupMember -GroupDn 'CN=DA' -GroupName 'Domain Admins' -GetMember $get)
        $members.Count | Should -Be 1
        $members[0].Note | Should -Match 'Access is denied'
        { Expand-NsaGroupMember -GroupDn 'CN=Ops' -GroupName 'Tier0-Ops' -GetMember $get } | Should -Throw '*Access is denied*'
    }
    It 'finds the IA01, IA02 and CF04 groups by SID instead of by English name' {
        $script:Ia01Block | Should -Not -Match 'Get-ADGroupMember \$g -Recursive'
        $script:Ia01Block | Should -Not -Match "Get-ADGroupMember 'Protected Users'"
        $script:Ia01Block | Should -Match "foreach \(\`$key in @\('DomainAdmins','EnterpriseAdmins','SchemaAdmins','Administrators'\)\)"
        $script:Ia01Block | Should -Match 'Get-ADGroup -Identity \$spec\.Sid -Server \$server -EA Stop'
        $script:Ia01Block | Should -Match 'Get-ADGroupMember -Identity \$protectedSpec\.Sid'
        $script:Ia02Block | Should -Not -Match "-match 'Domain Admins'"
        $script:Ia02Block | Should -Match "Get-NsaWellKnownGroupSid -Key 'DomainAdmins'"
        $script:Cf04Block | Should -Not -Match '\$privGroups'
        $script:Cf04Block | Should -Match 'Get-ADGroup -Identity \$spec\.Sid -Server \$server -EA Stop'
    }
}

Describe 'Accounts every domain has are not findings (IA02, IA07, CF04 nested helpers via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        $script:QuietNames = @('Get-NsaSidRid', 'Select-Ia02ServiceAccount', 'Select-Ia07SharedAccount', 'Test-Cf04StaleAccount')
        $script:QuietDefs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in @('Get-NsaSidRid', 'Select-Ia02ServiceAccount', 'Select-Ia07SharedAccount', 'Test-Cf04StaleAccount') }, $true))
        foreach ($name in $script:QuietNames) {
            . ([scriptblock]::Create(@($script:QuietDefs | Where-Object Name -eq $name)[0].Extent.Text))
        }
        $script:Ia02Block = Get-Block -Text $script:Text -Start "'IA02' = @\{ Type='AD'" -End "'IA04' = @\{ Type='AD'"
        $script:Ia07Block = Get-Block -Text $script:Text -Start "'IA07' = @\{ Type='AD'" -End "'IA08' = @\{ Type='AD'"
        $script:Cf04Block = Get-Block -Text $script:Text -Start "'CF04' = @\{ Type='AD'" -End "'CF06' = @\{ Type='Local'"
        $script:DomainSid = 'S-1-5-21-1004336348-1177238915-682003330'
        function New-Account([string]$Sam, [int]$Rid, $Enabled = $true, [string]$Sid = '') {
            if (-not $Sid) { $Sid = "$($script:DomainSid)-$Rid" }
            [pscustomobject]@{ SamAccountName = $Sam; DistinguishedName = "CN=$Sam,CN=Users,DC=corp,DC=example"; SID = $Sid; Enabled = $Enabled }
        }
    }

    It 'carries identical copies of Get-NsaSidRid in IA02 and IA07 and one copy of each selector' {
        $rid = @($script:QuietDefs | Where-Object Name -eq 'Get-NsaSidRid')
        $rid.Count | Should -Be 2
        $rid[1].Extent.Text | Should -BeExactly $rid[0].Extent.Text
        foreach ($name in @('Select-Ia02ServiceAccount', 'Select-Ia07SharedAccount', 'Test-Cf04StaleAccount')) {
            @($script:QuietDefs | Where-Object Name -eq $name).Count | Should -Be 1
        }
        $script:Ia02Block | Should -Match 'function Select-Ia02ServiceAccount \{'
        $script:Ia07Block | Should -Match 'function Select-Ia07SharedAccount \{'
        $script:Cf04Block | Should -Match 'function Test-Cf04StaleAccount \{'
    }
    It 'reads the RID only from a SID in this domain' {
        Get-NsaSidRid -Sid "$($script:DomainSid)-502" -DomainSid $script:DomainSid | Should -Be 502
        Get-NsaSidRid -Sid "$($script:DomainSid)-500" -DomainSid $script:DomainSid | Should -Be 500
        Get-NsaSidRid -Sid 'S-1-5-21-111-222-333-500' -DomainSid $script:DomainSid | Should -Be -1
        Get-NsaSidRid -Sid "$($script:DomainSid)5-500" -DomainSid $script:DomainSid | Should -Be -1
        Get-NsaSidRid -Sid 'S-1-5-32-544' -DomainSid $script:DomainSid | Should -Be -1
        Get-NsaSidRid -Sid '' -DomainSid $script:DomainSid | Should -Be -1
        Get-NsaSidRid -Sid "$($script:DomainSid)-500" -DomainSid '' | Should -Be -1
    }
    It 'IA02 leaves out krbtgt and disabled SPN accounts, and counts an account in both searches once' {
        $krbtgt = New-Account 'krbtgt' 502 $false
        $legacy = New-Account 'legacy.web' 1107 $false
        $clean = Select-Ia02ServiceAccount -Accounts @($krbtgt, $legacy) -DomainSid $script:DomainSid
        @($clean.Accounts).Count | Should -Be 0
        @($clean.Skipped).Count | Should -Be 2
        ($clean.Skipped | Where-Object { $_.Account.SamAccountName -eq 'krbtgt' }).Reason | Should -Be 'KDC account (RID 502)'
        ($clean.Skipped | Where-Object { $_.Account.SamAccountName -eq 'legacy.web' }).Reason | Should -Be 'disabled'

        $sql = New-Account 'svc_sql' 1105
        $unknown = New-Account 'svc_backup' 1106 $null
        $mixed = Select-Ia02ServiceAccount -Accounts @($krbtgt, $sql, $null, $sql, $unknown) -DomainSid $script:DomainSid
        @($mixed.Accounts | ForEach-Object SamAccountName) | Should -Be @('svc_sql', 'svc_backup')
        @($mixed.Skipped).Count | Should -Be 1
    }
    It 'IA07 leaves out the built-in Administrator by RID 500 whatever it is called, and counts each account once' {
        $renamed = New-Account 'corp-admin' 500
        $lookalike = New-Account 'Administrator' 1105
        $frontdesk = New-Account 'frontdesk' 1110
        $picked = Select-Ia07SharedAccount -Accounts @($renamed, $lookalike, $frontdesk, $frontdesk) -DomainSid $script:DomainSid
        @($picked.Accounts | ForEach-Object SamAccountName) | Should -Be @('Administrator', 'frontdesk')
        $picked.BuiltinAdmin.SamAccountName | Should -Be 'corp-admin'

        $clean = Select-Ia07SharedAccount -Accounts @($renamed, $renamed) -DomainSid $script:DomainSid
        @($clean.Accounts).Count | Should -Be 0

        $otherDomain = New-Account 'Administrator' 500 $true 'S-1-5-21-111-222-333-500'
        @((Select-Ia07SharedAccount -Accounts @($otherDomain) -DomainSid $script:DomainSid).Accounts).Count | Should -Be 1
        $noSid = Select-Ia07SharedAccount -Accounts @($renamed) -DomainSid ''
        @($noSid.Accounts).Count | Should -Be 1
        $noSid.BuiltinAdmin | Should -BeNullOrEmpty
    }
    It 'CF04 counts a never-used account as stale only when it was created before the threshold' {
        $now = Get-Date
        $threshold = $now.AddDays(-90)
        Test-Cf04StaleAccount -LastLogon $now.AddDays(-200) -Created $now.AddDays(-900) -Threshold $threshold | Should -BeTrue
        Test-Cf04StaleAccount -LastLogon $now.AddDays(-1) -Created $now.AddDays(-900) -Threshold $threshold | Should -BeFalse
        Test-Cf04StaleAccount -LastLogon $null -Created $now.AddDays(-7) -Threshold $threshold | Should -BeFalse
        Test-Cf04StaleAccount -LastLogon $null -Created $now.AddDays(-200) -Threshold $threshold | Should -BeTrue
        Test-Cf04StaleAccount -LastLogon $null -Created $null -Threshold $threshold | Should -BeTrue
    }
    It 'wires the selectors into the IA02, IA07 and CF04 blocks' {
        $script:Ia02Block | Should -Not -Match 'Sort-Object -Property SamAccountName -Unique'
        $script:Ia02Block | Should -Match '\$selection = Select-Ia02ServiceAccount -Accounts'
        $script:Ia02Block | Should -Match 'foreach \(\$s in \$selection\.Skipped\)'
        $script:Ia07Block | Should -Not -Match '\$found\+\+'
        $script:Ia07Block | Should -Match '\$selection = Select-Ia07SharedAccount -Accounts'
        $script:Ia07Block | Should -Match '\$found = \$selection\.Accounts\.Count'
        $script:Cf04Block | Should -Match '-Properties LastLogonDate,WhenCreated,'
        $script:Cf04Block | Should -Match 'Test-Cf04StaleAccount -LastLogon \$_\.LastLogonDate -Created \$_\.WhenCreated'
        $script:Cf04Block | Should -Not -Match 'Last: \$\(\$sp\.Last\.ToString'
        $script:Cf04Block | Should -Not -Match 'Last: \$\(\$sr\.LastLogonDate\.ToString'
    }
}

Describe 'IA06 LAPS coverage (nested check helper via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-Ia06LapsCoverage' }, $true)[0]
        . ([scriptblock]::Create($fn.Extent.Text))
        function New-Fleet([int]$Windows, [int]$Legacy, [int]$Both, [int]$None) {
            $n = 0; $list = @()
            foreach ($spec in @(@($Windows, $true, $false), @($Legacy, $false, $true), @($Both, $true, $true), @($None, $false, $false))) {
                for ($i = 0; $i -lt $spec[0]; $i++) { $n++; $list += @{ DN="CN=PC$n,OU=Workstations,DC=corp,DC=example"; WindowsLaps=$spec[1]; LegacyLaps=$spec[2] } }
            }
            , $list
        }
    }

    It 'counts the union by distinguished name instead of the larger of the two counts' {
        $result = Get-Ia06LapsCoverage -Computers (New-Fleet -Windows 50 -Legacy 45 -Both 0 -None 5) -WindowsSchema $true -LegacySchema $true
        $result.Covered | Should -Be 95
        $result.Outcome | Should -Be 'Covered'
        $low = Get-Ia06LapsCoverage -Computers (New-Fleet -Windows 5 -Legacy 4 -Both 2 -None 9) -WindowsSchema $true -LegacySchema $true
        $low.Covered | Should -Be 11
        $low.Outcome | Should -Be 'Low'
    }
    It 'counts one computer once when it shows up twice with different casing' {
        $computers = @(@{ DN='CN=PC1,DC=corp,DC=example'; WindowsLaps=$true; LegacyLaps=$false }, @{ DN='cn=pc1,dc=corp,dc=example'; WindowsLaps=$false; LegacyLaps=$true })
        $result = Get-Ia06LapsCoverage -Computers $computers -WindowsSchema $true -LegacySchema $true
        $result.Total | Should -Be 1
        $result.Covered | Should -Be 1
    }
    It 'keeps schema-absent, access-denied and zero coverage apart' {
        (Get-Ia06LapsCoverage -Computers (New-Fleet 0 0 0 12) -WindowsSchema $false -LegacySchema $false).Outcome | Should -Be 'SchemaAbsent'
        $denied = Get-Ia06LapsCoverage -SearchError 'Insufficient access rights to perform the operation.' -SearchAccessDenied $true
        $denied.Outcome | Should -Be 'Unreadable'
        ($denied.Lines -join "`n") | Should -Match 'needs Read on computer objects'
        (Get-Ia06LapsCoverage -Computers (New-Fleet 0 0 0 30) -WindowsSchema $true -LegacySchema $true).Outcome | Should -Be 'None'
    }
    It 'treats zero coverage as unreadable when this computer backs up LAPS to AD' {
        $result = Get-Ia06LapsCoverage -Computers (New-Fleet 0 0 0 30) -WindowsSchema $true -LegacySchema $true -LocalBackupDirectory 2
        $result.Outcome | Should -Be 'Unreadable'
        ($result.Lines -join "`n") | Should -Match 'Read Property on msLAPS-PasswordExpirationTime and ms-Mcs-AdmPwdExpirationTime'
        (Get-Ia06LapsCoverage -Computers (New-Fleet 0 0 0 30) -WindowsSchema $true -LegacySchema $true -LocalLegacyEnabled $true).Outcome | Should -Be 'Unreadable'
        (Get-Ia06LapsCoverage -Computers (New-Fleet 0 0 0 30) -WindowsSchema $true -LegacySchema $true -LocalBackupDirectory 1).Outcome | Should -Be 'None'
    }
    It 'reports no member computers separately' {
        (Get-Ia06LapsCoverage -Computers @() -WindowsSchema $true -LegacySchema $false).Outcome | Should -Be 'NoComputers'
    }
    It 'never measures coverage from the confidential password attributes' {
        $block = Get-Block -Text $script:Text -Start "'IA06' = @\{ Type='AD'" -End "'IA09' = @\{"
        $block | Should -Not -Match "Where-Object \{ \`$_\.'msLAPS-EncryptedPassword' \}"
        $block | Should -Not -Match "Where-Object \{ \`$_\.'ms-Mcs-AdmPwd' \}"
        $block | Should -Not -Match '\[math\]::Max'
        $block | Should -Match 'primaryGroupID=521'
        $block | Should -Match "if \(\`$lapsUnassessed -and \`$issues -eq 0\) \{ \`$status = 'Not Assessed' \}"
        # E_ACCESSDENIED and LDAP insufficient access rights (0x80072098), matching IA06_PamCheck.IsAccessDenied
        $block | Should -Match 'HResult -in @\(-2147024891, -2147016552'
    }
}

Describe 'EP01 primary antivirus decision (nested check helper via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-Ep01PrimaryAv' }, $true)[0]
        . ([scriptblock]::Create($fn.Extent.Text))
    }

    It 'treats an active third-party AV as primary when Defender is passive' {
        $result = Get-Ep01PrimaryAv -AntivirusEnabled $true -RealTimeProtectionEnabled $false -AmRunningMode 'Passive Mode' -Products @(@{ Name='Windows Defender'; State=0x060100 }, @{ Name='Sophos Anti-Virus'; State=0x041000 })
        $result.ThirdPartyPrimary | Should -BeTrue
        $result.ActiveThirdParty | Should -Be @('Sophos Anti-Virus')
    }
    It 'keeps Defender primary in normal mode' {
        $result = Get-Ep01PrimaryAv -AntivirusEnabled $true -RealTimeProtectionEnabled $true -AmRunningMode 'Normal' -Products @(@{ Name='Windows Defender'; State=0x061100 })
        $result.DefenderPrimary | Should -BeTrue
        $result.ThirdPartyPrimary | Should -BeFalse
    }
    It 'does not credit a registered but disabled third-party AV' {
        $result = Get-Ep01PrimaryAv -AntivirusEnabled $false -RealTimeProtectionEnabled $false -AmRunningMode 'Not running' -Products @(@{ Name='Sophos Anti-Virus'; State=0x040100 })
        $result.ThirdPartyPrimary | Should -BeFalse
    }
    It 'flags out-of-date third-party signatures the way the app does' {
        $stale = Get-Ep01PrimaryAv -AntivirusEnabled $true -RealTimeProtectionEnabled $false -AmRunningMode 'Passive Mode' -Products @(@{ Name='Windows Defender'; State=0x060100 }, @{ Name='Sophos Anti-Virus'; State=0x041010 })
        $stale.ThirdPartyPrimary | Should -BeTrue
        @($stale.StaleThirdParty) | Should -Be @('Sophos Anti-Virus')
        @((Get-Ep01PrimaryAv -AntivirusEnabled $true -RealTimeProtectionEnabled $false -AmRunningMode 'Passive Mode' -Products @(@{ Name='Sophos Anti-Virus'; State=0x041000 })).StaleThirdParty).Count | Should -Be 0
    }
    It 'counts tamper protection only when Defender is the primary engine' {
        $block = Get-Block -Text $script:Text -Start "'EP01' = @\{ Type='Local'" -End "'EP02' = @\{"
        $block | Should -Match "IsTamperProtected -and \`$thirdPartyPrimary"
        $block | Should -Match 'StaleThirdParty\.Count -gt 0\) \{ .*\$warnings\+\+'
    }
    It 'requires OnboardingState 1 before reporting Defender for Endpoint as onboarded' {
        $block = Get-Block -Text $script:Text -Start "'EP01' = @\{ Type='Local'" -End "'EP02' = @\{"
        $block | Should -Match "Status -eq 'Running' -and \`$mdeOnboarding -eq 1"
    }
}

Describe 'EP10 lifecycle evaluation (nested check helpers via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        foreach ($nm in @('Get-Ep10LifecycleTable','Get-Ep10EsuYears','Find-Ep10Release','Get-Ep10Verdict','ConvertTo-Ep10SqlProduct','ConvertTo-Ep10OfficeProduct','ConvertTo-Ep10ExchangeProduct')) {
            $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $nm }, $true)[0]
            . ([scriptblock]::Create($fn.Extent.Text))
        }
        $table = Get-Ep10LifecycleTable
        $today = [datetime]'2026-09-30'
    }

    It 'finds the release by caption, build and edition' {
        (Find-Ep10Release -Table $table -Caption 'Microsoft Windows 11 Pro' -Build 26200).Key | Should -Be 'win11-25h2-homepro'
        (Find-Ep10Release -Table $table -Caption 'Microsoft Windows 11 Education' -Build 22631).Key | Should -Be 'win11-23h2-ent'
        (Find-Ep10Release -Table $table -Caption 'Microsoft Windows 10 Enterprise LTSC' -Build 19044).Key | Should -Be 'win10-ltsc2021'
        (Find-Ep10Release -Table $table -Caption 'Windows 10 Enterprise' -Build 19044).Key | Should -Be 'win10-older'
        (Find-Ep10Release -Table $table -Caption 'Microsoft Windows 10 Enterprise 2015 LTSB' -Build 10240).Key | Should -Be 'win10-ltsb2015'
        (Find-Ep10Release -Table $table -Caption 'Microsoft Windows 10 IoT Enterprise 2015 LTSB' -Build 10240).Key | Should -Be 'win10-ltsb2015-iot'
        (Find-Ep10Release -Table $table -Caption 'Microsoft Windows Server 2012 R2 Standard' -Build 9600).Key | Should -Be 'server2012r2'
        Find-Ep10Release -Table $table -Caption 'Microsoft Windows 11 Pro' -Build 28000 | Should -BeNullOrEmpty
        Find-Ep10Release -Table $table -Caption 'Microsoft Windows 10 Enterprise LTSC' -Build 20348 | Should -BeNullOrEmpty
    }
    It 'reports ESU-enrolled Windows 10 as covered, not supported' {
        $win10 = Find-Ep10Release -Table $table -Caption 'Microsoft Windows 10 Pro' -Build 19045
        $covered = Get-Ep10Verdict -Entry $win10 -Today $today -Esu 'Enrolled' -EsuCoversUntil '2026-10-13'
        $covered.State | Should -Be 'EsuCovered'
        $covered.Text | Should -Be 'Windows 10 22H2: past end of support (2025-10-14), covered by Extended Security Updates until 2026-10-13'
        (Get-Ep10Verdict -Entry $win10 -Today $today -Esu 'Unknown').State | Should -Be 'EsuEligible'
        $ended = Get-Ep10Verdict -Entry $win10 -Today $today -Esu 'NotEnrolled'
        $ended.State | Should -Be 'EndOfSupport'
        $ended.Text | Should -Be 'Windows 10 22H2: end of support 2025-10-14, not enrolled in Extended Security Updates (available until 2028-10-10)'
        (Get-Ep10Verdict -Entry $win10 -Today ([datetime]'2026-11-01') -Esu 'Enrolled' -EsuCoversUntil '2026-10-13').State | Should -Be 'EndOfSupport'
    }
    It 'pins the evaluation date for supported, ending and closed ESU releases' {
        $pro24h2 = Get-Ep10Verdict -Entry (Find-Ep10Release -Table $table -Caption 'Windows 11 Pro' -Build 26100) -Today $today
        $pro24h2.State | Should -Be 'EndingSoon'
        $pro24h2.Text | Should -Be 'Windows 11 24H2 (Home/Pro): support ends 2026-10-13 (13 days)'
        (Get-Ep10Verdict -Entry (Find-Ep10Release -Table $table -Caption 'Windows 11 Pro' -Build 26200) -Today $today).State | Should -Be 'Supported'
        $r2 = Find-Ep10Release -Table $table -Caption 'Windows Server 2012 R2 Standard' -Build 9600
        (Get-Ep10Verdict -Entry $r2 -Today ([datetime]'2026-10-13')).State | Should -Be 'EsuEligible'
        (Get-Ep10Verdict -Entry $r2 -Today ([datetime]'2026-10-14')).Text | Should -Be 'Windows Server 2012 R2: end of support 2023-10-10, Extended Security Updates ended 2026-10-13'
        (Get-Ep10Verdict -Entry $null -Today $today).State | Should -Be 'Unknown'
    }
    It 'maps installed SQL Server, Office and Exchange versions' {
        ConvertTo-Ep10SqlProduct -InstanceId 'MSSQL13.MSSQLSERVER' -Version '13.0.6300.2' | Should -Be 'SQL Server 2016'
        ConvertTo-Ep10SqlProduct -InstanceId 'MSSQL15.SQLEXPRESS' -Version '' | Should -Be 'SQL Server 2019'
        ConvertTo-Ep10SqlProduct -InstanceId 'MSSQL11.MSSQLSERVER' -Version '11.0.7001.0' | Should -Be 'SQL Server 2012 or older'
        ConvertTo-Ep10OfficeProduct -DisplayName 'Microsoft Office Professional Plus 2019 - en-us' | Should -Be 'Office 2019'
        ConvertTo-Ep10OfficeProduct -DisplayName 'Microsoft Office 2016 Language Pack - French' | Should -BeNullOrEmpty
        ConvertTo-Ep10OfficeProduct -DisplayName 'Microsoft 365 Apps for enterprise - en-us' | Should -BeNullOrEmpty
        ConvertTo-Ep10ExchangeProduct -Major 15 -Minor 1 -Build 225 | Should -Be 'Exchange Server 2016'
        ConvertTo-Ep10ExchangeProduct -Major 15 -Minor 2 -Build 1748 | Should -Be 'Exchange Server 2019'
        ConvertTo-Ep10ExchangeProduct -Major 15 -Minor 2 -Build 2562 | Should -Be 'Exchange Server Subscription Edition'
    }
    It 'lists the three Windows 10 ESU years by activation ID' {
        $years = Get-Ep10EsuYears
        $years.Year | Should -Be @(1, 2, 3)
        $years[-1].Until | Should -Be ($table | Where-Object { $_.Key -eq 'win10-22h2' }).ESU
    }
    It 'runs locally on every host and sweeps only enabled AD computers' {
        $block = Get-Block -Text $script:Text -Start "'EP10' = @\{ Type='Local'" -End "'LM03' = @\{"
        $block | Should -Match "Get-ADComputer -Filter 'Enabled -eq \`$true'"
        $block | Should -Match 'PartOfDomain'
        $block | Should -Match 'SoftwareLicensingProduct'
        $block | Should -Not -Match 'EnableESUSubscriptionCheck'
    }
}

Describe 'EP04 hotpatch-aware patch recency (nested check helpers via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        foreach ($nm in @('Test-Ep04OsQualityUpdate','Get-Ep04LatestOsUpdate')) {
            $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $nm }, $true)[0]
            . ([scriptblock]::Create($fn.Extent.Text))
        }
    }

    It 'recognizes monthly OS updates and hotpatches but not .NET or definitions' {
        Test-Ep04OsQualityUpdate -Title '2026-09 Security Update (KB5129195) (26200.9457)' -OsBuild 26200 | Should -BeTrue
        Test-Ep04OsQualityUpdate -Title '2026-09 Security Update (KB5129195) (26200.9457)' -OsBuild 26100 | Should -BeFalse
        Test-Ep04OsQualityUpdate -Title '2026-05 Hotpatch for Windows Server 2025 (KB5058497)' -OsBuild 26100 | Should -BeTrue
        Test-Ep04OsQualityUpdate -Title '2026-09 .NET Framework Security Update (KB5126052)' -OsBuild 26200 | Should -BeFalse
        Test-Ep04OsQualityUpdate -Title 'Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.437.1)' -OsBuild 26200 | Should -BeFalse
    }
    It 'counts a hotpatch month that only shows in the Windows Update history' {
        $fixes = @([pscustomobject]@{ HotFixID='KB5051987'; InstalledOn=[datetime]'2026-07-22' })
        $history = @(@{ Title='2026-09 Hotpatch for Windows 11 Version 24H2 (KB5130001) (26100.4061)'; Date=[datetime]'2026-09-18' })
        $latest = Get-Ep04LatestOsUpdate -Hotfixes $fixes -History $history -OsBuild 26100
        $latest.Date | Should -Be ([datetime]'2026-09-18')
        $latest.Label | Should -Match 'Windows Update history'
    }
    It 'falls back to the hotfix list when the history has no OS update or is unreadable' {
        $fixes = @([pscustomobject]@{ HotFixID='KB5051987'; InstalledOn=[datetime]'2026-06-10' })
        (Get-Ep04LatestOsUpdate -Hotfixes $fixes -History @(@{ Title='2026-09 .NET Framework Security Update (KB5126052)'; Date=[datetime]'2026-09-20' }) -OsBuild 26200).Date | Should -Be ([datetime]'2026-06-10')
        (Get-Ep04LatestOsUpdate -Hotfixes $fixes -History $null -OsBuild 26200).Label | Should -Be 'KB5051987 (hotfix list)'
        Get-Ep04LatestOsUpdate -Hotfixes @() -History $null -OsBuild 26200 | Should -BeNullOrEmpty
    }
}

Describe 'EP04 CISA KEV matching against installed updates (nested check helpers via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        foreach ($nm in @('Get-Ep04KevFamily','Get-Ep04KevHits')) {
            $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $nm }, $true)[0]
            . ([scriptblock]::Create($fn.Extent.Text))
        }
        # Recorded in the CISA feed's shape (entries as published, trimmed to the fields the check reads).
        $script:KevFeed = @'
{"catalogVersion":"2026.09.29","count":8,"vulnerabilities":[
 {"cveID":"CVE-2008-4250","vendorProject":"Microsoft","product":"Windows","vulnerabilityName":"Microsoft Windows Server Service Remote Code Execution Vulnerability","dateAdded":"2026-03-03","dueDate":"2026-03-24","knownRansomwareCampaignUse":"Known"},
 {"cveID":"CVE-2026-40001","vendorProject":"Microsoft","product":"Windows","vulnerabilityName":"Microsoft Windows Common Log File System Driver Privilege Escalation","dateAdded":"2026-09-08","dueDate":"2026-09-29","knownRansomwareCampaignUse":"Known"},
 {"cveID":"CVE-2026-40002","vendorProject":"Microsoft","product":"Windows","vulnerabilityName":"Microsoft Windows Kernel Privilege Escalation","dateAdded":"2026-09-26","dueDate":"2026-10-17","knownRansomwareCampaignUse":"Unknown"},
 {"cveID":"CVE-2026-33824","vendorProject":"Microsoft","product":"Internet Key Exchange (IKE) Service Extensions","vulnerabilityName":"Microsoft Windows IKE Extension Remote Code Execution","dateAdded":"2026-08-18","dueDate":"2026-08-21","knownRansomwareCampaignUse":"Unknown"},
 {"cveID":"CVE-2009-0238","vendorProject":"Microsoft","product":"Office","vulnerabilityName":"Microsoft Office Remote Code Execution Vulnerability","dateAdded":"2026-04-14","dueDate":"2026-04-28","knownRansomwareCampaignUse":"Unknown"},
 {"cveID":"CVE-2019-1068","vendorProject":"Microsoft","product":"SQL Server","vulnerabilityName":"Microsoft SQL Server Remote Code Execution Vulnerability","dateAdded":"2026-08-26","dueDate":"2026-08-29","knownRansomwareCampaignUse":"Unknown"},
 {"cveID":"CVE-2020-0618","vendorProject":"Microsoft","product":"SQL Server","vulnerabilityName":"Microsoft SQL Server Reporting Services Remote Code Execution Vulnerability","dateAdded":"2024-09-18","dueDate":"2024-10-09","knownRansomwareCampaignUse":"Known"},
 {"cveID":"CVE-2026-40003","vendorProject":"Microsoft","product":".NET Framework","vulnerabilityName":"Microsoft .NET Framework Remote Code Execution","dateAdded":"2026-09-10","dueDate":"2026-10-01","knownRansomwareCampaignUse":"Unknown"}
]}
'@ | ConvertFrom-Json
        $script:KevToday = [datetime]'2026-09-30'
    }

    It 'maps KEV product names to the update stream that fixes them' {
        Get-Ep04KevFamily -Product 'Windows' | Should -Be 'Windows'
        Get-Ep04KevFamily -Product 'Exchange Server' | Should -Be 'Exchange'
        Get-Ep04KevFamily -Product 'Internet Key Exchange (IKE) Service Extensions' | Should -BeNullOrEmpty
        Get-Ep04KevFamily -Product 'Word' | Should -Be 'Office'
        Get-Ep04KevFamily -Product '.NET Framework' | Should -Be '.NET'
        Get-Ep04KevFamily -Product 'SQL Server' | Should -Be 'SQL Server'
    }
    It 'passes a host patched after every Windows entry was added, including old CVEs KEV re-added' {
        $hits = @(Get-Ep04KevHits -Entries $script:KevFeed.vulnerabilities -Families @('Windows') -UpdateDates @{} -LatestOsDate ([datetime]'2026-09-27') -Today $script:KevToday)
        $hits.Count | Should -Be 0
    }
    It 'counts entries added after a host missed the fixing month and marks them overdue' {
        $hits = @(Get-Ep04KevHits -Entries $script:KevFeed.vulnerabilities -Families @('Windows') -UpdateDates @{} -LatestOsDate ([datetime]'2026-08-11') -Today $script:KevToday)
        @($hits.CveId) | Should -Be @('CVE-2026-40002','CVE-2026-40001')
        ($hits | Where-Object CveId -eq 'CVE-2026-40001').Overdue | Should -BeTrue
        ($hits | Where-Object CveId -eq 'CVE-2026-40002').Overdue | Should -BeFalse
        @($hits | Where-Object { $_.CveId -eq 'CVE-2008-4250' }).Count | Should -Be 0
    }
    It 'flags a ransomware-linked entry, and fails the check only once it is overdue' {
        $hits = @(Get-Ep04KevHits -Entries $script:KevFeed.vulnerabilities -Families @('Windows') -UpdateDates @{} -LatestOsDate ([datetime]'2026-08-11') -Today $script:KevToday)
        $ransom = $hits | Where-Object CveId -eq 'CVE-2026-40001'
        $ransom.Ransomware | Should -BeTrue
        $ransom.Overdue | Should -BeTrue
        $early = @(Get-Ep04KevHits -Entries $script:KevFeed.vulnerabilities -Families @('Windows') -UpdateDates @{} -LatestOsDate ([datetime]'2026-08-11') -Today ([datetime]'2026-09-20'))
        ($early | Where-Object CveId -eq 'CVE-2026-40001').Overdue | Should -BeFalse
        $block = Get-Block -Text $script:Text -Start "'EP04' = @\{ Type='Local'" -End "'EP05' = @\{"
        $block | Should -Match 'if \(@\(\$ransomHits \| Where-Object \{ \$_\.Overdue \}\)\.Count -gt 0\) \{ \$kevRansomware = \$true \}'
        $block | Should -Match "elseif \(\`$kevRansomware\) \{'Fail'\}"
        $block | Should -Not -Match '\$p -match \$dp'
    }
    It 'judges separately serviced products against their own update date' {
        $families = @('Windows','Office','SQL Server','.NET')
        $dated = @(Get-Ep04KevHits -Entries $script:KevFeed.vulnerabilities -Families $families -LatestOsDate ([datetime]'2026-09-27') -Today $script:KevToday `
            -UpdateDates @{ 'Office'=[datetime]'2026-09-26'; 'SQL Server'=[datetime]'2019-09-24'; '.NET'=[datetime]'2026-09-15' })
        @($dated.CveId) | Should -Be @('CVE-2019-1068')
        $dated[0].Unverified | Should -BeFalse
        # CVE-2020-0618 was due more than a year ago, so the SQL Server date doesn't bring it back.
        $undated = @(Get-Ep04KevHits -Entries $script:KevFeed.vulnerabilities -Families $families -UpdateDates @{} -LatestOsDate ([datetime]'2026-09-27') -Today $script:KevToday)
        @($undated.CveId | Sort-Object) | Should -Be @('CVE-2009-0238','CVE-2019-1068')
        @($undated | Where-Object { -not $_.Unverified }).Count | Should -Be 0
        # .NET falls back to the OS update when no .NET update date is known.
        @(Get-Ep04KevHits -Entries $script:KevFeed.vulnerabilities -Families @('.NET') -UpdateDates @{} -LatestOsDate ([datetime]'2026-09-01') -Today $script:KevToday).CveId | Should -Be @('CVE-2026-40003')
    }
    It 'treats an old CVE KEV re-added as fixed by any update from after the following year' {
        # CVE-2023-21529 was fixed in February 2023 and added to KEV on 2026-04-13.
        $exchange = @([pscustomobject]@{ cveID='CVE-2023-21529'; vendorProject='Microsoft'; product='Exchange Server'; vulnerabilityName='Microsoft Exchange Server Remote Code Execution'; dateAdded='2026-04-13'; dueDate='2026-04-27'; knownRansomwareCampaignUse='Known' })
        @(Get-Ep04KevHits -Entries $exchange -Families @('Windows','Exchange') -UpdateDates @{ 'Exchange'=[datetime]'2025-03-11' } -LatestOsDate ([datetime]'2026-09-27') -Today $script:KevToday).Count | Should -Be 0
        @(Get-Ep04KevHits -Entries $script:KevFeed.vulnerabilities -Families @('SQL Server') -UpdateDates @{ 'SQL Server'=[datetime]'2026-07-15' } -LatestOsDate ([datetime]'2026-09-27') -Today $script:KevToday).Count | Should -Be 0
        # An Exchange server not updated since 2024 still gets it, overdue and ransomware-linked.
        $stale = @(Get-Ep04KevHits -Entries $exchange -Families @('Exchange') -UpdateDates @{ 'Exchange'=[datetime]'2024-06-11' } -LatestOsDate ([datetime]'2026-09-27') -Today $script:KevToday)
        @($stale.CveId) | Should -Be @('CVE-2023-21529')
        $stale[0].Overdue | Should -BeTrue
        $stale[0].Ransomware | Should -BeTrue
        # The year rule never hides a current-year entry added after the last update.
        @(Get-Ep04KevHits -Entries $script:KevFeed.vulnerabilities -Families @('Windows') -UpdateDates @{} -LatestOsDate ([datetime]'2026-08-11') -Today $script:KevToday).CveId | Should -Contain 'CVE-2026-40001'
    }
    It 'uses SQL Server update titles only when there is a single instance' {
        $block = Get-Block -Text $script:Text -Start "'EP04' = @\{ Type='Local'" -End "'EP05' = @\{ Type='Local'"
        $block | Should -Match '\$sqlTitled = if \(\$sqlInstances\.Count -eq 1\) \{ Get-Ep04NewestTitledDate'
        $block | Should -Match "\`$updateDates\['SQL Server'\] = & \`$newerOf \(& \`$serviceExeDate @\('MSSQLSERVER','MSSQL\`$\*'\)\) \`$sqlTitled"
    }
    It 'needs its exclusions to keep drivers and Store packages from dating a product' {
        $fn = ([System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)).FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-Ep04NewestTitledDate' }, $true)[0]
        . ([scriptblock]::Create($fn.Extent.Text))
        $history = @(
            @{ Title='2026-08 Security Update for SQL Server 2019 Native Client (KB5099001)'; Date=[datetime]'2026-08-20' },
            @{ Title='9WZDNCRFJ3PT-Microsoft.NET 8.0 Desktop Runtime'; Date=[datetime]'2026-09-01' },
            @{ Title='Security Update for SQL Server 2019 RTM GDR (KB5046859)'; Date=[datetime]'2025-01-15' },
            @{ Title='2026-06 Security Update for .NET Framework 4.8.1 (KB5099002)'; Date=[datetime]'2026-06-10' }
        )
        (Get-Ep04NewestTitledDate -History $history -Family 'SQL Server') | Should -Be ([datetime]'2025-01-15')
        (Get-Ep04NewestTitledDate -History $history -Family '.NET') | Should -Be ([datetime]'2026-06-10')
    }
    It 'dates products from their own update titles, not Store packages or SQL client drivers' {
        $fn = ([System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)).FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-Ep04NewestTitledDate' }, $true)[0]
        . ([scriptblock]::Create($fn.Extent.Text))
        # Titles as this PC's Windows Update history shows them, plus SQL Server and Exchange shapes.
        $history = @(
            [pscustomobject]@{ Date=[datetime]'2026-09-20'; Title='9PLL735RFDSM-Microsoft.NET.Native.Runtime.2.2' },
            [pscustomobject]@{ Date=[datetime]'2026-09-08'; Title='2026-09 .NET Framework Security Update (KB5126052)' },
            [pscustomobject]@{ Date=[datetime]'2026-09-22'; Title='Security Update for Microsoft OLE DB Driver 18 for SQL Server (KB5040711)' },
            [pscustomobject]@{ Date=[datetime]'2026-07-15'; Title='Security Update for SQL Server 2019 RTM GDR (KB5046859)' },
            [pscustomobject]@{ Date=[datetime]'2026-05-12'; Title='Security Update for Exchange Server 2019 Cumulative Update 14 (KB5049233)' },
            [pscustomobject]@{ Date=[datetime]'2026-09-25'; Title='Security Intelligence Update for Microsoft Defender Antivirus - KB2267602' }
        )
        Get-Ep04NewestTitledDate -History $history -Family '.NET' | Should -Be ([datetime]'2026-09-08')
        Get-Ep04NewestTitledDate -History $history -Family 'SQL Server' | Should -Be ([datetime]'2026-07-15')
        Get-Ep04NewestTitledDate -History $history -Family 'Exchange' | Should -Be ([datetime]'2026-05-12')
        Get-Ep04NewestTitledDate -History $history -Family 'Office' | Should -BeNullOrEmpty
        $block = Get-Block -Text $script:Text -Start "'EP04' = @\{ Type='Local'" -End "'EP05' = @\{"
        $block | Should -Not -Match '\$newestTitled'
        $block | Should -Match "Get-Ep04NewestTitledDate -History \`$wuHistory -Family '\.NET'"
    }
}

Describe 'EP04 KEV scenarios shared with the C# port (tests/NetworkSecurityAuditor.Tests/Fixtures/Kev)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        foreach ($nm in @('Get-Ep04KevFamily','Get-Ep04KevHits','Get-Ep04NewestTitledDate')) {
            $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $nm }, $true)[0]
            . ([scriptblock]::Create($fn.Extent.Text))
        }
        $kevDir = Join-Path $script:RepoRoot 'tests\NetworkSecurityAuditor.Tests\Fixtures\Kev'
        $script:KevScenarios = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $kevDir 'ep04-kev-scenarios.json') | ConvertFrom-Json
        $script:KevRecordedFeed = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $kevDir $script:KevScenarios.feed) | ConvertFrom-Json
        function ConvertTo-Ep04ScenarioDate { param($Value) if ($null -eq $Value -or [string]$Value -eq '') { $null } else { ([datetime]$Value).Date } }
    }

    It 'reads the recorded feed in the CISA shape' {
        $script:KevRecordedFeed.catalogVersion | Should -Be '2026.09.29'
        @($script:KevRecordedFeed.vulnerabilities).Count | Should -Be $script:KevRecordedFeed.count
        @($script:KevScenarios.hitScenarios).Count | Should -BeGreaterThan 10
    }
    It 'maps each product the way the C# port does' {
        foreach ($case in @($script:KevScenarios.familyCases)) {
            $family = Get-Ep04KevFamily -Product $case.product
            if ($null -eq $case.family) { $family | Should -BeNullOrEmpty -Because $case.product } else { $family | Should -Be $case.family -Because $case.product }
        }
    }
    It 'gives every scenario the expected KEV hits' {
        foreach ($scenario in @($script:KevScenarios.hitScenarios)) {
            $updateDates = @{}
            foreach ($p in @($scenario.updateDates.PSObject.Properties)) { $updateDates[$p.Name] = ConvertTo-Ep04ScenarioDate $p.Value }
            $hits = @(Get-Ep04KevHits -Entries @($script:KevRecordedFeed.vulnerabilities) -Families @($scenario.families) -UpdateDates $updateDates `
                -LatestOsDate (ConvertTo-Ep04ScenarioDate $scenario.latestOsDate) -Today (ConvertTo-Ep04ScenarioDate $scenario.today))
            $expected = @($scenario.expected)
            $hits.Count | Should -Be $expected.Count -Because $scenario.name
            for ($i = 0; $i -lt $expected.Count; $i++) {
                $hits[$i].CveId | Should -Be $expected[$i].cveID -Because $scenario.name
                $hits[$i].Family | Should -Be $expected[$i].family -Because $scenario.name
                $hits[$i].Overdue | Should -Be ([bool]$expected[$i].overdue) -Because "$($scenario.name) overdue"
                $hits[$i].Ransomware | Should -Be ([bool]$expected[$i].ransomware) -Because "$($scenario.name) ransomware"
                $hits[$i].Unverified | Should -Be ([bool]$expected[$i].unverified) -Because "$($scenario.name) unverified"
            }
        }
    }
    It 'dates each product from its own update titles' {
        $history = @($script:KevScenarios.titledDates.history | ForEach-Object { [pscustomobject]@{ Title = [string]$_.title; Date = [datetime]$_.date } })
        foreach ($p in @($script:KevScenarios.titledDates.expected.PSObject.Properties)) {
            $actual = Get-Ep04NewestTitledDate -History $history -Family $p.Name
            if ($null -eq $p.Value) { $actual | Should -BeNullOrEmpty -Because $p.Name } else { $actual | Should -Be (ConvertTo-Ep04ScenarioDate $p.Value) -Because $p.Name }
        }
    }
}

Describe 'EP08 TPM reporting without elevation (nested check helper via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-Ep08TpmAssessment' }, $true)[0]
        . ([scriptblock]::Create($fn.Extent.Text))
    }
    It 'reports a standard user TPM 2.0 from its PnP device without counting an issue' {
        # What Get-Tpm hands a standard user: a message string, not a TPM object.
        $a = Get-Ep08TpmAssessment -Tpm 'Administrator privilege is required to execute this command.' -SpecVersion '' -PnpDeviceIds @('ACPI\MSFT0101','MSFT0101') -PnpStatus 'OK'
        $a.Issue | Should -BeFalse
        $a.Lines | Should -Contain "TPM Present     : True (device status OK); readiness couldn't be read without elevation"
        $a.Lines | Should -Contain 'TPM Version     : 2.0 [TPM 2.0 OK]'
        ($a.Lines -join "`n") | Should -Not -Match '1\.2'
    }
    It 'says the TPM could not be read instead of claiming TPM 1.2 when nothing is readable' {
        $empty = [pscustomobject]@{ TpmPresent=$null; TpmReady=$null; TpmEnabled=$null }
        $a = Get-Ep08TpmAssessment -Tpm $empty -SpecVersion '' -PnpDeviceIds @() -PnpStatus '' -PnpQueryOk $false
        $a.Issue | Should -BeFalse
        $a.Lines | Should -Be @("TPM             : couldn't be read without elevation")
    }
    It 'keeps the elevated checks' {
        $ready = Get-Ep08TpmAssessment -Tpm ([pscustomobject]@{ TpmPresent=$true; TpmReady=$true; TpmEnabled=$true }) -SpecVersion '2.0, 0, 1.38' -PnpDeviceIds @('MSFT0101') -PnpStatus 'OK'
        $ready.Issue | Should -BeFalse
        $ready.Lines | Should -Contain 'TPM Present     : True | Ready: True | Enabled: True'
        $ready.Lines | Should -Contain 'TPM Version     : 2.0 [TPM 2.0 OK]'
        (Get-Ep08TpmAssessment -Tpm ([pscustomobject]@{ TpmPresent=$true; TpmReady=$false; TpmEnabled=$true }) -SpecVersion '2.0, 0, 1.38' -PnpDeviceIds @() -PnpStatus '').Issue | Should -BeTrue
        (Get-Ep08TpmAssessment -Tpm ([pscustomobject]@{ TpmPresent=$true; TpmReady=$true; TpmEnabled=$true }) -SpecVersion '1.2, 2, 3' -PnpDeviceIds @() -PnpStatus '').Lines | Should -Contain 'TPM Version     : 1.2 [TPM 1.2 - upgrade recommended]'
    }
    It 'counts a missing TPM when the device list was readable and shows none' {
        $a = Get-Ep08TpmAssessment -Tpm 'Administrator privilege is required to execute this command.' -SpecVersion '' -PnpDeviceIds @() -PnpStatus '' -PnpQueryOk $true
        $a.Issue | Should -BeTrue
        $a.Lines | Should -Contain 'TPM Present     : no TPM device found [!]'
        (Get-Ep08TpmAssessment -Tpm 'x' -SpecVersion '' -PnpDeviceIds @('ACPI\PNP0C31') -PnpStatus 'OK').Lines | Should -Contain 'TPM Version     : 1.2 [TPM 1.2 - upgrade recommended]'
    }
    It 'finds a TPM 2.0 whose MSFT0101 is only in its hardware IDs' {
        # A TPM whose ACPI _HID is MSFT0101 can carry no compatible ID; its hardware IDs are these.
        $a = Get-Ep08TpmAssessment -Tpm 'Administrator privilege is required to execute this command.' -SpecVersion '' -PnpDeviceIds @('ACPI\VEN_MSFT&DEV_0101','ACPI\MSFT0101','*MSFT0101') -PnpStatus 'OK'
        $a.Issue | Should -BeFalse
        $a.Lines | Should -Contain 'TPM Version     : 2.0 [TPM 2.0 OK]'
        $block = Get-Block -Text $script:Text -Start "'EP08' = @\{ Type='Local'" -End "'LM02' = @\{ Type='Local'"
        $block | Should -Match '\(@\(\$_\.CompatibleID\) \+ @\(\$_\.HardwareID\)\) -match'
        $block | Should -Match '-PnpDeviceIds @\(\$tpmPnp \| ForEach-Object \{ @\(\$_\.CompatibleID\) \+ @\(\$_\.HardwareID\) \}\)'
    }
}

Describe 'EP11 Secure Boot 2023 certificate transition (nested check helpers via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        foreach ($nm in @('ConvertFrom-Ep11AvailableUpdates','Get-Ep11EventMeaning','Get-Ep11Assessment')) {
            $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $nm }, $true)[0]
            . ([scriptblock]::Create($fn.Extent.Text))
        }
        $today = [datetime]'2026-09-30'
        function Invoke-Uefi { param($Status, $Capable = $null, $AvailableUpdates = 0, $ErrorCode = 0, $ErrorEvent = $null, [object[]]$Events = @())
            Get-Ep11Assessment -Firmware 'Uefi' -SecureBootEnabled 1 -Status $Status -ErrorCode $ErrorCode -ErrorEvent $ErrorEvent -Capable $Capable -AvailableUpdates $AvailableUpdates -Events $Events -Today $today
        }
    }

    It 'passes Updated and names the latest 1808 event' {
        $r = Invoke-Uefi -Status 'Updated' -Capable 2 -Events @(@{ Id=1808; Time=[datetime]'2026-09-27' })
        $r.Status | Should -Be 'Pass'
        $r.Headline | Should -Be 'Secure Boot 2023 certificates: Updated, booting from the boot manager signed by Windows UEFI CA 2023.'
        $r.Latest | Should -Match 'Latest certificate event: 1808 on 2026-09-27'
    }
    It 'treats InProgress as Partial and NotStarted as Fail' {
        $progress = Invoke-Uefi -Status 'InProgress' -Capable 1 -AvailableUpdates 0x4100
        $progress.Status | Should -Be 'Partial'
        $progress.Headline | Should -Match 'waiting for a restart'
        $progress.Headline | Should -Match 'expires 2026-10-19 \(19 days\)'
        (Invoke-Uefi -Status 'NotStarted' -Capable 0).Status | Should -Be 'Fail'
        (Invoke-Uefi -Status 'Pending').Status | Should -Be 'Partial'
    }
    It 'fails on a servicing error and points at the firmware' {
        $r = Invoke-Uefi -Status 'InProgress' -Capable 1 -AvailableUpdates 0x5944 -ErrorCode ([int]-2147024875) -ErrorEvent 1795 -Events @(@{ Id=1795; Time=[datetime]'2026-09-28' })
        $r.Status | Should -Be 'Fail'
        $r.Headline | Should -Match 'stopped with error 0x80070015 \(event 1795\)'
        $r.Headline | Should -Match 'Check the OEM for a firmware update'
    }
    It 'returns N/A for legacy BIOS, no Secure Boot support and Secure Boot off' {
        (Get-Ep11Assessment -Firmware 'Bios' -Today $today).Status | Should -Be 'N/A'
        (Get-Ep11Assessment -Firmware 'Unknown' -Today $today).Status | Should -Be 'N/A'
        $off = Get-Ep11Assessment -Firmware 'Uefi' -SecureBootEnabled 0 -Status 'NotStarted' -Today $today
        $off.Status | Should -Be 'N/A'
        $off.Headline | Should -Match 'Secure Boot is off'
    }
    It 'falls back to the events and the DB flag when no status is written' {
        (Invoke-Uefi -Status '' -AvailableUpdates $null -ErrorCode $null -Events @(@{ Id=1808; Time=[datetime]'2026-09-01' })).Status | Should -Be 'Pass'
        (Invoke-Uefi -Status '' -Capable 1 -AvailableUpdates $null -ErrorCode $null).Status | Should -Be 'Partial'
        $none = Invoke-Uefi -Status '' -Capable 0 -AvailableUpdates $null -ErrorCode $null -Events @(@{ Id=1801; Time=[datetime]'2026-09-01' })
        $none.Status | Should -Be 'Fail'
        $none.Headline | Should -Match "event 1801 says they aren't applied"
    }
    It 'decodes the AvailableUpdates bitmask the same way as the app' {
        $full = ConvertFrom-Ep11AvailableUpdates -Value 0x5944
        $full.Count | Should -Be 6
        $full | Should -Contain '0x0040: add Windows UEFI CA 2023 to the DB'
        $full | Should -Contain '0x0100: install the boot manager signed by Windows UEFI CA 2023'
        ConvertFrom-Ep11AvailableUpdates -Value 0x4000 | Should -Contain 'Only the 0x4000 modifier is left, so every requested update has been applied.'
        ConvertFrom-Ep11AvailableUpdates -Value 0x0042 | Should -Contain "0x0002: bits Microsoft doesn't document"
        @(ConvertFrom-Ep11AvailableUpdates -Value 0).Count | Should -Be 0
    }
    It 'reads AvailableUpdates from the SecureBoot key and leaves the 2023 status out of EP08' {
        $ep11 = Get-Block -Text $script:Text -Start "'EP11' = @\{ Type='Local'" -End "'LM03' = @\{"
        $ep11 | Should -Match "Get-ItemProperty -LiteralPath \`$sbKey -EA SilentlyContinue"
        $ep11 | Should -Match "ProviderName='Microsoft-Windows-TPM-WMI'"
        $ep08 = Get-Block -Text $script:Text -Start "'EP08' = @\{ Type='Local'" -End "'EP09' = @\{"
        $ep08 | Should -Not -Match 'UEFICA2023Status'
        $ep08 | Should -Match 'UEFISecureBootEnabled'
    }
}

Describe 'IA12 BadSuccessor helpers (nested check helpers via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        foreach ($nm in 'Get-Ia12Rid','Test-Ia12Tier0Sid','Test-Ia12Reportable','Get-Ia12PatchState','Test-Ia12Server2025','Get-Ia12RelevantRights','Get-Ia12AceReason','Get-Ia12ParentDn') {
            $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $nm }, $true)[0]
            . ([scriptblock]::Create($fn.Extent.Text))
        }
        $script:Dom = 'S-1-5-21-1004336348-1177238915-682003330'
    }

    It 'reads the real dMSA link attribute, not a nonexistent successor attribute' {
        $block = Get-Block -Text $script:Text -Start "'IA12' = @\{ Type='AD'" -End "'EP01' = @\{ Type='Local'"
        $block | Should -Match 'msDS-ManagedAccountPrecededByLink'
        $block | Should -Match 'msDS-SupersededManagedAccountLink'
        $block | Should -Not -Match 'msDS-ManagedAccountSucceededByLink'
        $block | Should -Not -Match 'msDS-DelegatedManagedServiceAccountSuccessor'
        $block | Should -Match 'CVE-2025-53779'
        $block | Should -Not -Match 'CVE-2025-21293'
    }

    It 'matches Tier 0 principals by SID across domain, forest root and builtin RIDs' {
        Test-Ia12Tier0Sid -Sid "$script:Dom-512" -DomainSid $script:Dom -ForestRootSid '' | Should -BeTrue
        Test-Ia12Tier0Sid -Sid "$script:Dom-500" -DomainSid $script:Dom -ForestRootSid '' | Should -BeTrue
        Test-Ia12Tier0Sid -Sid 'S-1-5-32-544' -DomainSid $script:Dom -ForestRootSid '' | Should -BeTrue
        Test-Ia12Tier0Sid -Sid 'S-1-5-18' -DomainSid $script:Dom -ForestRootSid '' | Should -BeTrue
        # Enterprise Admins live in the forest root domain.
        $child = 'S-1-5-21-2222222222-3333333333-4444444444'
        Test-Ia12Tier0Sid -Sid "$script:Dom-519" -DomainSid $child -ForestRootSid $script:Dom | Should -BeTrue
        Test-Ia12Tier0Sid -Sid "$script:Dom-513" -DomainSid $script:Dom -ForestRootSid '' | Should -BeFalse
        Test-Ia12Tier0Sid -Sid "$script:Dom-1105" -DomainSid $script:Dom -ForestRootSid '' | Should -BeFalse
        # A different domain whose SID merely starts the same must not match.
        Test-Ia12Tier0Sid -Sid "${script:Dom}5-512" -DomainSid $script:Dom -ForestRootSid '' | Should -BeFalse
    }

    It 'skips CREATOR OWNER and counts SELF only on a dMSA' {
        Test-Ia12Reportable -Sid 'S-1-3-0' -Scope 'Container' -DomainSid $script:Dom -ForestRootSid '' | Should -BeFalse
        Test-Ia12Reportable -Sid 'S-1-3-4' -Scope 'Container' -DomainSid $script:Dom -ForestRootSid '' | Should -BeFalse
        Test-Ia12Reportable -Sid 'S-1-5-10' -Scope 'Container' -DomainSid $script:Dom -ForestRootSid '' | Should -BeFalse
        Test-Ia12Reportable -Sid 'S-1-5-10' -Scope 'Dmsa' -DomainSid $script:Dom -ForestRootSid '' | Should -BeTrue
        Test-Ia12Reportable -Sid "$script:Dom-512" -Scope 'Container' -DomainSid $script:Dom -ForestRootSid '' | Should -BeFalse
        Test-Ia12Reportable -Sid "$script:Dom-1110" -Scope 'Container' -DomainSid $script:Dom -ForestRootSid '' | Should -BeTrue
    }

    It 'reads the August 2025 patch state from the update build revision' {
        Get-Ia12PatchState -Ubr $null | Should -Be 'Unknown'
        Get-Ia12PatchState -Ubr 4652 | Should -Be 'Unpatched'   # July 2025 cumulative update
        Get-Ia12PatchState -Ubr 4851 | Should -Be 'Patched'      # August 2025 hotpatch KB5064010
        Get-Ia12PatchState -Ubr 4945 | Should -Be 'Unpatched'
        Get-Ia12PatchState -Ubr 4946 | Should -Be 'Patched'      # August 2025 cumulative update KB5063878
        Get-Ia12PatchState -Ubr 6584 | Should -Be 'Patched'
    }

    It 'detects Windows Server 2025 from the OS name or the build number' {
        Test-Ia12Server2025 -OperatingSystem 'Windows Server 2025 Datacenter' -OperatingSystemVersion '10.0 (26100)' | Should -BeTrue
        Test-Ia12Server2025 -OperatingSystem 'Windows Server 2025 Standard' -OperatingSystemVersion '' | Should -BeTrue
        Test-Ia12Server2025 -OperatingSystem '' -OperatingSystemVersion '10.0 (26100)' | Should -BeTrue
        Test-Ia12Server2025 -OperatingSystem 'Windows Server 2022 Standard' -OperatingSystemVersion '10.0 (20348)' | Should -BeFalse
        Test-Ia12Server2025 -OperatingSystem '' -OperatingSystemVersion '' | Should -BeFalse
    }

    It 'names the rights that create a dMSA on a container' {
        $empty = '00000000-0000-0000-0000-000000000000'
        $dmsa = '0feb936f-47b3-49f2-9386-1dedc2c23765'
        Get-Ia12RelevantRights -Rights 'CreateChild' -ObjectType $empty -InheritOnly $false -Type 'Allow' -Scope 'Container' | Should -Be 'CreateChild (all classes)'
        Get-Ia12RelevantRights -Rights 'CreateChild' -ObjectType $dmsa -InheritOnly $false -Type 'Allow' -Scope 'Container' | Should -Be 'CreateChild (msDS-DelegatedManagedServiceAccount)'
        Get-Ia12RelevantRights -Rights 'CreateChild' -ObjectType 'bf967a86-0de6-11d0-a285-00aa003049e2' -InheritOnly $false -Type 'Allow' -Scope 'Container' | Should -BeNullOrEmpty
        Get-Ia12RelevantRights -Rights 'GenericAll' -ObjectType $empty -InheritOnly $false -Type 'Allow' -Scope 'Container' | Should -Be 'GenericAll'
        Get-Ia12RelevantRights -Rights 'GenericAll' -ObjectType $empty -InheritOnly $true -Type 'Allow' -Scope 'Container' | Should -BeNullOrEmpty
        Get-Ia12RelevantRights -Rights 'CreateChild' -ObjectType $empty -InheritOnly $false -Type 'Deny' -Scope 'Container' | Should -BeNullOrEmpty
        Get-Ia12RelevantRights -Rights 'WriteDacl, WriteOwner' -ObjectType $empty -InheritOnly $false -Type 'Allow' -Scope 'Container' | Should -Be 'WriteDacl, WriteOwner'
    }

    It 'names the rights that rewrite a dMSA link' {
        $preceded = 'a0945b2b-57a2-43bd-b327-4d112a4e8bd1'
        $state = '2f5c138a-bd38-4016-88b4-0ec87cbb4919'
        Get-Ia12RelevantRights -Rights 'WriteProperty' -ObjectType $preceded -InheritOnly $false -Type 'Allow' -Scope 'Dmsa' | Should -Be 'WriteProperty (msDS-ManagedAccountPrecededByLink)'
        Get-Ia12RelevantRights -Rights 'WriteProperty' -ObjectType $state -InheritOnly $false -Type 'Allow' -Scope 'Dmsa' | Should -Be 'WriteProperty (msDS-DelegatedMSAState)'
        Get-Ia12RelevantRights -Rights 'GenericWrite' -ObjectType '00000000-0000-0000-0000-000000000000' -InheritOnly $false -Type 'Allow' -Scope 'Dmsa' | Should -Be 'GenericWrite'
        Get-Ia12RelevantRights -Rights 'WriteProperty' -ObjectType 'bf967950-0de6-11d0-a285-00aa003049e2' -InheritOnly $false -Type 'Allow' -Scope 'Dmsa' | Should -BeNullOrEmpty
    }

    It 'gives a German ACE the same reason as an English one, by SID' {
        $german = [pscustomobject]@{ Sid="$script:Dom-1110"; Rights='CreateChild'; ObjectType='0feb936f-47b3-49f2-9386-1dedc2c23765'; InheritOnly=$false; Type='Allow' }
        $englishTier0 = [pscustomobject]@{ Sid="$script:Dom-512"; Rights='CreateChild, WriteDacl'; ObjectType='00000000-0000-0000-0000-000000000000'; InheritOnly=$false; Type='Allow' }
        Get-Ia12AceReason -Ace $german -Scope 'Container' -DomainSid $script:Dom -ForestRootSid '' | Should -Be 'CreateChild (msDS-DelegatedManagedServiceAccount)'
        Get-Ia12AceReason -Ace $englishTier0 -Scope 'Container' -DomainSid $script:Dom -ForestRootSid '' | Should -BeNullOrEmpty
    }

    It 'finds the parent DN, honoring an escaped comma' {
        Get-Ia12ParentDn -Dn 'CN=dmsa_web,OU=Service Accounts,DC=corp,DC=example' | Should -Be 'OU=Service Accounts,DC=corp,DC=example'
        Get-Ia12ParentDn -Dn 'CN=Smith\, John,OU=Apps,DC=corp,DC=example' | Should -Be 'OU=Apps,DC=corp,DC=example'
        Get-Ia12ParentDn -Dn 'DC=example' | Should -BeNullOrEmpty
    }
}

Describe 'IA11 Kerberos RC4 enforcement (nested check helpers via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        foreach ($nm in @('Test-KerberosEncUnset','ConvertTo-KerberosEncSummary','Get-KerberosEncClass','Resolve-KerberosDcDefault','Get-KdcEventMeaning','Measure-KerberosEncReadiness')) {
            $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $nm }, $true)[0]
            . ([scriptblock]::Create($fn.Extent.Text))
        }
        $script:Ia11Block = Get-Block -Text $script:Text -Start "'IA11' = @\{ Type='AD'" -End "'IA12' = @\{"
        function New-KerbAccount { param([string]$Name, [string]$Kind = 'user', [object]$Enc = $null, [bool]$UseDes = $false) [pscustomobject]@{ Name = $Name; Kind = $Kind; Enc = $Enc; UseDes = $UseDes } }
        function New-KerbEventSet { param([string]$HostName, [int[]]$Ids = @(), [bool]$Readable = $true, [string]$ErrorText = '') [pscustomobject]@{ Host = $HostName; Readable = $Readable; Error = $ErrorText; Capped = $false; Events = @($Ids | ForEach-Object { [pscustomobject]@{ Id = $_ } }) } }
        # The same accounts as the C# IA11-unset and IA11-rc4 fixtures.
        $script:UnsetAccounts = @(
            (New-KerbAccount 'svc_sql' 'user' 0x18),
            (New-KerbAccount 'svc_app' 'user'),
            (New-KerbAccount 'DC01$' 'computer' 0x1C),
            (New-KerbAccount 'NAS01$' 'computer'),
            (New-KerbAccount 'gmsa-web$' 'gMSA')
        )
    }

    It 'classifies ticket cipher bits: <Enc> (DES key only <UseDes>) is <Expected>' -ForEach @(
        @{ Enc = $null; UseDes = $false; Expected = 'Unset' },
        @{ Enc = 0; UseDes = $false; Expected = 'Unset' },
        @{ Enc = 0x20; UseDes = $false; Expected = 'Unset' },
        @{ Enc = 0x4; UseDes = $false; Expected = 'RC4Only' },
        @{ Enc = 0x24; UseDes = $false; Expected = 'RC4Only' },
        @{ Enc = 0x18; UseDes = $false; Expected = 'AES' },
        @{ Enc = 0x1C; UseDes = $false; Expected = 'AES' },
        @{ Enc = 0x3; UseDes = $false; Expected = 'DES' },
        @{ Enc = 0x1B; UseDes = $false; Expected = 'DES' },
        @{ Enc = 0x18; UseDes = $true; Expected = 'DES' }
    ) {
        Get-KerberosEncClass -Value $Enc -UseDesKeyOnly $UseDes | Should -Be $Expected
    }

    It 'resolves the DC default from the explicit value, then the phase, and says when it assumed' -ForEach @(
        @{ Default = $null; Phase = $null; Effective = 0x27; Assumed = $true },
        @{ Default = $null; Phase = 0; Effective = 0x27; Assumed = $false },
        @{ Default = $null; Phase = 1; Effective = 0x27; Assumed = $false },
        @{ Default = $null; Phase = 2; Effective = 0x18; Assumed = $false },
        @{ Default = $null; Phase = 7; Effective = 0x27; Assumed = $true },
        @{ Default = 0x18; Phase = 1; Effective = 0x18; Assumed = $false },
        @{ Default = 0x24; Phase = 2; Effective = 0x24; Assumed = $false },
        @{ Default = 0; Phase = 2; Effective = 0x18; Assumed = $false }
    ) {
        $resolved = Resolve-KerberosDcDefault -HostName 'dc01' -DefaultEncTypes $Default -Phase $Phase
        $resolved.Effective | Should -Be $Effective
        $resolved.Assumed | Should -Be $Assumed
    }

    It 'assumes 0x27 for an unreadable DC and names the error' {
        $resolved = Resolve-KerberosDcDefault -HostName 'dc02' -Readable $false -ErrorText 'The network path was not found.'
        $resolved.Effective | Should -Be 0x27
        $resolved.Assumed | Should -BeTrue
        $resolved.Explicit | Should -BeFalse
        $resolved.Basis | Should -Match 'The network path was not found'
    }

    It 'passes unset accounts when every DC enforces AES' {
        $dcs = @((Resolve-KerberosDcDefault -HostName 'dc01' -Phase 2), (Resolve-KerberosDcDefault -HostName 'dc02' -Phase 2))
        $result = Measure-KerberosEncReadiness -Accounts $script:UnsetAccounts -DcDefaults $dcs -EventSets @((New-KerbEventSet 'dc01'), (New-KerbEventSet 'dc02'))
        $result.Issues | Should -Be 0
        $result.Warnings | Should -Be 0
        ($result.Lines -join "`n") | Should -Match '\[OK\] 3 account\(s\) without msDS-SupportedEncryptionTypes get the DC default 0x18 \(AES128, AES256\)'
    }

    It 'leaves unset accounts as follow-ups when a DC still allows RC4 by default' {
        $dcs = @((Resolve-KerberosDcDefault -HostName 'dc01' -Phase 1), (Resolve-KerberosDcDefault -HostName 'dc02' -Phase 2))
        $result = Measure-KerberosEncReadiness -Accounts $script:UnsetAccounts -DcDefaults $dcs
        $text = $result.Lines -join "`n"
        $result.Issues | Should -Be 0
        $result.Warnings | Should -Be 3
        $text | Should -Match '\[DEFAULT-DEPENDENT\] 3 account\(s\) have no msDS-SupportedEncryptionTypes, and a DC default still allows RC4 \(0x27 on dc01\)'
        $text | Should -Match 'NAS01\$ \[computer\]'
        $text | Should -Match 'gmsa-web\$ \[gMSA\]'
    }

    It 'names an unreadable DC and the default it assumed' {
        $dcs = @((Resolve-KerberosDcDefault -HostName 'dc01' -Phase 2), (Resolve-KerberosDcDefault -HostName 'dc02' -Readable $false -ErrorText 'Access is denied.'))
        $text = (Measure-KerberosEncReadiness -Accounts $script:UnsetAccounts -DcDefaults $dcs).Lines -join "`n"
        $text | Should -Match 'dc02: 0x27 .*Registry not readable \(Access is denied\.\); assumed 0x27'
        $text | Should -Match '\(0x27 on dc02, assumed\)'
        $text | Should -Not -Match "No domain controller's Kerberos settings could be read"
        $none = (Measure-KerberosEncReadiness -Accounts $script:UnsetAccounts -DcDefaults @($dcs[1])).Lines -join "`n"
        $none | Should -Match "No domain controller's Kerberos settings could be read, so accounts without msDS-SupportedEncryptionTypes were evaluated against the pre-enforcement default 0x27"
    }

    It 'says which default it assumed when no DC is in the directory' {
        $result = Measure-KerberosEncReadiness -Accounts @((New-KerbAccount 'svc_app' 'user'))
        $text = $result.Lines -join "`n"
        $result.Warnings | Should -Be 1
        $text | Should -Match 'No domain controller was found in the directory\. Assumed the pre-enforcement default 0x27'
        $text | Should -Match '\(0x27 assumed, no DC found\)'
        $text | Should -Match 'Not read: no domain controller was found'
    }

    It 'fails an explicit DC default without AES or with DES' {
        $noAes = Measure-KerberosEncReadiness -Accounts $script:UnsetAccounts -DcDefaults @((Resolve-KerberosDcDefault -HostName 'dc01' -DefaultEncTypes 0x24))
        $noAes.Issues | Should -Be 1
        ($noAes.Lines -join "`n") | Should -Match '\[LEGACY-DEFAULT\] dc01 DefaultDomainSupportedEncTypes=0x24 has no AES'
        $des = Measure-KerberosEncReadiness -Accounts $script:UnsetAccounts -DcDefaults @((Resolve-KerberosDcDefault -HostName 'dc01' -DefaultEncTypes 0x27))
        $des.Issues | Should -Be 1
        ($des.Lines -join "`n") | Should -Match '\[DES-DEFAULT\] dc01 DefaultDomainSupportedEncTypes=0x27 enables DES'
        $rc4AndAes = Measure-KerberosEncReadiness -Accounts $script:UnsetAccounts -DcDefaults @((Resolve-KerberosDcDefault -HostName 'dc01' -DefaultEncTypes 0x3C))
        $rc4AndAes.Issues | Should -Be 0
        $rc4AndAes.Warnings | Should -Be 3
    }

    It 'fails RC4-only and DES accounts of every kind by name' {
        $accounts = @(
            (New-KerbAccount 'svc_web' 'user' 0x1C),
            (New-KerbAccount 'svc_legacy' 'user' $null $true),
            (New-KerbAccount 'NAS02$' 'computer' 0x4),
            (New-KerbAccount 'gmsa-legacy$' 'gMSA' 0x24),
            (New-KerbAccount 'msa-old$' 'sMSA' 0x1B)
        )
        $result = Measure-KerberosEncReadiness -Accounts $accounts -DcDefaults @((Resolve-KerberosDcDefault -HostName 'dc01' -Phase 2))
        $text = $result.Lines -join "`n"
        $result.Issues | Should -Be 4
        $result.Warnings | Should -Be 0
        $text | Should -Match '\[RC4-ONLY\] NAS02\$ \[computer\] \| 0x4 \(RC4-HMAC\)'
        $text | Should -Match '\[RC4-ONLY\] gmsa-legacy\$ \[gMSA\] \| 0x24 \(RC4-HMAC, AES-SK \(AES session keys\)\)'
        $text | Should -Match 'the service ticket is still RC4-encrypted'
        $text | Should -Match '\[DES\] msa-old\$ \[sMSA\]'
        $text | Should -Match '\[DES\] svc_legacy \[user\] \| USE_DES_KEY_ONLY'
        $text | Should -Match '\[INFO\] 1 AES account\(s\) also allow RC4'
    }

    It 'summarizes KDC events 201-209 per DC as follow-ups and names unreadable logs' {
        $dcs = @((Resolve-KerberosDcDefault -HostName 'dc01' -Phase 2), (Resolve-KerberosDcDefault -HostName 'dc02' -Phase 2))
        $sets = @((New-KerbEventSet 'dc01' @(201, 205, 201)), (New-KerbEventSet 'dc02' -Readable $false -ErrorText 'The RPC server is unavailable.'))
        $result = Measure-KerberosEncReadiness -Accounts @((New-KerbAccount 'svc_sql' 'user' 0x18)) -DcDefaults $dcs -EventSets $sets
        $text = $result.Lines -join "`n"
        $result.Issues | Should -Be 0
        $result.Warnings | Should -Be 1
        $text | Should -Match 'dc01: 3 event\(s\): 201 x2, 205 x1'
        $text | Should -Match '201: RC4 issued for a service without msDS-SupportedEncryptionTypes'
        $text | Should -Match 'dc02: not readable \(The RPC server is unavailable\.\)'
    }

    It 'has a meaning for every KDC event from 201 to 209' {
        foreach ($id in 201..209) { Get-KdcEventMeaning $id | Should -Not -Match 'not a CVE-2026-20833' }
    }

    It 'labels 0x20 as AES session keys, not FAST' {
        ConvertTo-KerberosEncSummary 0x24 | Should -Be '0x24 (RC4-HMAC, AES-SK (AES session keys))'
    }

    It 'reads each DC remotely at the documented registry paths and KDC event source' {
        $script:Ia11Block | Should -Match "OpenSubKey\('SYSTEM\\CurrentControlSet\\Services\\Kdc'\)"
        $script:Ia11Block | Should -Match "GetValue\('DefaultDomainSupportedEncTypes'\)"
        $script:Ia11Block | Should -Match "OpenSubKey\('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters'\)"
        $script:Ia11Block | Should -Match "GetValue\('RC4DefaultDisablementPhase'\)"
        $script:Ia11Block | Should -Match 'OpenRemoteBaseKey'
        $script:Ia11Block | Should -Match "Get-WinEvent -ComputerName \`$HostName -FilterHashtable"
        $script:Ia11Block | Should -Match "ProviderName='Kdcsvc'"
        $script:Ia11Block | Should -Match 'NoMatchingEventsFound'
        $script:Ia11Block | Should -Match 'primaryGroupID=521'
        $script:Ia11Block | Should -Match 'objectClass=msDS-GroupManagedServiceAccount\)\(objectClass=msDS-ManagedServiceAccount'
        $script:Ia11Block | Should -Not -Match 'Get-ItemProperty'
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
