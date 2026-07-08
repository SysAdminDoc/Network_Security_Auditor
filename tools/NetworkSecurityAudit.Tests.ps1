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
    $script:EvidenceBlock = Get-Block $script:Text '\$script:CheckEvidenceManifest\s*=\s*@\{' 'function Get-CheckEvidenceMetadata'
    $script:EvidenceIds   = Get-IdSet $script:EvidenceBlock "(?m)^\s*'([A-Z]{2}\d{2})'\s*=\s*@\{"
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

Describe 'External export version contracts' {
    It 'pins current external taxonomy and schema versions' {
        $expected = [ordered]@{
            AttackEnterprise = '19.1'
            AttackNavigator = '4.5'
            AttackNavigatorApp = '5.3.2'
            D3FEND = '1.4.0'
            OCSF = '1.8.0'
            OSCAL = '1.2.2'
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
        foreach ($nm in 'Get-PrivacyHash','Initialize-PrivacyReplacements','ConvertTo-RedactedText','Get-RedactedIdentity') {
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
        foreach ($nm in 'Get-CheckEvidenceMetadata','Test-ManualEvidenceRequired','Get-AuditExceptions','Get-FrameworkControlSummary') {
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
        $script:FleetBlock | Should -Match '\$hostOutFile\s*=\s*Join-Path \$fleetDir "\$\{safeTarget\}\.html"'
        $script:FleetBlock | Should -Match '\$localJsonPath\s*=\s*\$hostOutFile -replace ''\\\.html\$'', ''_findings\.json'''
        $script:FleetBlock | Should -Match '\$localJson\s*=\s*\$meta\.JsonPath'
    }

    It 'builds localhost child parameters as a typed splat' {
        $script:FleetBlock | Should -Not -Match '\$\(if\(\$NI\)'
        $script:FleetBlock | Should -Match '\$childParams\s*=\s*@\{'
        $script:FleetBlock | Should -Match 'ReadOnly\s*=\s*\[bool\]\$using:ReadOnly'
        $script:FleetBlock | Should -Match 'if \(\$using:fleetNoInternet\) \{ \$childParams\.NoInternet = \$true \}'
    }

    It 'forwards fleet and v4.11 switches during elevation or fails clearly for credentials' {
        $script:ElevationBlock | Should -Match 'Credential cannot be forwarded through a UAC relaunch'
        foreach ($token in '-ExportSIEM','-BrandingConfig','-TargetsCsv','-ThrottleLimit','-PerHostTimeout','-Remediate','-RemediateDryRun','-RemediateChecks','-BenchmarkImportPath') {
            $script:ElevationBlock | Should -Match ([regex]::Escape($token))
        }
    }
}

Describe 'Continuous delta engine (real functions via AST)' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        foreach ($nm in 'Compare-AuditSnapshot','Update-ExposureWindows','Get-AuditAlertPayload') {
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
    It 'carries the exposure first-seen timestamp forward for still-failing findings' {
        $prevExp = @{ IA01 = @{ first_seen='2026-06-01T00:00:00.0000000'; days=0; severity='Critical' } }
        $snap = [ordered]@{ findings=[ordered]@{ IA01=(F 'Fail' 'Critical' 'x'); IA02=(F 'Pass' 'High' 'y') } }
        $now = [datetime]'2026-06-11T00:00:00'
        $exp = Update-ExposureWindows -PrevExposure $prevExp -CurrentSnapshot $snap -Now $now -NowIso $now.ToString('o')
        $exp.Keys | Should -Be @('IA01')                    # IA02 passing -> no exposure
        $exp.IA01.first_seen | Should -Be '2026-06-01T00:00:00.0000000'
        $exp.IA01.days | Should -Be 10                       # 10 days of exposure carried forward
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
