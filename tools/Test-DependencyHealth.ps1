#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$SolutionPath = '',
    [string]$ExceptionsPath = '',
    [string]$OutputPath = '',
    [string]$OfflineReportsDirectory = '',
    [switch]$NoRestore,
    [switch]$Release,
    [datetime]$AsOfDate = (Get-Date)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($SolutionPath)) { $SolutionPath = Join-Path $repoRoot 'NetworkSecurityAuditor.slnx' }
if ([string]::IsNullOrWhiteSpace($ExceptionsPath)) { $ExceptionsPath = Join-Path $PSScriptRoot 'dependency-health-exceptions.json' }

function Assert-DependencyCondition {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Resolve-DependencyPath {
    param([string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) { return [System.IO.Path]::GetFullPath($Path) }
    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Path))
}

function ConvertTo-StableProjectPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $normalized = $Path.Replace('\','/')
    if (-not [System.IO.Path]::IsPathRooted($Path)) { return $normalized.TrimStart('./') }
    $full = [System.IO.Path]::GetFullPath($Path)
    $rootPrefix = $repoRoot.TrimEnd([char]'\',[char]'/') + [System.IO.Path]::DirectorySeparatorChar
    if ($full.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $full.Substring($rootPrefix.Length).Replace('\','/')
    }
    return $full.Replace('\','/')
}

function Read-DependencyJson {
    param([string]$Path, [string]$Label)
    Assert-DependencyCondition (Test-Path -LiteralPath $Path -PathType Leaf) "$Label not found: $Path"
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    Assert-DependencyCondition ($item.Length -le 25MB) "$Label exceeds the 25 MiB input limit."
    try { return Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "$Label is not valid JSON: $($_.Exception.Message)" }
}

function Invoke-DotnetDependencyReport {
    param([string[]]$ModeArguments, [string]$Label)
    $arguments = @('list', $SolutionPath, 'package') + $ModeArguments + @('--include-transitive', '--format', 'json')
    if ($NoRestore) { $arguments += '--no-restore' }
    $output = @(& dotnet @arguments 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE
    $text = $output -join [Environment]::NewLine
    if ($exitCode -ne 0) {
        if ($text.Length -gt 2000) { $text = $text.Substring($text.Length - 2000) }
        throw "dotnet list package $Label failed with exit code $exitCode`: $text"
    }
    $start = $text.IndexOf('{')
    $end = $text.LastIndexOf('}')
    Assert-DependencyCondition ($start -ge 0 -and $end -ge $start) "dotnet list package $Label returned no JSON object."
    try { return $text.Substring($start, $end - $start + 1) | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "dotnet list package $Label returned invalid JSON: $($_.Exception.Message)" }
}

function Get-ReportPackage {
    param($Report)
    $items = @()
    foreach ($project in @($Report.projects)) {
        $projectPath = ConvertTo-StableProjectPath ([string]$project.path)
        $frameworksProperty = $project.PSObject.Properties['frameworks']
        if (-not $frameworksProperty) { continue }
        foreach ($framework in @($frameworksProperty.Value)) {
            $topLevel = $framework.PSObject.Properties['topLevelPackages']
            foreach ($package in @(if($topLevel){$topLevel.Value}else{@()})) {
                $items += [pscustomobject]@{ Project=$projectPath; Framework=[string]$framework.framework; DependencyType='TopLevel'; Package=$package }
            }
            $transitive = $framework.PSObject.Properties['transitivePackages']
            foreach ($package in @(if($transitive){$transitive.Value}else{@()})) {
                $items += [pscustomobject]@{ Project=$projectPath; Framework=[string]$framework.framework; DependencyType='Transitive'; Package=$package }
            }
        }
    }
    return @($items)
}

function Get-PackageKey {
    param([string]$Project, [string]$Framework, [string]$DependencyType, [string]$Id)
    return "$($Project.ToUpperInvariant())|$($Framework.ToUpperInvariant())|$($DependencyType.ToUpperInvariant())|$($Id.ToUpperInvariant())"
}

function Get-UpdateKind {
    param([string]$ResolvedVersion, [string]$LatestVersion)
    $resolvedMatch = [regex]::Match($ResolvedVersion, '^(\d+)\.(\d+)\.(\d+)')
    $latestMatch = [regex]::Match($LatestVersion, '^(\d+)\.(\d+)\.(\d+)')
    if (-not $resolvedMatch.Success -or -not $latestMatch.Success) { return 'Unknown' }
    if ([int]$resolvedMatch.Groups[1].Value -ne [int]$latestMatch.Groups[1].Value) { return 'Major' }
    if ([int]$resolvedMatch.Groups[2].Value -ne [int]$latestMatch.Groups[2].Value) { return 'Minor' }
    if ([int]$resolvedMatch.Groups[3].Value -ne [int]$latestMatch.Groups[3].Value) { return 'Patch' }
    return 'Metadata'
}

function Get-OptionalPropertyText {
    param($Object, [string[]]$Names)
    foreach ($name in $Names) {
        $property = $Object.PSObject.Properties[$name]
        if ($property -and $null -ne $property.Value) { return [string]$property.Value }
    }
    return ''
}

function Get-MatchingDependencyException {
    param($Package, [object[]]$Exceptions, [datetime]$Date)
    foreach ($exception in $Exceptions) {
        if (-not ([string]$exception.package_id).Equals([string]$Package.id, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if ([string]$exception.resolved_version -ne [string]$Package.resolved_version) { continue }
        if ([string]$exception.latest_version -ne [string]$Package.latest_version) { continue }
        if ($exception.PSObject.Properties['project'] -and [string]$exception.project -and [string]$exception.project -ne '*' -and
            -not ([string]$exception.project).Equals([string]$Package.project, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $expires = [datetime]::MinValue
        Assert-DependencyCondition ([datetime]::TryParseExact([string]$exception.expires_on, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$expires)) "Dependency exception '$($exception.name)' has an invalid expires_on date."
        return [ordered]@{
            name = [string]$exception.name
            owner = [string]$exception.owner
            reason = [string]$exception.reason
            expires_on = $expires.ToString('yyyy-MM-dd')
            status = if ($expires.Date -ge $Date.Date) { 'Active' } else { 'Expired' }
        }
    }
    return $null
}

function Write-DependencyReport {
    param($Report, [string]$Path)
    $json = $Report | ConvertTo-Json -Depth 10
    if ([string]::IsNullOrWhiteSpace($Path)) { Write-Output $json; return }
    $resolved = Resolve-DependencyPath $Path
    $parent = Split-Path -Parent $resolved
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [System.IO.File]::WriteAllText($resolved, $json, (New-Object System.Text.UTF8Encoding($false)))
}

try {
    $SolutionPath = Resolve-DependencyPath $SolutionPath
    Assert-DependencyCondition (Test-Path -LiteralPath $SolutionPath -PathType Leaf) "Solution not found: $SolutionPath"
    $ExceptionsPath = Resolve-DependencyPath $ExceptionsPath
    $exceptionDocument = Read-DependencyJson -Path $ExceptionsPath -Label 'Dependency exception file'
    Assert-DependencyCondition ([string]$exceptionDocument.schema_version -eq '1.0') 'Dependency exception schema_version must be 1.0.'
    $exceptions = @($exceptionDocument.exceptions)
    $exceptionNames = @{}
    foreach ($exception in $exceptions) {
        foreach ($field in 'name','package_id','resolved_version','latest_version','owner','reason','expires_on') {
            Assert-DependencyCondition ($exception.PSObject.Properties[$field] -and -not [string]::IsNullOrWhiteSpace([string]$exception.$field)) "Dependency exception is missing required field '$field'."
        }
        $normalizedName = ([string]$exception.name).ToUpperInvariant()
        Assert-DependencyCondition (-not $exceptionNames.ContainsKey($normalizedName)) "Dependency exception name '$($exception.name)' is duplicated."
        $exceptionNames[$normalizedName] = $true
        $expires = [datetime]::MinValue
        Assert-DependencyCondition ([datetime]::TryParseExact([string]$exception.expires_on, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$expires)) "Dependency exception '$($exception.name)' has an invalid expires_on date."
    }

    if ($OfflineReportsDirectory) {
        $reportsDirectory = Resolve-DependencyPath $OfflineReportsDirectory
        Assert-DependencyCondition (Test-Path -LiteralPath $reportsDirectory -PathType Container) "Offline reports directory not found: $reportsDirectory"
        $inventoryReport = Read-DependencyJson -Path (Join-Path $reportsDirectory 'inventory.json') -Label 'Offline inventory report'
        $vulnerableReport = Read-DependencyJson -Path (Join-Path $reportsDirectory 'vulnerable.json') -Label 'Offline vulnerable report'
        $outdatedReport = Read-DependencyJson -Path (Join-Path $reportsDirectory 'outdated.json') -Label 'Offline outdated report'
        $executionMode = 'PrecomputedOffline'
        $restoreBehavior = 'No dotnet command or restore was invoked; results are only as fresh as the supplied reports.'
        $networkBehavior = 'No network access was attempted by this gate.'
    }
    else {
        $inventoryReport = Invoke-DotnetDependencyReport -ModeArguments @() -Label 'inventory'
        $vulnerableReport = Invoke-DotnetDependencyReport -ModeArguments @('--vulnerable') -Label 'vulnerability'
        $outdatedReport = Invoke-DotnetDependencyReport -ModeArguments @('--outdated') -Label 'outdated'
        $executionMode = 'LiveDotnet'
        $restoreBehavior = if ($NoRestore) { 'dotnet --no-restore was used; an existing assets file is required.' } else { 'dotnet may restore projects before listing packages.' }
        $networkBehavior = 'Configured NuGet sources may be queried for vulnerability advisories and latest versions, including with --no-restore.'
    }

    $packageMap = [ordered]@{}
    foreach ($item in Get-ReportPackage $inventoryReport) {
        $package = $item.Package
        $key = Get-PackageKey $item.Project $item.Framework $item.DependencyType ([string]$package.id)
        $packageMap[$key] = [ordered]@{
            project = $item.Project
            framework = $item.Framework
            id = [string]$package.id
            dependency_type = $item.DependencyType
            requested_version = Get-OptionalPropertyText $package @('requestedVersion')
            resolved_version = [string]$package.resolvedVersion
            latest_version = $null
            outdated = $false
            update_kind = $null
            vulnerabilities = @()
            exception = $null
        }
    }

    foreach ($item in Get-ReportPackage $outdatedReport) {
        $package = $item.Package
        $key = Get-PackageKey $item.Project $item.Framework $item.DependencyType ([string]$package.id)
        if (-not $packageMap.Contains($key)) {
            $packageMap[$key] = [ordered]@{ project=$item.Project; framework=$item.Framework; id=[string]$package.id; dependency_type=$item.DependencyType; requested_version=Get-OptionalPropertyText $package @('requestedVersion'); resolved_version=[string]$package.resolvedVersion; latest_version=$null; outdated=$false; update_kind=$null; vulnerabilities=@(); exception=$null }
        }
        $latest = Get-OptionalPropertyText $package @('latestVersion')
        if ($latest -and $latest -ne [string]$package.resolvedVersion) {
            $packageMap[$key].latest_version = $latest
            $packageMap[$key].outdated = $true
            $packageMap[$key].update_kind = Get-UpdateKind ([string]$package.resolvedVersion) $latest
        }
    }

    foreach ($item in Get-ReportPackage $vulnerableReport) {
        $package = $item.Package
        $key = Get-PackageKey $item.Project $item.Framework $item.DependencyType ([string]$package.id)
        if (-not $packageMap.Contains($key)) {
            $packageMap[$key] = [ordered]@{ project=$item.Project; framework=$item.Framework; id=[string]$package.id; dependency_type=$item.DependencyType; requested_version=Get-OptionalPropertyText $package @('requestedVersion'); resolved_version=[string]$package.resolvedVersion; latest_version=$null; outdated=$false; update_kind=$null; vulnerabilities=@(); exception=$null }
        }
        foreach ($vulnerability in @($package.vulnerabilities)) {
            $packageMap[$key].vulnerabilities += [ordered]@{
                severity = Get-OptionalPropertyText $vulnerability @('severity')
                advisory_url = Get-OptionalPropertyText $vulnerability @('advisoryurl','advisoryUrl')
            }
        }
    }

    $packages = @($packageMap.Values | Sort-Object project, framework, dependency_type, id)
    foreach ($package in $packages) {
        if ($package.outdated) { $package.exception = Get-MatchingDependencyException -Package $package -Exceptions $exceptions -Date $AsOfDate }
    }
    $vulnerablePackages = @($packages | Where-Object { @($_.vulnerabilities).Count -gt 0 })
    $vulnerabilityCount = ($vulnerablePackages | ForEach-Object { @($_.vulnerabilities).Count } | Measure-Object -Sum).Sum
    if ($null -eq $vulnerabilityCount) { $vulnerabilityCount = 0 }
    $outdatedPackages = @($packages | Where-Object { $_.outdated })
    $approvedOutdated = @($outdatedPackages | Where-Object { $_.exception -and $_.exception.status -eq 'Active' })
    $unapprovedOutdated = @($outdatedPackages | Where-Object { -not $_.exception -or $_.exception.status -ne 'Active' })

    $decisionStatus = 'Pass'; $exitCode = 0; $reasons = @()
    if ($vulnerablePackages.Count -gt 0) {
        $decisionStatus = 'Fail'; $exitCode = 2
        $reasons += "$($vulnerablePackages.Count) package occurrence(s) have $vulnerabilityCount vulnerability advisory record(s)."
    }
    if ($Release -and $unapprovedOutdated.Count -gt 0) {
        $decisionStatus = 'Fail'; if ($exitCode -eq 0) { $exitCode = 3 }
        $reasons += "$($unapprovedOutdated.Count) outdated package occurrence(s) lack an active exact-version exception."
    }
    elseif ($outdatedPackages.Count -gt 0 -and $decisionStatus -eq 'Pass') {
        $decisionStatus = if ($Release) { 'PassWithExceptions' } else { 'Warning' }
        if ($Release) {
            $reasons += "$($outdatedPackages.Count) outdated package occurrence(s) are covered by active exact-version exceptions."
        }
        else {
            $reasons += "$($outdatedPackages.Count) outdated package occurrence(s) were detected; local mode is warning-only."
        }
    }
    if ($reasons.Count -eq 0) { $reasons += 'No vulnerable or outdated package occurrences were reported.' }

    $vulnerableSources = $vulnerableReport.PSObject.Properties['sources']
    $outdatedSources = $outdatedReport.PSObject.Properties['sources']
    $sources = @(@(if ($vulnerableSources) { $vulnerableSources.Value } else { @() }) +
        @(if ($outdatedSources) { $outdatedSources.Value } else { @() }) |
        Where-Object { $_ } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    $report = [ordered]@{
        schema_version = '1.0'
        generated_at_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        as_of_date = $AsOfDate.ToString('yyyy-MM-dd')
        solution = ConvertTo-StableProjectPath $SolutionPath
        release_mode = [bool]$Release
        execution = [ordered]@{
            mode = $executionMode
            no_restore = [bool]$NoRestore
            restore_behavior = $restoreBehavior
            network_behavior = $networkBehavior
            sources = $sources
        }
        packages = $packages
        summary = [ordered]@{
            package_occurrences = $packages.Count
            direct_occurrences = @($packages | Where-Object { $_.dependency_type -eq 'TopLevel' }).Count
            transitive_occurrences = @($packages | Where-Object { $_.dependency_type -eq 'Transitive' }).Count
            vulnerable_package_occurrences = $vulnerablePackages.Count
            vulnerability_advisories = [int]$vulnerabilityCount
            outdated_package_occurrences = $outdatedPackages.Count
            approved_exception_occurrences = $approvedOutdated.Count
            unapproved_outdated_occurrences = $unapprovedOutdated.Count
            used_exception_names = @($approvedOutdated | ForEach-Object { $_.exception.name } | Sort-Object -Unique)
        }
        decision = [ordered]@{ status=$decisionStatus; exit_code=$exitCode; reasons=$reasons }
    }

    Write-DependencyReport -Report $report -Path $OutputPath
    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        Write-Information "Dependency health: $decisionStatus - $($packages.Count) package occurrence(s), $($vulnerablePackages.Count) vulnerable, $($outdatedPackages.Count) outdated, $($approvedOutdated.Count) excepted." -InformationAction Continue
    }
    exit $exitCode
}
catch {
    [Console]::Error.WriteLine("Dependency health failed: $($_.Exception.Message)")
    exit 1
}
