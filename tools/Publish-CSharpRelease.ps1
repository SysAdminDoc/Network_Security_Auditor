[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [string]$ArtifactsDir = '',
    [switch]$SkipTests,
    [switch]$SkipSigning,
    [string]$TimestampServer = 'http://timestamp.digicert.com'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$solutionPath = Join-Path $repoRoot 'NetworkSecurityAuditor.slnx'
$projectPath = Join-Path $repoRoot 'src\NetworkSecurityAuditor\NetworkSecurityAuditor.csproj'

if ([string]::IsNullOrWhiteSpace($ArtifactsDir)) {
    $ArtifactsDir = Join-Path $repoRoot 'artifacts\csharp-release'
}

function Resolve-RepoPath {
    param([string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
}

function Assert-UnderRepo {
    param([string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $repoRootWithSeparator = $repoRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.Equals($repoRoot, [System.StringComparison]::OrdinalIgnoreCase) -and
        -not $fullPath.StartsWith($repoRootWithSeparator, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to write outside repo root: $fullPath"
    }
}

$resolvedArtifactsDir = Resolve-RepoPath $ArtifactsDir

function Invoke-Checked {
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )

    Write-Host ">> $FilePath $($Arguments -join ' ')"
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE"
    }
}

function Get-ProjectVersion {
    [xml]$project = Get-Content -LiteralPath $projectPath -Raw
    $versionNode = $project.Project.PropertyGroup.Version | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($versionNode)) {
        throw "Project version not found in $projectPath"
    }

    return [string]$versionNode
}

function Get-ProjectTargetFramework {
    [xml]$project = Get-Content -LiteralPath $projectPath -Raw
    $targetFrameworkNode = $project.Project.PropertyGroup.TargetFramework | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($targetFrameworkNode)) {
        throw "Project target framework not found in $projectPath"
    }

    return [string]$targetFrameworkNode
}

function Get-CodeSigningCertificate {
    $stores = @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')
    foreach ($store in $stores) {
        try {
            if (-not (Test-Path $store)) {
                continue
            }

            $cert = Get-ChildItem -Path $store -CodeSigningCert -ErrorAction Stop |
                Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) } |
                Sort-Object NotAfter -Descending |
                Select-Object -First 1
            if ($cert) {
                return $cert
            }
        }
        catch {
            Write-Warning "Could not inspect certificate store $store`: $($_.Exception.Message)"
        }
    }

    return $null
}

function Set-ReleaseSignature {
    param(
        [string[]]$Paths,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $signed = @()
    foreach ($path in $Paths) {
        try {
            $signature = Set-AuthenticodeSignature -LiteralPath $path -Certificate $Certificate -TimestampServer $TimestampServer -ErrorAction Stop
        }
        catch {
            Write-Warning "Timestamped signing failed for $path; retrying without timestamp. $($_.Exception.Message)"
            $signature = Set-AuthenticodeSignature -LiteralPath $path -Certificate $Certificate -ErrorAction Stop
        }

        if ($signature.Status -ne 'Valid') {
            throw "Signing failed for $path with status $($signature.Status): $($signature.StatusMessage)"
        }

        $signed += [ordered]@{
            path = [System.IO.Path]::GetRelativePath($repoRoot, $path)
            status = [string]$signature.Status
            signer = $Certificate.Subject
            thumbprint = $Certificate.Thumbprint
        }
    }

    return $signed
}

function Get-Sha256Hex {
    param([string]$Path)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $hashBytes = $sha256.ComputeHash($stream)
        return (($hashBytes | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $stream.Dispose()
        $sha256.Dispose()
    }
}

function Resolve-NuGetPackageRoot {
    if (-not [string]::IsNullOrWhiteSpace($env:NUGET_PACKAGES)) {
        return [System.IO.Path]::GetFullPath($env:NUGET_PACKAGES)
    }

    return [System.IO.Path]::Combine(
        [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile),
        '.nuget',
        'packages')
}

function Get-NuGetPackageMetadata {
    param(
        [string]$PackageId,
        [string]$Version
    )

    $packageRoot = Resolve-NuGetPackageRoot
    $packageDir = Join-Path (Join-Path $packageRoot $PackageId.ToLowerInvariant()) $Version
    $metadata = [ordered]@{
        license_expression = ''
        license_url = ''
        authors = ''
        project_url = ''
    }

    if (-not (Test-Path -LiteralPath $packageDir)) {
        return $metadata
    }

    $nuspec = Get-ChildItem -LiteralPath $packageDir -Filter '*.nuspec' -File -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $nuspec) {
        return $metadata
    }

    try {
        [xml]$nuspecXml = Get-Content -LiteralPath $nuspec.FullName -Raw
        $metadataNode = $nuspecXml.package.metadata
        if ($metadataNode.license) {
            $metadata.license_expression = [string]$metadataNode.license.InnerText
        }

        if ($metadataNode.licenseUrl) {
            $metadata.license_url = [string]$metadataNode.licenseUrl
        }

        if ($metadataNode.authors) {
            $metadata.authors = [string]$metadataNode.authors
        }

        if ($metadataNode.projectUrl) {
            $metadata.project_url = [string]$metadataNode.projectUrl
        }
    }
    catch {
        Write-Warning "Could not parse package metadata for $PackageId $Version`: $($_.Exception.Message)"
    }

    return $metadata
}

function Get-PackageInventory {
    $jsonText = (& dotnet list $projectPath package --include-transitive --format json) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet list package failed with exit code $LASTEXITCODE"
    }

    $packageGraph = $jsonText | ConvertFrom-Json
    $packages = [ordered]@{}
    foreach ($project in $packageGraph.projects) {
        foreach ($framework in $project.frameworks) {
            foreach ($package in @($framework.topLevelPackages)) {
                $key = "$($package.id)|$($package.resolvedVersion)"
                if (-not $packages.Contains($key)) {
                    $metadata = Get-NuGetPackageMetadata -PackageId $package.id -Version $package.resolvedVersion
                    $packages[$key] = [ordered]@{
                        name = [string]$package.id
                        version = [string]$package.resolvedVersion
                        requested_version = [string]$package.requestedVersion
                        dependency_type = 'TopLevel'
                        license_expression = [string]$metadata.license_expression
                        license_url = [string]$metadata.license_url
                        authors = [string]$metadata.authors
                        project_url = [string]$metadata.project_url
                        purl = "pkg:nuget/$($package.id)@$($package.resolvedVersion)"
                    }
                }
            }

            foreach ($package in @($framework.transitivePackages)) {
                $key = "$($package.id)|$($package.resolvedVersion)"
                if (-not $packages.Contains($key)) {
                    $metadata = Get-NuGetPackageMetadata -PackageId $package.id -Version $package.resolvedVersion
                    $packages[$key] = [ordered]@{
                        name = [string]$package.id
                        version = [string]$package.resolvedVersion
                        requested_version = ''
                        dependency_type = 'Transitive'
                        license_expression = [string]$metadata.license_expression
                        license_url = [string]$metadata.license_url
                        authors = [string]$metadata.authors
                        project_url = [string]$metadata.project_url
                        purl = "pkg:nuget/$($package.id)@$($package.resolvedVersion)"
                    }
                }
            }
        }
    }

    return @($packages.Values | Sort-Object name, version)
}

function New-CycloneDxLicense {
    param([object]$Package)

    if (-not [string]::IsNullOrWhiteSpace($Package.license_expression)) {
        return @([ordered]@{ expression = $Package.license_expression })
    }

    if (-not [string]::IsNullOrWhiteSpace($Package.license_url)) {
        return @([ordered]@{
            license = [ordered]@{
                name = $Package.license_url
                url = $Package.license_url
            }
        })
    }

    return @([ordered]@{ license = [ordered]@{ name = 'Unknown' } })
}

function Write-CycloneDxSbom {
    param(
        [string]$Path,
        [string]$Version,
        [string]$TargetFramework,
        [object[]]$Packages
    )

    $components = @()
    foreach ($package in $Packages) {
        $component = [ordered]@{
            type = 'library'
            'bom-ref' = $package.purl
            name = $package.name
            version = $package.version
            scope = 'required'
            purl = $package.purl
            licenses = New-CycloneDxLicense -Package $package
            properties = @(
                [ordered]@{ name = 'nuget:dependency_type'; value = $package.dependency_type }
            )
        }

        if (-not [string]::IsNullOrWhiteSpace($package.authors)) {
            $component.author = $package.authors
        }

        if (-not [string]::IsNullOrWhiteSpace($package.project_url)) {
            $component.externalReferences = @(
                [ordered]@{
                    type = 'website'
                    url = $package.project_url
                }
            )
        }

        $components += $component
    }

    $rootComponentRef = "pkg:generic/NetworkSecurityAuditor@$Version"
    $bom = [ordered]@{
        bomFormat = 'CycloneDX'
        specVersion = '1.5'
        serialNumber = "urn:uuid:$([guid]::NewGuid())"
        version = 1
        metadata = [ordered]@{
            timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            tools = @(
                [ordered]@{
                    vendor = 'NetworkSecurityAuditor'
                    name = 'Publish-CSharpRelease.ps1'
                    version = $Version
                }
            )
            component = [ordered]@{
                type = 'application'
                'bom-ref' = $rootComponentRef
                name = 'NetworkSecurityAuditor'
                version = $Version
                properties = @(
                    [ordered]@{ name = 'dotnet:target_framework'; value = $TargetFramework },
                    [ordered]@{ name = 'dotnet:runtime'; value = '.NET 10 Desktop Runtime' }
                )
            }
        }
        components = $components
        dependencies = @(
            [ordered]@{
                ref = $rootComponentRef
                dependsOn = @($Packages | ForEach-Object { $_.purl })
            }
        )
    }

    $bom | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding UTF8
}

Assert-UnderRepo $resolvedArtifactsDir

if (Test-Path -LiteralPath $resolvedArtifactsDir) {
    Remove-Item -LiteralPath $resolvedArtifactsDir -Recurse -Force
}

$publishDir = Join-Path $resolvedArtifactsDir 'publish\NetworkSecurityAuditor'
$releaseDir = Join-Path $resolvedArtifactsDir 'release'
New-Item -ItemType Directory -Path $publishDir, $releaseDir -Force | Out-Null

if (-not $SkipTests) {
    Invoke-Checked dotnet @('test', $solutionPath, '-c', $Configuration, '--no-restore')
}

Invoke-Checked dotnet @(
    'publish',
    $projectPath,
    '-c',
    $Configuration,
    '-o',
    $publishDir,
    '--no-restore',
    '-p:SelfContained=false'
)

$version = Get-ProjectVersion
$targetFramework = Get-ProjectTargetFramework
$packageName = "NetworkSecurityAuditor-csharp-v$version-windows-net10"
$zipPath = Join-Path $releaseDir "$packageName.zip"
$sbomPath = Join-Path $releaseDir "$packageName.cdx.json"
$checksumPath = Join-Path $releaseDir 'SHA256SUMS.txt'
$manifestPath = Join-Path $releaseDir 'release-manifest.json'
$commit = (git -C $repoRoot rev-parse HEAD 2>$null)
if ($LASTEXITCODE -ne 0) {
    $commit = ''
}

$peFiles = Get-ChildItem -LiteralPath $publishDir -Recurse -Include '*.exe', '*.dll' -File |
    Sort-Object FullName |
    Select-Object -ExpandProperty FullName
$signing = [ordered]@{
    status = 'Skipped'
    signed_files = @()
    certificate_subject = ''
    certificate_thumbprint = ''
}

if ($SkipSigning) {
    $signing.status = 'SkippedByParameter'
}
else {
    $certificate = Get-CodeSigningCertificate
    if ($certificate) {
        $signedFiles = Set-ReleaseSignature -Paths $peFiles -Certificate $certificate
        $signing.status = 'Signed'
        $signing.signed_files = $signedFiles
        $signing.certificate_subject = $certificate.Subject
        $signing.certificate_thumbprint = $certificate.Thumbprint
    }
    else {
        $signing.status = 'NoCodeSigningCertificate'
        Write-Warning 'No valid local code-signing certificate was found; release package remains unsigned.'
    }
}

Compress-Archive -Path (Join-Path $publishDir '*') -DestinationPath $zipPath -Force

$packageInventory = Get-PackageInventory
Write-CycloneDxSbom -Path $sbomPath -Version $version -TargetFramework $targetFramework -Packages $packageInventory

$zipHash = Get-Sha256Hex -Path $zipPath
$sbomHash = Get-Sha256Hex -Path $sbomPath
$manifest = [ordered]@{
    project = 'NetworkSecurityAuditor'
    artifact = 'CSharpRewrite'
    version = $version
    configuration = $Configuration
    target_framework = $targetFramework
    generated_at_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    git_commit = [string]$commit
    install = [ordered]@{
        package = [System.IO.Path]::GetFileName($zipPath)
        instructions = 'Unzip the package on Windows with .NET 10 Desktop Runtime installed, then run NetworkSecurityAuditor.exe.'
        entrypoint = 'NetworkSecurityAuditor.exe'
        framework = '.NET 10 Desktop Runtime'
    }
    runtime_support = [ordered]@{
        framework = '.NET 10 Desktop Runtime'
        target_framework = $targetFramework
        support_policy = 'LTS'
        support_status = 'Supported'
        support_end_date = '2028-11-14'
        source = 'https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core'
    }
    signing = $signing
    sbom = [ordered]@{
        format = 'CycloneDX'
        spec_version = '1.5'
        file = [System.IO.Path]::GetFileName($sbomPath)
        sha256 = $sbomHash
        component_count = $packageInventory.Count
    }
    package_inventory = $packageInventory
    artifacts = @(
        [ordered]@{
            file = [System.IO.Path]::GetFileName($zipPath)
            sha256 = $zipHash
        },
        [ordered]@{
            file = [System.IO.Path]::GetFileName($sbomPath)
            sha256 = $sbomHash
        }
    )
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

$hashes = @()
foreach ($file in @($zipPath, $sbomPath, $manifestPath)) {
    $hash = Get-Sha256Hex -Path $file
    $hashes += "$hash  $([System.IO.Path]::GetFileName($file))"
}
$hashes | Set-Content -LiteralPath $checksumPath -Encoding ASCII

Write-Host "Release artifact: $zipPath"
Write-Host "Checksum file:    $checksumPath"
Write-Host "Manifest:         $manifestPath"
Write-Host "Signing status:   $($signing.status)"
