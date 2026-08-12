#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ReleaseDir = '',
    [switch]$RequireSignature,
    [string]$OutputJson = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-ReleaseCondition {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Get-ReleaseSha256 {
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        return (($sha.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $stream.Dispose()
        $sha.Dispose()
    }
}

function Read-BoundedJson {
    param([string]$Path, [long]$MaxBytes, [string]$Label)
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    Assert-ReleaseCondition ($item.Length -le $MaxBytes) "$Label exceeds the $MaxBytes-byte verification limit."
    try { return Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "$Label is not valid JSON: $($_.Exception.Message)" }
}

function Resolve-ReleaseFile {
    param([string]$Directory, [string]$Name)
    Assert-ReleaseCondition (-not [string]::IsNullOrWhiteSpace($Name)) 'Release file name is empty.'
    Assert-ReleaseCondition (-not [System.IO.Path]::IsPathRooted($Name)) "Release file name must be relative: $Name"
    Assert-ReleaseCondition ([System.IO.Path]::GetFileName($Name) -eq $Name) "Release file name must not contain a directory: $Name"
    Assert-ReleaseCondition ($Name -notmatch '[\\/]') "Release file name contains a path separator: $Name"
    return Join-Path $Directory $Name
}

function Get-RequiredProperty {
    param($Object, [string]$Name, [string]$Context)
    Assert-ReleaseCondition ($null -ne $Object) "$Context is missing."
    $property = $Object.PSObject.Properties[$Name]
    Assert-ReleaseCondition ($null -ne $property) "$Context.$Name is missing."
    return $property.Value
}

function Read-ZipEntryJson {
    param($Entry, [string]$Label)
    $stream = $Entry.Open()
    $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8, $true)
    try {
        $text = $reader.ReadToEnd()
        try { return $text | ConvertFrom-Json -ErrorAction Stop }
        catch { throw "$Label in the ZIP is not valid JSON: $($_.Exception.Message)" }
    }
    finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

try {
    if ([string]::IsNullOrWhiteSpace($ReleaseDir)) {
        if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'release-manifest.json')) {
            $ReleaseDir = $PSScriptRoot
        }
        else {
            $ReleaseDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts\csharp-release\release'
        }
    }
    elseif (-not [System.IO.Path]::IsPathRooted($ReleaseDir)) {
        $ReleaseDir = Join-Path (Get-Location).Path $ReleaseDir
    }

    $ReleaseDir = [System.IO.Path]::GetFullPath($ReleaseDir)
    Assert-ReleaseCondition (Test-Path -LiteralPath $ReleaseDir -PathType Container) "Release directory not found: $ReleaseDir"

    $checksumPath = Join-Path $ReleaseDir 'SHA256SUMS.txt'
    $manifestPath = Join-Path $ReleaseDir 'release-manifest.json'
    Assert-ReleaseCondition (Test-Path -LiteralPath $checksumPath -PathType Leaf) 'Missing SHA256SUMS.txt.'
    Assert-ReleaseCondition (Test-Path -LiteralPath $manifestPath -PathType Leaf) 'Missing release-manifest.json.'

    $checksumEntries = @{}
    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $checksumPath -ErrorAction Stop) {
        $lineNumber++
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $match = [regex]::Match($line, '^([0-9a-fA-F]{64})  ([^\r\n]+)$')
        Assert-ReleaseCondition $match.Success "Invalid checksum entry on line $lineNumber."
        $name = $match.Groups[2].Value
        $null = Resolve-ReleaseFile -Directory $ReleaseDir -Name $name
        Assert-ReleaseCondition (-not $checksumEntries.ContainsKey($name)) "Duplicate checksum entry: $name"
        $checksumEntries[$name] = $match.Groups[1].Value.ToLowerInvariant()
    }
    Assert-ReleaseCondition ($checksumEntries.Count -gt 0) 'SHA256SUMS.txt has no checksum entries.'
    Assert-ReleaseCondition ($checksumEntries.ContainsKey('release-manifest.json')) 'SHA256SUMS.txt does not cover release-manifest.json.'

    foreach ($name in $checksumEntries.Keys) {
        $path = Resolve-ReleaseFile -Directory $ReleaseDir -Name $name
        Assert-ReleaseCondition (Test-Path -LiteralPath $path -PathType Leaf) "Checksum entry is missing its file: $name"
        $actualHash = Get-ReleaseSha256 -Path $path
        Assert-ReleaseCondition ($actualHash -eq $checksumEntries[$name]) "Checksum mismatch for $name."
    }

    $manifest = Read-BoundedJson -Path $manifestPath -MaxBytes 5MB -Label 'release-manifest.json'
    Assert-ReleaseCondition ((Get-RequiredProperty $manifest 'schema_version' 'manifest') -eq '1.0') 'Unsupported release manifest schema_version.'
    Assert-ReleaseCondition ((Get-RequiredProperty $manifest 'project' 'manifest') -eq 'NetworkSecurityAuditor') 'Unexpected manifest project.'
    $version = [string](Get-RequiredProperty $manifest 'version' 'manifest')
    Assert-ReleaseCondition ($version -match '^\d+\.\d+\.\d+$') 'Manifest version is invalid.'

    $install = Get-RequiredProperty $manifest 'install' 'manifest'
    $runtimeSupport = Get-RequiredProperty $manifest 'runtime_support' 'manifest'
    $archive = Get-RequiredProperty $manifest 'archive' 'manifest'
    $sbomInfo = Get-RequiredProperty $manifest 'sbom' 'manifest'
    $verification = Get-RequiredProperty $manifest 'verification' 'manifest'
    $checksums = Get-RequiredProperty $manifest 'checksums' 'manifest'
    Assert-ReleaseCondition ([string]$checksums.algorithm -eq 'SHA256') 'Manifest checksum algorithm must be SHA256.'
    Assert-ReleaseCondition ([string]$checksums.file -eq 'SHA256SUMS.txt') 'Manifest checksum file must be SHA256SUMS.txt.'

    $packageName = [string](Get-RequiredProperty $install 'package' 'manifest.install')
    $entrypoint = [string](Get-RequiredProperty $install 'entrypoint' 'manifest.install')
    $sbomName = [string](Get-RequiredProperty $sbomInfo 'file' 'manifest.sbom')
    $verifierName = [string](Get-RequiredProperty $verification 'tool' 'manifest.verification')
    $requiredNames = @($packageName, $sbomName, $verifierName, 'release-manifest.json')
    foreach ($requiredName in $requiredNames) {
        $null = Resolve-ReleaseFile -Directory $ReleaseDir -Name $requiredName
        Assert-ReleaseCondition ($checksumEntries.ContainsKey($requiredName)) "SHA256SUMS.txt is missing required entry $requiredName."
    }

    $coveredNames = @($checksums.covered_files | ForEach-Object { [string]$_ })
    foreach ($requiredName in $requiredNames) {
        Assert-ReleaseCondition ($coveredNames -contains $requiredName) "Manifest checksum coverage omits $requiredName."
    }
    Assert-ReleaseCondition ($coveredNames.Count -eq $checksumEntries.Count) 'Manifest checksum coverage count differs from SHA256SUMS.txt.'
    foreach ($checksumName in $checksumEntries.Keys) {
        Assert-ReleaseCondition ($coveredNames -contains $checksumName) "Checksum entry is not declared by the manifest: $checksumName"
    }

    $artifactEntries = @($manifest.artifacts)
    Assert-ReleaseCondition ($artifactEntries.Count -ge 3) 'Manifest artifacts must include ZIP, SBOM, and verifier files.'
    foreach ($artifact in $artifactEntries) {
        $artifactName = [string](Get-RequiredProperty $artifact 'file' 'manifest.artifacts[]')
        $expectedHash = ([string](Get-RequiredProperty $artifact 'sha256' 'manifest.artifacts[]')).ToLowerInvariant()
        Assert-ReleaseCondition ($expectedHash -match '^[0-9a-f]{64}$') "Manifest artifact hash is invalid for $artifactName."
        $artifactPath = Resolve-ReleaseFile -Directory $ReleaseDir -Name $artifactName
        Assert-ReleaseCondition (Test-Path -LiteralPath $artifactPath -PathType Leaf) "Manifest artifact is missing: $artifactName"
        $actualHash = Get-ReleaseSha256 -Path $artifactPath
        Assert-ReleaseCondition ($actualHash -eq $expectedHash) "Manifest hash mismatch for $artifactName."
        Assert-ReleaseCondition ($checksumEntries[$artifactName] -eq $expectedHash) "Manifest and SHA256SUMS.txt disagree for $artifactName."
    }

    $zipPath = Resolve-ReleaseFile -Directory $ReleaseDir -Name $packageName
    $sbomPath = Resolve-ReleaseFile -Directory $ReleaseDir -Name $sbomName
    Assert-ReleaseCondition ([string]$archive.file -eq $packageName) 'Manifest archive.file differs from install.package.'
    Assert-ReleaseCondition ([string]$archive.format -eq 'zip') 'Manifest archive format must be zip.'
    Assert-ReleaseCondition ([string]$archive.entrypoint -eq $entrypoint) 'Manifest archive entrypoint differs from install.entrypoint.'
    Assert-ReleaseCondition ([string]$sbomInfo.sha256 -eq (Get-ReleaseSha256 -Path $sbomPath)) 'Manifest SBOM hash does not match bytes.'

    $sbom = Read-BoundedJson -Path $sbomPath -MaxBytes 50MB -Label 'CycloneDX SBOM'
    $specVersion = [string](Get-RequiredProperty $sbom 'specVersion' 'SBOM')
    Assert-ReleaseCondition ([string](Get-RequiredProperty $sbom 'bomFormat' 'SBOM') -eq 'CycloneDX') 'SBOM bomFormat must be CycloneDX.'
    Assert-ReleaseCondition ($specVersion -eq [string]$sbomInfo.spec_version) 'SBOM specVersion differs from the manifest.'
    Assert-ReleaseCondition ($specVersion -eq '1.5') 'Unsupported CycloneDX specVersion.'
    Assert-ReleaseCondition ([string](Get-RequiredProperty $sbom '$schema' 'SBOM') -eq 'https://cyclonedx.org/schema/bom-1.5.schema.json') 'SBOM does not declare the CycloneDX 1.5 JSON schema.'
    Assert-ReleaseCondition ([int](Get-RequiredProperty $sbom 'version' 'SBOM') -ge 1) 'SBOM version must be at least 1.'
    $rootComponent = Get-RequiredProperty (Get-RequiredProperty $sbom 'metadata' 'SBOM') 'component' 'SBOM.metadata'
    Assert-ReleaseCondition ([string]$rootComponent.name -eq 'NetworkSecurityAuditor') 'SBOM root component name is invalid.'
    Assert-ReleaseCondition ([string]$rootComponent.version -eq $version) 'SBOM root component version differs from the manifest.'
    Assert-ReleaseCondition (@($sbom.components).Count -eq [int]$sbomInfo.component_count) 'SBOM component count differs from the manifest.'

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
    $temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('nsa-release-verify-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $temporaryDirectory -Force | Out-Null
    try {
        $entriesByName = @{}
        [long]$uncompressedBytes = 0
        foreach ($entry in $zip.Entries) {
            $entryName = $entry.FullName.Replace('\\', '/')
            Assert-ReleaseCondition (-not [string]::IsNullOrWhiteSpace($entryName)) 'ZIP contains an unnamed entry.'
            Assert-ReleaseCondition (-not $entryName.StartsWith('/') -and $entryName -notmatch '(^|/)\.\.(/|$)' -and $entryName -notmatch '^[A-Za-z]:') "ZIP contains unsafe entry $entryName."
            Assert-ReleaseCondition (-not $entriesByName.ContainsKey($entryName)) "ZIP contains duplicate entry $entryName."
            $entriesByName[$entryName] = $entry
            $uncompressedBytes += [long]$entry.Length
        }
        Assert-ReleaseCondition ($entriesByName.ContainsKey($entrypoint)) "ZIP entrypoint is missing: $entrypoint"
        Assert-ReleaseCondition ($zip.Entries.Count -eq [int]$archive.entry_count) 'ZIP entry count differs from the manifest.'
        Assert-ReleaseCondition ($uncompressedBytes -eq [long]$archive.uncompressed_bytes) 'ZIP uncompressed byte count differs from the manifest.'

        $runtimeConfigName = [string](Get-RequiredProperty $archive 'runtime_config' 'manifest.archive')
        $depsName = [string](Get-RequiredProperty $archive 'deps_file' 'manifest.archive')
        Assert-ReleaseCondition ($entriesByName.ContainsKey($runtimeConfigName)) "ZIP runtime config is missing: $runtimeConfigName"
        Assert-ReleaseCondition ($entriesByName.ContainsKey($depsName)) "ZIP dependency metadata is missing: $depsName"
        $runtimeConfig = Read-ZipEntryJson -Entry $entriesByName[$runtimeConfigName] -Label $runtimeConfigName
        $runtimeOptions = Get-RequiredProperty $runtimeConfig 'runtimeOptions' 'runtimeconfig'
        $targetFramework = [string](Get-RequiredProperty $manifest 'target_framework' 'manifest')
        $runtimeTfm = [string](Get-RequiredProperty $runtimeOptions 'tfm' 'runtimeconfig.runtimeOptions')
        Assert-ReleaseCondition ($targetFramework -match '^net(\d+)\.\d+-windows$') 'Manifest target_framework is not a Windows target.'
        $targetMajor = [int]$matches[1]
        Assert-ReleaseCondition ($runtimeTfm -match "^net$targetMajor\.") 'Runtime config TFM differs from manifest target framework.'
        $runtimeFrameworks = if ($runtimeOptions.PSObject.Properties['frameworks']) { @($runtimeOptions.frameworks) } else { @($runtimeOptions.framework) }
        $desktopFramework = @($runtimeFrameworks | Where-Object { $_ -and [string]$_.name -eq 'Microsoft.WindowsDesktop.App' }) | Select-Object -First 1
        Assert-ReleaseCondition ($null -ne $desktopFramework) 'Runtime config does not require Microsoft.WindowsDesktop.App.'
        Assert-ReleaseCondition ([string]$desktopFramework.version -match "^$targetMajor\.") 'Windows Desktop runtime major version differs from the manifest target.'
        Assert-ReleaseCondition ([string]$install.framework -eq [string]$runtimeSupport.framework) 'Install and runtime-support framework metadata disagree.'
        Assert-ReleaseCondition ([string]$runtimeSupport.target_framework -eq $targetFramework) 'Runtime-support target framework differs from the manifest target.'

        $peEntries = @($zip.Entries | Where-Object { $_.FullName -match '\.(exe|dll)$' })
        Assert-ReleaseCondition ($peEntries.Count -gt 0) 'ZIP contains no executable or library files.'
        $signatureResults = @()
        foreach ($entry in $peEntries) {
            $safeRelative = $entry.FullName.Replace('/', [System.IO.Path]::DirectorySeparatorChar)
            $extractPath = Join-Path $temporaryDirectory $safeRelative
            $extractParent = Split-Path -Parent $extractPath
            if (-not (Test-Path -LiteralPath $extractParent)) { New-Item -ItemType Directory -Path $extractParent -Force | Out-Null }
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $extractPath, $true)
            try {
                $signature = Get-AuthenticodeSignature -LiteralPath $extractPath -ErrorAction Stop
                $signatureResults += [ordered]@{ file=$entry.FullName; status=[string]$signature.Status; thumbprint=if($signature.SignerCertificate){[string]$signature.SignerCertificate.Thumbprint}else{''} }
            }
            catch {
                $signatureResults += [ordered]@{ file=$entry.FullName; status='Error'; thumbprint=''; error=$_.Exception.Message }
            }
        }

        $signingState = [string](Get-RequiredProperty (Get-RequiredProperty $manifest 'signing' 'manifest') 'status' 'manifest.signing')
        $invalidSignatures = @($signatureResults | Where-Object { $_.status -ne 'Valid' })
        if ($signingState -eq 'Signed') {
            Assert-ReleaseCondition ($invalidSignatures.Count -eq 0) "Manifest claims Signed but $($invalidSignatures.Count) PE file(s) lack a valid Authenticode signature."
            $expectedThumbprint = [string]$manifest.signing.certificate_thumbprint
            if ($expectedThumbprint) {
                Assert-ReleaseCondition (@($signatureResults | Where-Object { $_.thumbprint -ne $expectedThumbprint }).Count -eq 0) 'Authenticode signer thumbprint differs from the manifest.'
            }
            Write-Host "Authenticode: valid on $($signatureResults.Count) PE file(s)."
        }
        else {
            Write-Host "Authenticode: not signed ($signingState); signature was not claimed."
        }
        if ($RequireSignature) {
            Assert-ReleaseCondition ($signingState -eq 'Signed') "A signature is required, but manifest signing status is $signingState."
            Assert-ReleaseCondition ($invalidSignatures.Count -eq 0) 'A signature is required, but one or more PE signatures are invalid.'
        }

        $result = [ordered]@{
            status = 'Verified'
            release_directory = $ReleaseDir
            project = [string]$manifest.project
            version = $version
            package = $packageName
            target_framework = $targetFramework
            checksum_entries = $checksumEntries.Count
            zip_entries = $zip.Entries.Count
            sbom_spec_version = $specVersion
            sbom_components = @($sbom.components).Count
            manifest_signing_status = $signingState
            signature_required = [bool]$RequireSignature
            authenticode = $signatureResults
        }
        if ($OutputJson) {
            $jsonPath = if ([System.IO.Path]::IsPathRooted($OutputJson)) { $OutputJson } else { Join-Path (Get-Location).Path $OutputJson }
            $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
        }
        Write-Host "VERIFIED: $packageName (v$version, $targetFramework, CycloneDX $specVersion)." -ForegroundColor Green
    }
    finally {
        $zip.Dispose()
        if (Test-Path -LiteralPath $temporaryDirectory) { Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
catch {
    [Console]::Error.WriteLine("Release verification failed: $($_.Exception.Message)")
    exit 1
}
