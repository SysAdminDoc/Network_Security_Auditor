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
$packageName = "NetworkSecurityAuditor-csharp-v$version-windows-net9"
$zipPath = Join-Path $releaseDir "$packageName.zip"
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

$zipHash = Get-Sha256Hex -Path $zipPath
$manifest = [ordered]@{
    project = 'NetworkSecurityAuditor'
    artifact = 'CSharpRewrite'
    version = $version
    configuration = $Configuration
    generated_at_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    git_commit = [string]$commit
    install = [ordered]@{
        package = [System.IO.Path]::GetFileName($zipPath)
        instructions = 'Unzip the package on Windows with .NET 9 Desktop Runtime installed, then run NetworkSecurityAuditor.exe.'
        entrypoint = 'NetworkSecurityAuditor.exe'
        framework = '.NET 9 Desktop Runtime'
    }
    signing = $signing
    artifacts = @(
        [ordered]@{
            file = [System.IO.Path]::GetFileName($zipPath)
            sha256 = $zipHash
        }
    )
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

$hashes = @()
foreach ($file in @($zipPath, $manifestPath)) {
    $hash = Get-Sha256Hex -Path $file
    $hashes += "$hash  $([System.IO.Path]::GetFileName($file))"
}
$hashes | Set-Content -LiteralPath $checksumPath -Encoding ASCII

Write-Host "Release artifact: $zipPath"
Write-Host "Checksum file:    $checksumPath"
Write-Host "Manifest:         $manifestPath"
Write-Host "Signing status:   $($signing.status)"
