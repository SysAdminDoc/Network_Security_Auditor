<#
.SYNOPSIS
    WCAG 2.2 AA contrast validation for all NetworkSecurityAudit themes.
.DESCRIPTION
    Extracts color tokens from each theme and severity palette, computes
    WCAG 2.2 relative-luminance contrast ratios for every foreground/background
    pair, and fails if any pair violates AA thresholds (4.5:1 text, 3:1 UI).
.NOTES
    Exit 0 = all pass, Exit 1 = failures found.
    Run: pwsh -File tools/Test-ThemeContrast.ps1
         powershell -File tools/Test-ThemeContrast.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$scriptPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\NetworkSecurityAudit.ps1'))

if (-not (Test-Path $scriptPath)) {
    Write-Host "FAIL: Cannot find $scriptPath" -ForegroundColor Red
    exit 1
}

$content = [System.IO.File]::ReadAllText($scriptPath)

# ── Parse theme definitions ─────────────────────────────────────────────────

function ConvertTo-ThemeHash {
    param([string]$block)
    $theme = @{}
    $pairs = [regex]::Matches($block, "(\w+)\s*=\s*'(#[0-9a-fA-F]{6})'")
    foreach ($m in $pairs) {
        $theme[$m.Groups[1].Value] = $m.Groups[2].Value
    }
    $theme
}

$themes = [ordered]@{}
$themePattern = "'([^']+)'\s*=\s*@\{([^}]+)\}"
$themeMatches = [regex]::Matches($content, $themePattern)
foreach ($m in $themeMatches) {
    $name = $m.Groups[1].Value
    $body = $m.Groups[2].Value
    if ($body -match 'WindowBg' -and $body -match 'TextPrimary') {
        $themes[$name] = ConvertTo-ThemeHash $body
    }
}

if ($themes.Count -eq 0) {
    Write-Host 'FAIL: No themes extracted from script.' -ForegroundColor Red
    exit 1
}

# ── Parse severity colors ───────────────────────────────────────────────────

$severityColors = @{}
$sevPattern = "(\w+)\s*=\s*'(#[0-9a-fA-F]{6})'"
$sevBlock = [regex]::Match($content, '\$script:SeverityColors\s*=\s*@\{([^}]+)\}')
if ($sevBlock.Success) {
    $sevMatches = [regex]::Matches($sevBlock.Groups[1].Value, $sevPattern)
    foreach ($m in $sevMatches) {
        $severityColors[$m.Groups[1].Value] = $m.Groups[2].Value
    }
}

# ── WCAG 2.2 contrast computation ───────────────────────────────────────────

function ConvertFrom-Hex {
    param([string]$hex)
    $hex = $hex.TrimStart('#')
    $r = [Convert]::ToInt32($hex.Substring(0,2), 16) / 255.0
    $g = [Convert]::ToInt32($hex.Substring(2,2), 16) / 255.0
    $b = [Convert]::ToInt32($hex.Substring(4,2), 16) / 255.0
    @($r, $g, $b)
}

function Get-LinearChannel {
    param([double]$c)
    if ($c -le 0.04045) { $c / 12.92 }
    else { [Math]::Pow(($c + 0.055) / 1.055, 2.4) }
}

function Get-RelativeLuminance {
    param([string]$hex)
    $rgb = ConvertFrom-Hex $hex
    $rl = Get-LinearChannel $rgb[0]
    $gl = Get-LinearChannel $rgb[1]
    $bl = Get-LinearChannel $rgb[2]
    0.2126 * $rl + 0.7152 * $gl + 0.0722 * $bl
}

function Get-ContrastRatio {
    param([string]$fg, [string]$bg)
    $l1 = Get-RelativeLuminance $fg
    $l2 = Get-RelativeLuminance $bg
    if ($l1 -lt $l2) { $tmp = $l1; $l1 = $l2; $l2 = $tmp }
    ($l1 + 0.05) / ($l2 + 0.05)
}

# ── Define contrast pairs ───────────────────────────────────────────────────
# Type: 'text' = 4.5:1, 'ui' = 3:1

$contrastPairs = @(
    # Primary text on backgrounds
    @{ FG='TextPrimary'; BG='WindowBg';   Type='text'; Label='Primary text on window' }
    @{ FG='TextPrimary'; BG='PanelBg';    Type='text'; Label='Primary text on panel' }
    @{ FG='TextPrimary'; BG='CardBg';     Type='text'; Label='Primary text on card' }
    @{ FG='TextPrimary'; BG='SurfaceBg';  Type='text'; Label='Primary text on surface' }
    @{ FG='TextPrimary'; BG='InputBg';    Type='text'; Label='Primary text on input' }
    @{ FG='TextPrimary'; BG='HoverBg';    Type='text'; Label='Primary text on hover' }
    @{ FG='TextPrimary'; BG='HintBg';     Type='text'; Label='Primary text on hint' }
    @{ FG='TextPrimary'; BG='CheckedBg';  Type='text'; Label='Primary text on checked' }

    # Secondary text on backgrounds
    @{ FG='TextSecondary'; BG='WindowBg';   Type='text'; Label='Secondary text on window' }
    @{ FG='TextSecondary'; BG='PanelBg';    Type='text'; Label='Secondary text on panel' }
    @{ FG='TextSecondary'; BG='CardBg';     Type='text'; Label='Secondary text on card' }
    @{ FG='TextSecondary'; BG='SurfaceBg';  Type='text'; Label='Secondary text on surface' }
    @{ FG='TextSecondary'; BG='InputBg';    Type='text'; Label='Secondary text on input' }

    # Accent as UI component
    @{ FG='Accent';      BG='WindowBg';  Type='ui'; Label='Accent on window' }
    @{ FG='Accent';      BG='PanelBg';   Type='ui'; Label='Accent on panel' }
    @{ FG='Accent';      BG='CardBg';    Type='ui'; Label='Accent on card' }
    @{ FG='Accent';      BG='SurfaceBg'; Type='ui'; Label='Accent on surface' }
    @{ FG='AccentHover';  BG='PanelBg';  Type='ui'; Label='AccentHover on panel' }

    # Border/component contrast
    @{ FG='BorderDim';    BG='WindowBg';  Type='ui'; Label='Border on window' }
    @{ FG='BorderDim';    BG='PanelBg';   Type='ui'; Label='Border on panel' }
    @{ FG='BorderDim';    BG='CardBg';    Type='ui'; Label='Border on card' }

    # Progress indicators
    @{ FG='ProgressGood'; BG='BarBg';     Type='ui'; Label='ProgressGood on bar' }
    @{ FG='ProgressMid';  BG='BarBg';     Type='ui'; Label='ProgressMid on bar' }

    # Checked state
    @{ FG='CheckedBorder'; BG='CheckedBg'; Type='ui'; Label='CheckedBorder on checked bg' }

    # Hint area
    @{ FG='HintBorder'; BG='HintBg'; Type='ui'; Label='HintBorder on hint bg' }

    # Scroll thumb
    @{ FG='ThumbBg'; BG='WindowBg'; Type='ui'; Label='Thumb on window' }
    @{ FG='ThumbBg'; BG='PanelBg';  Type='ui'; Label='Thumb on panel' }
)

# ── Run checks ──────────────────────────────────────────────────────────────

$totalChecks = 0
$failures = @()
$warnings = @()

Write-Host ''
Write-Host '=== Theme Contrast Validation (WCAG 2.2 AA) ===' -ForegroundColor Cyan
Write-Host ''

foreach ($themeName in $themes.Keys) {
    $t = $themes[$themeName]
    $themeFailCount = 0
    Write-Host "  Theme: $themeName" -ForegroundColor White

    foreach ($pair in $contrastPairs) {
        $fgHex = $t[$pair.FG]
        $bgHex = $t[$pair.BG]
        if (-not $fgHex -or -not $bgHex) { continue }

        $ratio = Get-ContrastRatio $fgHex $bgHex
        $threshold = if ($pair.Type -eq 'text') { 4.5 } else { 3.0 }
        $totalChecks++

        if ($ratio -lt $threshold) {
            $failures += [PSCustomObject]@{
                Theme     = $themeName
                Label     = $pair.Label
                FG        = "$($pair.FG) ($fgHex)"
                BG        = "$($pair.BG) ($bgHex)"
                Ratio     = [Math]::Round($ratio, 2)
                Required  = $threshold
                Type      = $pair.Type
            }
            $themeFailCount++
        }
    }

    # Severity text on theme backgrounds (text used as colored labels)
    foreach ($sevName in $severityColors.Keys) {
        $sevHex = $severityColors[$sevName]
        foreach ($bgToken in @('WindowBg', 'PanelBg', 'CardBg')) {
            $bgHex = $t[$bgToken]
            if (-not $bgHex) { continue }
            $ratio = Get-ContrastRatio $sevHex $bgHex
            $totalChecks++
            if ($ratio -lt 3.0) {
                $failures += [PSCustomObject]@{
                    Theme     = $themeName
                    Label     = "$sevName severity on $bgToken"
                    FG        = "$sevName ($sevHex)"
                    BG        = "$bgToken ($bgHex)"
                    Ratio     = [Math]::Round($ratio, 2)
                    Required  = 3.0
                    Type      = 'ui'
                }
                $themeFailCount++
            }
        }
    }

    if ($themeFailCount -eq 0) {
        Write-Host "    All pairs pass." -ForegroundColor Green
    } else {
        Write-Host "    $themeFailCount failure(s)" -ForegroundColor Red
    }
}

Write-Host ''
Write-Host "--- Summary ---" -ForegroundColor Cyan
Write-Host "  Themes checked:  $($themes.Count)"
Write-Host "  Pairs checked:   $totalChecks"

if ($failures.Count -gt 0) {
    Write-Host "  FAILURES:        $($failures.Count)" -ForegroundColor Red
    Write-Host ''
    Write-Host '  Failed Pairs:' -ForegroundColor Red
    foreach ($f in $failures) {
        Write-Host "    [$($f.Theme)] $($f.Label): $($f.Ratio):1 (need $($f.Required):1) -- $($f.FG) on $($f.BG)" -ForegroundColor Yellow
    }
    Write-Host ''
    Write-Host 'RESULT: FAIL' -ForegroundColor Red
    exit 1
} else {
    Write-Host "  Failures:        0" -ForegroundColor Green
    Write-Host ''
    Write-Host 'RESULT: PASS' -ForegroundColor Green
    exit 0
}
