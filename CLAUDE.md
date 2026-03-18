# CLAUDE.md - Network Security Auditor

## Overview
Single-file PowerShell security audit tool. 67 automated checks across 8 security domains, 7 compliance frameworks, MITRE ATT&CK mapping, ransomware readiness scoring, three-tier HTML reporting, and RMM integration.

## Tech Stack
- PowerShell 5.1+ (single .ps1 file, no dependencies)
- WPF GUI with 7 dark themes (no light themes)
- Async scanning via `[PowerShell]::Create()` + `BeginInvoke()` with `DispatcherTimer` polling

## Key File
- `NetworkSecurityAudit.ps1` — The entire tool (~8,400 lines)

## Version
- **v4.0.0** — version string appears in: script header `.VERSION`, window title, save state, HTML report footer, README badge

## Architecture
- **Environment Detection** (lines 1-230): OS, domain, modules, Azure AD, Intune
- **Auto-Checks** (`$script:AutoChecks` hashtable): 67 scriptblocks returning `@{Status; Findings; Evidence}`
  - Type='AD' requires domain controller / AD module
  - Type='Local' runs on any Windows endpoint
- **Compliance Mapping** (`$script:FrameworkMap`): CIS, NIST 800-171, CMMC, HIPAA, PCI-DSS, SOC 2, ISO 27001
- **MITRE ATT&CK** (`$script:MitreMap`): All 67 checks mapped to tactics/techniques
- **Ransomware Score**: 4-domain model (Prevention, Protection, Detection, Recovery)
- **Scan Profiles**: Quick/Standard/Full/ADOnly/LocalOnly + framework-specific
- **Risk Tiers**: 0=Read-Only, 1=Remote Read, 2=Probing, 3=Modifying
- **Silent Mode**: `-Silent` flag for RMM deployment, runs synchronously with per-check timeout
- **RMM Integration**: NinjaRMM, Datto, ConnectWise, Syncro, HaloPSA, generic registry

## Gotchas
- **No keyboard shortcuts** — removed per project rules
- **No light themes** — dark only (7 themes)
- **No emoji/unicode** in PowerShell output
- **Win32_Product is slow** — always use registry uninstall keys instead
- **WPF ComboBox** requires full ControlTemplate for dark mode
- **Silent mode** runs checks in isolated runspaces with 120s timeout per check
- **Version strings** must match across all locations when bumping

## Build / Run
```powershell
# GUI mode
.\NetworkSecurityAudit.ps1

# Silent/RMM mode
.\NetworkSecurityAudit.ps1 -Silent -ScanProfile Full

# HIPAA compliance scan
.\NetworkSecurityAudit.ps1 -Silent -ScanProfile HIPAA -OutputPath "C:\Reports\audit.html"
```

## Status
- v4.0.0: Full compliance framework mapping, MITRE ATT&CK, ransomware scoring, attack path analysis, three-tier reporting, RMM integration for 6 platforms
