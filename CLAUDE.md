# CLAUDE.md - Network Security Auditor

## Overview
Single-file PowerShell security audit tool. 67 automated checks across 8 security domains, 8 compliance frameworks, MITRE ATT&CK mapping, ransomware readiness scoring, domain security maturity scoring, AD IOC detection, CISA KEV cross-referencing, three-tier HTML reporting, and RMM integration.

## Tech Stack
- PowerShell 5.1+ (single .ps1 file, no dependencies)
- WPF GUI with 7 dark themes (no light themes)
- Async scanning via `[PowerShell]::Create()` + `BeginInvoke()` with `DispatcherTimer` polling

## Key File
- `NetworkSecurityAudit.ps1` — The entire tool (~8,900 lines)

## Version
- **v4.1.0** — version string appears in: script header `.VERSION`, window title, subtitle, save state, HTML report header/footer, silent mode banner, runner popup, SARIF export

## Architecture
- **Environment Detection** (lines 1-230): OS, domain, modules, Azure AD, Intune
- **Auto-Checks** (`$script:AutoChecks` hashtable): 67 scriptblocks returning `@{Status; Findings; Evidence}`
  - Type='AD' requires domain controller / AD module
  - Type='Local' runs on any Windows endpoint
- **Compliance Mapping** (`$script:FrameworkMap`): CIS, NIST 800-171, CMMC, HIPAA, PCI-DSS, SOC 2, ISO 27001, DISA STIG
- **MITRE ATT&CK** (`$script:MitreMap`): All 67 checks mapped to tactics/techniques
- **Scoring Engines**:
  - Ransomware Score: 4-domain model (Prevention, Protection, Detection, Recovery)
  - Domain Maturity Score: 4-domain model (Privileged Access, Identity Hygiene, Infrastructure Hardening, Visibility)
  - Risk Score: Weighted per-check scoring with letter grades
- **Attack Path Analysis**: 6 chains (Phishing->DC, LateralMove->Ransomware, External->Exfil, Insider, Kerberoasting, ADCS Abuse)
- **AD IOC Detection**: krbtgt age, DCSync perms, AdminSDHolder tampering, SID History
- **CISA KEV**: Live cross-reference against installed software (EP04)
- **Scan Profiles**: Quick/Standard/Full/ADOnly/LocalOnly + 6 framework-specific (HIPAA/PCI/CMMC/SOC2/ISO27001/STIG)
- **Risk Tiers**: 0=Read-Only, 1=Remote Read, 2=Probing, 3=Modifying
- **Silent Mode**: `-Silent` flag for RMM deployment, runs synchronously with per-check timeout
- **Export Formats**: HTML, JSON, JSONL, CSV, SARIF, PDF, Intune compliance, Compliance summary
- **RMM Integration**: NinjaRMM, Datto, ConnectWise, Syncro, HaloPSA, generic registry

## Gotchas
- **No keyboard shortcuts** — removed per project rules
- **No light themes** — dark only (7 themes)
- **No emoji/unicode** in PowerShell output
- **Win32_Product is slow** — always use registry uninstall keys instead
- **WPF ComboBox** requires full ControlTemplate for dark mode
- **Silent mode** runs checks in isolated runspaces with 120s timeout per check
- **GUI mode** has 90s timeout per check
- **Version strings** must match across ~10 locations when bumping
- **CISA KEV** requires internet access (gracefully skips on timeout)
- **PDF export** requires Edge or Chrome installed on the system
- **STIG V-IDs** are mapped to all 67 checks in `$stigMap` block

## Build / Run
```powershell
# GUI mode
.\NetworkSecurityAudit.ps1

# Silent/RMM mode
.\NetworkSecurityAudit.ps1 -Silent -ScanProfile Full

# DISA STIG compliance scan
.\NetworkSecurityAudit.ps1 -Silent -ScanProfile STIG -OutputPath "C:\Reports\audit.html"

# Full export suite
.\NetworkSecurityAudit.ps1 -Silent -ExportJSON -ExportCSV -ExportJSONL -ExportSARIF -ExportPDF
```

## Version History
- v4.1.0: DISA STIG framework, CISA KEV cross-reference, AD IOC detection (Golden Ticket/DCSync/AdminSDHolder/SID History), AMSI bypass detection, Credential Guard deep audit, CIS L1 registry checks (20 items), Domain Security Maturity score, 2 new attack path chains, SARIF/PDF/Intune exports, Win10 EOL fleet tracking
- v4.0.0: Full compliance framework mapping, MITRE ATT&CK, ransomware scoring, attack path analysis, three-tier reporting, RMM integration for 6 platforms
