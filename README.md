# Network Security Audit v4.0

A comprehensive, single-file PowerShell security audit tool with a full WPF GUI. Runs 67 automated checks across 8 security domains, maps findings to 7 compliance frameworks and MITRE ATT&CK, generates multi-tier reports, and integrates with every major RMM platform for headless deployment.

One script. No dependencies to pre-install. Works on any Windows machine from standalone workstations to enterprise domain controllers.

---

## Why This Exists

Most security audit tools are either expensive commercial platforms that require agents and infrastructure, or basic scripts that check a handful of settings and dump text to a console. There's nothing in between for the IT professional who needs to walk into any environment — a 5-person office, a healthcare clinic, a 500-seat enterprise — and produce a professional, evidence-backed security assessment in under an hour.

This tool fills that gap. It auto-detects the environment, runs every check it can, skips what doesn't apply, scores the results against real compliance frameworks, and generates reports suitable for executives, IT managers, and technical staff. It runs silently via RMM for scheduled fleet assessments or interactively through a polished GUI for on-site audits.

---

## Quick Start

### Interactive (GUI)

```powershell
# Right-click → Run with PowerShell, or:
.\NetworkSecurityAudit_v3.ps1
```

The tool auto-elevates to admin, detects your environment (domain/workgroup/hybrid), and launches the GUI. Click **Scan All** to run every applicable check.

### Headless (RMM / Scheduled Task)

```powershell
# Full scan, all exports, silent
.\NetworkSecurityAudit_v3.ps1 -Silent -ScanProfile Full

# Quick triage, executive report only
.\NetworkSecurityAudit_v3.ps1 -Silent -ScanProfile Quick -ReportTier Executive

# HIPAA compliance scan with custom output path
.\NetworkSecurityAudit_v3.ps1 -Silent -ScanProfile HIPAA -OutputPath "C:\Reports\audit.html"

# Full scan with all export formats
.\NetworkSecurityAudit_v3.ps1 -Silent -ExportJSON -ExportCSV -ExportJSONL
```

---

## Features

### 67 Automated Security Checks

Every check runs in an isolated runspace with timeout protection. Results include findings text, evidence collection, severity rating, and compliance mapping.

<details>
<summary><strong>Identity & Access (10 checks)</strong></summary>

| ID | Check | Severity |
|----|-------|----------|
| IA01 | Privileged Groups + Delegation | Critical |
| IA02 | Service Accounts + Kerberoast Risk | Critical |
| IA03 | MFA Coverage | Critical |
| IA04 | Terminated Employee Accounts | Critical |
| IA05 | Password Policy | High |
| IA06 | PAM / Privileged Access (LAPS) | High |
| IA07 | Shared/Generic Accounts | Medium |
| IA08 | Guest/Vendor Account Lifecycle | Medium |
| IA09 | Conditional Access / Remote Access | Medium |
| IA10 | Stale/Inactive Accounts (90+ days) | High |

</details>

<details>
<summary><strong>Endpoint Security (10 checks)</strong></summary>

| ID | Check | Severity |
|----|-------|----------|
| EP01 | Defender / EDR Deployment + ASR Rules | Critical |
| EP02 | BitLocker / Disk Encryption | Critical |
| EP03 | SMB / Protocol Hardening (signing, NTLM, LLMNR) | High |
| EP04 | Patch Compliance | High |
| EP05 | Local Admin / Privilege Escalation Paths | High |
| EP06 | Host Firewall + Attack Surface | Medium |
| EP07 | Application Control + Macro Policy (AppLocker/WDAC) | Medium |
| EP08 | Hardware Security (VBS, Credential Guard, LSA, TPM, Secure Boot) | High |
| EP09 | AutoRun / AutoPlay | Low |
| EP10 | End-of-Life Operating Systems | High |

</details>

<details>
<summary><strong>Network Perimeter (10 checks)</strong></summary>

| ID | Check | Severity |
|----|-------|----------|
| NP01 | Firewall Rules (any/any, stale, overbroad) | Critical |
| NP02 | Open Ports + Listening Services | Critical |
| NP03 | VPN Configuration + Split Tunneling | High |
| NP04 | DNS Filtering Configuration | High |
| NP05 | Egress / Outbound Filtering | High |
| NP06 | Stale Firewall Rules | Medium |
| NP07 | IDS/IPS Presence + Signatures | Medium |
| NP08 | TLS / Crypto Configuration (SCHANNEL) | Low |
| NP09 | NAT / Port Forwarding Exposure | High |
| NP10 | Firmware / Software Version Hygiene | Medium |

</details>

<details>
<summary><strong>Backup & Recovery (8 checks)</strong></summary>

| ID | Check | Severity |
|----|-------|----------|
| BR01 | Backup Solution Detection (3-2-1 rule) | Critical |
| BR02 | Backup Restore Test Evidence | Critical |
| BR03 | Immutable / Air-Gapped Backups | Critical |
| BR04 | RTO/RPO Documentation | High |
| BR05 | Backup Encryption | High |
| BR06 | Backup Monitoring / Alerting | High |
| BR07 | DR Plan / Tabletop Exercise | Medium |
| BR08 | Cloud/SaaS Backup (M365, Google Workspace) | Medium |

</details>

<details>
<summary><strong>Logging & Monitoring (8 checks)</strong></summary>

| ID | Check | Severity |
|----|-------|----------|
| LM01 | DNS Query Logging | High |
| LM02 | Centralized Logging / SIEM | High |
| LM03 | Audit Policy + PowerShell Logging | High |
| LM04 | Firewall Logging + Retention | Medium |
| LM05 | Failed Logon Monitoring | Medium |
| LM06 | File Integrity Monitoring | Medium |
| LM07 | Log Retention + Event Log Sizes (CIS benchmarks) | Medium |
| LM08 | Security Alerting + Notification | High |

</details>

<details>
<summary><strong>Network Architecture (7 checks)</strong></summary>

| ID | Check | Severity |
|----|-------|----------|
| NA01 | Network Segmentation | Critical |
| NA02 | VLAN Separation (user/server/IoT/guest) | High |
| NA03 | Wireless Security (WPA3/WPA2-Enterprise) | High |
| NA04 | Network Documentation / Diagram Currency | Medium |
| NA05 | 802.1X / NAC Deployment | Medium |
| NA06 | Management Interface Isolation | Medium |
| NA07 | Switch Port Security + Unused Port Management | High |

</details>

<details>
<summary><strong>Physical Security (6 checks)</strong></summary>

| ID | Check | Severity |
|----|-------|----------|
| PS01 | Physical Access Controls + Screen Lock | High |
| PS02 | Visitor Sign-in / Access Policy | Medium |
| PS03 | Camera / Surveillance Coverage | Medium |
| PS04 | Clean Desk / Credential Exposure | Medium |
| PS05 | Network Jack / Guest VLAN Security | Low |
| PS06 | UPS / Power Protection | Low |

</details>

<details>
<summary><strong>Common Findings (8 checks)</strong></summary>

| ID | Check | Severity |
|----|-------|----------|
| CF01 | Service Accounts with DA + Weak Passwords | Critical |
| CF02 | Egress Filtering Absent | Critical |
| CF03 | Backups Never Restore-Tested | Critical |
| CF04 | Former Employee Accounts Active | Critical |
| CF05 | Open File Shares | High |
| CF06 | Flat Network (no segmentation) | High |
| CF07 | Broad Local Admin Rights | High |
| CF08 | No DNS / Content Filtering | High |

</details>

### Compliance Framework Mapping

Every check maps to one or more controls across 7 frameworks:

| Framework | Standard | Coverage |
|-----------|----------|----------|
| **CIS** | Controls v8.1 | All 67 checks mapped |
| **NIST** | SP 800-171 Rev 2 | All 67 checks mapped |
| **CMMC** | Level 2 (v2.0) | All 67 checks mapped |
| **HIPAA** | Security Rule | ~45 checks |
| **PCI-DSS** | v4.0.1 | ~48 checks |
| **SOC 2** | Type II (Trust Criteria) | ~60 checks |
| **ISO 27001** | :2022 (Annex A) | All 67 checks mapped |

Framework-specific scan profiles run only the checks relevant to that standard.

### MITRE ATT&CK Mapping

All 67 checks map to ATT&CK Enterprise techniques (v15.1) with tactic and technique IDs. The HTML report includes a visual heatmap showing coverage across the ATT&CK matrix and identifying gaps.

### Ransomware Readiness Score

A dedicated scoring engine evaluates ransomware resilience across four domains:

- **Prevention** — EDR, AppLocker/WDAC, macro restrictions, egress filtering
- **Protection** — Credential Guard, LSA Protection, BitLocker, local admin controls
- **Detection** — IDS/IPS, SIEM, logging, alerting
- **Recovery** — Backup immutability, restore testing, DR planning, RTO/RPO

The score produces an independent letter grade separate from the overall security score.

### Weighted Risk Scoring

Checks are weighted by severity (Critical=10, High=7, Medium=5, Low=3) and category importance. The weighted score produces an overall letter grade:

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 90-100% | Strong security posture |
| B | 80-89% | Good with minor gaps |
| C | 70-79% | Moderate risk, action needed |
| D | 60-69% | Significant gaps |
| F | <60% | Critical risk |

### Three-Tier Reporting

Every HTML report can include up to three tiers, each targeting a different audience:

- **Executive** — Letter grade, risk summary, top 5 findings, ransomware readiness, compliance status. One page, no jargon.
- **Management** — Category breakdowns, remediation roadmap with priority/effort/timeline, framework scorecards, trend indicators.
- **Technical** — Full findings with evidence, per-check compliance mapping, MITRE technique references, remediation steps, scan timestamps.

### GUI

Full WPF interface with:

- **8 themes** — Midnight, Slate, Nord, Dracula, Monokai, Light, Solarized Dark, Catppuccin Mocha (auto-detects system light/dark preference)
- **Categorized tab navigation** with scan progress per category
- **Per-check controls** — status dropdown, findings, evidence, notes, remediation assignment/due date/status
- **Live risk score dashboard** updated as checks complete
- **Keyboard navigation** — Ctrl+1-8 for categories, Ctrl+S save, Ctrl+E export, arrow keys between checks
- **Pre-flight connectivity check** before scanning (ping, WinRM, AD module, SMB, DNS, elevation, Defender)
- **Turnkey environment setup** — auto-installs RSAT, configures WinRM, sets audit policies

### Headless / Silent Mode

Designed for RMM deployment. The `-Silent` flag runs the full scan pipeline with zero interaction:

1. Auto-elevates to admin
2. Detects environment (domain/workgroup/standalone)
3. Runs selected scan profile
4. Exports HTML report + structured data
5. Writes findings to RMM platform fields
6. Returns exit code for RMM alerting

### RMM Integration

Automatic platform detection and field population:

| Platform | Method | Fields |
|----------|--------|--------|
| NinjaRMM | `Ninja-Property-Set` | Grade, Score, Date, Findings, Ransomware, Compliance |
| Datto RMM | CentraStage UDF Registry | Custom1-5 |
| ConnectWise Automate | LabTech EDF Registry | Grade, Score, Date, Ransomware, Compliance, ReportPath |
| Syncro | `Set-SyncroCustomField` | SecurityAuditGrade, Score, Ransomware, Compliance |
| HaloPSA | Registry Cache | Grade, Score, Ransomware, Compliance |
| Generic | `HKLM:\SOFTWARE\NetworkSecurityAudit` | All fields (any RMM can read) |

### Exit Codes

| Code | Condition | RMM Action |
|------|-----------|------------|
| 0 | A/B grade, no critical failures | Green |
| 1 | D/F grade OR ransomware score < 40% | Immediate alert |
| 2 | Findings present, grade C+ | Review needed |
| 3 | Any compliance framework < 60% | Compliance alert |

### Export Formats

| Format | File | Use Case |
|--------|------|----------|
| HTML | `SecurityAudit_*.html` | Human-readable report with all three tiers |
| JSON | `*_findings.json` | Per-finding structured data with full metadata |
| JSONL | `*_siem.jsonl` | One event per finding for Splunk/Elastic/Sentinel |
| CSV | `*.csv` | Pivot table analysis with compliance columns |
| Compliance Summary | `*_summary.json` | Compact RMM dashboard payload |

---

## Requirements

- **PowerShell** 5.1+ (ships with Windows 10/11 and Server 2016+)
- **Windows** 10/11 or Server 2016/2019/2022/2025
- **Administrator** elevation (auto-prompted via UAC)
- **No external modules required** — the script handles everything

Optional for full coverage:
- **RSAT / Active Directory module** — required for AD-type checks (IA01-IA10, CF01, CF04, EP10). The tool auto-offers to install RSAT on first run.
- **Domain-joined machine** — non-domain machines skip AD checks automatically and run all 55 local checks.

---

## Parameters

```
-Silent              Run headless (no GUI). Auto-scans, exports, exits.
-ScanProfile         Quick | Standard | Full | ADOnly | LocalOnly |
                     HIPAA | PCI | CMMC | SOC2 | ISO27001
                     Default: Full (all 67 checks)
-OutputPath          Report output path. Default: Desktop
-ReportTier          Executive | Management | Technical | All
                     Default: All
-ReadOnly            Safety mode - skip system-modifying checks.
                     Default: $true
-Client              Client name for report header.
                     Default: domain name or computer name
-Auditor             Auditor name for report header.
                     Default: current username
-ExportJSON          Also export structured findings JSON
-ExportCSV           Also export CSV
-ExportJSONL         Also export SIEM-format JSONL
```

---

## Scan Profiles

| Profile | Checks | Time | Use Case |
|---------|--------|------|----------|
| **Quick** | ~20 | ~15 min | Critical-only field triage |
| **Standard** | ~45 | ~30 min | Routine assessment |
| **Full** | 67 | ~60 min | Comprehensive audit |
| **ADOnly** | ~12 | ~10 min | Domain-focused checks only |
| **LocalOnly** | ~55 | ~45 min | Endpoint-only (no AD required) |
| **HIPAA** | ~45 | ~30 min | Healthcare compliance |
| **PCI** | ~48 | ~35 min | Payment card compliance |
| **CMMC** | 67 | ~60 min | Defense contractor compliance |
| **SOC 2** | ~60 | ~50 min | Service organization compliance |
| **ISO 27001** | 67 | ~60 min | International standard compliance |

---

## RMM Deployment Examples

### NinjaRMM
```powershell
# Add as a scripted condition or scheduled automation
powershell.exe -ExecutionPolicy Bypass -File "C:\Tools\NetworkSecurityAudit_v3.ps1" -Silent -ScanProfile Standard
# Results appear in device custom fields automatically
```

### Datto RMM
```powershell
# Component script — results write to UDF Custom1-5
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Tools\NetworkSecurityAudit_v3.ps1" -Silent -ScanProfile Quick -ReportTier Executive
```

### ConnectWise Automate
```powershell
# Script — results write to EDF registry keys
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Tools\NetworkSecurityAudit_v3.ps1" -Silent -ExportJSON -ExportCSV
# Monitor exit codes: 0=green, 1=critical, 2=warning, 3=compliance-fail
```

### Scheduled Task (any environment)
```powershell
# Weekly security posture check
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Tools\NetworkSecurityAudit_v3.ps1 -Silent -ScanProfile Standard -OutputPath C:\Reports"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
Register-ScheduledTask -TaskName "WeeklySecurityAudit" -Action $action -Trigger $trigger -RunLevel Highest -User "SYSTEM"
```

---

## How Scoring Works

### Overall Security Score

Each of the 67 checks has a severity weight (Critical=10, High=7, Medium=5, Low=3). Each category also has a weight reflecting its relative importance. The score is calculated as:

```
Per-category:  (earned points / max points) * 100
Overall:       weighted average across all categories
```

Pass = full points, Partial = half points, Fail = zero, N/A = excluded from calculation.

### Ransomware Readiness

A separate 100-point scale evaluates specific ransomware defense capabilities mapped to the four-domain model (Prevention, Protection, Detection, Recovery). This produces an independent grade — an environment can score well overall but poorly on ransomware readiness if backup and recovery controls are weak.

### Compliance Scoring

Each framework profile defines which checks map to which controls. The score represents the percentage of applicable controls that pass or partially pass.

---

## Save / Load / Diff

Audit state (all check statuses, findings, evidence, notes, remediation tracking) can be saved to JSON and reloaded later. This enables:

- Pausing and resuming audits across sessions
- Comparing two audit snapshots to show improvement over time
- Building a historical record of security posture

---

## Project Structure

This is a single-file tool by design. One `.ps1` file, no modules, no config files, no build process. Download it and run it.

```
NetworkSecurityAudit_v3.ps1    # The entire tool (~8,700 lines)
README.md                      # This file
ROADMAP.md                     # Development roadmap and changelog
```

---

## Contributing

Contributions are welcome. Areas where help is most needed:

- **Additional auto-check scripts** for specific technologies (Exchange, SQL Server, VMware, etc.)
- **Cloud/hybrid identity checks** (Entra ID, M365 Secure Score, Intune compliance)
- **Additional compliance framework mappings** (FedRAMP, NIST 800-53, Essential Eight, Cyber Essentials)
- **Bug reports** from diverse environments (different OS versions, domain configurations, edge cases)
- **Localization** of check descriptions and report text

Please open an issue before starting work on major features to discuss approach.

---

## License

MIT

---

## Acknowledgments

Built with PowerShell 5.1, WPF, and an unreasonable number of hours reading CIS Benchmarks, NIST publications, and RMM API documentation.
