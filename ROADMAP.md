# Roadmap

Single-file PowerShell security audit: 67 checks across 8 domains mapped to 7 frameworks + MITRE ATT&CK, multi-tier reports, RMM integration. Roadmap focuses on cloud/hybrid identity, remediation automation, and continuous-assessment mode.

## Planned Features

### Cloud / Hybrid Identity
- Entra ID (Azure AD) checks via Graph API with delegated auth
- Microsoft 365 Secure Score ingestion + delta tracking
- Intune compliance policy audit + device-posture reporting
- Defender for Endpoint / Defender for Identity alert pull
- Conditional Access policy coverage analysis (gaps + overprivileged exclusions)
- Cross-tenant guest enumeration with stale-guest detection

### Remediation Automation
- One-click remediation for safe Pass-to-Fix checks (LLMNR disable, SMBv1 disable, LAPS enforcement)
- Remediation dry-run with WhatIf + reg/policy diff preview
- Remediation rollback manifest (JSON with before/after for every changed key)
- Remediation evidence attachment (screenshots / command output) stored in audit JSON

### Continuous Assessment
- Scheduled delta-scan mode: only re-check what's changed since last scan
- Drift alert webhook (Discord/Slack/Teams) when a previously Pass check flips to Fail
- Historical trending with 90-day score sparkline embedded in HTML report
- Exposure window calculation (time a finding remained open)

### New Check Categories
- **Application Security** — IIS hardening, Exchange CU level, SQL Server auth mode
- **Email Security** — DMARC/DKIM/SPF records, MX misconfig, O365 secure defaults
- **Cloud Infra** — Azure resource misconfig via Azure Resource Graph
- **Kubernetes/Container** — hostile-workload detection on Windows containers
- **Data Loss Prevention** — share permissions audit (EVERYONE with write), USB mass-storage policy

### Reporting
- Client branding (logo + color) for MSP white-label reports
- PowerPoint export for exec readouts
- SARIF 2.2 support when it lands
- Compliance gap roadmap (prioritized remediation plan per framework)
- Benchmark comparison: how does this environment compare to industry median

### Integration
- ServiceNow / Jira ticket creation for each critical finding
- PagerDuty / Opsgenie alert routing on exit-code 1
- Splunk HEC push in addition to JSONL file
- Vanta / Drata evidence-sync for compliance automation platforms

## Competitive Research
- **PingCastle** — gold standard for AD security assessment; mirror domain-maturity depth.
- **CrowdStrike Falcon Identity** — commercial AD IOC reference; check coverage gaps against their detections.
- **Microsoft Security Compliance Toolkit / Policy Analyzer** — authoritative source on baseline diffs.
- **Purple Knight (Semperis)** — free AD-focused assessor; feature-match on AD checks.

## Nice-to-Haves
- Agentless remote scan mode via WinRM / PSRemoting for fleet sweeps from one admin jumpbox
- Linux host audit via SSH (basic CIS checks) to cover hybrid environments
- Attack path visualization (BloodHound-lite) for AD results
- STIX/TAXII export for threat-intel platforms
- Mobile-readable HTML report (responsive CSS + collapsed categories)
- Parallel scan mode with configurable throttle for large hosts (Exchange servers, DCs)
- Auto-generated Pester tests from each finding (proof + regression detection)

## Open-Source Research (Round 2)

### Related OSS Projects
- https://github.com/0xsarwagya/CIS_Scripts — CIS v3.0.0 audit + enforce for Win11 Basic/Enterprise + Linux, modular PS scripts, logs dir
- https://github.com/okanyildiz/WindowsSecurityAudit — 58 PS functions across 14 modules, CIS L1+L2, 100+ controls, remediation scripts, scoring
- https://github.com/Gyrfalc0n/CIS-Windows-audit — single-script CIS audit, simple report output
- https://github.com/Myohannn/CIS-Auditor-Windows — pulls latest Nessus .audit file, converts to Excel for per-org customization, multiprocessing + remote
- https://github.com/Aryan-136/CIS-Sentinel-Automated-Auditing-for-Windows-Linux-Systems — cross-platform Win11 + RHEL/Ubuntu CIS auditor
- https://github.com/Sneakysecdoggo/Wynis — PS best-practice audit (AV, appdata exes, listening ports, local users, optional features)
- https://github.com/s3curityb3ast/windows_auditor — small PS compliance reporter with adjustable MBSS parameters
- https://github.com/FB-Pro/Audit-Test-Automation — commercial-grade HTML reports with intl security standard mapping (reference only)

### Features to Borrow
- Remediation scripts alongside detection — each CIS finding ships a `-Remediate` flag that applies the fix (okanyildiz/WindowsSecurityAudit) — NSA is detection-only, add optional remediation
- Pull latest CIS benchmark .audit file from Nessus at runtime (Myohannn) — keeps benchmark coverage current without NSA version bumps
- Multiprocessing for parallel remote audit of dozens of machines (Myohannn) — batch audit a clinic's workstations from one admin box
- Cross-platform parity: PS for Windows, Bash for Linux, same report schema (Aryan-136/CIS-Sentinel) — NSA is Windows-only, add Linux sidecar for mixed environments
- CIS L1 (Basic) vs L2 (High Security) profile selector (okanyildiz) — NSA has frameworks, add L1/L2 split within CIS
- Audit policy customization via Excel round-trip (Myohannn) — MSPs edit CIS in Excel, re-import; fits sysadmin workflow
- Baseline diff mode: capture baseline, re-audit, report deltas (Wynis pattern) — detect drift on a machine over time
- Listening-port enumeration + AppData EXE discovery as supplementary checks (Wynis) — beyond pure CIS

### Patterns & Architectures Worth Studying
- Modular PS script-per-control layout (okanyildiz 14 modules) vs monolith — easier to update individual controls without regression
- MITRE ATT&CK ID embedded per-control (NSA already does this, worth hardening against CIS + MITRE-D3FEND mapping)
- Results schema as JSON + NDJSON for SIEM ingest — NSA produces HTML/reports, add machine-readable outputs for Splunk/ELK pipelines
- Remote audit over WinRM with per-host credentials (Myohannn) vs local-only — enables RMM integration beyond script-push
- Single-file vs module-manifest distribution — NSA's single-file is an intentional deployment win; most OSS tools are multi-file; keep it as the differentiator
