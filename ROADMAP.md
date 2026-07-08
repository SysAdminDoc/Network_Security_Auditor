# Project Roadmap

Last updated: 2026-06-06
Canonical roadmap file: `ROADMAP.md`
Project root: `\\vmware-host\Shared Folders\repos\Network_Security_Auditor`
Current product: single-file PowerShell 5.1+ Windows security assessment tool

This roadmap resumes the previous roadmap rather than discarding it. The prior ideas around cloud identity, remediation automation, continuous assessment, new check categories, reporting, integrations, and open-source research have been deduplicated into the structured backlog and specs below.

## 1. Project Understanding

### Current Summary

Network Security Auditor is a single-file PowerShell/WPF audit tool for Windows endpoints, SMB environments, and domain environments. The implementation is intentionally consolidated in `NetworkSecurityAudit.ps1` for low-friction RMM deployment and one-file downloads. It currently provides 67 audit checks across 8 security domains, GUI and silent modes, scan profiles, multi-framework compliance mappings, MITRE ATT&CK mapping, ransomware readiness scoring, domain maturity scoring, CISA KEV lookup, structured exports, PDF/SARIF/Intune exports, and RMM field writes.

Primary local evidence:

- `NetworkSecurityAudit.ps1:48` defines CLI parameters including `-Silent`, scan profiles, report tiers, read-only mode, and structured export switches.
- `NetworkSecurityAudit.ps1:127` starts environment detection, including OS, domain, module, Defender, SMB, BitLocker, Azure AD/Entra join, and Intune/MDM signals.
- `NetworkSecurityAudit.ps1:488` defines 7 dark WPF themes.
- `NetworkSecurityAudit.ps1:560` defines audit categories, check metadata, hints, severity, weights, and built-in compliance text.
- `NetworkSecurityAudit.ps1:1019` starts `$script:AutoChecks`, the 67 auto-check scriptblock map.
- `NetworkSecurityAudit.ps1:3707` defines scan profiles: Quick, Standard, Full, ADOnly, LocalOnly, HIPAA, PCI, CMMC, SOC2, ISO27001, and STIG.
- `NetworkSecurityAudit.ps1:3846` defines structured framework mapping for NIST 800-171, CMMC, PCI-DSS, SOC 2, ISO 27001, and STIG.
- `NetworkSecurityAudit.ps1:4033` defines MITRE ATT&CK mapping.
- `NetworkSecurityAudit.ps1:4213` defines ransomware readiness scoring.
- `NetworkSecurityAudit.ps1:4295` defines domain security maturity scoring.
- `NetworkSecurityAudit.ps1:7333` starts enhanced HTML reporting.
- `NetworkSecurityAudit.ps1:8120` through `NetworkSecurityAudit.ps1:8547` define JSON, JSONL, CSV, compliance summary, SARIF, Intune, and PDF exports.
- `NetworkSecurityAudit.ps1:8664` starts headless/silent mode for RMM deployment.

### Target Users

| User | Jobs | Needs |
|---|---|---|
| MSP technician | Run fast client audits during onboarding, quarterly reviews, and incident triage. | One-file deployment, RMM compatibility, reliable exit codes, concise executive outputs, clear remediation priorities. |
| Internal sysadmin | Understand Windows/domain posture without buying a large platform. | Read-only safety, evidence collection, local reports, repeatable baselines, clear next steps. |
| Security consultant | Produce professional assessments for SMB and midmarket clients. | White-label reports, technical appendix, compliance mappings, repeatable methodology, confidence in tool behavior. |
| Compliance assessor | Map observed posture to HIPAA, PCI-DSS, CMMC, SOC 2, ISO 27001, STIG, and NIST controls. | Exact control evidence, exceptions, exportable artifacts, defensible scoring, audit trail. |
| Power user / security engineer | Extend checks, automate fleet scans, push findings into SIEM/GRC/ticketing tools. | Machine-readable schema, integration hooks, testable check contracts, stable output formats. |

### Core User Jobs

- Run a guided GUI audit on a Windows endpoint or domain-joined admin workstation.
- Run silent scans through RMM or scheduled tasks with predictable outputs and exit codes.
- Produce executive, management, and technical reports from one scan.
- Capture evidence, findings, notes, remediation owner, due date, and remediation status.
- Map findings to compliance frameworks and MITRE ATT&CK techniques.
- Track ransomware readiness and domain maturity separately from general score.
- Export findings into JSON, JSONL, CSV, SARIF, PDF, Intune, and RMM fields.
- Compare saved audits to show posture change over time.

### Current Strengths

- Strong deployment story: one PowerShell file and no required external modules.
- Broad check coverage for SMB security posture, AD hygiene, endpoint hardening, backups, logging, perimeter, physical security, and common findings.
- Existing safety model with risk tiers and default read-only scanning.
- Good report breadth: HTML, JSON, JSONL, CSV, SARIF, compliance summary, Intune JSON, and optional PDF.
- Practical RMM integration across NinjaRMM, Datto, ConnectWise Automate, Syncro, HaloPSA, and generic registry.
- Evidence-oriented finding output, not just pass/fail.
- Dark-theme WPF GUI with scan profiles and category navigation.
- Parser validation passed on 2026-06-06 using `System.Management.Automation.Language.Parser.ParseInput`; parser errors: 0.

### Current Weaknesses

- A lightweight static validation gate and GitHub Actions workflow now exist, but there is still no Pester suite or PSScriptAnalyzer configuration.
- `CHANGELOG.md:5` has a malformed date placeholder: `%Y->-`.
- Local `screenshot.png` does not appear to show Network Security Auditor; it looks like an unrelated terminal/video-extension screen. README embeds remote GitHub attachment screenshots, but the repo-local screenshot is misleading.
- Cloud/hybrid coverage is mostly detection and roadmap-level today. The script detects Azure AD/Entra join and Intune management, but it does not yet perform Graph-backed Secure Score, Conditional Access, guest lifecycle, app consent, or Defender/Intune policy audits.
- CISA KEV matching currently depends on lightweight product matching in `EP04`; it should evolve into cached catalog metadata plus richer installed-software and server-role correlation.
- The single-file design is valuable for distribution but makes regression control hard without a generator, manifest, or section-level tests.
- `ReadOnly` behavior needs clearer product semantics: scan filtering honors risk tiers, but silent-mode RMM registry writes and explicit setup/configuration functions are still present in the same executable flow.
- GUI is effective but dense: many text buttons, crowded scan bar controls, limited progressive disclosure, and no visible evidence of accessibility validation.
- No central multi-client dashboard, history store, or scheduled delta mode yet.

---

## 2. Current Feature Inventory

| Area | Existing Feature | Evidence | Maturity | Notes |
|---|---|---|---|---|
| Distribution | Single-file PowerShell tool | `README.md:474`, `NetworkSecurityAudit.ps1` | Strong | Keep as the public artifact; add generator/tests behind it rather than splitting runtime distribution. |
| CLI | Silent mode, scan profile, report tier, read-only flag, client/auditor, export switches | `NetworkSecurityAudit.ps1:48` | Strong | Needs version constant and shell-safe argument tests. |
| Environment detection | OS, domain/workgroup, modules, Defender, SMB, BitLocker, AppLocker, WinRM, Entra join, Intune | `NetworkSecurityAudit.ps1:127` | Strong local, shallow cloud | Expand into Graph-backed cloud posture. |
| GUI | WPF app, category tabs, scan bar, console, profile selector, framework selector, save/load/diff | `NetworkSecurityAudit.ps1:4425`, `NetworkSecurityAudit.ps1:5447`, `NetworkSecurityAudit.ps1:7201` | Functional | Dense UI; needs screenshot refresh and accessibility audit. |
| Themes | 7 dark themes | `NetworkSecurityAudit.ps1:488` | Strong | Dark-only matches project rule. |
| Audit catalog | 67 checks across 8 domains | `NetworkSecurityAudit.ps1:560`, `README.md:79` | Strong | Add schema validation so IDs, profiles, maps, and exports cannot drift. |
| Auto-checks | `$script:AutoChecks` scriptblocks returning status/findings/evidence | `NetworkSecurityAudit.ps1:1019` | Strong but monolithic | Add check contract tests and per-check metadata manifest. |
| Scan profiles | Quick, Standard, Full, ADOnly, LocalOnly, framework profiles | `NetworkSecurityAudit.ps1:3707` | Strong | Validate profile membership against AutoCheckIDs and FrameworkMap in CI. |
| Safety model | Risk tiers 0-3 and default read-only mode | `NetworkSecurityAudit.ps1:3787`, `NetworkSecurityAudit.ps1:8717` | Good | Add explicit "writes performed" summary and optional `-NoRmmWrite`. |
| Compliance mapping | CIS, NIST 800-171, CMMC, HIPAA, PCI-DSS, SOC 2, ISO 27001, STIG | `NetworkSecurityAudit.ps1:3846`, `README.md:218` | Broad | Needs exact evidence model and framework version validation. |
| MITRE mapping | ATT&CK mapping and attack path narratives | `NetworkSecurityAudit.ps1:4033`, `NetworkSecurityAudit.ps1:4151` | Good | Add D3FEND and object-level attack path graph later. |
| Ransomware score | Prevention, protection, detection, recovery scoring | `NetworkSecurityAudit.ps1:4213`, `README.md:256` | Good | Add trend and exposure-window tracking. |
| Domain maturity score | Privileged access, identity hygiene, infrastructure hardening, visibility | `NetworkSecurityAudit.ps1:4295`, `README.md:245` | Good | Compare against PingCastle/Purple Knight score categories. |
| Reports | Three-tier HTML report with compliance matrix, attack paths, remediation, scorecards | `NetworkSecurityAudit.ps1:7333` | Strong | Add white-label and PowerPoint export. |
| Structured exports | JSON, JSONL, CSV, summary JSON, SARIF, Intune JSON, PDF | `NetworkSecurityAudit.ps1:8120` | Strong | Add schema snapshots and output contract tests. |
| RMM integration | NinjaRMM, Datto, ConnectWise, Syncro, HaloPSA, registry | `NetworkSecurityAudit.ps1:8858` | Strong | Add `-NoRmmWrite`, dry-run, and integration field docs. |
| Docs | README, changelog, roadmap | `README.md`, `CHANGELOG.md`, `ROADMAP.md` | Medium | Changelog malformed; screenshot mismatch; README lacks trust/safety page. |
| Validation | Static parser/catalog/profile/framework/version gate | `tools/Test-NetworkSecurityAudit.ps1`, GitHub Actions | Initial | Add Pester and PSScriptAnalyzer coverage without executing host-modifying checks. |

---

## 2A. Cycle 5 Check Catalog Audit Findings

Cycle 5 inspected the catalog and auto-check maps without executing the audit script.

### Coverage Invariants

| Invariant | Result | Evidence |
|---|---|---|
| Audit items | 67 | Regex extraction from `ID='XX00'; Severity=...; Weight=...` entries. |
| Auto-checks | 67 | Regex extraction from `$script:AutoChecks` keys. |
| Framework map entries | 67 | Regex extraction from `$script:FrameworkMap`. |
| Risk tier entries | 67 | Regex extraction from `$script:RiskTiers`. |
| Missing auto-checks | 0 | Every audit item has an auto-check ID. |
| Auto-checks outside catalog | 0 | Every auto-check ID exists in the audit catalog. |
| Missing framework mapping | 0 | Every audit item has framework map coverage. |
| Missing risk tier | 0 | Every audit item has a risk tier. |

Category counts: BR:8, CF:8, EP:10, IA:10, LM:8, NA:7, NP:10, PS:6.

Auto-check types: AD:12, Local:55. No check currently uses the documented `Remote` type even though the comment at `NetworkSecurityAudit.ps1:1017` says Remote is supported. This is a good future extension point for fleet mode, but tests should assert only known type values are used.

Tier 2 or higher checks: `CF02:2`, `CF08:2`, `NP04:2`. These are probing checks because they test outbound/DNS behavior against external resolvers or domains. The scan manifest should call them out explicitly before execution.

### Semantic Gaps Found

| Check / Area | Observation | Product Risk | Roadmap Action |
|---|---|---|---|
| `IA03` MFA coverage | Current logic checks RDP NLA, installed Graph/Azure modules, ADFS service, MFA agent software, smart card policy, and Windows Hello for Business local indicators. It does not verify tenant-wide MFA registration or Conditional Access enforcement. | Label can overstate cloud MFA assurance. | Split into "local MFA/remote-access signals" now and add Graph-backed MFA coverage in NSA-004. |
| `IA09` Conditional Access / Remote Access | Current logic checks local RDP settings, local VPN adapters/connections/software, and split-tunnel signals. It does not inspect Entra Conditional Access policies. | Compliance/MITRE mapping for Conditional Access can appear stronger than evidence supports. | Rename locally or add cloud check IDs for actual Conditional Access coverage. |
| Physical/security policy checks | `PS01`, `PS02`, `PS03`, `PS05`, and similar documentation/physical controls include checklist prompts and often return `Partial` because local automation cannot prove the physical process. | Scores may mix machine-verified facts with interview/checklist prompts. | Add `EvidenceMode` metadata: `Automated`, `Heuristic`, `Checklist`, `InterviewRequired`, `ExternalRequired`. |
| Backup documentation checks | `BR04` and `BR07` include documentation/checklist-style evidence; `BR02`/`CF03` rely partly on event logs and prompts. | Critical backup/DR scoring can appear more objective than actual evidence. | Add explicit "manual evidence required" state and report caveats. |
| Status thresholds | Thresholds are hard-coded inside scriptblocks, e.g. privileged group counts, patch age 30/60 days, egress open-port counts, subnet/ARP flatness. | MSPs cannot tune policy for stricter or looser clients without editing code. | Move thresholds into check metadata or a policy profile file. |
| Internet/probing behavior | `CF02`, `CF08`, and `NP04` use outbound tests/resolution. `EP04` uses CISA KEV internet retrieval. | `-NoInternet` now skips these public-network touches; cache metadata and richer skipped-check reporting still need work. | Covered by NSA-003 safety manifest and NSA-012 KEV cache path. |
| Comment drift | Quick profile comments imply `CF01/CF02/CF05` are SMB signing/SMBv1/open shares, but `CF01` is privileged service accounts and `CF02` is egress filtering. | Maintainer confusion and bad release confidence. | Add profile comment validation or remove stale inline comments once manifest tests exist. |

### New Backlog Refinement

Add a sub-feature under NSA-001/NSA-011: **Check Evidence Mode Manifest**.

Acceptance criteria:

---

## 2B. Cycle 6 Export Schema Audit Findings

Cycle 6 inspected report and export paths without executing the audit script. Main code areas reviewed: `NetworkSecurityAudit.ps1:3963` through `NetworkSecurityAudit.ps1:4007` for compliance string formatting, `NetworkSecurityAudit.ps1:7333` through `NetworkSecurityAudit.ps1:8120` for enhanced HTML reporting, and `NetworkSecurityAudit.ps1:8120` through `NetworkSecurityAudit.ps1:8583` for JSON, JSONL, CSV, compliance summary, SARIF, Intune, and PDF export functions.

### Export Surface Map

| Surface | Current Shape | Contract Risk | Roadmap Action |
|---|---|---|---|
| Compliance string helper | `Get-ComplianceString` emits CIS, NIST CSF, NIST 800-171, CMMC, HIPAA, PCI, SOC 2, and ISO 27001. | STIG mappings exist in `$script:FrameworkMap` but are not included in formatted finding strings. | Add STIG output branch and contract tests for every framework target. |
| HTML report | Header says 7 frameworks and lists CIS, NIST, CMMC, HIPAA, PCI-DSS, SOC 2, and ISO 27001. Framework score cards iterate `$script:FrameworkMeta.Keys`, but some matrix/gap-analysis paths use hard-coded framework lists. | STIG can appear in score cards but be missing from summary copy, the all-framework matrix, and gap reference text. | Replace hard-coded framework arrays/copy with `$script:FrameworkMeta` and add HTML snapshot checks for `All` and `STIG`. |
| Structured findings JSON | Centralized `schema_version`, `tool_version`, findings, environment, scores, `compliance_frameworks`, STIG detail fields, and MITRE objects. | JSON schemas are still not published for downstream consumers. | Publish JSON schema and snapshot fixtures for contract validation. |
| JSONL | One event per finding with SIEM-friendly flattened fields and truncation at 4000 chars for findings and 2000 chars for evidence. | STIG omitted; truncation is implicit and not machine-detectable. | Add STIG field plus `findings_truncated`, `findings_original_length`, `evidence_truncated`, and `evidence_original_length`. |
| CSV | Pivot-friendly rows with score, status, finding, evidence, remediation, framework, and MITRE columns. | STIG omitted; text fields are spreadsheet-bound but not visibly protected from formula injection if user-entered notes/fields begin with `=`, `+`, `-`, or `@`. | Add STIG column, schema snapshot, and spreadsheet-safe cell neutralization for free-text fields. |
| Compliance summary JSON | Compact dashboard summary with `schema_version = '2.1'`, category scores, framework scores, ransomware score, critical findings, and counts. | Summary has stronger framework coverage than per-finding exports, so consumers may see STIG in summary but not in detailed records. | Align summary/detail framework keys and validate both from the same fixture. |
| SARIF | Emits SARIF 2.1.0 rules and Fail/Partial results with severity/category/weight properties. | Results have no `locations`, which limits usefulness in GitHub/Azure DevOps and makes findings harder to deep link. | Add logical locations such as `network-security-audit://check/IA01` or report artifact URIs. |
| Intune JSON | Emits `SecurityAuditGrade`, `SecurityAuditScore`, compliance flags, critical failures, and checks. | No schema version, timestamp, tool version, target, client, auditor, or environment metadata. | Promote to a versioned Intune compliance export contract. |
| PDF | Converts HTML to PDF through browser automation after resolving the HTML path. | UNC paths, provider-qualified paths, spaces, and restricted hosts need explicit tests. | Add path-handling tests and fallback diagnostics for PDF generation. |

### Cross-Export Findings

- STIG is a first-class framework in `$script:FrameworkMeta`, `$script:FrameworkChecks`, and the scan profile list, but several export and HTML formatting paths still behave as if there are only 7 frameworks.
- Export version strings now use the centralized product version; remaining export contract gaps are STIG field parity, schema publication, truncation metadata, SARIF locations, spreadsheet-safe CSV cells, and PDF path tests.
- JSON schema files are not committed for any machine-readable export. Downstream RMM, SIEM, dashboard, GRC, and compliance consumers therefore have no stable contract to pin against.
- Summary and detail exports can drift because framework fields are assembled separately in each function. This should be generated from a shared framework/export manifest.
- CSV is useful for MSP workflows, but spreadsheet safety should be explicit because notes, assignee, evidence, and findings can eventually include operator-entered text.

### New Backlog Refinement

Add a sub-feature under NSA-001/NSA-006/NSA-011: **Export Contract Pack**.

Acceptance criteria:

- [ ] Every export includes `schema_version`, `tool_version`, `timestamp`, `client`, `auditor`, `target`, and environment metadata unless the format standard forbids it.
- [ ] Every compliance framework in `$script:FrameworkMeta` appears consistently in HTML, JSON, JSONL, CSV, summary JSON, and compliance strings.
- [ ] JSON schemas are committed for structured findings, summary, Intune, JSONL events, and any future dashboard aggregate format.
- [ ] Snapshot fixtures validate JSON, JSONL, CSV headers, SARIF shape, Intune shape, and HTML framework sections.
- [ ] PDF export has automated path tests for local paths, spaces, and UNC paths.

---

## 2C. Cycle 7 Silent Mode and RMM Safety Audit Findings

Cycle 7 traced silent-mode execution, RMM field writes, setup actions, and other persistent side effects. Main code areas reviewed: `NetworkSecurityAudit.ps1:49` through `NetworkSecurityAudit.ps1:99` for CLI state and auto-elevation, `NetworkSecurityAudit.ps1:244` through `NetworkSecurityAudit.ps1:470` for setup helper functions, `NetworkSecurityAudit.ps1:6022` through `NetworkSecurityAudit.ps1:6909` for turnkey setup, `NetworkSecurityAudit.ps1:8589` through `NetworkSecurityAudit.ps1:8647` for manual WinRM/audit-policy actions, and `NetworkSecurityAudit.ps1:8664` through `NetworkSecurityAudit.ps1:8981` for headless/RMM execution.

### Write Surface Inventory

| Surface | Current Behavior | Risk / Gap | Roadmap Action |
|---|---|---|---|
| Auto-elevation | Non-admin launch restarts `powershell.exe` with `-Verb RunAs -WindowStyle Hidden`, then exits the original process. | In unattended RMM/scheduler contexts, the parent process may exit before results are produced and exit code/report paths can be lost. Relaunch pass-through omits `-ExportSARIF` and `-ExportPDF`. | Add `-NoElevate`, detect non-interactive sessions, preserve all flags, and document exit-code behavior when elevation is unavailable. |
| Silent report files | Silent mode always writes HTML, findings JSON, JSONL, CSV, Intune JSON, and summary JSON; SARIF/PDF are optional. Default path is the Desktop. | `-ExportJSONL` and `-ExportCSV` flags are effectively redundant in silent mode; default Desktop output may be wrong for service accounts; there is no write manifest. | Add explicit output directory resolution, write manifest, and flags to choose export set. |
| Generic registry cache | Silent mode always writes `HKLM:\SOFTWARE\NetworkSecurityAudit` with score, grade, ransomware score, compliance flags, counts, and paths. | This write happens even when `ReadOnly` is true and even when no RMM provider is present. | Add `-NoRmmWrite` or `-NoRegistryWrite`; report skipped writes distinctly from failed writes. |
| NinjaRMM | If `Ninja-Property-Set` exists, silent mode writes seven custom fields. | Field names and value formats are implicit and not documented as a contract. | Add provider field schema and dry-run preview. |
| Datto RMM | If `HKLM:\SOFTWARE\CentraStage` exists, silent mode writes `Custom1` through `Custom5`. | Hard-coded UDF slots can collide with existing MSP conventions. | Make Datto field mapping configurable and document defaults. |
| ConnectWise Automate | If `HKLM:\SOFTWARE\LabTech\Service` exists, silent mode creates/writes `HKLM:\SOFTWARE\LabTech\Service\SecurityAudit`. | Registry EDF cache is useful, but it is not gated by a write-policy flag and has no cleanup/version marker. | Gate with RMM write policy and add schema/version fields. |
| Syncro RMM | If `Set-SyncroCustomField` exists, silent mode writes four custom fields. | Uses provider module side effects with no dry-run or field validation. | Add provider detection summary and field-write result object. |
| HaloPSA | If `HKLM:\SOFTWARE\HaloPSA` exists, silent mode writes `HKLM:\SOFTWARE\HaloPSA\SecurityAudit`. | Registry-cache path is implicit and not part of a documented support contract. | Add provider schema and skip/fail distinction. |
| Turnkey setup | GUI launch prompts for PSGallery trust, NuGet provider install, RSAT install, WinRM, firewall rules, audit policies, Remote Registry, and DC discovery. Several modifying options are default-checked when admin. | The tool's read-only product promise can be misunderstood because setup can modify the host before scans. | Separate "assessment read-only" from "setup/configure" mode and require a setup write manifest. |
| Manual configure buttons | GUI WinRM button calls `Enable-AuditWinRM`; audit policy function can run `auditpol /set`. | These actions do not appear tied to `ReadOnly` semantics or a global write policy. | Route every modifying action through a shared `Invoke-WriteAction` gate. |
| Internet access | `EP04` downloads the CISA KEV catalog via `Invoke-WebRequest`. Tier 2 checks can also perform outbound/probing behavior. | `-NoInternet` skips known public downloads/probes; no cache-only KEV mode exists. | Add KEV cache metadata and richer skipped-check reasons. |
| Exit codes | Comments say exit code 3 means "any framework below 60%"; code sets framework pass flags at 80% and uses them only when failures exist. | RMM alert semantics are ambiguous and may not match documented threshold. | Define exit-code contract and test grade/framework/failure combinations. |

### Safety Model Gaps

- `ReadOnly` currently filters scan IDs by risk tier, but it does not mean "no writes". Silent mode still writes files and registry/RMM fields, and GUI setup can modify system configuration.
- The same script contains read-only assessment, setup/configuration, RMM publishing, and report generation, but there is no central policy object that records whether each write is allowed, skipped, attempted, succeeded, or failed.
- Provider-specific RMM writes are best-effort and continue on failure, which is operationally useful, but the final summary does not include a structured write outcome table.
- Compliance string ordering is based on hashtable key enumeration. For RMM fields and dashboards, stable framework ordering would reduce noisy diffs.
- Default-checked setup actions improve onboarding but should show exact changes before execution, especially PSGallery trust, package provider install, firewall rule enables, Remote Registry start, and audit policy changes.

### New Backlog Refinement

Add a sub-feature under NSA-003/NSA-014: **Unified Write Policy and RMM Contract**.

Acceptance criteria:

- [ ] `ReadOnly` is renamed or clarified so users know whether it means scan safety only or zero persistent writes. (Partly done: read-only now blocks host-modifying setup; silent-mode RMM/registry writes still occur unless `-NoRmmWrite`/`-NoRegistryWrite`.)
- [ ] RMM field schemas are documented for NinjaRMM, Datto, ConnectWise Automate, Syncro, HaloPSA, and generic registry output.
- [ ] Datto custom-field slots are configurable instead of hard-coded to `Custom1` through `Custom5`.
- [ ] Exit codes are covered by tests for grade, ransomware score, fail count, and framework threshold combinations.
- [ ] Internet access is centrally gated and offline/cache-only mode produces explicit skipped reasons.

---

## 2D. Cycle 8 GUI Accessibility and Layout Audit Findings

Cycle 8 inspected the WPF GUI construction, custom control templates, setup dialog, filter/export controls, keyboard handling, and HTML report CSS. Main local code areas reviewed: `NetworkSecurityAudit.ps1:488` through `NetworkSecurityAudit.ps1:560` for themes, `NetworkSecurityAudit.ps1:4426` through `NetworkSecurityAudit.ps1:4583` for the main XAML layout, `NetworkSecurityAudit.ps1:4646` through `NetworkSecurityAudit.ps1:4741` for custom button/combo templates, `NetworkSecurityAudit.ps1:5386` through `NetworkSecurityAudit.ps1:5444` for checkbox/input helpers, `NetworkSecurityAudit.ps1:5540` through `NetworkSecurityAudit.ps1:5749` for tab and item-card construction, `NetworkSecurityAudit.ps1:6098` through `NetworkSecurityAudit.ps1:6414` for the setup dialog, `NetworkSecurityAudit.ps1:7108` through `NetworkSecurityAudit.ps1:7204` for filters and keyboard handling, and `NetworkSecurityAudit.ps1:7410` through `NetworkSecurityAudit.ps1:8029` for HTML/CSS report generation.

External design/accessibility references used for this pass:

- Microsoft UI Automation accessibility best practices: https://learn.microsoft.com/en-us/dotnet/framework/ui-automation/accessibility-best-practices
- Microsoft WPF UI Automation custom control guidance: https://learn.microsoft.com/en-us/dotnet/desktop/wpf/controls/ui-automation-of-a-wpf-custom-control
- W3C WCAG 2.2: https://www.w3.org/TR/WCAG22/
- Microsoft Fluent 2 accessibility guidance: https://fluent2.microsoft.design/accessibility
- Microsoft Fluent 2 color and focus-state guidance: https://fluent2.microsoft.design/color

### GUI Findings

| Area | Current Behavior | Risk / Gap | Roadmap Action |
|---|---|---|---|
| Programmatic accessibility | `rg` found no `AutomationProperties`, explicit automation names, or help text. Standard controls help, but many controls are built dynamically and labels are only visual. | Screen readers and UI automation tests may not expose enough name/role/value context for auditor fields, check cards, scan buttons, and setup actions. | Add a small `Set-A11y` helper that applies `AutomationProperties.Name` and `HelpText` to every actionable control. |
| Custom button template | `Apply-ButtonTheme` replaces button templates and only defines mouse-over styling. There is no explicit `IsKeyboardFocused` or disabled-state trigger. | Keyboard users may not see a clear focus indicator after theming, and disabled/action-risk states are not consistently visible. | Add a focus border trigger and disabled trigger to the shared button template. |
| Custom combo template | `Apply-ComboTheme` uses a custom `ToggleButton` and popup template. It has hover/open border states but no explicit keyboard-focus state or automation help text. | Profile/framework selectors are core workflow controls and need visible keyboard focus plus screen-reader labels. | Add focus state, names/help text, and snapshot/automation checks for open/closed states. |
| Clickable `TextBlock` | The guidance toggle is a `TextBlock` with `Add_MouseLeftButtonDown`. | It is mouse-centric and may not expose an invoke pattern or keyboard activation. | Replace with a real `Button` styled as a compact text action. |
| Check row density | Each check card combines checkbox title, weight/severity badges, per-item scan button, compliance text, guidance, status/remediation controls, assignment/due fields, and three text areas. | Power users get dense information, but the first row can become crowded for long check titles and small windows. | Keep density but add card header wrapping, two-row metadata layout, and saved compact/expanded view modes. |
| Fixed-width scan bar | Main window has `MinWidth=1000`, scan target/profile/framework widths are fixed, and the scan bar uses many `Auto` columns. | On smaller displays or zoom >100%, controls can squeeze or overflow before users can complete the core scan workflow. | Convert scan bar to wrap/grid breakpoints: target/credentials/profile on first row, scan actions on second row. |
| Setup dialog defaults | Turnkey setup defaults many modifying actions to checked when admin, including package/provider, modules, WinRM, firewall, audit policies, and Remote Registry. | The dialog is visually polished but does not visually separate read-only discovery from host-modifying actions strongly enough. | Add risk grouping, write manifest preview, and an explicit "read-only discovery only" preset. |
| Progress and status | Progress bars use color and numeric text in some areas, but category progress bars and status badges rely heavily on color. | Color-blind and high-contrast users need redundant labels and non-color state cues. | Add text labels/icons and test contrast for all seven themes. |
| Keyboard behavior | There is Ctrl+Wheel zoom, Ctrl+0 reset, and Escape defocus. Repo notes say keyboard shortcuts were removed; current shortcuts are not workflow shortcuts but should still be documented or made discoverable outside main copy. | Hidden keyboard behavior can surprise users, and focus can be lost after dialogs. | Add focus-return handling after setup/export dialogs and keep any shortcut-like behavior limited to accessibility/zoom. |
| Theme contrast | Themes are dark-only and tasteful, but several combinations should be measured, especially Dracula secondary text, Monokai secondary text, badge text over severity colors, and focus indicators. | Good-looking palettes can still miss contrast targets. | Add a theme contrast audit script for text, border, badge, and focus token pairs. |

### HTML Report Findings

| Area | Current Behavior | Risk / Gap | Roadmap Action |
|---|---|---|---|
| Responsiveness | CSS uses fixed body padding, max-width 1200, grid dashboards, two-column category grids, five-column score stats, four-column ransomware domains, and wide technical tables. There is print CSS but no mobile/reflow `@media` rule. | HTML reports can be hard to read on phones, tablets, narrow browser panes, or embedded ticketing/GRC viewers. | Add responsive breakpoints and horizontal table wrappers. |
| Table usability | Technical tables can contain long findings, evidence, compliance, MITRE details, and remediation columns. | Dense rows are useful for technical readers but can become horizontally crowded and hard to scan. | Add sticky headers, column priority modes, and collapsible details per finding. |
| Focus and links | The report has limited interactive controls today, but exported HTML lacks `:focus-visible` styling for links or future controls. | Future filters/toggles/deep links may be inaccessible by keyboard unless styles are added now. | Add global `:focus-visible` and deep-link anchors for every check ID. |
| Status symbols | HTML uses `[X]`, `[ ]`, `P`, `X`, `~`, and color-coded classes. | ASCII fallback is good, but should be standardized in a legend so client readers understand symbols. | Add a status legend near the report header. |
| Long evidence text | Findings are placed in `<pre class='find'>` with max-height and scrolling; evidence is inline text. | Very long evidence can overwhelm tables and reduce print readability. | Add "summary first, expandable evidence" for browser view and print appendix mode. |
| Target size | Report tags and small badges are compact. Some future filter/deep-link controls could fall below WCAG 2.2 target-size expectations if implemented as tiny chips. | Small controls are hard for touch and motor-impaired users. | Use at least 24 px target size for interactive report controls and keep badges non-interactive unless sized as buttons. |

### Product Fit

The current GUI should remain a dense operational tool, not a marketing page. The best upgrade path is not a visual redesign. It is a focused accessibility/polish pass that:

- Preserves dark-only themes and fast scanning workflows.
- Improves keyboard focus and screen-reader metadata.
- Reduces horizontal crowding in the scan bar and check cards.
- Clarifies host-modifying setup actions before they run.
- Makes exported reports easier to read in narrow, printed, and client-facing contexts.
- Replaces rounded pill-style decorative badges with compact square or low-radius status tags where project UI rules require it.

### New Backlog Refinement

Add a sub-feature under NSA-017/NSA-013: **Accessibility and Report Reflow Pass**.

Acceptance criteria:

- [ ] Every actionable WPF control has an automation name and, where useful, help text.
- [ ] Shared button, combo, tab, checkbox, and text-action styles include visible keyboard focus states.
- [ ] Mouse-only clickable `TextBlock` controls are replaced with keyboard-invokable controls.
- [ ] Setup dialog has separate "read-only discovery" and "host-modifying setup" groupings with a write preview.
- [ ] Scan bar and check-card headers remain usable at 1000 px width and 150 percent zoom.
- [ ] All seven themes pass a scripted contrast audit for primary text, secondary text, input text, button text, severity tags, and focus indicators.
- [ ] HTML report has responsive breakpoints, table wrappers, sticky headers, check anchors, status legend, and focus-visible styles.
- [ ] Report interactive targets meet WCAG 2.2 target-size expectations where controls are interactive.
- [ ] Automated UI smoke test verifies the app opens, tab order reaches core controls, and exported HTML reflows at desktop/tablet/mobile widths.

---

## 2E. Cycle 9 Entra and Microsoft Graph Implementation Plan

Cycle 9 inspected the current local Entra/Intune detection path, the identity-adjacent checks that already use cloud-oriented labels, the framework mappings attached to those checks, and current Microsoft Graph documentation for the first cloud assessment pack.

Local code areas reviewed:

- `NetworkSecurityAudit.ps1:197` through `NetworkSecurityAudit.ps1:221` detects Azure AD/Entra join and Intune enrollment locally with `dsregcmd /status` and `HKLM:\SOFTWARE\Microsoft\Enrollments`.
- `NetworkSecurityAudit.ps1:2365` through `NetworkSecurityAudit.ps1:2412` implements `IA03` as local MFA/remote-access signals: RDP NLA, installed AzureAD/Microsoft.Graph modules, ADFS service, MFA/SSO agent software, smart card policy, and Windows Hello for Business indicators.
- `NetworkSecurityAudit.ps1:2457` through `NetworkSecurityAudit.ps1:2488` implements `IA09` as local RDP/VPN posture: RDP enabled/NLA/port, VPN adapters, built-in VPN connections, split tunneling, and VPN software.
- `NetworkSecurityAudit.ps1:3850` and `NetworkSecurityAudit.ps1:3856` map `IA03` and `IA09` to MFA/Conditional Access-relevant controls even though the current evidence is local and heuristic.
- `rg` found no current `Connect-MgGraph`, `Invoke-MgGraphRequest`, `graph.microsoft`, Secure Score, Conditional Access, risky user, sign-in, Intune compliance policy, or alert API implementation in the script.

Official Microsoft references used:

- Microsoft Graph auth concepts: https://learn.microsoft.com/en-us/graph/auth/auth-concepts
- Microsoft Graph permissions overview: https://learn.microsoft.com/en-us/graph/permissions-overview
- Microsoft Graph throttling guidance: https://learn.microsoft.com/en-us/graph/throttling
- Secure Score list API: https://learn.microsoft.com/en-us/graph/api/security-list-securescores?view=graph-rest-1.0
- Conditional Access policies list API: https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0
- Conditional Access What If/evaluate API: https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-evaluate?view=graph-rest-1.0
- Authentication methods user registration details API: https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0
- Sign-ins API: https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0
- User list and `signInActivity` API notes: https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0
- Risky users API: https://learn.microsoft.com/en-us/graph/api/riskyuser-list?view=graph-rest-1.0
- Application list API: https://learn.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0
- Service principal list API: https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list?view=graph-rest-1.0
- OAuth2 permission grant resource: https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant?view=graph-rest-1.0
- Intune device compliance policies list API: https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-devicecompliancepolicy-list?view=graph-rest-1.0
- Intune managed devices list API: https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list?view=graph-rest-1.0
- Security alerts v2 list API: https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0
- Directory audits list API: https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0
- Devices list API: https://learn.microsoft.com/en-us/graph/api/device-list?view=graph-rest-1.0

### Local vs Cloud Check Boundaries

| Existing / Proposed ID | Scope | Current or Proposed Evidence | Roadmap Action |
|---|---|---|---|
| `IA03` or `IA03-L` | Local MFA and strong-auth signals | RDP NLA, ADFS service, MFA/SSO agent software, smart card policy, Windows Hello for Business policy/enrollment/PIN settings. | Keep the check but rename/report it as local MFA/strong-auth indicators so it does not imply tenant-wide MFA enforcement. |
| `IA09` or `IA09-L` | Local remote-access posture | RDP enabled/NLA/port, VPN adapters/software, split tunnel on local VPN profiles. | Keep the check but rename/report it as remote-access/VPN posture. Move actual Conditional Access assurance to new `CL` checks. |
| `CL01` through `CL12` | Microsoft Graph tenant posture | Secure Score, Conditional Access, MFA registration, sign-ins, guests, risky users, apps/consent, Intune, Defender/Sentinel-style alerts, directory audit, device inventory. | Add a new cloud namespace with explicit permissions, source endpoint, tenant prerequisites, and skip states. |

### First Cloud Check Set

| ID | Check | Primary Graph Endpoint(s) | Least-Privilege Permission(s) / Prerequisites | Evidence and Report Output | Skip / Risk Handling |
|---|---|---|---|---|---|
| `CL01` | M365 Secure Score | `GET /security/secureScores?$top=1` | `SecurityEvents.Read.All`; national cloud support excludes China per Microsoft docs. | Current score, max score, percentage, control scores, enabled services, comparative score basis, provider, source timestamp. Add "M365 Secure Score" card and trend hook. | `NotPermitted` for 403, `NotLicensed` or `NotConfigured` when tenant has no security score data, `Skipped` when cloud auth is absent. |
| `CL02` | Conditional Access policy inventory | `GET /identity/conditionalAccess/policies` | `Policy.Read.All`; delegated user also needs a supported Entra role such as Security Reader, Global Reader, Security Administrator, or Conditional Access Administrator. | Enabled/report-only/disabled counts, included/excluded users/groups/roles/apps, grant controls, session controls, created/modified dates, break-glass exclusions. | Separate "not permitted" from "no policies configured"; flag disabled-only or report-only-only tenants. |
| `CL03` | Conditional Access MFA/admin coverage | `GET /identity/conditionalAccess/policies`; optional `POST /identity/conditionalAccess/evaluate` | `Policy.Read.All` for policy inventory; `Policy.Read.ConditionalAccess` or stronger for What If evaluation. | Whether admins are covered by MFA, whether all users or high-risk users are covered, dangerous exclusions, service principal scenarios, legacy/client app coverage. | What If requires complete sign-in context; report evaluation confidence and fall back to static policy analysis if evaluation is unavailable. |
| `CL04` | MFA registration and auth methods | `GET /reports/authenticationMethods/userRegistrationDetails` | `AuditLog.Read.All`; delegated roles include Reports Reader, Security Reader, Security Administrator, or Global Reader. Microsoft notes this API does not work for disabled users. | Tenant counts and percentages for MFA registered, MFA capable, passwordless capable, SSPR state, methods registered, admin vs non-admin coverage. | Exclude disabled users explicitly and report disabled-user blind spot instead of treating them as pass/fail. |
| `CL05` | Legacy auth and sign-in risk signals | `GET /auditLogs/signIns?$filter=createdDateTime ...` | `AuditLog.Read.All`; Conditional Access details also require CA-readable roles/permissions. Sign-in logs are limited to tenant retention. | Legacy client app use, failed/successful legacy sign-ins, app/resource, UPN, IP/location summary, CA status when available, last 30-day view by default. | Use bounded time filters to avoid timeouts; classify retention/licensing gaps separately. |
| `CL06` | Stale members and guests | `GET /users?$select=displayName,userPrincipalName,userType,accountEnabled,createdDateTime,signInActivity` | User read permission plus `AuditLog.Read.All` for `signInActivity`; Microsoft notes P1/P2 license requirement for sign-in activity and max page size 500 when selected/filtered. | Stale members, stale guests, never-signed-in accounts, disabled accounts, guest age, last successful sign-in, high-risk inactive admins when role data is later added. | If `signInActivity` is unavailable, degrade to age/account-enabled findings and mark activity evidence `NotLicensed` or `NotPermitted`. |
| `CL07` | Risky users | `GET /identityProtection/riskyUsers` | `IdentityRiskyUser.Read.All`; delegated user needs Global Reader, Security Operator, Security Reader, or Security Administrator; Identity Protection is license-gated in practice. | Count by `riskLevel` and `riskState`, unresolved high-risk users, stale risk updates, deleted/processing state. | Treat missing Identity Protection as `NotLicensed`; avoid failing tenants only because the API is unavailable. |
| `CL08` | Enterprise apps, credentials, and consent grants | `GET /applications`, `GET /servicePrincipals`, OAuth2 permission grants | `Application.Read.All` for app/SP inventory; grant-related reads need exact permission validation during implementation. | High-privilege app permissions, admin-consented delegated grants, multi-tenant apps, stale/expiring credentials, owner gaps, disabled service principals. | `keyCredentials` selection has documented throttling; use `$select`, paging, and throttling backoff carefully. |
| `CL09` | Intune compliance policy posture | `GET /deviceManagement/deviceCompliancePolicies`; optional `GET /deviceManagement/managedDevices` | `DeviceManagementConfiguration.Read.All`; managed device inventory uses `DeviceManagementManagedDevices.Read.All`; active Intune license required. | Compliance policies by platform, assignments, last modified, status overview where available, unmanaged/noncompliant device counts if managedDevices is permitted. | `NotLicensed` when Intune is absent, `Partial` when policy inventory is available but device inventory is not. |
| `CL10` | Security alerts / Defender summary | `GET /security/alerts_v2` | `SecurityAlert.Read.All`; delegated user needs Security Reader, Global Reader, Security Operator, or Security Administrator. | Active high/critical alerts, stale unresolved alerts, service source, severity, MITRE techniques, incident links when present, source timestamps. | Filter by severity/status/time window and page through `@odata.nextLink`; distinguish no alerts from no provider data. |
| `CL11` | Directory audit and privileged change watch | `GET /auditLogs/directoryAudits` | `AuditLog.Read.All`; delegated roles include Reports Reader, Security Reader, Security Administrator. | Recent privileged role changes, app consent events, CA policy changes, access review/PIM-related audit categories, admin reset events. | Treat as an evidence timeline and delta source; do not over-score without event retention context. |
| `CL12` | Device inventory and join health | `GET /devices`; optional `GET /deviceManagement/managedDevices` | `Device.Read.All`; Intune managed devices require `DeviceManagementManagedDevices.Read.All` and active Intune license. | Stale registered devices, disabled devices, join/registration state, compliance state from Intune, last sync, OS/platform, ownership. | Keep Entra device inventory separate from Intune management inventory so non-Intune tenants still get value. |

### Permission and Auth Model

Add a `CloudPermissionManifest` beside the existing check metadata. Each cloud check should declare:

- `CheckId`, `DisplayName`, `Endpoint`, `ApiVersion`, `HttpMethod`, `DefaultProfile`, `Category`, `FrameworkMap`, and `EvidenceMode`.
- Delegated scopes, application scopes, required Entra role hints, license prerequisites, national-cloud availability, beta/v1 status, paging style, and cache TTL.
- Supported result statuses: `Pass`, `Fail`, `Partial`, `Skipped`, `NotLicensed`, `NotPermitted`, `NotConfigured`, and `Error`.
- Data classification for every field: safe-to-report, tenant-sensitive, user-sensitive, secret, or redact.

The first UX should expose permission bundles instead of a raw scope wall:

- **Cloud Discovery:** tenant metadata, device join context, lightweight user/app inventory where permitted.
- **Identity Core:** Conditional Access policies, MFA registration, sign-ins, users/guests, risky users.
- **Security Core:** Secure Score, alerts, directory audit events.
- **Intune:** compliance policies and managed device compliance state.
- **Full Cloud:** all cloud checks with the widest consent prompt.

Do not store refresh tokens, access tokens, client secrets, certificates, or device codes in reports, state files, RMM fields, or logs. Reports may include auth mode, scopes requested, scopes granted when safely retrievable, tenant name/id if the user accepts that disclosure, and source timestamps. Default MSP/client-safe exports should allow tenant ID hashing or redaction.

### Graph Request Wrapper Requirements

Implement a narrow wrapper before implementing individual checks:

- `Connect-CloudAuditGraph` or equivalent preflight that can use delegated interactive/device-code auth first and app-only later.
- `Invoke-GraphAuditRequest` wrapper around `Invoke-MgGraphRequest` or direct REST, with `@odata.nextLink` paging, `$select`, `$filter`, `$top`, consistency headers, beta/v1 selection, and structured error classification.
- Throttling handling that honors `Retry-After` on HTTP 429 and falls back to exponential backoff when no header is returned, per Microsoft throttling guidance.
- Stable evidence envelopes for each call: `endpoint`, `api_version`, `request_window`, `source_timestamp`, `permission_scope`, `auth_mode`, `tenant`, `paging_summary`, `throttle_count`, and `redaction_summary`.
- Unit fixtures for Graph responses so cloud check logic can be tested offline without a tenant.

### Report and Export Shape

Cloud findings should be emitted through the same report/export surfaces as local checks while preserving provenance. Add or extend a normalized result shape:

```powershell
@{
    check_id          = 'CL02'
    source            = 'MicrosoftGraph'
    status            = 'Fail'
    severity          = 'High'
    endpoint          = '/identity/conditionalAccess/policies'
    api_version       = 'v1.0'
    auth_mode         = 'Delegated'
    permission_scope  = @('Policy.Read.All')
    tenant_ref        = '<hash-or-id-based-on-privacy-setting>'
    source_timestamp  = '2026-06-06T00:00:00Z'
    evidence_facts    = @()
    skipped_reason    = $null
    raw_metadata      = @{ redacted = $true }
}
```

Report sections to add:

- Cloud Permission Preflight: requested scopes, granted scopes where available, role/licensing prerequisites, skipped checks, and privacy mode.
- Identity Cloud Summary: Secure Score, CA coverage, MFA registration, legacy auth, risky users, stale guests/users.
- Cloud Findings: normal check cards for `CL` IDs with the same remediation, owner, due-date, evidence, framework, and MITRE fields as local checks.
- Cloud Evidence Appendix: endpoint/source timestamps, redaction notes, API version, and status taxonomy.
- MSP-Friendly Exception Summary: not licensed, not permitted, not configured, skipped, and errors grouped separately from true failures.

### Acceptance Criteria for Cycle 9 Scope


---

## 2F. Cycle 10 Continuous Assessment Schema Findings

Cycle 10 inspected current saved-state, diff, structured export, silent-mode, scoring, and RMM paths, then mapped them to a durable recurring-assessment model.

Local code areas reviewed:

- GUI save state includes `Client`, `Auditor`, `Date`, `Theme`, centralized product/schema version metadata, `ScanTarget`, and per-check `Checked`, `Status`, `Notes`, `Findings`, `Evidence`, `RemAssign`, `RemDue`, `RemStatus`, and `ScanTime`.
- `NetworkSecurityAudit.ps1:7216` through `NetworkSecurityAudit.ps1:7247` restores saved state but does not validate schema version, tool version, check catalog version, removed/renamed checks, or unknown future fields.
- `NetworkSecurityAudit.ps1:7274` through `NetworkSecurityAudit.ps1:7313` compares two manual GUI save files, but only reports `Status` and `RemStatus` changes in a message box. It does not produce a reusable delta artifact, score trend, exposure windows, evidence change detection, or silent-mode output.
- `NetworkSecurityAudit.ps1:8035` through `NetworkSecurityAudit.ps1:8061` auto-exports HTML, findings JSON, CSV, and summary JSON as point-in-time files. `NetworkSecurityAudit.ps1:8107` through `NetworkSecurityAudit.ps1:8114` auto-saves GUI state to Desktop, but silent mode does not append an audit history.
- `NetworkSecurityAudit.ps1:8120` through `NetworkSecurityAudit.ps1:8235` exports structured findings JSON with schema `2.1`, timestamp, environment, scores, compliance summaries, counts, and all findings. It lacks a run ID, stable finding fingerprint, previous-run reference, catalog hash, history schema version, and delta fields.
- `NetworkSecurityAudit.ps1:8239` through `NetworkSecurityAudit.ps1:8310` exports one JSONL event per finding, which is close to a history event stream, but it is still a single-run export and has no `run_summary`, `delta_state`, `first_seen`, `last_seen`, `exposure_days`, or `previous_status`.
- `NetworkSecurityAudit.ps1:8390` through `NetworkSecurityAudit.ps1:8462` exports a compact dashboard summary with current scores and critical findings only; it is a good seed for a per-run summary record but not a history store.
- `NetworkSecurityAudit.ps1:8664` through `NetworkSecurityAudit.ps1:8978` always produces silent-mode artifacts and RMM fields, but those fields expose only current grade/score/compliance/fail counts and output paths. They do not expose new criticals, resolved criticals, score delta, worst exposure age, baseline age, or history path.
- `README.md:459` through `README.md:465` states that save/load/diff enables historical records, but current automation is not yet a durable history or continuous monitoring engine.

External references used:

- Microsoft Graph delta query overview: https://learn.microsoft.com/en-gb/graph/delta-query-overview
- Microsoft Graph change notifications overview: https://learn.microsoft.com/en-us/graph/change-notifications-overview
- Microsoft Graph Secure Score API: https://learn.microsoft.com/en-us/graph/api/security-list-securescores?view=graph-rest-1.0
- Wazuh Security Configuration Assessment "How SCA works": https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/how-it-works.html
- CIS-CAT Pro Dashboard overview: https://ciscat-pro-dashboard.docs.cisecurity.org/en/latest/source/About%20Dashboard/
- NIST OSCAL assessment results model: https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-results/
- OASIS SARIF v2.1.0 standard: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html

### Current Gaps

| Area | Current Behavior | Gap for Continuous Assessment | Roadmap Action |
|---|---|---|---|
| Saved state | GUI state is saved as one JSON object keyed by check ID. | Good for resume, weak for trend: no run ID, no history schema, no catalog hash, no previous baseline pointer, and no version validation. | Add a versioned `AuditSnapshot` format that can be written by both GUI and silent mode. |
| Diff engine | GUI asks for two JSON files and displays a message box. | Comparison is not reusable by silent mode, exports, dashboards, RMM, or future automation; it ignores score/evidence/severity/remediation-detail changes. | Replace ad hoc diff with `Compare-AuditSnapshot` returning structured delta objects. |
| JSON exports | Findings JSON contains rich current-state data. | It cannot represent first-seen/last-seen, new/resolved/unchanged states, accepted risk carry-forward, or source provenance across runs. | Add `run_id`, `snapshot_id`, `history_schema_version`, `finding_fingerprint`, `delta_state`, and `previous_run_ref`. |
| JSONL exports | One event per finding is already SIEM-friendly. | It emits all findings each run but does not indicate whether an event is new, updated, unchanged, absent/resolved, or carried forward. | Add history JSONL records and reserve export JSONL for SIEM events derived from history/delta. |
| Summary export | Compact RMM payload includes current score and critical findings. | No trend or exposure-window fields, so MSP dashboards cannot tell whether posture improved or worsened. | Add score deltas, new/resolved critical counts, worst exposure age, baseline age, and history health fields. |
| RMM fields | Current fields overwrite latest grade/score/date/findings/compliance. | RMM only sees the latest point-in-time result; a repeated scan that gets worse is indistinguishable without external history. | Add optional delta-aware fields and keep current fields backward-compatible. |
| Cloud readiness | Cycle 9 added future `CL` checks and Graph provenance requirements. | Cloud APIs can return skipped/not licensed/not permitted and Graph delta tokens; those cannot be forced into simple pass/fail history. | Treat unavailable cloud states as first-class history states and store opaque Graph delta token metadata outside client reports. |

### External Lessons Applied

- Wazuh SCA stores agent/server state, sends change events instead of flooding all unchanged checks, marks not-applicable states with reasons, and uses policy/result integrity hashes. Network Security Auditor should do the same locally: store a catalog/check-manifest hash, append changed events, and periodically write a compact full snapshot for recovery.
- CIS-CAT Pro Dashboard focuses on recent/current configuration posture rather than indefinite raw retention, recommends less than two years of dashboard history, supports exceptions/rescoring, and can alert when imported scores deviate beyond a threshold. Network Security Auditor should default to a practical retention window, expose exceptions separately from remediation, and make score-deviation alerts configurable.
- Microsoft Graph delta query uses opaque `@odata.nextLink` and `@odata.deltaLink` state tokens. Future cloud history should store token references in private state, not reports, and should handle deleted resources, eventual consistency, and "sync from now" initialization.
- Microsoft Secure Score supports retrieving score collections with `$top`, `$skip`, and `$filter`. This can seed M365 score trend cards without inventing a separate scoring history for `CL01`.
- OSCAL assessment results explicitly support assessment reports and continuous monitoring with observations, risks, findings, reviewed controls, assessment subjects, evidence, and expiration concepts. The internal history schema should align with those concepts before adding an OSCAL export.
- SARIF baseline concepts show why every compared result needs a comprehensive baseline state, not just changed findings. NSA delta exports should classify every current and baseline finding as new, unchanged, updated, or absent/resolved before deriving human-friendly labels.

### Proposed History Storage Model

Use a local append-friendly history pack while preserving the current one-file deployment model:

```text
SecurityAudit_<client>_<target>_history/
  history.jsonl
  snapshots/
    <run_id>.snapshot.json
  baselines/
    latest.snapshot.json
    accepted-baseline.snapshot.json
  exports/
    <run_id>_delta.json
    <run_id>_delta.html
```

Default location should be next to the selected output path in silent mode, and Desktop in GUI/turnkey mode. Add `-HistoryPath`, `-BaselinePath`, `-NoHistory`, `-TrendDays`, `-AlertPreview`, and future `-WebhookUrl` CLI parameters. `-NoHistory` must still allow normal point-in-time reports.

### Proposed Snapshot Schema

Every run should produce a `run_summary` plus normalized finding states. Suggested top-level fields:

```json
{
  "record_type": "audit_snapshot",
  "history_schema_version": "1.0",
  "export_schema_version": "2.2",
  "tool": "NetworkSecurityAudit",
  "tool_version": "4.1.0",
  "run_id": "<guid-or-hash>",
  "snapshot_id": "<sha256-of-normalized-snapshot>",
  "previous_run_id": "<nullable>",
  "baseline_run_id": "<nullable>",
  "started_at": "2026-06-06T00:00:00Z",
  "completed_at": "2026-06-06T00:00:00Z",
  "client": "<client>",
  "target": "<host-or-tenant>",
  "scan_profile": "Full",
  "report_tier": "All",
  "read_only": true,
  "catalog_hash": "<sha256-of-check-catalog-and-framework-map>",
  "policy_hash": "<sha256-of-risk-tier-threshold-policy>",
  "environment_hash": "<privacy-safe-host-env-hash>",
  "scores": {},
  "counts": {},
  "output_paths": {},
  "write_results": [],
  "findings": []
}
```

Each finding should include:

```json
{
  "finding_fingerprint": "<sha256>",
  "check_id": "EP04",
  "source": "Local",
  "target_ref": "<host-or-tenant-hash>",
  "subject_ref": "<optional-object-id-or-resource>",
  "category": "Endpoint Security",
  "severity": "High",
  "weight": 5,
  "status": "Fail",
  "effective_state": "NonCompliant",
  "previous_status": "Pass",
  "delta_state": "NewFailure",
  "remediation_status": "Open",
  "previous_remediation_status": "Open",
  "first_seen": "2026-06-01T00:00:00Z",
  "last_seen": "2026-06-06T00:00:00Z",
  "last_changed": "2026-06-06T00:00:00Z",
  "last_passed": "2026-05-01T00:00:00Z",
  "occurrence_count": 3,
  "exposure_days": 5,
  "findings_hash": "<sha256-normalized-text>",
  "evidence_hash": "<sha256-normalized-evidence>",
  "evidence_mode": "Automated",
  "skip_reason": null,
  "not_applicable_reason": null,
  "accepted_risk": false,
  "suppression_expires": null,
  "frameworks": {},
  "mitre": {}
}
```

The fingerprint should be stable across runs and support future object-level cloud findings:

```text
sha256(tool_id + check_id + source + normalized_target + normalized_subject + framework_version)
```

For local host-level checks, `normalized_subject` can be empty. For future Graph checks, it can represent a user ID, app ID, service principal ID, policy ID, device ID, alert ID, or tenant-wide synthetic subject.

### Delta State Rules

Use raw status, effective state, and delta state separately:

| Raw Status | Effective State | Notes |
|---|---|---|
| `Pass` | `Compliant` | Does not accrue exposure. |
| `Partial` | `Degraded` | Accrues exposure unless the check manifest marks partial as informational. |
| `Fail` | `NonCompliant` | Accrues exposure. |
| `N/A` | `NotApplicable` | Does not accrue exposure but needs a reason when known. |
| `Not Assessed` | `Unknown` | Does not prove remediation; should not reset exposure by default. |
| `Skipped` | `Unavailable` | Carries previous exposure forward with stale-evidence warning. |
| `NotLicensed` | `UnavailableLicensed` | Cloud-specific; separate from fail. |
| `NotPermitted` | `UnavailablePermission` | Cloud-specific; separate from fail and useful for permission UX. |
| `NotConfigured` | `MissingConfiguration` | Can be pass/fail depending on check manifest. |
| `Error` | `CollectionError` | Does not prove remediation; requires retry/diagnostic. |

Recommended `delta_state` values:

- `NewFailure`: previously absent/compliant/unknown, now noncompliant or degraded.
- `Resolved`: previously noncompliant/degraded, now compliant or not applicable by policy.
- `Worsened`: severity, status, evidence, affected object count, or score impact worsened.
- `Improved`: status, evidence, affected object count, remediation status, or score impact improved but not fully resolved.
- `UnchangedFail`: noncompliant and materially unchanged.
- `UnchangedPass`: compliant and unchanged.
- `UpdatedEvidence`: status unchanged but evidence/findings/remediation details changed.
- `Unavailable`: current scan could not collect enough evidence and should carry previous exposure forward.
- `Suppressed`: finding remains present but is accepted/deferred with an active exception.
- `ExpiredSuppression`: accepted/deferred exception expired and the finding should re-alert.
- `AbsentFromCurrentRun`: existed in baseline but no longer appears; emit only in delta output, not as a current snapshot finding.

Exposure-window rules:

- `first_seen` starts when a finding first becomes `NonCompliant` or `Degraded`.
- `last_seen` updates only when the finding is actually observed in the current run.
- `last_changed` updates when raw status, effective state, remediation status, severity, subject, or evidence hash changes.
- `exposure_days` is `now - first_seen` for active noncompliant/degraded findings.
- `Unavailable`, `NotPermitted`, `NotLicensed`, `Skipped`, and `Error` do not reset exposure. They should retain previous `first_seen` and mark `evidence_stale=true`.
- `Resolved` records `resolved_at` and should preserve the final exposure window for reporting.
- `Suppressed` and `Accepted Risk` do not erase exposure; they only change alerting and executive rollup behavior.

### Alert and Dashboard Payloads

Add a preview-first alert payload that can be written to JSON before any webhook delivery exists:

```json
{
  "event_type": "network_security_audit_delta",
  "run_id": "<run-id>",
  "client": "<client>",
  "target": "<target>",
  "timestamp": "2026-06-06T00:00:00Z",
  "trigger": "new_critical_or_score_drop",
  "score": { "current": 72, "previous": 81, "delta": -9, "grade": "C", "previous_grade": "B" },
  "ransomware_score": { "current": 60, "previous": 78, "delta": -18 },
  "counts": {
    "new_failures": 4,
    "resolved_failures": 2,
    "worsened": 3,
    "improved": 5,
    "unavailable": 1,
    "active_critical": 2
  },
  "worst_exposure_days": 31,
  "top_new_findings": [],
  "output_paths": {}
}
```

RMM-compatible fields should stay compact and backward-compatible:

- `SecurityAuditScoreDelta`
- `SecurityAuditGradePrevious`
- `SecurityAuditNewCritical`
- `SecurityAuditResolvedCritical`
- `SecurityAuditWorstExposureDays`
- `SecurityAuditBaselineAgeDays`
- `SecurityAuditHistoryPath`
- `SecurityAuditDeltaPath`
- `SecurityAuditHistoryHealth`

### Implementation Sequence

1. Add `Convert-AuditStateToSnapshot` that normalizes GUI and silent-mode state into one snapshot object.
2. Add `Get-AuditCatalogHash` and `Get-AuditPolicyHash` so history can detect check catalog/framework/threshold drift.
3. Add `Get-FindingFingerprint` and text normalization for evidence/findings hashes.
4. Add `Compare-AuditSnapshot` that returns a structured delta object for every current and baseline finding.
5. Add `Append-AuditHistory` that writes `run_summary`, `finding_delta`, and `history_health` JSONL records with file locking/retry.
6. Add `Export-DeltaJSON` and `Export-DeltaHTML` for GUI, silent mode, and dashboard ingestion.
7. Refactor the GUI `Diff` button to use the same comparison engine and offer export instead of message-box-only output.
8. Add silent-mode CLI flags: `-HistoryPath`, `-BaselinePath`, `-NoHistory`, `-TrendDays`, `-AlertPreview`, and later `-WebhookUrl`.
9. Add migration support for current GUI save files whose `Items` object lacks history metadata.
10. Add tests with two fixed snapshots to prove new/resolved/worsened/improved/unchanged/unavailable/exposure behavior.

### Acceptance Criteria for Cycle 10 Scope

- [ ] Silent mode can append to a history JSONL file and write a full snapshot without requiring the GUI save path.
- [ ] Existing GUI save files can still load and compare through a compatibility adapter.
- [ ] Delta output includes `NewFailure`, `Resolved`, `Worsened`, `Improved`, `UnchangedFail`, `UnchangedPass`, `UpdatedEvidence`, `Unavailable`, `Suppressed`, `ExpiredSuppression`, and `AbsentFromCurrentRun`.
- [ ] Exposure windows survive skipped/not permitted/not licensed/error states instead of resetting to zero.
- [ ] Score trends cover overall risk, ransomware score, category scores, framework scores, and future Secure Score.
- [ ] RMM summary fields can show current score plus score delta, new criticals, resolved criticals, worst exposure days, and baseline age.
- [ ] Alert payloads can be generated and previewed without sending network traffic.
- [ ] History retention and compaction are configurable so Desktop/RMM output folders do not grow forever.
- [ ] History records include catalog and policy hashes to flag false deltas after check definitions, framework mappings, or scoring thresholds change.

---

## 3. Competitive Research

| Competitor / Source | Type | Relevant Features | UX Ideas | Technical Ideas | Notes | Confidence |
|---|---|---|---|---|---|---|
| PingCastle Healthcheck | Free/commercial AD assessment | AD healthcheck, 4 sub-scores, rules, details, report model | Add domain score drilldowns for privileged accounts, trusts, stale objects, and anomalies | Add PingCastle-style domain map and rule-detail "solve it" equivalent | Source: https://www.pingcastle.com/documentation/healthcheck/ | High |
| PingCastle Enterprise | Commercial scale AD assessment | Centralized display of healthcheck reports and enterprise-scale AD posture | Add multi-client/multi-domain dashboard path while preserving one-file scan | Import multiple scan outputs into a local static dashboard | Source: https://www.pingcastle.com/services/enterprise/ | Medium |
| Semperis Purple Knight | Free AD/Entra/Okta assessment | 185+ IOEs/IOCs, hybrid AD/Entra/Okta coverage, MITRE/D3FEND tags, prioritized guidance | Add "Find, Prioritize, Fix, Validate" flow to report and GUI | Add D3FEND mapping and Graph permissions setup wizard | Source: https://www.semperis.com/purple-knight/ | High |
| Purple Knight FAQ | Trust/safety reference | Free, no phone-home claim, read-only AD behavior, SIEM limitation in free tool | Add visible trust panel explaining local-only data handling and read-only behavior | Add scan manifest listing every query/write before run | Source: https://www.semperis.com/purple-knight/faq/ | High |
| Microsoft Graph Secure Score | Cloud security score API | `GET /security/secureScores`, delegated/app permissions, national cloud availability | Add M365 Secure Score card and change trend | Use Graph Secure Score as cloud posture input and benchmark delta | Source: https://learn.microsoft.com/en-us/graph/api/security-list-securescores | High |
| Microsoft Security Compliance Toolkit / Policy Analyzer | Baseline comparison toolkit | Microsoft-recommended baselines, GPO comparison, local policy/registry comparison, Excel export | Add "baseline diff" report section for GPO/local policy drift | Integrate LGPO/Policy Analyzer output ingestion or parallel baseline check schema | Source: https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10 | High |
| CIS-CAT Pro Assessor v4 | CIS benchmark assessor | 100+ CIS Benchmarks, local/remote assessment, multiple report formats, dashboard integration | Add benchmark selection and exceptions model | Add customizable benchmark manifest and import/export of organization-specific policy baselines | Source: https://ciscat-assessor.docs.cisecurity.org/en/latest/About/ | High |
| CIS-CAT Pro Dashboard | Central repository/dashboard | Stores assessor results, shows recent compliance trends, exceptions, rescored averages | Add MSP rollup dashboard and exception management | Define normalized assessment-result schema compatible with dashboard ingestion concepts | Source: https://ciscat-pro-dashboard.docs.cisecurity.org/en/latest/source/About%20Dashboard/ | Medium |
| Wazuh SCA | Open-source SIEM/XDR configuration assessment | Agent policy files, CIS benchmark policies, endpoint compliance scans | Add optional Wazuh package export with policies/dashboards | Export JSONL fields aligned to Wazuh/SIEM dashboards and policy IDs | Source: https://documentation.wazuh.com/current/compliance/nist/configuration-assessment.html | High |
| Tenable Nessus compliance checks | Paid vulnerability/compliance scanner | Windows `.audit` files, registry/local security policy/file checks, credentialed audits | Add "custom policy pack" UX for MSP-tuned checks | Support importing or generating Nessus-style audit snippets for benchmark parity checks | Source: https://docs.tenable.com/nessus/compliance-checks-reference/Content/WindowsConfigurationAuditComplianceFileReference.htm | Medium |
| CISA KEV catalog | Official vulnerability prioritization feed | Official exploited-vulnerability catalog available as CSV, JSON, JSON schema | Add KEV timeline and remediation due-date emphasis | Cache catalog, add schema validation, vendor/product normalization, ransomware-known flag | Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog | High |
| NIST OSCAL | Security/compliance automation model | Machine-readable compliance documentation, assessment results, POA&M concepts | Add auditor-grade export path for GRC users | Export assessment results and remediation plan to OSCAL-compatible JSON | Source: https://pages.nist.gov/OSCAL | Medium |
| Lynis | Unix/Linux security audit | Hardening index, compliance checks, Unix/Linux/macOS focus | Add cross-platform sidecar with same report vocabulary | Linux sidecar can normalize Lynis/OpenSCAP outputs into NSA schema | Source: https://cisofy.com/documentation/lynis/features/ | Medium |

---

## 4. User Pain Points and Market Signals

| Source | Pain Point | Evidence | Opportunity | Priority |
|---|---|---|---|---|
| Purple Knight FAQ | Security teams care whether an assessment tool phones home or modifies AD. | Purple Knight explicitly answers data handling and AD write questions. | Add a trust/safety page, scan manifest, no-phone-home statement, and per-mode write summary. | P0 |
| PingCastle Reddit discussions | Users value easy AD audits but ask whether they can trust tools in sensitive AD environments. | Reddit search results include confidentiality/trust questions around PingCastle. | Put safety guarantees and offline operation front-and-center in README and report metadata. | P1 |
| Purple Knight product positioning | Hybrid AD now means AD, Entra ID, and Okta, not just on-prem AD. | Purple Knight 5.0 Community promotes AD, Entra ID, and Okta IOE/IOC coverage. | Build Entra Graph pack first; keep Okta as P3 unless user demand appears. | P1 |
| CIS-CAT / Microsoft SCT | Compliance users expect exact benchmark recommendations and baseline diffs. | CIS-CAT and SCT both emphasize baseline comparison and detailed report artifacts. | Add exact benchmark-level evidence, exceptions, and baseline diff mode. | P1 |
| Wazuh SCA / Tenable audit files | Enterprise/security teams expect policy-as-data and recurring assessment. | Wazuh uses policy files; Tenable uses `.audit` compliance files. | Add a check manifest and optional policy import/generation path. | P2 |
| RMM workflows | MSPs need recurring scans, exit codes, and custom fields but also need history and cross-client rollups. | Current code writes RMM fields and exits, but no central dashboard exists. | Add standalone static dashboard generated from JSON/JSONL outputs. | P1 |
| Local repo evidence | Local screenshot is unrelated to the app. | `screenshot.png` visual inspection on 2026-06-06. | Replace screenshot and add automated release asset checks. | P1 |
| Local repo evidence | No tests or lint config are committed. | `rg` found no Pester/CI; PSScriptAnalyzer unavailable locally. | Add parser/PSScriptAnalyzer/Pester harness and GitHub Actions. | P0 |

---

## 5. UX/UI Audit

### Visual Design

The WPF interface is useful and dense, with a dark operational feel and 7 dark themes. The current product fits an admin/security workflow better than a marketing-style app. However, the scan bar, footer filters, and export controls are crowded, and most controls are text buttons instead of compact icon buttons with tooltips. The local `screenshot.png` does not appear to represent this app, which weakens README trust and release polish.

Recommended direction:

- Keep the dark-only stance.
- Preserve the dense tool feel, but separate "run scan", "review findings", "export/share", and "settings/integrations" as first-class zones.
- Replace misleading local screenshots with current app screenshots for GUI, HTML report, executive summary, and silent-mode output.
- Use clearer hierarchy for score, critical findings, scan state, and next action.
- Avoid decorative rounded-pill badges; use restrained square/4px-radius status tags and icon+text where necessary.

### Navigation

Current navigation is category-tab based and practical for 67 checks. It should be expanded with:

- A left-side category list or compact index for large screens.
- A searchable check list by ID, title, severity, framework, status, and auto-check availability.
- Saved views: Failures, Critical, AD-only, Local-only, Needs evidence, Assigned to me, Due soon.
- Deep links in exported HTML to each finding ID.
- A "scan run summary" route/state showing skipped checks and why they were skipped.

Project note: repo instructions say keyboard shortcuts were removed. Do not add shortcut-driven UX unless the project rule is explicitly changed.

### Onboarding

The app has practical turnkey setup and pre-flight functions, but first-run trust and safety are not explicit enough. Before a first scan, users should see:

- What will be read.
- What can modify the system in the selected mode.
- Which checks will be skipped because modules, domain, admin rights, Graph permissions, or internet access are unavailable.
- Where output files and RMM fields will be written.
- Whether CISA KEV internet access will be attempted.

### Core Workflows

1. GUI full audit:
   - Select client/auditor/date, target, scan profile, framework.
   - Run pre-flight.
   - Run profile.
   - Review failures, evidence, and remediation fields.
   - Export tiered report and structured data.

2. RMM silent audit:
   - Run with `-Silent`.
   - Detect environment.
   - Execute profile with timeout.
   - Write files, RMM fields, registry cache, and exit code.

3. Future recurring assessment:
   - Load prior baseline.
   - Run changed checks or full scan.
   - Compute deltas and exposure window.
   - Alert on score regressions or critical new failures.

### Empty States

Add purpose-built states for:

- No scan run yet.
- No AD module/domain detected.
- No Defender cmdlets available.
- No Graph authorization configured.
- No prior baseline for diff mode.
- No failures found.
- No report output path available.

Each state should say what is unavailable, why, and the next safe action.

### Error States

Improve:

- Permission errors with exact missing permission and fallback behavior.
- Timeout errors with check ID, elapsed time, operation attempted, and whether partial evidence exists.
- Internet errors for KEV lookup with cache status.
- Export failures with path, disk space, file lock, and browser availability for PDF.
- RMM write failures separated from scan failures so exit codes remain defensible.

### Premium Feel Improvements

- Progress should show current check, skipped count, timeout count, and estimated remaining checks.
- Reports should have polished summary cards, compact evidence sections, and expandable technical details.
- Add skeleton/loading states in WPF where long scans or report generation happen.
- Add "copy evidence" and "copy remediation" actions in report and GUI.
- Use stable spacing, consistent type scale, and consistent severity/status colors across GUI and HTML report.

### Accessibility

WPF accessibility needs explicit validation:

- Tab order across client/auditor/date/scan controls/check fields.
- Screen reader names for scan buttons, status combos, report controls, and category tabs.
- Contrast validation across all 7 dark themes.
- Focus indicators that are visible and not only color-dependent.
- Reduced-motion/no-animation compatibility where flash/highlight timers are used.
- Text wrapping for long check titles and hints.

---

## 6. Feature Backlog

| ID | Feature | Description | User Value | Business Value | Evidence | Effort | Impact | Priority | Confidence |
|---|---|---|---|---|---|---|---|---|---|
| NSA-004 | Entra ID and M365 Graph assessment pack | CL01-CL13 implemented with mock support; remaining CL03-CL05, CL07-CL12 need tenant access. | 5 | 5 | CL01/CL02/CL06/CL13 live; remaining blocked on tenant. | 5 | 5 | P1 | High |
| ~~NSA-006~~ | ~~Remote fleet scan mode~~ | **SHIPPED v4.11.0** `-TargetsCsv`, `-ThrottleLimit`, `-PerHostTimeout`, `-Credential`. | - | - | - | - | - | DONE | - |
| ~~NSA-007~~ | ~~Remediation dry-run and rollback~~ | **SHIPPED v4.11.0** `-Remediate`, `-RemediateDryRun`, `-RemediateChecks` with 6 safe remediations and JSON rollback manifest. | - | - | - | - | - | DONE | - |
| ~~NSA-009~~ | ~~White-label executive pack~~ | **SHIPPED v4.11.0** `-BrandingConfig` JSON with logo, colors, cover page, branded header/footer. | - | - | - | - | - | DONE | - |
| NSA-011 | Check manifest and build-time bundler | Blocked: architectural design needed. See `Roadmap_Blocks.md`. | 3 | 4 | Monolith is now 13,800+ lines. | 4 | 4 | P1 | Medium |
| ~~NSA-014~~ | ~~SIEM content packs~~ | **SHIPPED v4.11.0** `-ExportSIEM` generates Splunk, Elastic, Sentinel, Wazuh configs + field mapping JSON. | - | - | - | - | - | DONE | - |
| NSA-015 | AD attack path visualization | Blocked: design needed. See `Roadmap_Blocks.md`. | 4 | 4 | Attack path narratives exist. | 5 | 4 | P2 | Medium |
| NSA-016 | Policy import/export | Blocked: schema design needed. See `Roadmap_Blocks.md`. | 4 | 4 | Tenable `.audit`; Wazuh policy files. | 5 | 4 | P2 | Medium |
| NSA-017 | GUI information architecture refresh | Blocked: WPF layout risk. See `Roadmap_Blocks.md`. | 4 | 4 | WPF XAML is dense. | 4 | 4 | P2 | High |
| NSA-018 | Linux/Unix sidecar | Blocked: cross-platform scope. See `Roadmap_Blocks.md`. | 3 | 3 | Lynis source. | 5 | 3 | P3 | Medium |
| NSA-019 | SaaS backup and cloud app coverage | Blocked: API credentials needed. See `Roadmap_Blocks.md`. | 4 | 3 | BR08 mentions SaaS backup. | 5 | 3 | P3 | Medium |
| NSA-020 | GRC/ticketing integrations | Blocked: integration credentials. See `Roadmap_Blocks.md`. | 3 | 4 | Previous roadmap planned integrations. | 5 | 3 | P3 | Low |

Scoring model: `(User Value + Business Value + Strategic Differentiation + Confidence) - Effort` should be applied during implementation planning. The table above uses priority labels after applying judgment.

---

## 7. Detailed Feature Specs

### Feature: Entra ID and M365 Graph Assessment Pack (NSA-004)

**Problem:**
The market has moved from on-prem AD-only to hybrid identity. Current code detects Azure AD/Entra join and Intune enrollment but lacks Graph-backed posture checks.

**Proposed Solution:**
Add an optional cloud assessment mode using Microsoft Graph:

- Secure Score ingestion and delta.
- Conditional Access coverage and risky exclusions.
- MFA registration and authentication methods.
- Legacy authentication/app password risk.
- Guest user lifecycle and stale guests.
- Privileged role assignment and PIM posture.
- App consent and overprivileged enterprise apps.
- Intune compliance policy coverage.
- Defender for Endpoint/Identity alert summary.

**User Stories:**

- As an MSP, I want one report that covers AD and M365 identity posture.
- As a sysadmin, I want Conditional Access gaps explained in plain language.
- As an auditor, I want Graph permission requirements documented before authentication.

**Technical Requirements:**

- Microsoft Graph module or direct REST path. Prefer a narrow `Microsoft.Graph.Authentication` / `Invoke-MgGraphRequest` integration first so the one-file distribution does not require many Graph submodules.
- `CloudPermissionManifest` for every cloud check with endpoint, API version, HTTP method, delegated/application scopes, Entra role hints, license prerequisites, national cloud support, beta/v1 flag, paging behavior, cache TTL, and privacy classification.
- Permission preflight with least-privileged permission display and profile bundles: Cloud Discovery, Identity Core, Security Core, Intune, and Full Cloud.
- Token handling that never stores access tokens, refresh tokens, device codes, client secrets, certificates, or raw auth headers in reports, state files, RMM fields, or logs.
- Cloud check IDs `CL01` through `CL12`, with framework/MITRE mapping and explicit separation from local `IA03`/`IA09` evidence.
- `Invoke-GraphAuditRequest` wrapper with `@odata.nextLink` paging, bounded `$filter` queries, `$select`, consistency headers, beta/v1 routing, `Retry-After` handling, exponential backoff fallback, and structured error classification.
- Cloud result status taxonomy: `Pass`, `Fail`, `Partial`, `Skipped`, `NotLicensed`, `NotPermitted`, `NotConfigured`, and `Error`.
- Graceful skip when tenant auth is not configured, permissions are denied, tenant licensing is absent, or an API/provider has no data.

**Cycle 9 First Cloud Check Set:**

| ID | Check | Primary Endpoint(s) | Core Prerequisites | Report Output |
|---|---|---|---|---|
| `CL01` | M365 Secure Score | `/security/secureScores?$top=1` | `SecurityEvents.Read.All` | Secure Score card, score percentage, control scores, enabled services, source timestamp. |
| `CL02` | Conditional Access inventory | `/identity/conditionalAccess/policies` | `Policy.Read.All` and supported Entra role for delegated reads | Enabled/report-only/disabled policies, exclusions, grant/session controls, risky gaps. |
| `CL03` | CA MFA/admin coverage | `/identity/conditionalAccess/policies`, optional `/identity/conditionalAccess/evaluate` | `Policy.Read.All`; `Policy.Read.ConditionalAccess` or stronger for What If | Admin MFA coverage, all-user/high-risk scenarios, service-principal and legacy-client coverage. |
| `CL04` | MFA registration/auth methods | `/reports/authenticationMethods/userRegistrationDetails` | `AuditLog.Read.All`; Reports Reader/Security Reader-style role | MFA registered/capable, passwordless capable, method mix, admin/non-admin coverage. |
| `CL05` | Legacy auth/sign-in evidence | `/auditLogs/signIns` with bounded time filters | `AuditLog.Read.All`; retention and CA-read permissions affect fields | Legacy client use, app/user/IP summaries, CA status when available. |
| `CL06` | Stale users and guests | `/users?$select=displayName,userPrincipalName,userType,accountEnabled,createdDateTime,signInActivity` | User read permission; `AuditLog.Read.All` and P1/P2 for `signInActivity` | Stale members, stale guests, never-signed-in accounts, disabled-user handling. |
| `CL07` | Risky users | `/identityProtection/riskyUsers` | `IdentityRiskyUser.Read.All`; Identity Protection licensing | Risk counts by level/state, unresolved high-risk users, stale risk updates. |
| `CL08` | Apps and consent grants | `/applications`, `/servicePrincipals`, OAuth2 permission grants | `Application.Read.All` plus grant-read validation | High-privilege apps, admin-consented grants, stale credentials, owner gaps. |
| `CL09` | Intune compliance posture | `/deviceManagement/deviceCompliancePolicies`, optional `/deviceManagement/managedDevices` | `DeviceManagementConfiguration.Read.All`; Intune license; managed devices need `DeviceManagementManagedDevices.Read.All` | Compliance policies, assignments, platform coverage, noncompliant/unmanaged device counts when permitted. |
| `CL10` | Security alerts summary | `/security/alerts_v2` | `SecurityAlert.Read.All` and supported security role for delegated reads | Active high/critical alerts, stale unresolved alerts, service source, MITRE techniques. |
| `CL11` | Directory audit timeline | `/auditLogs/directoryAudits` | `AuditLog.Read.All` | Recent privileged role, app consent, CA policy, PIM/access-review, and password reset events. |
| `CL12` | Device inventory and join health | `/devices`, optional `/deviceManagement/managedDevices` | `Device.Read.All`; Intune license for managed devices | Stale/disabled devices, join state, compliance state, last sync, ownership. |

**Acceptance Criteria:**

**Dependencies:**
Microsoft Graph availability, tenant consent model, Entra roles, licensing, and throttling limits. Sources: Microsoft Graph auth concepts, permissions overview, Secure Score, Conditional Access, authentication methods, sign-ins, risky users, applications/service principals, Intune, alerts, directory audits, devices, and throttling docs.

**Risks:**
Permissions and licensing vary by tenant. The UX must distinguish "not licensed", "not permitted", "not configured", and "pass/fail".

### Feature: Remote Fleet Scan Mode (NSA-006)

**Problem:**
MSPs often need to audit many endpoints from a jumpbox. Current GUI has target/WinRM/pre-flight concepts, but no full fleet orchestration.

**Proposed Solution:**
Add `-TargetsCsv`, `-ThrottleLimit`, `-Credential`, `-PerHostTimeout`, and aggregate export support. Use WinRM/PSRemoting for Windows endpoints and local run for localhost.

**Acceptance Criteria:**

- [ ] A CSV with host/client/site/tags can run a selected profile across multiple hosts.
- [ ] Each host produces an individual JSON and optional HTML report.
- [ ] Aggregate CSV/JSON summarizes host status, score, critical count, and skipped checks.
- [ ] Failed/offline hosts do not stop the whole batch.
- [ ] Read-only and risk-tier behavior applies per host.

**Dependencies:**
Reliable pre-flight, target identity, and runspace lifecycle.

**Risks:**
Remote execution environments differ widely. Must capture connection failures as first-class results, not generic scan failure.

### Feature: Remediation Dry-Run and Rollback (NSA-007)

**Problem:**
The tool already identifies many safe misconfigurations, but detection-only output leaves MSPs doing manual remediation. Remediation must be trustworthy and reversible.

**Proposed Solution:**
Start with safe pass-to-fix checks:

- Disable LLMNR.
- Disable SMBv1.
- Require SMB signing where appropriate.
- Enforce LAPS/Windows LAPS detection-to-guidance first, then remediation where safe.
- Increase event log sizes.
- Enable PowerShell script block logging.

Every remediation includes WhatIf, before/after diff, rollback manifest, and evidence.

**Acceptance Criteria:**

- [ ] No remediation runs unless `-ReadOnly:$false` and explicit remediation selection are provided.
- [ ] Every remediation has a dry-run preview.
- [ ] Every changed registry/policy/service value is captured before and after.
- [ ] Rollback manifest can restore prior local values.
- [ ] HTML and JSON attach remediation evidence.

**Dependencies:**
Safety manifest and central check metadata.

**Risks:**
Policy settings may be domain-managed and revert. Detect local vs GPO-controlled settings and warn.

### Feature: White-Label Executive Pack (NSA-009)

**Problem:**
MSPs and consultants need polished client-facing outputs for QBRs and sales/renewal workflows.

**Proposed Solution:**
Add client branding metadata:

- Logo.
- Primary/accent colors.
- Prepared by / MSP contact.
- Executive summary tone selection.
- PowerPoint export.
- PDF/HTML cover page.

**Acceptance Criteria:**

- [ ] Branding can be supplied via CLI config JSON and GUI fields.
- [ ] HTML/PDF report uses logo and colors without breaking dark report readability.
- [ ] PowerPoint export includes score, top risks, ransomware readiness, compliance gaps, and remediation phases.
- [ ] Reports still clearly identify tool version and scan limitations.

**Dependencies:**
Report templating and maybe PowerPoint generation utility.

**Risks:**
Branding should not hide severity or reduce accessibility contrast.

---

## 8. Technical Architecture Improvements

| Area | Current Observation | Recommended Improvement | Why It Matters | Priority |
|---|---|---|---|---|
| Architecture | One 8,446-line `.ps1` file holds UI, data, checks, exports, scoring, and RMM. | Keep single-file release, but author in source sections/modules with a build script that emits one file. | Preserves deployment advantage while improving maintainability. | P1 |
| Versioning | Version strings are duplicated and drifting. | Central product/version constants plus release validation. | Prevents confusing reports and release assets. | P0 |
| Check metadata | Check definitions, framework maps, MITRE maps, profiles, and scoring are separate hashtables. | Add manifest validation and eventually a single source-of-truth catalog. | Prevents missing mappings and broken profiles. | P0 |
| State management | GUI controls appear to be the live state source for exports. | Introduce a normalized in-memory result model and bind UI/export to it. | Makes tests and silent mode more reliable. | P1 |
| Safety | Risk tiers and read-only mode exist, but writes need better surfacing. | Add pre-run manifest, write summary, no-write switches, and clear docs. | Builds trust for security-sensitive environments. | P0 |
| Cloud API | Entra/Intune detection exists; Graph assessment absent. | Add optional Graph client with permission preflight and cloud check IDs. | Hybrid identity is a market expectation. | P1 |
| CISA KEV | EP04 downloads catalog and performs limited matching. | Add cache, schema validation, richer installed software inventory, vendor/product normalization. | Reduces false negatives and improves patch prioritization. | P1 |
| Report rendering | HTML is assembled in large string-building blocks. | Move to simple templating functions or section renderers with tests. | Easier to add branding, accessibility, and output consistency. | P1 |
| Exports | Many export formats exist, but schemas are implicit. | Add JSON schemas and snapshot tests. | Prevents breaking downstream RMM/SIEM consumers. | P0 |
| RMM | RMM writes are embedded in silent mode. | Add integration abstraction and dry-run/no-write controls. | Makes behavior safer and easier to test. | P1 |
| Testing | No committed tests or CI. | Add parser/Pester/PSScriptAnalyzer/GitHub Actions. | Critical for a large single-file tool. | P0 |
| Performance | GUI uses async runspaces and timers; silent mode uses per-check timeout. | Add timing metrics per check and historical slow-check report. | Helps tune long scans and avoid RMM timeouts. | P2 |
| Observability | Logs are visible in GUI and console output. | Add structured run log export with check start/end/status/duration. | Useful for support and audit defensibility. | P1 |
| Security | HTML encoding is used in many report sections. | Add output encoding tests and secret redaction rules. | Prevents report injection and credential leakage. | P0 |
| Accessibility | No automated UI accessibility evidence. | Add manual checklist, contrast validation, and tab-order review. | Client-facing GUI/report quality. | P2 |
| Documentation | README is strong, but changelog and local screenshot need cleanup. | Add docs/release checklist and asset validation. | Improves trust and release polish. | P1 |

---

## 9. Design System and Premium UI Plan

### Typography

- Use a compact, readable type scale: 20-22 title, 14-16 section headers, 12-13 body, 10-11 metadata.
- Keep monospace only for console/log/evidence.
- Do not scale font size with viewport width.

### Spacing

- Adopt a consistent 4/8/12/16 spacing system.
- Use stable heights for scan bar, footer, score widgets, and per-check header rows.
- Keep cards at 8px radius or below; avoid nested cards.

### Color

- Preserve dark-only themes.
- Keep severity colors consistent across GUI and HTML.
- Validate contrast for every theme.
- Avoid one-note theme dominance in future report templates.

### Components

- Scan profile selector.
- Framework selector.
- Check status selector.
- Evidence/findings/notes fields.
- Remediation owner/due/status.
- Filter segmented controls.
- Report export menu instead of many adjacent export buttons.
- Icon+tooltip for Save, Load, Diff, Export, Reset, Refresh, Copy, Open report.

### Forms

- Inline validation for output path, target, permissions, and Graph tenant configuration.
- Clear disabled states for unavailable checks.
- Required/optional markers for report metadata.

### Tables

- Sticky headers in HTML reports.
- Sort/filter by severity, status, framework, category, owner, due date.
- Compact row density with expandable evidence.

### Modals

- Use modals for scan manifest, Graph permissions, remediation preview, and export settings.
- Always show cancel/confirm and a summary of consequences for actions that write.

### Navigation

- Category tabs remain valid.
- Add search and saved filters.
- Add report table of contents and deep links.

### Motion

- Use minimal scan progress and flash feedback.
- Avoid motion that interferes with repeated operational use.
- Respect reduced-motion settings if accessible through WPF/environment.

### Loading States

- Per-check "Queued", "Running", "Timed out", "Skipped", "Complete".
- Export progress for HTML/PDF/PowerPoint.
- Graph auth/loading state when cloud pack is added.

### Empty States

- No scan run.
- No failed findings.
- No baseline.
- No cloud auth.
- No RMM detected.
- No internet/cache for KEV.

### Accessibility

- Visible focus states.
- Screen reader names.
- Tab-order review.
- Color-independent severity labels.
- Long text wrapping.

---

## 10. Implementation Phases

### Phase 0: Foundation

**Goals**

- Make releases safe and consistent.
- Establish automated validation.
- Fix visible trust/polish issues.

**Features**

- NSA-001 automated quality gate.
- NSA-002 version/branding authority.
- NSA-003 safety manifest and write controls.
- NSA-013 screenshot/docs release pipeline.

**Dependencies**

- Pester/PSScriptAnalyzer availability.
- Agreement on version constant and release flow.

**Estimated Complexity**

Medium.

**Risks**

- PSScriptAnalyzer noise.
- Existing RMM users relying on implicit registry writes.

**Definition of Done**

- CI passes.
- Parser and manifest tests run locally.
- Version strings consistent.
- Changelog date valid.
- Local screenshot reflects current app.
- README includes safety/write behavior.

### Phase 1: Core Product Upgrade

**Goals**

- Strengthen current workflows before expanding.
- Make reports and outputs more defensible.

**Features**

- NSA-005 continuous delta assessment.
- NSA-008 evidence-grade compliance output.
- NSA-012 CISA KEV enrichment.
- Structured run log and export schemas.

**Dependencies**

- Stable result schema.
- Versioning and tests from Phase 0.

**Estimated Complexity**

Medium-high.

**Risks**

- Schema migration from existing saves.
- KEV product matching false positives/negatives.

**Definition of Done**

- Historical trend and delta report works from two saved scans.
- JSON schema is documented.
- KEV cache and schema validation exist.
- Compliance evidence has separate facts/rationale/remediation.

### Phase 2: Premium UX

**Goals**

- Improve client-facing polish and daily operator ergonomics.

**Features**

- NSA-009 white-label executive pack.
- NSA-017 GUI IA refresh.
- Better empty/error states.
- Accessibility pass.

**Dependencies**

- Report section renderer cleanup.
- Design tokens for GUI and HTML report.

**Estimated Complexity**

Medium.

**Risks**

- WPF layout regressions.
- Report branding reducing contrast.

**Definition of Done**

- Current screenshots generated.
- HTML report has a polished executive summary and technical appendix.
- GUI search/saved filters exist.
- Contrast and tab-order checks are documented.

### Phase 3: Competitive Feature Expansion

**Goals**

- Match modern hybrid-identity assessment expectations.

**Features**

- NSA-004 Entra ID and M365 Graph assessment pack.
- NSA-015 AD attack path visualization.
- D3FEND mapping.

**Dependencies**

- Graph auth/permission design.
- Cloud check IDs and framework mapping.

**Estimated Complexity**

High.

**Risks**

- Graph permission/licensing complexity.
- Tenant data sensitivity.

**Definition of Done**

- Cloud profile runs and gracefully skips unavailable/licensed endpoints.
- Secure Score and Conditional Access findings are exported.
- AD/hybrid report shows prioritized identity risks.

### Phase 4: Power Users and Scale

**Goals**

- Support MSP scale, SIEM/GRC workflows, and policy-as-data.

**Features**

- NSA-006 remote fleet scan mode.
- NSA-010 static multi-client dashboard.
- NSA-014 SIEM content packs.
- NSA-016 policy import/export.

**Dependencies**

- Stable result/history schema.
- Report/dashboard generator.

**Estimated Complexity**

High.

**Risks**

- Remote auth and network edge cases.
- Dashboard data leakage if published externally.

**Definition of Done**

- Fleet scan handles offline hosts.
- Dashboard processes a folder of outputs.
- Splunk/Elastic/Sentinel/Wazuh field maps documented.
- Custom policy pack can validate a simple registry check.

### Phase 5: Experimental / Moonshots

**Goals**

- Expand beyond Windows SMB audits while preserving one-file value.

**Features**

- NSA-007 remediation automation expansion.
- NSA-018 Linux/Unix sidecar.
- NSA-019 SaaS backup/cloud app coverage.
- NSA-020 GRC/ticketing integrations.

**Dependencies**

- Safety model maturity.
- Integration credentials/config strategy.

**Estimated Complexity**

High.

**Risks**

- Remediation can harm environments if not tightly controlled.
- Third-party APIs vary by licensing and tenant configuration.

**Definition of Done**

- Remediation is dry-run first with rollback.
- Linux sidecar produces normalized results.
- At least one ticketing/GRC integration works with dry-run preview.

---

## 11. Research Log

| Date | Cycle | Research Area | Sources / Files Reviewed | Key Findings | Roadmap Changes |
|---|---|---|---|---|---|
| 2026-06-06 | Cycle 1: Repository comprehension | Repo instructions, current roadmap, README, changelog, git history | `README.md`, `CHANGELOG.md`, `ROADMAP.md`, `git log -10` | Project is a single-file PS/WPF auditor; existing roadmap was thin; recent commits include roadmap/branding cleanup. | Rebuilt roadmap structure and preserved prior roadmap ideas. |
| 2026-06-06 | Cycle 2: Current feature inventory | Main script structure and key sections | `NetworkSecurityAudit.ps1` sections for params, env detection, themes, checks, profiles, mappings, scoring, exports, silent mode | 67-check single-file architecture is strong but needs validation, schema, and version authority. | Added feature inventory, architecture improvements, and P0 quality items. |
| 2026-06-06 | Cycle 3: Quality and UX audit | Parser validation, test/lint search, screenshot review | `NetworkSecurityAudit.ps1`, `screenshot.png`, `rg` for tests/CI, PowerShell parser | Parser errors: 0 via `ParseInput`; PSScriptAnalyzer not installed; no committed tests/CI found; local screenshot appears unrelated. | Added NSA-001, NSA-002, NSA-013, UX findings, continuation notes. |
| 2026-06-06 | Cycle 4: Competitive landscape | AD/compliance/cloud assessment tools | PingCastle, Purple Knight, Microsoft Graph Secure Score, Microsoft SCT, CIS-CAT, Wazuh SCA, Tenable Nessus, CISA KEV, NIST OSCAL, Lynis | Competitors emphasize trust/safety, hybrid identity, repeatable scoring, dashboards, exact benchmark evidence, policy-as-data, and remediation guidance. | Added competitive research table, pain points, and P1/P2 feature specs. |
| 2026-06-06 | Cycle 5: Check catalog audit | ID coverage, auto-check type coverage, risk-tier coverage, heuristic/checklist review | `NetworkSecurityAudit.ps1:1019`, `NetworkSecurityAudit.ps1:2457`, `NetworkSecurityAudit.ps1:2904`, `NetworkSecurityAudit.ps1:3249`, `NetworkSecurityAudit.ps1:3542`, extraction scripts | Catalog integrity is strong: 67 audit items, 67 auto-checks, 67 framework maps, 67 risk tiers, no ID gaps. Main issue is evidence semantics: some checks are heuristic/checklist/interview prompts but score like automated checks. | Added Cycle 5 findings and evidence-mode manifest refinement. |
| 2026-06-06 | Cycle 6: Export schema audit | HTML, JSON, JSONL, CSV, compliance summary, SARIF, Intune, PDF export contracts | `NetworkSecurityAudit.ps1:3963`, `NetworkSecurityAudit.ps1:7333`, `NetworkSecurityAudit.ps1:8120`, `NetworkSecurityAudit.ps1:8239`, `NetworkSecurityAudit.ps1:8314`, `NetworkSecurityAudit.ps1:8390`, `NetworkSecurityAudit.ps1:8466`, `NetworkSecurityAudit.ps1:8519`, `NetworkSecurityAudit.ps1:8547` | Export breadth is strong, but STIG is missing from multiple detail exports/HTML paths, versions are not centralized, schemas are implicit, JSONL truncation lacks flags, SARIF has no locations, and Intune JSON lacks basic metadata. | Added Cycle 6 findings and export contract pack refinement. |
| 2026-06-06 | Cycle 7: Silent mode and RMM safety audit | CLI auto-elevation, setup actions, silent exports, RMM field writes, registry cache, exit-code semantics | `NetworkSecurityAudit.ps1:49`, `NetworkSecurityAudit.ps1:71`, `NetworkSecurityAudit.ps1:244`, `NetworkSecurityAudit.ps1:391`, `NetworkSecurityAudit.ps1:6022`, `NetworkSecurityAudit.ps1:6409`, `NetworkSecurityAudit.ps1:8664`, `NetworkSecurityAudit.ps1:8858`, `NetworkSecurityAudit.ps1:8949` | ReadOnly is scan-filtering, not no-write. Silent mode always writes several files and a generic HKLM cache, provider RMM fields are implicit, setup can modify host config, auto-elevation can break RMM exit-code continuity, and exit-code comments differ from threshold logic. | Added Cycle 7 findings and unified write policy/RMM contract refinement. |
| 2026-06-06 | Cycle 8: GUI accessibility and layout audit | WPF control templates, scan bar, check cards, setup dialog, filters, keyboard handling, HTML report CSS | `NetworkSecurityAudit.ps1:488`, `NetworkSecurityAudit.ps1:4426`, `NetworkSecurityAudit.ps1:4646`, `NetworkSecurityAudit.ps1:5386`, `NetworkSecurityAudit.ps1:5540`, `NetworkSecurityAudit.ps1:6098`, `NetworkSecurityAudit.ps1:7108`, `NetworkSecurityAudit.ps1:7410`; Microsoft WPF/UI Automation docs; W3C WCAG 2.2; Fluent 2 accessibility/color docs | GUI is dense and useful, but lacks explicit automation metadata, custom controls need keyboard focus states, guidance toggles are mouse-centric, scan bar/check cards can crowd at zoom, setup writes need stronger separation, and HTML report lacks responsive/reflow styles. | Added Cycle 8 findings and accessibility/report reflow refinement. |
| 2026-06-06 | Cycle 9: Entra/Graph implementation plan | Local cloud detection, identity check semantics, Microsoft Graph API/permission docs | `NetworkSecurityAudit.ps1:197`, `NetworkSecurityAudit.ps1:2365`, `NetworkSecurityAudit.ps1:2457`, `NetworkSecurityAudit.ps1:3850`, `NetworkSecurityAudit.ps1:3856`; Microsoft Graph auth, permissions, throttling, Secure Score, Conditional Access, auth methods, sign-ins, users/signInActivity, risky users, apps/service principals, OAuth2 grants, Intune, alerts, directory audits, and devices docs | Current Entra/Intune support is local-only detection. `IA03` and `IA09` use cloud-oriented labels/framework mappings but only collect local RDP/VPN/module/agent/WHfB evidence. The first Graph pack needs explicit permissions, role/licensing prerequisites, skip states, privacy classification, and a request wrapper before check logic. | Added Cycle 9 findings, `CL01`-`CL12` cloud pack plan, Graph wrapper requirements, cloud result schema, report sections, and NSA-004 implementation notes. |
| 2026-06-06 | Cycle 10: Continuous assessment schema | GUI save/load/diff, auto-save/export, structured JSON/JSONL/summary, silent-mode artifacts/RMM, scoring functions, external continuous assessment patterns | `NetworkSecurityAudit.ps1:7201`, `NetworkSecurityAudit.ps1:7274`, `NetworkSecurityAudit.ps1:8035`, `NetworkSecurityAudit.ps1:8107`, `NetworkSecurityAudit.ps1:8120`, `NetworkSecurityAudit.ps1:8239`, `NetworkSecurityAudit.ps1:8390`, `NetworkSecurityAudit.ps1:8664`, `NetworkSecurityAudit.ps1:8858`, `NetworkSecurityAudit.ps1:8950`; README save/load/diff and RMM docs; Wazuh SCA docs; CIS-CAT Pro Dashboard docs; Microsoft Graph delta/change notification/Secure Score docs; NIST OSCAL assessment results; OASIS SARIF baseline concepts | Current state is point-in-time: GUI save/load works, GUI diff only compares status/remediation in a message box, silent mode emits current artifacts and RMM fields, and no durable history/delta engine exists. Recurring assessment needs run IDs, finding fingerprints, catalog/policy hashes, first/last seen, exposure windows, unavailable-state carry-forward, and alert/RMM delta payloads. | Added Cycle 10 findings, history storage model, snapshot/finding schema, delta-state rules, alert/RMM payload shape, implementation sequence, and expanded NSA-005. |

---

## 12. Research Queries To Run Later

- "Network security audit PowerShell tool MSP RMM comparison"
- "PingCastle Enterprise multi domain dashboard features"
- "Purple Knight D3FEND MITRE mapping indicators list"
- "CIS-CAT Pro Dashboard exceptions rescored averages documentation"
- "Microsoft Graph Conditional Access policy coverage API examples"
- "Microsoft Graph authentication methods MFA registration reporting"
- "Microsoft Defender for Endpoint vulnerability management API secure configuration assessment"
- "Intune compliance policy Graph API device compliance report"
- "CISA KEV JSON schema fields ransomwareKnownExploited"
- "Nessus Windows audit file registry check syntax examples"
- "Wazuh SCA custom policy Windows registry examples"
- "OSCAL assessment-results JSON example POA&M"
- "PowerShell Pester test single file script private functions"
- "PSScriptAnalyzer GitHub Actions Windows PowerShell 5.1"
- "PowerShell WPF accessibility screen reader AutomationProperties"
- "MSP security assessment report examples executive remediation roadmap"
- "RMM custom field security score Ninja Datto Syncro best practices"
- "PowerPoint report generation PowerShell Open XML examples"
- "BloodHound attack path visualization AD lightweight graph"
- "Lynis JSON export normalize compliance score"
- "Microsoft Graph delta query users devices directory audit change tracking PowerShell"
- "security assessment exposure window trend schema JSON examples"
- "Microsoft Secure Score history API trend export"
- "PowerShell compare saved JSON audit results schema migration"
- "OSCAL assessment results observation finding risk JSON example"
- "OSCAL POA&M risks tasks remediation example"
- "NIST SP 800-171 assessment methodology objective evidence"
- "CMMC assessment guide evidence objective examples"
- "CIS-CAT ARF XML assessment result format"

---

## 13. Open Questions

| ID | Question | Why It Matters | Current Assumption |
|---|---|---|---|
| OQ-001 | Should the canonical file remain `ROADMAP.md` or should a lowercase `roadmap.md` be added? | Prompt asks for `roadmap.md`, but repo already uses `ROADMAP.md`. | Continue using existing `ROADMAP.md` to avoid duplicate roadmap files. |
| OQ-002 | Should silent mode write RMM/registry fields by default in read-only mode? | Trust/safety and RMM compatibility may conflict. | Preserve existing behavior but add `-NoRmmWrite` and explicit write summary. |
| OQ-003 | Should source stay physically single-file, or can authoring be modular with generated single-file release? | Maintainability vs deployment simplicity. | Keep release single-file; allow source-generation if accepted. |
| OQ-004 | What cloud platforms matter first: Entra/M365 only, or Okta/Google Workspace too? | Scope of cloud identity pack. | Entra/M365 first because current script already detects Microsoft signals. |
| OQ-005 | Should remediation automation be included in the same script or emitted as separate signed runbooks? | Safety and trust. | Same script can preview/generate remediations first; execution should require explicit opt-in. |
| OQ-006 | Is GitHub Actions available for this repo and should it target Windows PowerShell 5.1 only? | Runtime compatibility. | Test Windows PowerShell 5.1 first, optionally add PowerShell 7 parser-only validation. |
| OQ-007 | Should docs claim compliance "coverage" or "assessment support"? | Legal/compliance positioning. | Use "assessment support" and clearly state limitations. |

---

## 14. Next Research Cycles

1. Cycle 11: Compliance evidence model - map current findings to evidence facts, control objectives, exceptions, and OSCAL-like export.
2. Cycle 12: Remote fleet scanning architecture - design target CSV, throttle, per-host results, and aggregate report.
3. Cycle 13: Remediation safety model - select first safe remediations and design dry-run/rollback manifest.
4. Cycle 14: Release pipeline and docs polish - fix changelog/date/screenshot, define release checklist, and validate README claims.
5. Cycle 15: Open-source implementation inspiration - inspect comparable OSS audit scripts for manifest formats, test structure, and remediation gating.
6. Cycle 16: Export fixture implementation plan - define exact mock audit state and expected artifacts for schema snapshots.
7. Cycle 17: RMM contract fixture plan - define dry-run provider mocks and expected field/write-result records.
8. Cycle 18: Accessibility implementation fixture plan - define UI automation smoke tests, theme contrast fixture, and HTML reflow snapshots.
9. Cycle 19: Graph permission UX and MSP multi-tenant delegation plan - refine delegated/app-only auth, partner scenarios, consent evidence, and tenant privacy defaults.
10. Cycle 20: History fixture and alert-threshold implementation plan - define sample snapshots, baseline migration cases, retention/compaction, and alert preview fixtures.

---

## Research-Driven Additions

Items completed in v4.11.0 (2026-06-16): HardeningKitty/CIS-CAT/SCT benchmark import (`-BenchmarkImportPath`), Entra Connect hard-match posture check (CL13), SIEM content packs (`-ExportSIEM`), remediation dry-run (`-Remediate`/`-RemediateDryRun`), white-label executive pack (`-BrandingConfig`), remote fleet scan (`-TargetsCsv`).

Remaining items moved to `Roadmap_Blocks.md` — blocked on operator decisions, tenant access, or large-scope design work.

## Research-Driven Additions (C# Rewrite — 2026-06-16)

All research-driven items for this cycle have been implemented or moved to `Roadmap_Blocked.md`.

## Research-Driven Additions (2026-06-19)

Items completed in v5.2.0: OSCAL UUID fix, CSV quoting fix, version centralization, privacy redaction copy-on-export, SARIF security-severity, Intune export, ExitCode enum, three-tier HTML reports, PDF export, white-label branding, multi-client dashboard, pre-flight checker, waiver store in silent mode, compliance summary CLI, SIEM content packs, CMMC Level 1/2 report, full-catalog roundtrip test, OSCAL/SARIF validation tests.





## Research-Driven Additions

- [ ] P1 - Port PowerShell MSP automation parity into the C# CLI
  Why: The C# silent mode lacks PowerShell v4.11 MSP workflows such as RMM field writes, remote fleet scanning, continuous history/delta, benchmark import, cloud assessment import, remediation dry-run, and write-suppression flags.
  Evidence: `NetworkSecurityAudit.ps1`; `src/NetworkSecurityAuditor/App.xaml.cs`; PingCastle console aggregation; Prowler scheduled scans; HardeningKitty audit/config/backup modes.
  Touches: `src/NetworkSecurityAuditor/App.xaml.cs`, `Models/AuditOptions.cs`, `Services/`, `Export/`, new tests under `tests/NetworkSecurityAuditor.Tests/`.
  Acceptance: C# CLI supports documented equivalents for RMM/write manifest controls, `--targets-csv`, `--benchmark-import`, `--cloud-assessment-path`, `--history`, and remediation dry-run with rollback manifest tests.
  Complexity: XL

- [ ] P1 - Add Graph-backed Entra/M365 C# check pack
  Why: Competitors now treat cloud identity posture as table-stakes, and local IA03/IA09 checks cannot prove tenant MFA or Conditional Access coverage.
  Evidence: Microsoft Graph Secure Score, Conditional Access policy, authentication methods, sign-in activity, and Maester v2.1.0 sources; `src/NetworkSecurityAuditor/Data/ScanProfiles.cs`.
  Touches: new `Checks/Cloud/` classes, `Services/GraphClient`, `Models/CloudAssessment*`, `Data/CheckCatalog.cs`, `Data/FrameworkMappings.cs`, exporters, tests with offline fixtures.
  Acceptance: Cloud profile runs CL01 Secure Score, CL02 Conditional Access baseline/exclusions, MFA registration/auth methods, stale guests/sign-in activity, privileged role exposure, and MDE/Intune availability checks with permission/license skip states.
  Complexity: XL

- [ ] P1 - Make WPF scan progress state sequential and testable
  Why: `StartScanAsync()` marks every selected check as running before execution, causing misleading overlays and crowded status during long scans.
  Evidence: `src/NetworkSecurityAuditor/ViewModels/MainViewModel.cs`; `src/NetworkSecurityAuditor/Checks/CheckRunner.cs`.
  Touches: `src/NetworkSecurityAuditor/ViewModels/MainViewModel.cs`, possible progress payload model, view-model unit tests.
  Acceptance: Only the actively executing check shows `IsRunning`; queued checks remain idle; cancellation clears the active check; a unit test verifies state transitions for a multi-check profile.
  Complexity: M

- [ ] P1 - Add GUI export parity and a compact export settings flow
  Why: WPF exposes most exports as crowded sidebar buttons but omits SIEM content packs and CMMC reports that the CLI already supports.
  Evidence: `src/NetworkSecurityAuditor/MainWindow.xaml`; `src/NetworkSecurityAuditor/App.xaml.cs`; Prowler OCSF/SARIF/export examples.
  Touches: `src/NetworkSecurityAuditor/MainWindow.xaml`, `ViewModels/MainViewModel.cs`, `Export/SiemContentPackExporter.cs`, `Export/CmmcReportGenerator.cs`, UI tests or view-model command tests.
  Acceptance: GUI can export SIEM content packs and CMMC HTML/JSON; export buttons are replaced or grouped by a compact settings/menu flow; privacy mode and selected output folder apply consistently.
  Complexity: L

- [ ] P1 - Add dashboard latest-per-client and trend semantics
  Why: Current dashboard rows every findings file and does not compute latest-per-client or score trends despite README claims and MSP dashboard expectations.
  Evidence: `src/NetworkSecurityAuditor/Export/DashboardGenerator.cs`; README dashboard section; Prowler scheduled scan UI release notes.
  Touches: `src/NetworkSecurityAuditor/Export/DashboardGenerator.cs`, `tests/NetworkSecurityAuditor.Tests/ExportTests.cs`, README after implementation.
  Acceptance: Dashboard groups scans by stable client/host key, shows latest row per client, adds trend sparkline/data over the selected history window, and lists skipped/duplicate files deterministically in HTML and CSV.
  Complexity: L

- [ ] P1 - Publish export schemas and golden contract fixtures
  Why: The repo has many machine-readable exports but no committed JSON schemas or golden fixtures to protect SIEM/GRC/RMM consumers from silent field drift.
  Evidence: `src/NetworkSecurityAuditor/Export/*.cs`; OCSF Compliance Finding schema; OSCAL assessment-results docs; Prowler OCSF/SARIF outputs.
  Touches: `schemas/` or `docs/schemas/` if allowed by repo hygiene, `tests/NetworkSecurityAuditor.Tests/ExportTests.cs`, all exporters that lack stable schema metadata.
  Acceptance: JSON, JSONL, OCSF, OSCAL, Intune, compliance summary, dashboard aggregate, and SIEM content pack outputs have schemas or golden fixtures validated in tests.
  Complexity: L

- [ ] P2 - Restore multi-theme WPF parity or remove theme claims
  Why: C# view-model exposes only Catppuccin Mocha while repo notes and README still describe seven dark themes.
  Evidence: `src/NetworkSecurityAuditor/ViewModels/MainViewModel.cs`; `src/NetworkSecurityAuditor/Theme/Themes.xaml`; README GUI section.
  Touches: `Theme/Themes.xaml`, `ViewModels/MainViewModel.cs`, `MainWindow.xaml`, `tools/Test-ThemeContrast.ps1`, screenshot refresh.
  Acceptance: Either all seven dark themes are selectable and contrast-tested, or product docs claim only Catppuccin Mocha for the C# rewrite.
  Complexity: M

- [ ] P2 - Add benchmark and lifecycle data refresh strategy
  Why: CIS/STIG/Windows lifecycle and Defender baselines change frequently, and current metadata is code-embedded rather than update-reviewed through a repeatable manifest.
  Evidence: `src/NetworkSecurityAuditor/Data/CheckCatalog.cs`; CIS Benchmarks; DoD STIG library; Microsoft Windows Server 2025 and SMB signing docs; HardeningKitty finding-list model.
  Touches: `Data/CheckCatalog.cs`, `Data/FrameworkMappings.cs`, new benchmark metadata manifest, validation tests.
  Acceptance: A versioned metadata manifest records CIS/STIG/Microsoft baseline source URL, reviewed date, supported OS/build, and check coverage; validation fails when source metadata is missing or stale beyond the chosen review window.
  Complexity: L

- [ ] P2 - Add signed local C# release artifact flow
  Why: The repo now has a .NET/WPF executable path but no documented local publish artifact contract comparable to the downloadable PowerShell script.
  Evidence: `src/NetworkSecurityAuditor/NetworkSecurityAuditor.csproj`; README download section; local-build-only repo policy.
  Touches: release script/tooling, README release section, CHANGELOG version checklist, GitHub Release attachment process.
  Acceptance: Local release command cleans previous artifacts, runs tests, publishes the C# app in the chosen artifact format, signs when a certificate is available, emits checksums, and documents exactly what users install.
  Complexity: M

---

## Audit Backlog — Deep Audit 2026-07-07 (C# rewrite v5.2.4 + legacy PS1 v4.11.0)

> Generated by a 6-agent parallel deep audit. Baseline at time of audit: `dotnet build` clean (0 warnings), 133/133 xUnit tests green, PS1 static validation passed. **No fixes were applied** — every item below is verified-real and ready to execute.

### Instructions for the AI executing this backlog

1. **Work top-down by priority** (P0 -> P1 -> P2 -> P3). Within a priority, group by file/subsystem so related edits share a commit and a rebuild.
2. **Re-verify before fixing.** This repo has been audited many times; even in this vetted list, confirm the code still reads as described (line numbers drift) and the bug is reachable before editing. If a finding is already fixed or was a false positive, delete it from this backlog and move on — do not "fix" correct code.
3. **Every fix gets a regression test.** Add/extend xUnit tests in `tests/NetworkSecurityAuditor.Tests/` (match existing style). For scoring/mapping/export bugs a test is mandatory; for pure-UI/threading bugs, add one where feasible and note in the commit if not.
4. **Add the three missing structural tests early** (mapping-key parity catalog<->MITRE<->D3FEND<->Framework; technique-ID format regex; `dict.Add` duplicate-ID fail-fast). They will catch regressions while you fix the mapping items.
5. **Baseline discipline:** run `dotnet build NetworkSecurityAuditor.slnx -c Release` and `dotnet test` after each batch. For PS1 changes run `.\tools\Test-NetworkSecurityAudit.ps1`. Never push red.
6. **Commit discipline:** conventional commits, author `SysAdminDoc <matt_parker@outlook.com>`, no AI attribution/trailers, push to `main` directly. One logical change per commit.
7. **When done with a batch:** delete completed items from this section (completed work lives in git history + CHANGELOG.md), update CHANGELOG.md, and bump the version once for the session syncing every version string (`.csproj`, `VersionInfo.cs`, window title path, README badge, HTML/JSON export headers).
8. **Blocked/needs-decision items** move to `Roadmap_Blocked.md` with a one-line reason (e.g. sourcing genuine DISA STIG rule IDs, product decision on whether errors should score as unmet).
9. **Cross-cutting note:** many C# items share one root cause — checks are synchronous (`Task.FromResult`) and run on the UI thread. Fixing the threading model (P1 group A) changes the behavior of several progress/timeout findings; do that batch first, then re-test the dependent items.

---

### P1 — Critical (correctness / security / core UX)

**Group B — Export security & schema validity**


**Group C — Compliance mapping drift (client-facing, feeds every export; add parity/format tests alongside)**


**Group D — Check correctness (confident-but-wrong findings; highest reputational risk)**


**Group E — Legacy PS1 v4.11 fleet scan (newest, least-audited code)**


**Group F — GUI correctness (results have no visual signal / core workflows broken)**

- [ ] **P1 — Six VM features have no UI surface at all:** `SearchText`, `StatusFilter(s)`, `PrivacyMode`, `SelectedTheme/AvailableThemes`, `DomainMaturityScore/Grade`, and `SaveStateCommand`/`LoadStateCommand`. Consequences: GUI manual assessments can't be saved/loaded, GUI exports can never be privacy-redacted, search/filter is dead, Domain Maturity is computed but shown nowhere. Where: `MainViewModel.cs:22-28,41,44,68-72,497-580` vs `MainWindow.xaml`. Fix: add search box, status filter, privacy toggle, Save/Load buttons, Domain Maturity card.

---

### P2 — High

**Checks (fail-open / masking)**
- [ ] **P2 — IA01 flags every privileged-group member `[STALE]` -> `Fail` on any domain.** `lastLogonTimestamp` via `DirectoryEntry.Properties` returns an `IADsLargeInteger` COM object, so `is long` is always false and `lastLogon` stays `DateTime.MinValue`. Where: `Checks/IdentityAccess/IA01_PrivilegedGroupsCheck.cs:114-121`. Fix: convert via the IADsLargeInteger reflection helper IA05 already has (extract to a shared util).
- [ ] **P2 — CF02 egress test fails open:** connecting high-risk ports to `1.1.1.1` (which doesn't listen) counts a failed connect as "BLOCKED" -> `Pass` on a wide-open network. Where: `Checks/CommonFindings/CF02_EgressTestCheck.cs:17-28,54-72`. Fix: require positive confirmation of filtering.
- [ ] **P2 — CF08 DNS filter test fails open:** NXDOMAIN on test domains that never resolve anyway counts as "blocked" -> `Pass` with no filtering. Where: `CF08_DnsFilterTestCheck.cs:63-105,128-130`. Fix: use a domain that *should* resolve to a known-good IP when unfiltered.
- [ ] **P2 — EP07 `failCount--` masks real failures** (decrements the shared counter when Office/Smart App Control is absent, subtracting AppLocker/WDAC failures; can flip to `Pass`). Same idiom in LM07 (`:114-116`) and a milder LM01 (`:99`). Where: `Checks/EndpointSecurity/EP07_AppControlCheck.cs:218-219,267-268`. Fix: track per-sub-check applicability.
- [ ] **P2 — EP06 host-firewall parse is English-locale-dependent and fails open** (`Contains("State ... OFF")` with hardcoded spacing; WMI fallback only runs on throw; dead vars). Where: `EP06_HostFirewallCheck.cs:66-72,76,209-222`. Fix: parse robustly / use WMI `MSFT_NetFirewallProfile`.

**Export / scoring**
- [ ] **P2 — CSV formula-injection neutralizer misses tab- and CR-prefixed payloads** (`\t=...`, `\r=...` emitted raw; `\t`/`\r` not in the quote-trigger set). Where: `Export/CsvExporter.cs:62-63`. Fix: neutralize when the first (or first non-whitespace) char is `= + - @ \t \r`.
- [ ] **P2 — DashboardGenerator CSV has zero formula-injection neutralization** (`client/host/os/grade/timestamp` from ingested `*_findings.json`). Where: `Export/DashboardGenerator.cs:205-209`. Fix: reuse `CsvExporter.Escape`.
- [ ] **P2 — DashboardGenerator injects the untrusted `grade` value unescaped into an HTML class attribute.** Where: `DashboardGenerator.cs:165,174`. Fix: allowlist grades A-F or `Esc()` the class value.
- [ ] **P2 — NavigatorExporter: NA/NotAssessed (score -1) outranks Fail (0) as "worst"** -> failing techniques render grey instead of red in the ATT&CK layer (understates risk). Where: `Export/NavigatorExporter.cs:23-36`. Fix: order Fail > Partial > Pass; assessed statuses always dominate NA.
- [ ] **P2 — SarifExporter root property is `"schema"`, not `"$schema"`** -> strict SARIF validators reject the file. Where: `Export/SarifExporter.cs:97`. Fix: `[JsonPropertyName("$schema")]`.
- [ ] **P2 — DomainMaturityEngine: an all-N/A domain contributes 0% but keeps its weight in the denominator**, hard-capping a non-domain-joined host at ~45/"F" even with perfect endpoint/logging results (domains 1-2 are all `CheckType.AD`). Where: `Scoring/DomainMaturityEngine.cs:51-53`. Fix: divide by the sum of weights of domains with `possible > 0` (mirror `RansomwareReadinessEngine`).
- [ ] **P2 — Errors and timeouts collapse to `CheckStatus.NA`** (fail-open; NA is excluded from all denominators, so a crashed/hung check *raises* the score). No `Error` status exists. Where: `Models/CheckResult.cs:19-25`, `Checks/CheckRunner.cs:72-76`, `Models/Enums.cs:3-10`. Fix: add an `Error` status (string-serialized -> save-compatible), surface error/timeout counts separately, decide explicitly whether errors score as unmet. **Partly Blocked** (product decision).
- [ ] **P2 — RiskScoreEngine formula doesn't match the README** (`(int)Severity * CategoryWeights * check.Weight`, and `Weight==(int)Severity` for 68/69 checks -> severity effectively squared; no per-category normalization). Where: `Scoring/RiskScoreEngine.cs:19-21` vs README. Fix: reconcile code and README.
- [ ] **P2 — SprsScoreEngine gives `Partial` full SPRS credit** (only `Fail` deducts); DoD SPRS is binary. Where: `Scoring/SprsScoreEngine.cs:46-53`. Fix: treat Partial as unmet (or apply the two documented partial-credit controls).
- [ ] **P2 — Add missing structural tests:** mapping-key parity (catalog == MITRE == D3FEND == Framework keys), technique-ID format (`^T\d{4}(\.\d{3})?$`, `^TA\d{4}$`, `^D3-[A-Z]+$`), and `dict.Add` duplicate-ID fail-fast. Where: `tests/NetworkSecurityAuditor.Tests/`. (Do this early per instructions.)

**App / silent mode**
- [ ] **P2 — Silent-mode self-elevation returns exit code 0 (Green) immediately and detaches the real scan** — RMM/scheduler sees success regardless of result; UAC stalls unattended runs. Where: `App.xaml.cs:31-53`. Fix: skip auto-elevation in silent/dashboard mode (warn + run degraded) or `WaitForExit` and forward the child's exit code.
- [ ] **P2 — Silent-mode console progress is not live and prints after the summary** (same never-yields root cause). Where: `App.xaml.cs:152-164,209-220`. Fix: print directly in the runner loop via a synchronous callback.
- [ ] **P2 — Waivers don't affect score, fail counts, or exit codes** — a fully-waived environment still exits non-zero forever, so CI can't gate. `--waivers` only annotates `vm.Notes`; GUI has no waiver support. Where: `App.xaml.cs:185-207,209-214,351-357`. Fix: exclude actively-waived checks from failCount/scoring, or add a documented flag. **May be Blocked** (product decision).
- [ ] **P2 — Startup blocks the UI thread on WMI + `dsregcmd`** (multi-second freeze; unbounded hang if dsregcmd wedges). Where: `MainWindow.xaml.cs:19-24`, `Services/EnvironmentDetector.cs:12-31,156-200`. Fix: `await Task.Run(EnvironmentDetector.Detect)`.

**Legacy PS1 branding / fleet security**
- [ ] **P2 — Branding `footer_text` injected unencoded into the report header** (other FooterText sinks encode it) -> XSS in delivered reports. Where: `NetworkSecurityAudit.ps1:11177`. Fix: `HtmlEncode` the value.
- [ ] **P2 — `logo_base64` injected verbatim into a single-quoted `src` attribute** -> attribute-breakout XSS. Where: `NetworkSecurityAudit.ps1:262-263,11139,11171`. Fix: validate against `^data:image/[a-z+.-]+;base64,[A-Za-z0-9+/=]+$` (and whitelist mime for logo_path).
- [ ] **P2 — CSV `Client` field allows parameter injection into remote audit runs** (PS 5.1 doesn't escape embedded quotes in native command lines; `x" -ReadOnly "False` flips flags on every fleet host). Where: `NetworkSecurityAudit.ps1:326,349-351`. Fix: reject/escape `"` in CSV fields, or pass values via env/`-EncodedCommand`.

**GUI theme / a11y / layout**
- [ ] **P2 — DatePicker renders light** (calendar popup uses SystemColors). Where: `MainWindow.xaml:311-315`. Fix: dark DatePicker/Calendar template or styled TextBox+validation.
- [ ] **P2 — App launches showing grade "F" / "0/100" before anything is assessed** (no "not scanned" empty state). Where: `MainViewModel.cs:117,154`, `RiskScoreEngine.cs:35,45`. Fix: show "—"/"Not scanned" until >=1 check assessed.
- [ ] **P2 — `BorderDim` (#7f839b) used as text foreground for 10-11px labels fails WCAG AA** (3.35:1 on cards, 2.44:1 on the status bar). Where: `MainWindow.xaml:67,74,97,107,254,265,288,301,309,368`, `Themes.xaml:10`. Fix: add a `TextMuted` token >= #a6adc8.
- [ ] **P2 — Corner-radius rule violation: `CornerRadius="2"` on a 3px bar** (outside {0,4,6,8,10,12} and > half-height = pill). Where: `MainWindow.xaml:235`. Fix: `CornerRadius="0"`.
- [ ] **P2 — Hardcoded hex bypassing theme tokens** (`#33585b70`, `#585b70`, `#881e1e2e` scrim, `#1e1e2e` literals; Catppuccin hex in C#). Where: `MainWindow.xaml:212,238,321`, `Themes.xaml:53,133`, `CheckItemViewModel.cs:43-69`, `MainViewModel.cs:119-127`. Fix: promote to tokens (`OverlayScrim`, `BadgeBg`, `OnAccent`).
- [ ] **P2 — Non-virtualized ItemsControl of 69 heavy cards fully rebuilds on every check completion** (`FilteredChecks` returns a fresh enumerable; progress callback raises `PropertyChanged(FilteredChecks)`), destroying caret/focus mid-typing. Where: `MainWindow.xaml:174`, `MainViewModel.cs:82-115,600`. Fix: `ListBox`/virtualizing panel + `ICollectionView`.
- [ ] **P2 — Sidebar has no ScrollViewer** (~600+ DIP fixed content; export buttons clip on short/125%-scaled displays). Where: `MainWindow.xaml:33-166`. Fix: wrap sidebar in a ScrollViewer / give categories a MinHeight.
- [ ] **P2 — Export buttons enabled during a scan and before any scan** (writes partial or all-"F" reports silently). Where: `MainWindow.xaml:128-165`. Fix: gate on `!IsScanning`.

---

### P3 — Medium / Low

**Checks**
- [ ] P3 — Resource leaks: `SearchResultCollection` not disposed (`EP10_EolOsCheck.cs:170`, + dead `ManagementObjectSearcher` at 128-133); `ServiceController[]` from `GetServices()` not disposed (`LM06:100`, `LM07:135`, `LM08:102,217`).
- [ ] P3 — `RunCommand` helpers redirect StandardError but never drain it -> pipe-buffer deadlock on chatty stderr (EP06:240, LM03:341, NA01:246, NA02/03/07, NP02/03/09, CF05/06/07). Fix: async-read both streams.
- [ ] P3 — EP04 parses `Win32_QuickFixEngineering.InstalledOn` with current culture (fails on non-US locales; hex-FILETIME case unhandled) -> fail-open patch recency. `EP04:118`. Use `CultureInfo.InvariantCulture`.
- [ ] P3 — EP03 NetBIOS check flags `nodeType != 2` and `NetbiosOptions == 0` as failures -> false NetBIOS FAIL on most hardened machines. `EP03:212-223`.
- [ ] P3 — EP01 SecurityCenter2 `productState` bit decode is non-standard (`>>12&0xF`, `>>4&0xF`) -> misreports enabled/up-to-date (evidence text only). `EP01:143-144`.
- [ ] P3 — EP02/EP08 treat non-admin / unsupported-OS WMI unavailability as `Fail` instead of `NA` -> false failures. `EP02:87-94`, `EP08:121-133,187-190`.
- [ ] P3 — BR03/BR06/LM05 iterate full `EventLog.Entries` via the COM indexer (slow/O(n^2) on large logs). Prefer `EventLogReader` + XPath.
- [ ] P3 — NP03 infers split-tunnel from `defaultRoutes > 1` -> false positive on multi-NIC machines. `NP03:190-207`.
- [ ] P3 — NA03 wireless netsh parse is English-locale-dependent + substring `Contains` false matches. `NA03:20-24,73-77`.
- [ ] P3 — IA05 `Math.Abs(maxPwdAgeTicks)` throws `OverflowException` on `long.MinValue` ("never" sentinel) -> NA. `IA05:59,126`. Use unchecked negation / handle MinValue.

**App / services**
- [ ] P3 — `IntuneManaged` true whenever the label `"EnrollmentType :"` appears regardless of value (`= none` still true). `EnvironmentDetector.cs:174-175`.
- [ ] P3 — `dsregcmd` `ReadToEnd()` blocks before `WaitForExit(5000)` -> dead timeout, process never killed, handle leak. `EnvironmentDetector.cs:170-171`.
- [ ] P3 — Value-taking flags consume a following flag as their value (`--client --export-csv`); last-position value flag silently ignored; unknown flags silently ignored. `App.xaml.cs:405-439`.
- [ ] P3 — Alias inconsistency: `--no-elevate` has no `-NoElevate`; `--export-defectdojo` has no `-ExportDefectDojo`. `App.xaml.cs:414-415,444-445`.
- [ ] P3 — Elevated relaunch (`runas`) doesn't preserve working directory -> relative `--output`/`--waivers`/`--branding` resolve under system32. `App.xaml.cs:38-47`.
- [ ] P3 — Dashboard "input dir not found" exits 1, colliding with `ExitCode.ImmediateAlert`. `App.xaml.cs:90` vs `Enums.cs:71-77`. Use a distinct code (64+).
- [ ] P3 — Progress denominators use `profileIds.Length` even when AD checks are filtered -> silent output ends at "[58/70]" looking aborted. `App.xaml.cs:163`, `MainViewModel.cs:223-228`, `CheckRunner.cs:103-104`.
- [ ] P3 — All-N/A run reports 0%/"F"/exit 1 ("no data" == "critical"). `App.xaml.cs:351-353`, `RiskScoreEngine.cs:35`. Distinct handling when `possible == 0`.
- [ ] P3 — Hardcoded `C:\Windows`/`C:\Program Files\LAPS` break on non-C: SystemRoot. `EnvironmentDetector.cs:93-110,227`. Use `Environment.GetFolderPath`.
- [ ] P3 — `VersionInfo.cs:8` duplicates the csproj `"5.2.4"` literal (stale in null-assembly path). Derive from `AssemblyInformationalVersion`.
- [ ] P3 — `AttachConsole(-1)` return unchecked; output interleaves with the shell prompt; document that exit codes need `Start-Process -Wait`. `App.xaml.cs:79,119`.

**Export**
- [ ] P3 — Culture-sensitive calendar date formatting across exporters (no `CultureInfo.InvariantCulture` on `ToString("yyyy-MM-dd")`, RemediationDueDate, timestamps). DefectDojoExporter:68/95, JsonExporter:77, HtmlReportGenerator:52/63/197, DashboardGenerator:147/166, CmmcReportGenerator:43, MainViewModel:533.
- [ ] P3 — Dashboard staleness compares `DateTime.UtcNow` against a local-kind parse (off by UTC offset). `DashboardGenerator.cs:54-55,105`. Use `DateTimeOffset` + `AssumeUniversal`.
- [ ] P3 — Privacy-mode GUI export copy drops `DurationMs` (0 for every finding). `MainViewModel.cs:255-272`.
- [ ] P3 — CMMC control `EvidenceSummary` is whatever check iterated last, regardless of status. `CmmcReportGenerator.cs:147-148`.
- [ ] P3 — PdfExporter redirects stdout without draining (pipe-deadlock risk) and `File.Exists` passes on a stale PDF from a prior run. `PdfExporter.cs:28,39-52`. Delete target before launch; don't redirect (or drain).
- [ ] P3 — No atomic writes: every artifact uses `File.WriteAllTextAsync` (open-truncate) -> partial/corrupt files on mid-write failure. All export call sites. Fix: write `.tmp` then `File.Move(..., overwrite:true)`.
- [ ] P3 — `--output` dir-vs-file ambiguity + raw `--client` in filename (`\`,`:`,`..\`). `App.xaml.cs:234-239`. Sanitize.
- [ ] P3 — `Dashboard_Escapes_Client_Names` test is tautological (tests an inline `string.Replace`, never calls `DashboardGenerator`); dead `brandColor` at HtmlReportGenerator.cs:24. `ExportTests.cs:436-443`. Make dashboard HTML testable.

**Data / scoring / models**
- [ ] P3 — Malformed D3FEND ID `"D3F-UGPH"` (only non-`D3-` prefix). `D3FendMappings.cs:24`. (Format test catches it.)
- [ ] P3 — NP05 `Weight=8` with `Severity.High(=7)` — sole Weight!=Severity outlier (legacy carryover; double-counted by RiskScoreEngine). `CheckCatalog.cs:645-646`.
- [ ] P3 — "Physical Security" weight+accent for a category with zero checks (dead fossil behind the PS mapping drift). `CategoryWeights.cs:25,57`. Remove.
- [ ] P3 — E8/CyberEssentials profile membership inconsistent with framework columns (IA01/IA02 in E8/CE profiles but no E8/CE column; NA03 has an E8 column but isn't in the E8 profile). `FrameworkMappings.cs:14-37,453` vs `ScanProfiles.cs:82-90`.
- [ ] P3 — Banker's rounding at grade boundaries (`Math.Round` ToEven; 89.5->90 but 88.5->88). RiskScoreEngine:35, RansomwareReadinessEngine:54, DomainMaturityEngine:52/56. Use `MidpointRounding.AwayFromZero`.
- [ ] P3 — Duplicate check/mapping ID silently overwrites (`dict[id]=` vs `dict.Add`). `CheckCatalog.cs:1096-1099` + mapping initializers. (Covered by the fail-fast test above.)
- [ ] P3 — Waiver expiry compares unspecified-kind JSON `DateTime` against `DateTime.UtcNow` (flips by UTC offset). `Models/RiskWaiver.cs:16`. Normalize to UTC date / `DateOnly`.

**Legacy PS1**
- [ ] P3 — Successful fleet results discarded as TimedOut (wall-clock checked at processing time, not completion). `NetworkSecurityAudit.ps1:363-374`. Use `$meta.Job.PSEndTime - StartTime`; only `Stopped` = timeout.
- [ ] P3 — Sensitive audit residue (full findings/SIEM/CSV) left in each remote host's TEMP with fixed filenames; `Stop-Job` doesn't kill the remote process. `NetworkSecurityAudit.ps1:346-353`. Unique temp names + `finally { Remove-Item }` + best-effort remote cleanup.
- [ ] P3 — No validation on `-ThrottleLimit` / `-PerHostTimeout` (`0`/negative -> busy-loop or instant timeout). `NetworkSecurityAudit.ps1:95-96,322,415`. `[ValidateRange(1,64)]` / `[ValidateRange(1,86400)]`.
- [ ] P3 — Fleet aggregate math: `score -gt 0` filter excludes real 0%/grade-F hosts from `avg_score`/`worst_host`; all-blank CSV -> `exit 1` for a fleet that scanned nothing. `NetworkSecurityAudit.ps1:435-437`. Track a `has_score` flag; error when count 0.
- [ ] P3 — Branding `website` href not scheme-validated (`javascript:` survives HtmlEncode). `NetworkSecurityAudit.ps1:11154,11821`. Require `^https?://`.
- [ ] P3 — Fleet child scans silently ignore `-PrivacyMode`/`-Auditor`/`-ReportTier`/`-Export*` (privacy fleet produces unredacted per-host JSON). `NetworkSecurityAudit.ps1:335,349`. Forward the flags.
- [ ] P3 — Dead `$sessionOpts` (built with credential, never used). `NetworkSecurityAudit.ps1:316-317`. Delete.
- [ ] P3 — Branding config fail-silent: missing `-BrandingConfig` path ignored with no warning; raw base64 without `data:` prefix embedded -> broken `<img>`. `NetworkSecurityAudit.ps1:257,262-263`.

**GUI microcopy / a11y (P3)**
- [ ] P3 — Status dropdown shows raw enum names "NotAssessed"/"NA" (friendly labels exist in `StatusFilters`). `MainWindow.xaml:15-19,226-231`.
- [ ] P3 — "…not implemented in the C# rewrite yet… Use the PowerShell artifact" leaks porting history to users. `MainViewModel.cs:200`, `App.xaml.cs:146-147`.
- [ ] P3 — Status bar "N/A: {n}" lumps `NA` and `NotAssessed` (reads "N/A: 69" at launch). `MainViewModel.cs:587`, `MainWindow.xaml:371`.
- [ ] P3 — 12 export buttons (OCSF/OSCAL/Navigator/Summary/DefectDojo/Intune) have no tooltips and no "EXPORT" section header; "Summary" is ambiguous. `MainWindow.xaml:128-165`.
- [ ] P3 — No keyboard-focus visuals in custom templates (`AccentButton`/`SecondaryButton`/`DarkListBoxItem` lack `IsKeyboardFocused`). `Themes.xaml:51-139`.
- [ ] P3 — Card input fields (Findings/Evidence/Notes/Assignee/DatePicker x69) have no `AutomationProperties.Name` for screen readers. `MainWindow.xaml:257-315`.
