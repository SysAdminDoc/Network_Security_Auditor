# Changelog

All notable changes to Network_Security_Auditor will be documented in this file.

## [Unreleased]

### Security
- Fixed: C# HTML report links now use attribute-safe encoding, only render HTTP(S) external links, and avoid unsafe `mailto:` links from malformed branding email values.

### Reliability
- Fixed: C# CF01 SYSVOL GPP password scanning now honors cancellation, skips oversized preference XML files, and records traversal/read limits instead of reading every matched file unbounded.
- Fixed: C# saved audit-state loading now restores the saved scan profile, parses remediation due dates with invariant `yyyy-MM-dd`, and clears invalid due dates instead of preserving stale UI values.
- Fixed: C# firewall netsh fallback checks now use the shared timeout-aware command runner instead of raw process reads that could block before timeout handling.

## [v5.2.7] - 2026-07-09

### Platform
- Changed: C# rewrite now targets .NET 10 (`net10.0-windows`), refreshes compatible package pins, and emits `windows-net10` release artifacts with `.NET 10 Desktop Runtime` install metadata.
- Added: C# release tool now emits a CycloneDX SBOM, includes package/license inventory and .NET runtime support metadata in the release manifest, and covers the SBOM in `SHA256SUMS.txt`.
- Fixed: C# environment detection now parses Intune enrollment state correctly, prevents `dsregcmd` stdout deadlocks with timeout cleanup, and derives Windows/LAPS paths from the host environment instead of hardcoded `C:` locations.
- Fixed: C# headless argument parsing now warns on missing or unknown flags, keeps following switches from being consumed as values, supports `-NoElevate` and `-ExportDefectDojo`, preserves the elevated relaunch working directory, and returns exit code 64 for missing dashboard input folders.
- Fixed: C# NA03 wireless checks now prefer invariant exported WLAN profile XML and exact normalized authentication classification, avoiding English `netsh` label dependence and substring false positives.
- Fixed: C# IA05 password-policy conversion now handles Active Directory's `long.MinValue` interval sentinel without overflowing and reports it as a never-expiring password age policy.
- Fixed: C# scan progress now uses AD-filtered applicable check counts, no-data scans report grade `N/A` with exit code 65 instead of a false critical alert, console attachment checks its return value, and version display derives from assembly informational metadata instead of a stale fallback literal.
- Fixed: C# exporters, GUI export filenames, and saved audit-state remediation dates now use invariant date formatting so non-US host cultures cannot alter machine-readable date contracts.
- Fixed: C# text artifacts now write through an atomic temp-file-and-move path, PDF export deletes stale targets and avoids undrained stdout, and file-looking `--output` values resolve to their parent directory while client-derived file names remain sanitized.
- Fixed: C# catalog metadata, framework scan profiles, grade-boundary rounding, and waiver expiry semantics now stay aligned with their scoring and mapping contracts.

### UX
- Changed: C# GUI now uses a premium security-operations workstation shell with a persistent category progress rail, command/status bar, risk score band, dense virtualized check table, selected-check inspector, and integrated activity console.
- Fixed: C# GUI startup now loads the check catalog before slower environment detection completes, giving the first-run shell immediate structure and avoiding a blank workspace during preflight.
- Changed: C# GUI now surfaces scan readiness, export availability, filter result counts, search placeholder text, no-results recovery, preflight detail in the console, stable focus states, and screen-reader live scan progress.
- Added: C# GUI now has non-intrusive WPF UI Automation smoke coverage for the background launch mode, primary scan/export/filter controls, inspector fields, activity log, and accessibility landmarks.
- Fixed: C# GUI selected-format exports now show a busy status, disable duplicate export actions while writing, and surface crash-log-backed failure recovery.
- Fixed: C# GUI neutral status badges now use readable foreground contrast, and category health cards use explicit Pass/Partial/Fail labels instead of terse color-dependent abbreviations.

### Exports
- Added: C# GUI and silent mode can now emit OSCAL POA&M JSON with remediation tasks linked to stable OSCAL finding UUIDs, active waiver metadata, owners, due dates, and remediation text.
- Added: C# silent mode can import Intune STIG audit baseline JSON/CSV evidence and carry source/version/device/status details into HTML, JSON, CSV, and OSCAL exports without claiming new local STIG checks.
- Fixed: C# HTML, JSON, and compliance summary exports now separate Met, Partial, Fail, and Not assessed framework counts instead of counting Partial controls as passing.
- Fixed: C# HTML reports now include Partial findings in top findings and remediation roadmap sections, use semantic table captions/headers, and render clearer remediation link text.
- Fixed: C# CMMC reports now choose evidence from the worst mapped check for shared controls and emit semantic control-table markup.
- Fixed: C# dashboard HTML now has an actionable empty state, marks missing/invalid scan dates as stale, URL-encodes report links, and uses descriptive report link labels.
- Fixed: C# CSV exports now use friendly human status labels for Not assessed and N/A.

## [v5.2.5] - 2026-07-08

### UX
- Changed: C# GUI now uses a premium workstation layout with a command bar, KPI strip, category health cards, compact virtualized check review list, selected-check evidence/remediation inspector, and scan console.
- Fixed: C# GUI status labels now use friendly user-facing text, separates N/A from Not assessed counts, adds keyboard focus states to custom controls, and removes rewrite-history wording from unavailable-profile messages.

## [v5.2.4] - 2026-06-28

### Security
- Fixed: PowerShell fleet mode now rejects double quotes in `TargetsCsv` Host/Client/Site/Tags fields before building child scan parameters, blocking CSV-driven flag injection in remote audit runs.
- Fixed: PowerShell branding logos now validate `logo_base64` image data URIs and whitelist `logo_path` MIME types before placing logo data in HTML `src` attributes.
- Fixed: PowerShell HTML reports now HTML-encode branding `footer_text` in the report header subtitle instead of injecting it as raw markup.
- Fixed: C# CSV exports now neutralize spreadsheet formulas that begin after leading whitespace, tab, or carriage-return characters.
- Fixed: C# dashboard exports now reuse the shared CSV escaping routine and constrain grade CSS classes to an allowlist before rendering HTML attributes.

### Correctness
- Added: C# benchmark and lifecycle metadata now lives in a versioned manifest with source URLs, review dates, supported OS/builds, check coverage, and stale-review validation.
- Added: Local C# release tooling now cleans generated artifacts, runs xUnit by default, publishes the WPF app, signs when a code-signing certificate is available, and emits a zipped artifact with SHA256 and release manifest files.
- Fixed: C# EP10, LM06, LM07, and LM08 now dispose LDAP search-result and service-controller collections instead of leaking handles during repeated scans.
- Fixed: C# command helpers now drain stdout and stderr concurrently with timeout-aware process termination, preventing chatty child commands from deadlocking scans.
- Fixed: C# EP04 hotfix recency now parses `InstalledOn` values with invariant culture and FILETIME fallbacks instead of failing open on non-US locales or hex dates.
- Fixed: C# EP03 NetBIOS assessment now fails only on explicitly enabled adapter settings instead of treating DHCP-default values or non-P-node `NodeType` as exposure proof.
- Fixed: C# EP01 SecurityCenter2 AV evidence now decodes `productState` as provider/scanner/signature bytes instead of non-standard nibbles.
- Fixed: C# EP02 and EP08 now treat unavailable BitLocker, Device Guard, and Secure Boot platform evidence as N/A instead of confirmed failed controls.
- Fixed: C# BR03, BR06, and LM05 now query recent event-log windows with `EventLogReader` XPath instead of iterating full `EventLog.Entries` collections.
- Fixed: C# NP03 no longer treats multiple default routes alone as split-tunnel evidence, avoiding false positives on multi-NIC systems.
- Fixed: C# GUI export commands now stay disabled until at least one check is assessed and automatically disable while a scan is running.
- Fixed: C# GUI scan progress now has deterministic sequential running-state coverage so only the active check is marked as running and cancellation clears the active row.
- Added: Export contract schemas and golden fixtures now cover structured findings, JSONL events, OCSF, OSCAL, Intune, compliance summary, dashboard aggregate rows, and SIEM field mappings.
- Fixed: C# dashboard generation now groups scans by client/host, shows only the latest row per client, emits score trends, and reports skipped or duplicate files in HTML and CSV outputs.
- Added: C# GUI exports now use a compact format selector/output-folder flow and include SIEM content packs plus CMMC HTML/JSON exports.
- Fixed: C# GUI check filtering now uses a stable `ICollectionView` and a recycling virtualized `ListBox` instead of recreating a heavy `ItemsControl` enumerable on each filter/status update.
- Fixed: C# GUI grade, severity, status, overlay, selected-list, and accent foreground colors now resolve through WPF theme tokens instead of hardcoded hex values in XAML/view models.
- Fixed: C# GUI muted labels now use a higher-contrast `TextMuted` token and the 3px status bar no longer uses a pill corner radius.
- Fixed: C# GUI startup now shows an unassessed overall-grade empty state (dash / `Not scanned`) until at least one check has a Pass, Partial, or Fail result.
- Fixed: C# GUI due-date entry now uses a dark styled validated `yyyy-MM-dd` text field instead of a light system DatePicker popup.
- Fixed: C# GUI startup now detects WMI, domain, Azure AD, and Intune environment signals on a worker thread instead of blocking the WPF dispatcher during window load.
- Fixed: C# silent-mode active waivers now exclude waived Fail/Partial checks from effective scoring, fail/partial counts, framework threshold checks, and exit-code decisions while preserving accepted-risk notes in exports.
- Fixed: C# silent-mode progress now prints through an inline runner callback instead of dispatcher-posted `Progress<T>` output that could appear after the summary.
- Fixed: C# silent/dashboard modes no longer trigger UAC self-elevation and immediately return success before the real scan; headless runs stay in-process and warn when unelevated.
- Fixed: C# D3FEND IA01 mapping now uses the valid `D3-UGPH` technique ID instead of malformed `D3F-UGPH`.
- Fixed: C# SPRS scoring now treats Partial checks as unmet controls instead of awarding full SPRS credit.
- Fixed: C# overall risk scoring now matches the documented per-category weighted-average formula and no longer squares severity by multiplying severity and check weight.
- Fixed: C# Domain Maturity scoring now normalizes by domains that have assessed checks so all-N/A identity domains no longer cap endpoint-only results.
- Fixed: C# SARIF export now emits the strict root `$schema` property instead of `schema`.
- Fixed: C# ATT&CK Navigator export now lets assessed failures outrank NotAssessed/NA entries when multiple checks map to the same technique.
- Fixed: C# EP06 host firewall checks now prefer structured `MSFT_NetFirewallProfile` data, parse `netsh` fallback output without fixed spacing, and fail closed when profile status cannot be verified.
- Fixed: C# EP07, LM07, and LM01 now track applicable sub-checks directly instead of using `failCount--`/`totalChecks--` adjustments that could mask real failures.
- Fixed: C# CF08 DNS filtering now uses known-valid vendor test domains with a control lookup instead of counting arbitrary NXDOMAIN responses as proof of filtering.
- Fixed: C# CF02 egress filtering now uses a known outbound port test listener with a control-port guard instead of treating closed public IP ports as confirmed filtering.
- Fixed: C# IA01 privileged-group review now converts Active Directory `IADsLargeInteger` logon timestamps correctly instead of marking every privileged user stale.
- Fixed: C# GUI now surfaces search, status filtering, privacy mode, theme selection, save/load state, and Domain Maturity controls in the sidebar, with sidebar scrolling for smaller displays.
- Fixed: C# GUI ComboBox popups/items, scrollbars, tooltips, and context menus now use dark WPF templates instead of default light system chrome.
- Fixed: C# GUI grade, severity, and per-check status indicators now bind to live color properties instead of hardcoded gray/text-primary brushes.
- Fixed: C# GUI manual status changes now refresh pass/fail/partial/N/A counters, overall grade, ransomware readiness, domain maturity, and status-filtered views immediately.
- Fixed: PowerShell fleet mode now validates `-TargetsCsv`, deduplicates target names before queuing jobs, sanitizes per-host artifact names, parses localhost findings JSON from the derived silent-mode path, and forwards v4.11 fleet/remediation/export switches through elevation.
- Fixed: C# NP01, NP05, and NP06 firewall checks now read port and address constraints from associated WMI filter classes, with `netsh` fallback when filter access is denied, instead of relying on missing `MSFT_NetFirewallRule` properties.
- Fixed: C# per-check ATT&CK, D3FEND, and framework rows now match current labels for DNS filtering, temporary firewall rules, egress filtering, former-employee access, network flatness, failed-logon monitoring, file-integrity monitoring, and local-admin rights.
- Fixed: C# CF03 security awareness training now maps to awareness/training controls and no longer appears in the Essential Eight backup profile.
- Fixed: C# EP10 mappings now represent end-of-life operating system exposure with T1190/T1210, Software Update hardening, and SI-2/CM-8 controls instead of removable-media controls.
- Changed: C# STIG scoring no longer emits fabricated sequential V-IDs; only prose-backed IA11/IA12 STIG readiness notes remain, and the STIG profile is narrowed to those checks.
- Fixed: C# PS01-PS06 catalog and framework mappings now use policy, incident response, compliance monitoring, risk, and training HIPAA/FedRAMP/CSF citations instead of stale physical-security controls.
- Fixed: C# BR03-BR07 ATT&CK, D3FEND, and compliance mappings now match restore testing, RTO/RPO documentation, backup encryption, backup monitoring, and DR plan catalog entries.
- Fixed: C# NA03-NA07 ATT&CK, D3FEND, and compliance mappings now match the current wireless, network documentation, 802.1X/NAC, management isolation, and guest isolation catalog entries.
- Fixed: C# OSCAL export now emits OSCAL kebab-case field names, valid finding status states/reasons, and risk levels as risk properties instead of invalid top-level fields.
- Fixed: C# privacy mode now uses redacted environment clones and redacted check copies across GUI and silent exporters, including notes, remediation assignees, auditor/client strings, tenant names, and client-derived filenames.
- Fixed: C# HTML reports now escape environment subtitle fields (`ComputerName` and `OSCaption`) to block stored report XSS from hostile local system metadata.
- Fixed: C# `--output` now treats the supplied value as the report output directory and sanitizes client-derived filename segments before writing dashboard or silent-mode artifacts.
- Fixed: C# app-level exception handling now writes crash logs for dispatcher, unobserved task, AppDomain, and corrupt audit-state load failures instead of hard-crashing without diagnostics.
- Fixed: C# scans now run each check on a worker task, abandon blocking checks when the per-check timeout expires, and update GUI progress from sequential start/completion events instead of freezing the dispatcher.
- Fixed: Stop Scan command enablement now follows scan state immediately, and final scan status uses the returned result count instead of queued progress callbacks.
- Fixed: C# dashboard and silent headless modes now observe runner exceptions, write failures to stderr, and always shut down with a non-zero exit code instead of leaving a hung WPF process.
- Fixed: C# `Cloud` profile no longer expands to all local and Active Directory checks. It is explicitly disabled until Graph-backed CLxx checks are implemented, and CLI/GUI scans now report that state instead of running misleading endpoint/domain coverage.
- Added: Regression tests proving the C# Cloud profile resolves to no local/AD checks and the runner returns no results for it.

### Testing
- Added: Structural tests now enforce catalog/MITRE/D3FEND/framework key parity, ATT&CK and D3FEND ID formats, and duplicate check-ID fail-fast behavior.

### Documentation
- Changed: README now separates the production PowerShell artifact from the C# rewrite, removes stale hosted-workflow validation examples, documents local C# test/build/publish commands, and clarifies C# Cloud profile behavior.
- Changed: README now documents the C# rewrite as Catppuccin Mocha-only while the legacy PowerShell WPF artifact retains the seven-theme selector.

## [v5.2.3] - 2026-06-20

### Compliance & Data
- Fixed: OCSF exporter now includes all 11 compliance frameworks in requirements (was 5 of 11).
- Fixed: DefectDojo exporter now includes all 11 frameworks in references (was 5 of 11).
- Fixed: OSCAL exporter now includes all 11 frameworks as props on findings (was NIST-only).
- Fixed: Sentinel SIEM schema expanded to 35 columns matching full JSONL event schema. `OverallScore_d` type corrected from `"int"` to `"double"`.
- Fixed: Elastic index template expanded to 31 fields matching full JSONL schema (was 18).
- Fixed: SIEM field mapping document now includes all 11 compliance frameworks plus duration_ms.
- Added: CSV export now includes metadata comment line with host, score, grade, and UTC timestamp.

### Security
- Fixed: CSS injection via branding color values blocked. `EffectivePrimary`/`EffectiveAccent` now validated against strict CSS color regex (hex, named colors, rgb() only).

### Reliability
- Fixed: All exporters now use `DateTime.UtcNow` consistently (DefectDojo, HTML report, CMMC report, Dashboard were using local time).
- Fixed: DashboardGenerator no longer silently swallows JSON parsing errors. Skipped files and error reasons are shown in dashboard HTML and CSV output.

## [v5.2.2] - 2026-06-20

### Security
- Fixed: XSS in Dashboard HTML — client names, hostnames, and OS strings from JSON files now HTML-escaped. Previously injected raw values.
- Fixed: XSS in CMMC report — `env.ComputerName` now HTML-escaped in subtitle.
- Fixed: XSS via `RemediationUrl` in HTML reports — URLs now validated for http/https scheme before rendering as links. Prevents `javascript:` URI injection.
- Fixed: XSS via `LogoBase64` and `ContactEmail` in HTML reports — values now HTML-escaped in attribute contexts.
- Fixed: CSV injection in Dashboard CSV — values now properly escaped with double-quote handling instead of raw interpolation.
- Fixed: PDF browser process now killed on timeout instead of being orphaned. Removed `--no-sandbox` flag.

### Correctness
- Fixed: CMMC Level 2 eligibility logic — `>= 110` (full) now checked before `>= 88` (conditional). Previously the full-eligibility branch was unreachable dead code; a score of 110 would incorrectly show "conditional with POA&M".
- Fixed: ATT&CK Navigator exporter now uses worst-case status for techniques mapped to multiple checks, instead of first-seen-wins which silently dropped failures.
- Fixed: OCSF exporter now includes all MITRE ATT&CK techniques per finding instead of only the first.
- Fixed: OCSF exporter null guards for `Findings` and `Evidence` length checks — prevents NullReferenceException if either field is null.
- Fixed: PdfExporter now reads stderr before waiting for exit to prevent pipe deadlock.

### Correctness (continued)
- Fixed: OSCAL method mapping — automated checks now use "TEST" instead of "EXAMINE" per NIST OSCAL spec. Heuristic uses "EXAMINE", interview uses "INTERVIEW".
- Fixed: OSCAL/JSONL null guards for Findings/Evidence fields to prevent NullReferenceException.

### Testing
- Added: CMMC full-eligibility regression test (score 110 → "Eligible (full)")
- Added: Navigator worst-case status dedup test (EP01 fail → technique score 0)
- Added: HTML RemediationUrl XSS prevention test (javascript: scheme blocked)
- Added: Dashboard HTML escaping verification test (131 total tests)

### Maintainability
- Changed: CsvExporter, JsonlExporter, and DefectDojoExporter now accept `IEnumerable<CheckItemViewModel>` instead of `ObservableCollection`. Removes unnecessary data copying at call sites.

## [v5.2.1] - 2026-06-20

- Fixed: Assembly version bumped to 5.2.0 (was still 5.0.0 in csproj). All exports and window title now report correct version.
- Fixed: Navigator GUI export now respects PrivacyMode. Previously bypassed `GetExportChecks()` and leaked un-redacted data.
- Fixed: Removed unused variable `eventTriggered` in LM08_AlertingCheck. Build now produces zero warnings.
- Fixed: JSON export from silent mode now includes computed Client and Auditor names instead of empty strings.
- Changed: GUI PDF export now explicitly passes `ReportTier.All` to HTML generator for clarity.
- Changed: `--export-all` now includes SIEM content packs, CMMC report, and PDF in addition to previous 9 formats.
- Added: CLI argument parsing tests (22 tests) covering all flag variants, `--export-all` completeness, PowerShell-style aliases, and edge cases.
- Added: AuditState save/load roundtrip test (4 tests) validating serialization fidelity, ToolVersion from assembly, and error handling.
- Changed: `ParseArgs()` and `CliArgs` made `internal` with `InternalsVisibleTo` for testability.
- Added: BrandingConfig loading tests (4 tests) — valid JSON, missing file, empty JSON defaults, unknown fields ignored.
- Added: PreflightChecker output tests (7 tests) — admin/non-admin, domain/non-domain, result count, name/detail validation.
- Added: WaiverStore operations tests (10 tests) — add, replace, get active, case-insensitive lookup, expiration, remove, serialize/deserialize roundtrip, file I/O.
- Fixed: DashboardGenerator.GenerateCsv synchronous `.Wait()` wrapper replaced with public async `GenerateCsvAsync()`. Eliminates potential deadlock on UI SynchronizationContext.
- Added: CIS Benchmark version metadata (`cis_benchmark`) on all checks. Endpoint/OS checks reference CIS Windows 11 Enterprise v5.0.0 / Windows Server 2025 v2.0.0. All other checks reference CIS Controls v8.1. Field included in JSON export per finding.
- Added: Per-check scan duration (`duration_ms`) in JSON findings and JSONL events. Duration captured from CheckRunner timeout-aware execution and threaded through CheckItemViewModel to all export formats.

## [v5.2.0] - 2026-06-19

- Fixed: OSCAL observation-finding UUID cross-reference. Findings now correctly reference their parent observation UUIDs instead of string IDs that never matched.
- Fixed: CSV formula injection quoting. Values with formula prefixes (`=`, `+`, `-`, `@`) are now unconditionally quoted to prevent malformed rows when the value also contains commas.
- Fixed: Privacy redaction no longer mutates ViewModel state. Exports with privacy mode operate on copies, preserving original data for subsequent non-private exports.
- Changed: Version strings centralized via `VersionInfo.cs`. All exports, silent mode banner, window title, and audit state now read version from assembly metadata instead of hardcoded literals.
- Changed: Silent mode exit codes now use `ExitCode` enum instead of raw int literals for clarity and maintainability.
- Added: SARIF `security-severity` property (0.1-10.0) on all rules for GitHub Code Scanning severity display (Critical=9.5, High=8.0, Medium=5.5, Low=3.0).
- Added: Intune compliance JSON export. GUI button and `--export-intune` CLI flag produce `SecurityAuditGrade`, `SecurityAuditScore`, compliance flags, and critical failures in Intune-compatible JSON.
- Added: `--export-compliance-summary` CLI flag for silent mode. Produces the compact RMM dashboard payload alongside other exports. `--export-all` now includes both Intune and compliance summary.
- Added: CMMC Level 1/2 self-assessment report. `--export-cmmc` generates HTML and JSON reports mapping NIST 800-171 controls to check results with per-control pass/fail/partial status, SPRS weight, deduction, evidence summary, and Level 1 practice identification. Includes SPRS score, confidence level, and CMMC Level 2 eligibility indicator.
- Added: SIEM content pack export. `--export-siem` generates Splunk props.conf, Elastic index template, Microsoft Sentinel custom table definition, Wazuh decoder/rules XML, and a universal field mapping JSON reference.
- Added: Pre-flight connectivity check in GUI. On startup, checks admin elevation, domain membership, AD module, Defender, WinRM, BitLocker, and SMB availability. Results shown in sidebar with pass/warn and guidance for each unavailable capability.
- Added: Multi-client dashboard generator. `--dashboard --input-dir C:\Scans` builds a static HTML rollup from `*_findings.json` exports with per-client grade, score, ransomware readiness, critical findings, stale-scan flags, and links to individual reports. Companion CSV export included.
- Added: White-label branding for HTML reports. `--branding config.json` applies company name, logo (base64), primary/accent colors, tagline, contact info, footer text, and optional cover page to HTML output. Branding config uses snake_case JSON format.
- Added: Three-tier HTML report generation (Executive/Management/Technical). `--report-tier Executive` produces a 1-page score summary with top 5 findings. `--report-tier Management` adds category breakdown, compliance framework coverage, and remediation roadmap. `--report-tier Technical` adds full per-check findings with evidence, ATT&CK mapping, framework control IDs, and D3FEND coverage. `--report-tier All` (default) produces all three tiers.
- Added: PDF export via Edge/Chrome headless rendering. GUI button and `--export-pdf` CLI flag with 30-second timeout and diagnostic fallback message.
- Added: Waiver store integration for silent mode. `--waivers path.json` loads risk waivers during silent scans. Active waivers annotate check notes with `[ACCEPTED RISK]` justification, approver, and expiration. Expired waivers produce console warnings.
- Added: OSCAL observation-finding UUID linkage test, SARIF schema/security-severity validation tests, Intune export test, full-catalog (69-check) export roundtrip test covering all 11 exporters, and HTML Executive tier isolation test. Test suite now has 80 tests.
- Fixed: CSV column count test corrected from 24 to 23 (matching actual header).

## [v5.1.0] - 2026-06-16

- Added: MITRE D3FEND defensive technique data in all exports (JSON, HTML, CSV, JSONL, SARIF, DefectDojo). Each finding includes D3FEND stages, techniques, labels, and description.
- Added: CIS Controls v8.1 and HIPAA Security Rule as structured framework mappings for all 69 checks. Compliance scoring, CSV, and JSONL now include all 11 frameworks.
- Added: E8 and CyberEssentials columns to CSV export. MITRE ATT&CK tactics/techniques added to JSONL events.
- Added: D3FEND columns (stages, techniques) to CSV export for SIEM pivot-table workflows.
- Added: DomainMaturity score/grade persistence in audit state save/load.
- Added: Centralized FrameworkDefinitions for all exporters — single source of truth for framework names and selectors.
- Added: Exit code 3 for compliance framework threshold (any framework below 60% triggers ComplianceAlert exit code for RMM alerting).
- Added: HTML report D3FEND coverage section showing defensive stage distribution across all checks.
- Changed: JSON findings now include framework_controls.cis and framework_controls.hipaa fields.
- Added: GUI export buttons for all 8 formats (HTML, JSON, CSV, JSONL, SARIF, Navigator, DefectDojo, Compliance Summary).
- Added: WPF AutomationProperties.Name on scan controls, category list, profile selector, status dropdowns for screen reader support.
- Added: Responsive HTML report CSS breakpoints at 768px and 480px for tablet/mobile viewing.
- Fixed: DefectDojo exporter now sets unique_id_from_tool for stable deduplication across re-imports.
- Added: ATT&CK v19 tactic split — Defense Impairment (TA0112) for checks involving disabling AV, logging, and firewalls. Navigator layer updated to ATT&CK version 19.0.
- Added: Windows Server 2025 security default awareness. EP03, EP08, and IA11 annotate mandatory defaults (SMB signing, Credential Guard, AES-only Kerberos) on Server 2025+ builds.
- Added: SPRS score calculation for CMMC Level 2. Weighted 1/3/5 point deductions per unmet NIST 800-171 control. Included in JSON export and HTML report score card.
- Added: OCSF v1.4.0 Compliance Finding (class 2003) export. Replaces deprecated Security Finding class. CLI: `--export-ocsf`.
- Added: NIST OSCAL v1.1.3 assessment results export with observations, findings, and risks. CLI: `--export-oscal`.
- Added: OCSF and OSCAL GUI export buttons.
- Added: CI/CD integration section in README with GitHub Actions SARIF upload workflow example.

## [v4.11.1] - 2026-07-09

### Security
- Fixed: PowerShell fleet mode now validates throttle/timeout ranges, forwards privacy/auditor/report/export options to child scans, uses unique remote temp artifacts with cleanup, includes 0% scored hosts in aggregates, and warns on invalid branding config paths or website URLs.

## [v4.11.0] - 2026-06-16

- Added: CL13 Entra Connect hard-match and source-anchor posture check. Identifies privileged synced users with `onPremisesImmutableId` that are exposed to hard-match takeover. Runs during `-ScanProfile Cloud` alongside CL01/CL02/CL06. Surfaces affected accounts with immutableId prefix, sAMAccountName, and role flags.
- Added: Benchmark result import. New `-BenchmarkImportPath` parameter imports HardeningKitty CSV, Microsoft Policy Analyzer CSV, or DISA STIG Checklist (.ckl) results. Imported findings appear in a dedicated HTML report section and in structured JSON exports with source, benchmark, version, and per-finding pass/fail/expected/actual data.
- Added: SIEM content packs (NSA-014). New `-ExportSIEM` switch generates platform-specific ingestion configs: Splunk `props.conf`/`transforms.conf`, Elastic index template, Microsoft Sentinel custom table definition, Wazuh decoder/rules XML, and a universal field mapping JSON reference.
- Added: Remediation dry-run framework (NSA-007). New `-Remediate` and `-RemediateDryRun` switches with optional `-RemediateChecks` filter. Six safe remediations: disable LLMNR (NA07), disable SMBv1 (CF04), require SMB signing (CF05), increase Security event log (LM01), enable script block logging (LM03), enable module logging (LM04). Each records before/after values and writes a JSON rollback manifest. Requires `-ReadOnly:$false` to apply; dry-run previews changes without modifying the system.
- Added: Remote fleet scan mode (NSA-006). New `-TargetsCsv` parameter with `-ThrottleLimit`, `-PerHostTimeout`, and `-Credential` runs silent-mode audits across multiple hosts via PSRemoting. Each host produces a per-host `_findings.json`; a `fleet_summary.csv` and `fleet_summary.json` aggregate scores, grades, fail counts, and error states. Failed/offline hosts do not block the batch.
- Added: White-label executive pack (NSA-009). New `-BrandingConfig` parameter accepts a JSON file with company name, logo (base64 or path), primary/accent colors, contact info, tagline, footer text, and cover page toggle. HTML reports render a branded cover page, header logo/company bar, custom accent gradient, and branded footer with contact links. Structured JSON exports include a `branding` metadata block. Silent mode logs active branding.

## [v4.10.9] - 2026-06-16

- Added: Check evidence-mode manifest covering all 69 checks with `EvidenceMode`, `AuthorityLevel`, `DataSources`, `InternetRequired`, `WritesPossible`, `DefaultRiskTier`, and `ManualFollowUp` metadata.
- Changed: HTML reports and JSON/JSONL/CSV/SARIF/compliance-summary exports now distinguish automated, heuristic, checklist, interview-required, and external-required evidence. Framework summaries retain default scoring and add manual-validation counts plus automated-only scoring metadata.
- Added: Static and Pester validation now fail if any audit check lacks evidence-mode metadata.

## [v4.10.8] - 2026-06-16

- Changed: Cloud assessment provenance now flows through JSONL, CSV, compliance summary, SARIF, Intune compliance JSON, and dashboard exports using the same privacy redaction path as HTML and structured JSON.

## [v4.10.7] - 2026-06-16

- Added: `-ScanProfile Cloud` for Microsoft Graph cloud assessment without an on-premises domain. The cloud manifest now declares CL01-CL12 with permissions, role hints, license prerequisites, endpoints, output fields, skip states, and privacy classes; CL01 Secure Score, CL02 Conditional Access baseline, and CL06 guest lifecycle checks emit HTML/JSON evidence from live Graph or offline mocks.

## [v4.10.6] - 2026-06-16

- Changed: Imported cloud assessment provenance now redacts tenant names, tenant IDs, source paths, and token-like values under `-PrivacyMode`. HTML reports show cloud source provenance and structured JSON exports include an explicit `provenance` block.

## [v4.10.5] - 2026-06-16

- Added: Microsoft Graph request wrapper with offline mock-response fixtures for paging, `Retry-After` throttling, and permission/license error classification. The wrapper returns source timestamps and permission scopes without requiring tenant credentials during tests.

## [v4.10.4] - 2026-06-16

- Added: Imported cloud assessment results now normalize `NotLicensed`, `NotPermitted`, `NotConfigured`, `Skipped`, `Error`, and `Other` separately from true `Fail` results. HTML and structured JSON exports include the unavailable/status breakdown, and fixture tests cover the status taxonomy offline.

## [v4.10.3] - 2026-06-16

- Changed: Scoped `IA03` and `IA09` as local/remote-access indicator checks instead of tenant MFA or Conditional Access proof. Reports now state that Graph-backed tenant proof requires cloud assessment inputs or future cloud checks.
- Added: Static validation now fails if `IA03`/`IA09` labels or README wording drift back to overclaiming tenant MFA or Conditional Access coverage.

## [v4.10.2] - 2026-06-16

- Added: CVE-2025-33073 NTLM reflection correlation across IA01, EP03, and EP04. Reports now identify delegation blast radius, SMB signing/name-resolution exposure, June 2025+ patch evidence, CISA KEV status, and a dedicated attack-path chain when all signals fail together.
- Changed: ATT&CK context strings now call out CVE-2025-33073 exposure for privileged delegation, SMB/NTLM hardening, and patch-compliance checks.
- Added: ESC16 certificate mapping methods audit in CF01 ADCS scan. Detects weak CertificateMappingMethods (UPN/Subject-Issuer) combined with non-enforced StrongCertificateBindingEnforcement.
- Added: Windows 11 Administrator Protection posture check in EP05. Reports TypeOfAdminApprovalMode state on 24H2+ builds with remediation guidance; N/A on older builds.
- Added: SMB over QUIC and client access control audit in EP03. Detects QUIC server/client enablement, certificate configuration, and client access control rules on Server 2025/Win11 24H2+.
- Added: Framework source manifest with mapping provenance. FrameworkMeta now includes SourceVersion, SourceUrl, ReviewedDate, and Confidence for all 11 frameworks. Structured JSON exports emit a `framework_provenance` block.
- Changed: EP10 OS lifecycle data externalized into a versioned lifecycle table with per-product Status, EOL date, ESU eligibility, source URL, and review date. Covers Windows XP through Server 2025.
- Changed: `-PrivacyMode` redaction now covers all export surfaces (HTML, OCSF, OSCAL, SARIF, Intune, compliance summary, ATT&CK Navigator, run log) in addition to JSON/JSONL/CSV.
- Changed: GitHub Actions pinned to commit SHAs; PSScriptAnalyzer and Pester locked to exact versions (1.25.0 / 5.7.1).
- Released: v4.10.0 published to GitHub Releases with checksum and attestation.

## [v4.10.1] - 2026-06-16

- Changed: Refreshed external export contracts to ATT&CK Enterprise v19.1, OCSF v1.8.0, and OSCAL v1.2.2 while keeping ATT&CK Navigator layer output on the current v4.5 layer format.
- Added: Export artifacts now include a source-version manifest with upstream release URLs and review dates for ATT&CK, Navigator, D3FEND, OCSF, and OSCAL metadata.
- Changed: Static validation now pins the expected external taxonomy/schema versions and fails if export metadata drifts from the central manifest.

## [v4.10.0] - 2026-06-14

- Added: Continuous delta assessment. Silent runs now write a compact snapshot, compare it to the previous baseline with a shared pure comparison engine (`Compare-AuditSnapshot`), and append a run summary to `history.jsonl`. Surfaces new/resolved/worsened/improved/updated-evidence/unavailable findings, new and resolved criticals, a score delta, and per-critical exposure windows (first-seen carried forward across runs). The HTML report gains a "Change Since Baseline" section; the findings JSON gains a `continuous` block (delta, exposure, preview alert payload); RMM fields gain `ScoreDelta`/`NewCriticals`/`ResolvedCriticals`/`WorstExposureDays`/`BaselineAgeDays`. The GUI Diff button now uses the same engine and writes `*_delta.json`. History records carry run/snapshot/baseline IDs, catalog/policy hashes, output paths, and write-result references. Schema-version mismatches are flagged before comparison. New params: `-HistoryPath`, `-BaselinePath`, `-NoHistory`, `-TrendDays`, `-AlertPreview`, `-HistoryRetentionDays` (snapshots pruned past retention; 0 keeps all).
- Fixed: snapshot comparison now extracts finding keys via `IDictionary`, so the live `OrderedDictionary` snapshot compares correctly (previously yielded zero deltas).
- Added: Evidence-grade compliance output in the structured findings JSON — an `exceptions` array surfacing every accepted-risk/deferred finding with its control mappings, owner, expiration, and rationale; a `framework_controls` single-framework control summary (control, status, observed fact, narrative) emitted when a framework scan profile is active; an `evidence_model` note separating observed facts (`evidence`) from narrative (`findings`); per-finding `assessment_method`; explicit `score_excludes_na` on framework scores; and a `mapping_limitations` disclaimer (also shown in the HTML compliance section) noting heuristic/checklist controls require manual validation.
- Added: `-Dashboard` mode — generates a static multi-client rollup HTML (plus CSV) from a folder of `*_findings.json` exports. Shows per-client latest grade/score, ransomware readiness, critical counts, framework coverage, a score trend, and a stale-scan flag, with a critical-findings-by-category rollup. Runs with no server, no scan, no elevation, and no host changes; links back to each client's HTML report when present; embeds only aggregate scores (no evidence/notes). New params: `-InputDir`, `-StaleDays`.
- Added: Unified write manifest — every persistent side effect (RMM field write, registry cache, host-modifying setup) is routed through a single `Register-AuditWrite` gate that records `ActionId`, `Provider`, `Destination`, `RiskTier`, `RequiresAdmin`, `Allowed`, `Attempted`, `Succeeded`, `Error`, and `RollbackHint`.
- Added: `-WriteManifestOnly` switch — previews every intended RMM/registry/setup write and performs none of them (implies `-NoRmmWrite` and `-NoRegistryWrite`).
- Added: Silent mode now prints a post-run write summary (intended / written / skipped / failed) driven by the manifest, and the structured JSON export discloses `writes.any_attempted`, `writes.write_manifest_only`, and the full manifest so a report always states whether anything was written.
- Changed: Read-only mode (the default) now blocks all host-modifying setup — WinRM/PSRemoting, Remote Registry, WMI/Event Log firewall rules, and audit-policy configuration — via a shared `Block-IfReadOnly` guard on both the standalone setup functions and the turnkey setup selections. Host changes require an explicit `-ReadOnly:$false`.
- Changed: README "Trust and Safety" section documents the write gate, write disclosure, and `-WriteManifestOnly`.
- Added: Pester v5 quality-gate suite at `tools/NetworkSecurityAudit.Tests.ps1` covering parser health, catalog/profile/framework/risk/D3FEND ID consistency, version-surface drift, export serialization, lint cleanliness, and the legacy static gate. No test executes a real audit check or modifies the host.
- Added: `PSScriptAnalyzerSettings.psd1` rule set enforcing syntax, correctness, and security rules while documenting each excluded rule as an intentional single-file design choice. The main script now reports zero analyzer findings.
- Changed: CI `powershell-validation.yml` now installs Pester 5 + PSScriptAnalyzer and runs the static gate, the linter, and the Pester suite on `windows-2022` and `windows-2025`, uploading Pester results as an artifact.
- Fixed: Renamed assignments to PowerShell automatic variables flagged by analysis — `$matches` (GPP cpassword scan) and the `$Profile` parameters of `Start-RunLogEntry`/`Add-SkippedRunLogEntry` (now `$ProfileName`) — removing latent shadowing bugs.
- Added: README CI badge and an expanded "Development Validation" section documenting the three local gate commands.

## [v4.9.0] - 2026-06-13

- Changed: `EP04` CISA KEV cross-reference now caches the catalog locally (24-hour TTL), falls back to cache on network failure or `-NoInternet`, detects additional products (IIS, .NET, Office, Edge), surfaces `knownRansomwareCampaignUse` ransomware-linked entries with overdue flags, validates catalog schema, and widens the matching window from 180 to 365 days.
- Added: `-ExportNavigator` switch to export MITRE ATT&CK Navigator v4.5 layer JSON with technique scoring, gradient colors, and per-check comments.
- Added: `-CloudAssessmentPath` parameter to import Maester and CISA ScubaGear JSON results into HTML reports and structured JSON exports.
- Added: `EP10` now detects Windows 10 Extended Security Update (ESU) enrollment status via registry.
- Added: `EP03` now audits NTLM restriction, receive, audit, and NTLMv1 SSO block policies via `MSV1_0` registry keys.
- Added: `EP08` now checks Secure Boot 2023 UEFI CA/DBX transition status and pending updates (KB5025885).
- Changed: Structured findings JSON now includes `cloud_assessments` array when cloud assessment imports are present.
- Changed: Validation gate now checks `-ExportNavigator` and `-CloudAssessmentPath` auto-elevation pass-through and NTLM restriction keywords.
- Added: `IA06` now audits LAPS password read/decrypt delegation by inspecting OU ACLs for schema-attribute-specific access, flagging broad groups and distinguishing Tier-0 from overbroad principals.
- Added: `-ExportOCSF` switch to export OCSF v1.3 Security Finding (class_uid 2001) JSONL for vendor-neutral SIEM and MDR ingestion.
- Added: `EP07` now checks Smart App Control state (Win11 22H2+) and Windows Recall policy/user setting (Win11 24H2+), gated by OS build number.
- Added: `IA09` now inventories 20+ remote access and RMM tools by registry, running service, and portable-path detection, flagging unsigned portable executables and excessive tool counts per CISA/NSA advisory guidance.
- Changed: `EP01` ASR section now lists individual rule names and modes, flags 6 high-value rules when missing or audit-only, and reports Defender exclusion counts with executable extension warnings.
- Added: FedRAMP Moderate (NIST 800-53 Rev 5) compliance framework mapping with scan profile, GUI selector, compliance strings, and HTML/JSON/JSONL/CSV export fields for all 69 checks.
- Added: `-ExportOSCAL` switch to export NIST OSCAL v1.1.2 assessment-results JSON with observations, findings, reviewed controls, and framework control mappings for GRC and FedRAMP workflows.
- Added: `-PrivacyMode` switch to redact hostnames, IP addresses, domain names, usernames, and client identifiers in all structured exports (JSON, JSONL, CSV) using SHA256-based pseudonyms while preserving finding and scoring integrity.
- Added: `tools/Test-ThemeContrast.ps1` WCAG 2.2 AA contrast validation script for all 7 dark themes, covering 273 foreground/background pairs with 4.5:1 text and 3:1 UI component thresholds.
- Fixed: All 7 theme palettes adjusted for WCAG 2.2 AA contrast compliance -- brightened borders, hints, thumbs, and secondary text; darkened surface backgrounds; bumped Critical severity color from `#ef4444` to `#f87171`.
- Added: Passive version-staleness notice that checks GitHub releases on startup (GUI status bar and silent-mode log line) and notes when a newer version is available; fully skipped when `-NoInternet` is set; never downloads or modifies anything.

## [v4.8.1] - 2026-06-11

- Fixed: Silent and auto-export paths now suppress direct export function return values so unattended console output only shows labeled status lines.
- Changed: Validation now guards silent and auto-export calls against raw path output regressions.

## [v4.8.0] - 2026-06-11

- Added: `CF01` ADCS scan now detects ESC9 no-security-extension templates, ESC11 RPC enrollment encryption gaps, ESC13 issuance-policy OID group links, and ESC15/EKUwu schema-v1 supply-in-request exposure.
- Changed: README ADCS IOC coverage and validation now include ESC9, ESC11, ESC13, and ESC15.

## [v4.7.1] - 2026-06-11

- Fixed: `N/A` scan results now use distinct neutral tab badges, scan-button labels, card flash color, and silent console icons instead of warning/error fallbacks.
- Changed: Validation now guards `N/A` status presentation paths.

## [v4.7.0] - 2026-06-11

- Added: `IA12` BadSuccessor/dMSA exposure detection for Windows Server 2025 dMSA objects, migration links, target backlinks, and OU create/control ACL risk.
- Changed: README, scan profiles, framework mappings, MITRE ATT&CK, MITRE D3FEND, and validation gate now cover 69 checks.
- Fixed: GUI and silent scan result mapping now preserves explicit `N/A` statuses from checks instead of converting them to `Not Assessed`.

## [v4.6.1] - 2026-06-11

- Fixed: Letter-grade and threshold-color calculations now return a single scalar value instead of multi-value arrays for high scores.
- Changed: Validation now rejects `switch($true)` threshold expressions to prevent score/export drift.

## [v4.6.0] - 2026-06-11

- Added: Structured per-check run log with start/end time, duration, status, skip reason, timeout, error, and slow-check fields.
- Changed: Structured findings JSON now includes `run_log_summary` and `run_log`; silent and auto-export runs now write `_runlog.jsonl`.
- Changed: HTML reports now flag checks that exceed 30 seconds.

## [v4.5.0] - 2026-06-11

- Added: UK NCSC Cyber Essentials (`CyberEssentials`) framework/profile mapping with 36 checks across firewalls, secure configuration, user access control, malware protection, and security update management.
- Changed: HTML, JSON, JSONL, CSV, summary, GUI selector, silent-mode profile handling, and validation now include Cyber Essentials.
- Fixed: `EP02` now reports BitLocker provider or access failures as partial evidence limitations instead of aborting a non-admin scan.

## [v4.4.1] - 2026-06-11

- Changed: README quick start now uses a download, hash, signature-state, inspect, then run workflow instead of `irm | iex`.
- Changed: Trust and Safety guidance now documents read scope, network touches, output behavior, RMM writes, `-NoInternet`, `-NoRmmWrite`, and `-NoRegistryWrite`.

## [v4.4.0] - 2026-06-11

- Added: ACSC Essential Eight (`E8`) framework/profile mapping with 27 relevant checks and maturity-level indicators.
- Changed: HTML, JSON, JSONL, CSV, summary, GUI selector, and silent-mode profile handling now include Essential Eight.
- Fixed: Silent profile filtering no longer collides with PowerShell's read-only `$PID`.
- Fixed: XAML tooltip text now escapes `ATT&CK` correctly.
- Fixed: `EP01` now reports Defender provider failures as partial findings instead of aborting the check wrapper.
- Fixed: Theme label coloring now uses the valid `TextSecondary` token.

## [v4.3.1] - 2026-06-11

- Fixed: README compliance profile counts now match the actual `FrameworkChecks` coverage.
- Changed: Validation gate now enforces README framework profile count consistency.

## [v4.3.0] - 2026-06-11

- Added: MITRE D3FEND v1.4.0 defensive technique map for all 68 checks.
- Added: HTML D3FEND stage coverage summary and per-finding D3FEND context.
- Changed: JSON, JSONL, CSV, and SARIF exports now include D3FEND technique metadata.
- Changed: Validation gate now enforces D3FEND map completeness and export-field coverage.

## [v4.2.1] - 2026-06-11

- Fixed: `IA11` now explicitly checks `krbtgt` Kerberos encryption flags and password age for RC4/DES readiness.

## [v4.2.0] - 2026-06-11

- Added: `IA11` Kerberos RC4/DES deprecation readiness check for AD encryption flags, trusts, KDC Event IDs 201-209, and local Kerberos policy state.
- Changed: README, scan profiles, framework mappings, MITRE mappings, and validation gate now cover 68 checks.

## [v4.1.9] - 2026-06-11

- Fixed: Remote Registry setup now uses `sc.exe` instead of service cmdlets that can surface progress UI in unattended runs.

## [v4.1.8] - 2026-06-11

- Added: `-NoRegistryWrite` switch to suppress registry-backed RMM/cache writes while preserving command-based RMM integrations.

## [v4.1.7] - 2026-06-11

- Added: `-NoElevate` switch to keep silent/unattended runs in the original process without UAC relaunch.

## [v4.1.6] - 2026-06-11

- Added: `-NoInternet` flag to skip CISA KEV downloads, DNS filtering probes, egress probes, and external preflight DNS checks.

## [v4.1.5] - 2026-06-11

- Changed: SARIF results now include stable logical check locations and check URI artifact links.

## [v4.1.4] - 2026-06-11

- Changed: JSONL export now includes truncation flags and original text lengths for long findings/evidence fields.

## [v4.1.3] - 2026-06-11

- Added: `-NoRmmWrite` silent-mode switch to skip RMM and registry field writes while still generating reports and exports.

## [v4.1.2] - 2026-06-11

- Fixed: CSV exports now neutralize spreadsheet formula prefixes in operator-controlled text fields.

## [v4.1.1] - 2026-06-11

- Added: Dependency-free PowerShell validation gate for parser, catalog, profile, framework, export flag, STIG, and version consistency checks.
- Added: GitHub Actions workflow for the validation gate.
- Fixed: Centralized product/version metadata across GUI, silent mode, save state, HTML, JSON, JSONL, summary, SARIF, and Intune export surfaces.
- Fixed: Auto-elevation now preserves `-ExportSARIF` and `-ExportPDF`.
- Fixed: Compliance strings and JSON/JSONL/CSV detail exports now include STIG mappings.
- Changed: README version badges, trust/safety guidance, and validation docs.

## [v4.1.0] - 2026-06-10

- Fixed: Fix 20 GUI/UX/edge case issues from comprehensive audit
- Fixed: Fix 10 bugs found during code audit
- v4.1.0: DISA STIG, CISA KEV, AD IOC detection, new exports, maturity score
- Changed: Improve checks, fix risk tiers, harden HTML report, clean up themes
- Fixed: Fix version mismatch, performance, security, and style issues
- Changed: Update README.md
- Added: Add screenshot to README
- Added: Add screenshot to README
- README: fix script filename reference, remove nonexistent ROADMAP.md, add version badge
- Changed: Update README.md
