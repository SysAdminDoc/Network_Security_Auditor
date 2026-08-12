# Changelog

All notable changes to Network_Security_Auditor will be documented in this file.

## Unreleased

### Security
- Added a stable, offline-testable dependency health gate for direct/transitive inventory, vulnerability advisories, and version drift. Vulnerabilities always block; release drift requires named, owned, dated exact-version exceptions, and release bundles now include the gated JSON decision.
- Added an independently executable C# release-bundle verifier. Release output now self-checks every checksum and manifest hash, CycloneDX 1.5 declarations, safe ZIP entries, entrypoint/runtime metadata, and Authenticode state; `-RequireSignature` rejects unsigned bundles without overstating skipped signing.
- Fixed: Fleet artifacts now use collision-safe target names, reject missing or schema-invalid child results instead of counting them as completed, and redact aggregate identities and source paths in privacy mode.
- Fixed: C# release artifact cleanup now rejects repository roots, source directories, and reparse-point paths before any recursive deletion.
- Fixed: C# audit-state loading now validates schema, machine identity, complete check coverage, and enum values before mutation; state, waiver, and dashboard JSON imports now enforce size/file-count budgets.
- Fixed: C# external exports now emit the documented OCSF 1.8.0, OSCAL 1.2.2, and ATT&CK Enterprise 19.1 metadata; Intune STIG CSV evidence is emitted as its own rectangular artifact.
- Fixed: C# PDF export stages generated output and atomically replaces the destination only after a non-empty PDF is produced.
- Fixed: C# privacy exports now redact structured JSON/YAML/header secrets and strip identifying branding fields from silent HTML output while retaining normal-mode branding.
- Fixed: PowerShell continuous history now separates default baselines by client and target, rejects identity-mismatched comparisons, atomically persists snapshots, and reports locked/failed writes in console and JSON output.
- Fixed: PowerShell privacy exports now recursively redact structured secrets, remediation/benchmark/write metadata, and identifying branding across HTML, JSON, JSONL, and CSV outputs.

### Accessibility
- Fixed: PowerShell action buttons and severity badges now choose a foreground that remains readable across normal and hover states, with automated WCAG contrast coverage for all seven themes.

### Reliability
- Added denominator-safe MSP executive KPIs across C# and PowerShell dashboard HTML/CSV/JSON, compliance summaries, and PowerShell history. Invalid, unavailable, and duplicate inputs no longer inflate coverage or score populations; freshness, critical-change, exception, exposure-age, and remediation-aging metrics publish explicit denominators.
- Added a non-invasive diagnostics profile to both delivery surfaces. It emits bounded text/JSON readiness reports for elevation, Windows capabilities, output paths, PDF discovery, import limits, internet policy, and Graph configuration without persisting identities or credentials.
- Fixed and completed per-target single-flight scan locking across the C# and PowerShell silent paths. Locks now compile cleanly, preserve verified live owners, recover dead or PID-reused stale owners after a bounded age, emit `AlreadyRunning` exit code 68, and are covered for overlapping, canceled, crashed, completed, and unrelated-target runs.
- Fixed: Individual C# saves and exports now share busy-state gating, contextual failure reporting, crash-log capture, and cleanup; closing the window cancels active scans within a bounded shutdown period.
- Fixed: PDF export discovers validated per-user Edge/Chrome installations and safely resolves executable candidates from rooted PATH entries.
- Fixed: Crash logs now redact common secret, path, and identity data and retain only bounded, locked rotating archives.
- Fixed: Intune STIG imports tolerate provider casing differences, malformed rows, and duplicate or blank CSV headers while surfacing bounded import warnings.
- Fixed: Existing dotted output directories are preserved by the C# CLI instead of being mistaken for file paths.
- Fixed: PowerShell benchmark imports now bound file bytes and record counts, isolate malformed or unsupported sources, and preserve per-file diagnostics in reports and structured output.
- Added: Benchmark imports now compute raw-content SHA-256 digests, consume adjacent provenance manifests, reject digest mismatches, and disclose format, review, licensing, redistribution, target, and verification state. The built-in catalog remains mapping-only and does not redistribute benchmark text.
- Fixed: PowerShell cloud-assessment imports now retain explicit missing, malformed, unsupported, empty, and unrecognized-source diagnostics in reports and structured exports instead of silently dropping them.
- Fixed: PowerShell `-TrendDays` now validates its range and filters dashboard trend points while retaining the latest scan and full source history.
- Fixed: Fleet timeout cleanup now runs as a bounded remoting job with a short grace period, removes duplicate cleanup calls, and records cleanup failure separately from the host audit result.
- Fixed: PowerShell Graph requests now extract status and Retry-After values from thrown live errors and apply bounded retries to throttling and transient HTTP failures.
- Added: C# and PowerShell export batches now emit a deterministic data-handling manifest describing privacy mode, identity strategy, field classifications, source-path policy, artifact names, and secret exclusions.
- Changed: C# waiver files now use a versioned disposition lifecycle with proposed/approved/rejected/revoked/expired states, immutable event history, recertification scope, v1 migration, privacy-safe export, and OSCAL POA&M history fields.

### Performance
- Fixed: PowerShell dashboard imports now enforce configurable file-count, per-file-byte, and total-byte budgets and show bounded skip diagnostics in the dashboard.

### Testing
- Added mixed-fleet and export-contract fixtures covering empty, partial, duplicate, stale, privacy-redacted, malformed, unavailable, exception, and remediation-aging dashboard inputs.
- Added a repository version-surface test that keeps optional `CLAUDE.md` guidance aligned with the authoritative C# project and PowerShell product versions.
- Made the Pester quality suite ASCII-safe so all 83 tests parse and pass under both Windows PowerShell 5.1 and PowerShell 7.
- Added: Export contract tests now enforce the schema validation keywords used by committed contracts, including dynamic maps, references, composition, and negative fixtures.

## [v5.3.3 / v4.11.4] - 2026-08-09

### Maintenance
- Synchronized release metadata after draining the actionable roadmap. Enterprise AD, Intune, and PSRemoting validation remains documented in the blocked queue because it requires external targets or credentials.

### Accessibility
- Fixed: Check and category list items now announce meaningful security content instead of view-model class names, and live readiness, progress, export, filtered-count, grade, and persistence regions expose their changing values.
- Changed: Scrollbar thumbs and keyboard focus boundaries now meet component-contrast targets, with larger scrollbar and privacy-toggle hit areas plus automated WPF token-contrast coverage.
- Added: Invalid remediation dates now expose a persistent, assertive inline validation message in addition to visual error styling.

### UX
- Fixed: Category progress treats not-applicable checks as completed and never labels a partially completed category as clear.

### Maintenance
- Finalized the actionable roadmap. Live enterprise validation for AD, Intune, and PSRemoting remains documented in the blocked queue because it requires external targets or credentials.

## [v5.3.1 / v4.11.2] - 2026-07-09

### UX
- Added: The C# workstation now exposes live assessment persistence status, distinguishing unsaved edits, active scans, report exports, and a clean in-memory state in the footer.
- Changed: Save state and Load state now provide actionable disabled help and pause while scans or report exports are mutating assessment data.

### Reliability
- Fixed: Check-result, evidence, findings, remediation, profile, and theme changes now mark assessment state as unsaved; successful saves and state loads clear the indicator deterministically.

## [v5.3.0 / v4.11.2] - 2026-07-09

### UX
- Changed: Re-imagined the C# GUI as a premium 1440x900 security posture workstation with a calmer command deck, stronger posture hierarchy, clearer control boundaries, and a resizable checks-and-inspector workbench.
- Changed: The selected-check inspector now exposes assessment status and findings immediately, keeps the full evidence/remediation workflow accessible through one continuous scroll surface, and labels report export accurately.
- Fixed: Unscanned ransomware and domain-maturity summaries now remain neutral instead of showing false `F 0/100` results, while degraded pre-flight readiness uses warning semantics instead of success green.
- Changed: The activity console now follows new entries, scan selection no longer disrupts an analyst's current inspector work, and save/load actions use explicit state-oriented labels.

### Accessibility
- Added: Interactive controls now use a higher-contrast boundary token, buttons include pressed and intentional disabled states, and check rows expose a full keyboard-focus outline.
- Fixed: The unavailable Cloud profile is no longer offered by the C# GUI, and scan controls stay disabled with explanatory help until environment detection and pre-flight checks complete.

### Reliability
- Fixed: Unexpected check-runner failures now leave the workspace in a recoverable error state, preserve completed evidence, write a crash log, and do not generate a misleading completion report.
- Fixed: Automated GUI screenshots now wait for initialization readiness and warm the WPF render surface before capture, preventing partially painted acceptance images.

## [v5.2.9 / v4.11.2] - 2026-07-09

### Reliability
- Fixed: C# GUI scans now generate and open the HTML report automatically after successful completion, with crash-log-backed status feedback if report writing or shell launch fails.
- Fixed: C# CF02 egress checks now await and cancel TCP connect attempts instead of abandoning timed-out socket tasks that can surface as unobserved exceptions after a scan.

## [v5.2.8 / v4.11.2] - 2026-07-09

### Security
- Fixed: C# HTML report links now use attribute-safe encoding, only render HTTP(S) external links, and avoid unsafe `mailto:` links from malformed branding email values.
- Fixed: PowerShell branding configs now reject malformed `contact_email` values before rendering report `mailto:` links.
- Fixed: C# branding and Intune STIG import files now enforce explicit size limits before reading content into memory.

### Reliability
- Fixed: C# CF01 SYSVOL GPP password scanning now honors cancellation, skips oversized preference XML files, and records traversal/read limits instead of reading every matched file unbounded.
- Fixed: C# saved audit-state loading now restores the saved scan profile, parses remediation due dates with invariant `yyyy-MM-dd`, and clears invalid due dates instead of preserving stale UI values.
- Fixed: C# firewall netsh fallback checks now use the shared timeout-aware command runner instead of raw process reads that could block before timeout handling.
- Fixed: C# automated error, not-implemented, and timeout evidence timestamps now use invariant UTC formatting across host cultures.

### UX
- Changed: C# GUI scan controls now expose disabled-state help text, lock profile changes during active scans, and show a visible `yyyy-MM-dd` due-date hint for remediation tracking.

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

## Roadmap archive — 2026-08-10 — ROADMAP.md

<details>
<summary>Original roadmap snapshot</summary>

````markdown
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

---

### P2 — High

**Checks (fail-open / masking)**

**Export / scoring**

**App / silent mode**

**Legacy PS1 branding / fleet security**

**GUI theme / a11y / layout**

---

### P3 — Medium / Low

**App / services**

**Data / scoring / models**

**Legacy PS1**

**GUI microcopy / a11y (P3)**

## Research-Driven Additions

### P0

### P1

### P2

## Research-Driven Additions

### P1

### P2

- [ ] P2 — Add integrity and licensing provenance to imported benchmark/content packs
  Why: The current benchmark manifest validates source identity, version, URL, review date, staleness, supported OS/builds, and covered checks, but it cannot prove which content bytes were assessed or whether redistribution is permitted. NIST SP 800-70 Rev. 5 treats machine-readable checklists as executable verification artifacts; Scapolite research emphasizes versioned authoring/generated artifacts/tests; HardeningKitty demonstrates the value of signed/stable content.
  Evidence: `src/NetworkSecurityAuditor/Data/BenchmarkMetadata.cs:7-160,190-240`, `src/NetworkSecurityAuditor/Data/BenchmarkMetadata.json`, and PowerShell import initialization at `NetworkSecurityAudit.ps1:13692-13795`; sources: https://csrc.nist.gov/pubs/sp/800/70/r5/final, https://arxiv.org/abs/2209.08824, and https://github.com/scipag/HardeningKitty.
  Touches: `BenchmarkMetadata` model/manifest, PowerShell benchmark importer, imported STIG/CKL/JSON/CSV result metadata, export schemas, release/content tests, and documentation for embedded versus user-supplied content.
  Acceptance: Each content source records format, source/version/review date, supported targets, license/redistribution status, SHA-256 digest, and verification status. User-supplied imports compute and export the digest; a supplied manifest mismatch is rejected or clearly degraded; stale/unverified/unlicensed content never appears equivalent to the built-in verified catalog. Tamper, stale, unsupported-OS, and license-policy fixtures are covered without bundling copyrighted benchmark text.
  Complexity: M

- [ ] P2 — Add per-target single-flight locking and stale-run recovery for unattended scans
  Why: The current C# headless path and PowerShell history path can be invoked repeatedly by Task Scheduler/RMM without a shared run identity or cross-process lock, so overlapping runs can contend for the same output/history files and produce misleading baselines. Prowler’s current release notes emphasize queueing/duplicate-scan control, while Guerrilla deliberately keeps cadence external and compares only completed runs.
  Evidence: C# orchestration at `src/NetworkSecurityAuditor/App.xaml.cs:315-589` and PowerShell history at `NetworkSecurityAudit.ps1:10991-11092,14317-14349`; no run-lock/owner manifest is present in those entry paths. Sources: https://github.com/prowler-cloud/prowler/releases and https://guerrilla.army/.
  Touches: C# headless runner/output resolution, PowerShell silent/fleet/history entry points, history schemas, exit-code definitions, and concurrent-process tests.
  Acceptance: A lock keyed by normalized client/target/output/history identity records tool version, PID, start time, and run ID. A second invocation receives a documented `AlreadyRunning`/queued result without writing partial artifacts; stale locks are recoverable only after bounded process/age validation; locks are per target so unrelated fleet hosts still run in parallel. A canceled, crashed, and completed run is tested, and only a completed contract result can become a history baseline.
  Complexity: M

- [ ] P2 — Add denominator-safe MSP executive KPIs to dashboard and history outputs
  Why: The C# dashboard currently exposes client count, average score, critical count, stale count, latest row, and a score sparkline, while the existing history roadmap covers score deltas and critical changes. Operators still lack a trustworthy view of scan coverage, invalid/skipped/not-permitted hosts, exception debt, remediation aging, and freshness denominators; commercial SCA dashboards and MSP community signals repeatedly prioritize those operational metrics.
  Evidence: `src/NetworkSecurityAuditor/Export/DashboardGenerator.cs:15-43,171-283,388-409` and PowerShell dashboard/history paths `NetworkSecurityAudit.ps1:933-1135,10991-11092`; sources: https://www.qualys.com/apps/security-configuration-assessment, https://www.pingcastle.com/services/enterprise/, and https://www.reddit.com/r/msp/comments/xg9hd1.
  Touches: C# `DashboardGenerator`, `ComplianceSummaryExporter`, history/delta models, PowerShell `Export-MultiClientDashboard`/history summary, privacy manifest, dashboard JSON/CSV schemas, and golden fixtures.
  Acceptance: Dashboard JSON/CSV/HTML report `assets_discovered`, `assets_valid`, `assets_scanned`, `assets_skipped`, `assets_failed`, `freshness`, `open/new/resolved criticals`, `oldest high/critical age`, `active/expired exception counts`, and remediation-aging buckets with explicit denominators. Malformed, skipped, and unavailable results never inflate coverage or become zero-risk rows; average/median scores state their population; fixtures cover empty, partial, duplicate, stale, privacy, and mixed-success fleet inputs.
  Complexity: M

- [ ] P2 — Ship an independently executable release-bundle verifier
  Why: The local release script already creates a ZIP, CycloneDX SBOM, checksum manifest, and release manifest, but verification is currently manual and the optional Authenticode state is not the same as an external provenance attestation. Prowler publishes SBOM/provenance attestations and verifies downloaded tool checksums; CISA supply-chain guidance treats consumer verification as a release requirement.
  Evidence: `tools/Publish-CSharpRelease.ps1:421-517`, `tests/NetworkSecurityAuditor.Tests/ReleaseToolingTests.cs:1-100`, and `README.md:113-121,504-520`; sources: https://github.com/prowler-cloud/prowler/releases, https://github.com/CycloneDX/sbom-utility, and https://www.cisa.gov/topics/cyber-threats-and-advisories/sbom/sbomresourceslibrary.
  Touches: `tools/Publish-CSharpRelease.ps1`, a new non-markdown `tools/Verify-CSharpRelease.ps1`, release-tool tests, `README.md`, and the release manifest/checksum contract.
  Acceptance: The verifier exits nonzero for missing/tampered ZIP, SBOM, manifest, or checksum entries; validates every manifest hash against bytes; validates the SBOM against its declared CycloneDX schema/version; checks ZIP entry/entrypoint/runtime metadata; reports Authenticode status and supports `-RequireSignature` without claiming a signature when signing was skipped. README commands work against a locally produced bundle, and a tamper fixture fails before installation.
  Complexity: M

- [ ] P2 — Establish a repeatable local dependency freshness and vulnerability gate
  Why: The repository’s 2026-08-10 package audit found no vulnerable packages but did find available patch updates for the direct `System.*` references and the test SDK. The release script runs tests and emits an SBOM, but no checked-in gate defines how vulnerability findings, patch drift, and accepted exceptions affect a local release.
  Evidence: `src/NetworkSecurityAuditor/NetworkSecurityAuditor.csproj:26-29`, `tests/NetworkSecurityAuditor.Tests/NetworkSecurityAuditor.Tests.csproj:12-15`, `tools/Publish-CSharpRelease.ps1:406-419,463-498`, and the 2026-08-10 `dotnet list ... package --vulnerable/--outdated --include-transitive` results; package source: https://www.nuget.org/packages/Microsoft.NET.Test.Sdk and lifecycle source: https://dotnet.microsoft.com/en-us/platform/support/policy.
  Touches: a new non-markdown `tools/Test-DependencyHealth.ps1`, release-tool invocation, package-version exception/allowlist format, README release instructions, and release-tool tests.
  Acceptance: The gate reports direct/transitive versions, vulnerable advisories, and patch drift in stable machine-readable output; any vulnerable package fails the release, outdated packages are warning-only locally but fail `-Release` unless a dated, named exception exists, and `--no-restore`/offline behavior is explicit. A fixture or mocked command output proves vulnerability failure, approved exception, and clean-state pass without adding CI or silently changing package versions.
  Complexity: S

- [ ] P2 — Support Windows High Contrast without changing the dark premium default
  Why: The C# application exposes only `Catppuccin Mocha` in `MainViewModel.AvailableThemes` and hard-codes its dark resource palette. The existing roadmap covers PowerShell’s seven-theme contrast audit and general WPF focus/UI smoke work, but it does not cover the Windows system High Contrast contract. Microsoft’s guidance requires apps to respect system contrast resources and preserve visible state/focus.
  Evidence: `src/NetworkSecurityAuditor/ViewModels/MainViewModel.cs:122,169,271-275`, `src/NetworkSecurityAuditor/Theme/Themes.xaml:4-40`, and the WPF control templates below that resource dictionary; source: https://learn.microsoft.com/en-us/windows/apps/design/accessibility/high-contrast-themes.
  Touches: `src/NetworkSecurityAuditor/Theme/Themes.xaml`, `App.xaml`, `MainViewModel`, custom button/combo/checkbox/scroll templates, status/severity templates, and headless resource/accessibility tests.
  Acceptance: When Windows High Contrast is enabled, the application switches to system foreground/background/control/focus resources (or a documented equivalent override), every interactive control retains visible keyboard focus/disabled/selected/error states, and status is conveyed by text/icon plus color. The default Catppuccin Mocha appearance and saved-theme compatibility remain unchanged; tests exercise high-contrast resource loading and all custom templates.
  Complexity: M

### P3

- [ ] P3 — Extract user-facing microcopy into a localization-neutral resource boundary
  Why: English UI/report strings are embedded throughout the 14k-line PowerShell artifact and in C# XAML/export string builders, making terminology, date/number formatting, and future translation drift difficult to control. HardeningKitty documents English-system limitations, while the project supports multilingual Windows deployments through PowerShell 5.1 and should not let localized display text alter machine contracts.
  Evidence: user-facing string generation in `NetworkSecurityAudit.ps1:7600-9305,11374-12780`, C# XAML under `src/NetworkSecurityAuditor/*.xaml`, and `src/NetworkSecurityAuditor/Export/DashboardGenerator.cs:171-283`; comparator evidence: https://github.com/scipag/HardeningKitty.
  Touches: PowerShell string/catalog sections, C# resource dictionaries or `.resx` resources, HTML/PDF/export templates, stable schema labels/IDs, and invariant-culture tests.
  Acceptance: All user-visible labels, statuses, buttons, empty/error messages, and report headings resolve through a named English resource catalog; check IDs, status enum values, JSON keys, ISO timestamps, and CSV headers remain invariant. A test switches the resource provider and proves output formatting does not change machine fields; no translation beyond the English baseline is required for this item.
  Complexity: L
````

</details>
