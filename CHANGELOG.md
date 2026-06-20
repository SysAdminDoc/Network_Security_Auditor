# Changelog

All notable changes to Network_Security_Auditor will be documented in this file.

## [v5.2.0] - 2026-06-19

- Fixed: OSCAL observation-finding UUID cross-reference. Findings now correctly reference their parent observation UUIDs instead of string IDs that never matched.
- Fixed: CSV formula injection quoting. Values with formula prefixes (`=`, `+`, `-`, `@`) are now unconditionally quoted to prevent malformed rows when the value also contains commas.
- Fixed: Privacy redaction no longer mutates ViewModel state. Exports with privacy mode operate on copies, preserving original data for subsequent non-private exports.
- Changed: Version strings centralized via `VersionInfo.cs`. All exports, silent mode banner, window title, and audit state now read version from assembly metadata instead of hardcoded literals.
- Changed: Silent mode exit codes now use `ExitCode` enum instead of raw int literals for clarity and maintainability.
- Added: SARIF `security-severity` property (0.1-10.0) on all rules for GitHub Code Scanning severity display (Critical=9.5, High=8.0, Medium=5.5, Low=3.0).
- Added: Intune compliance JSON export. GUI button and `--export-intune` CLI flag produce `SecurityAuditGrade`, `SecurityAuditScore`, compliance flags, and critical failures in Intune-compatible JSON.
- Added: `--export-compliance-summary` CLI flag for silent mode. Produces the compact RMM dashboard payload alongside other exports. `--export-all` now includes both Intune and compliance summary.
- Added: PDF export via Edge/Chrome headless rendering. GUI button and `--export-pdf` CLI flag with 30-second timeout and diagnostic fallback message.
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
