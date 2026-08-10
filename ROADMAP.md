# Project Roadmap

Actionable work only. Historical and completed roadmap material is archived in CHANGELOG.md; blocked work is kept in Roadmap_Blocked.md.

## Actionable Items

- [ ] Run a guided GUI audit on a Windows endpoint or domain-joined admin workstation.

- [ ] Run silent scans through RMM or scheduled tasks with predictable outputs and exit codes.

- [ ] Produce executive, management, and technical reports from one scan.

- [ ] Capture evidence, findings, notes, remediation owner, due date, and remediation status.

- [ ] Map findings to compliance frameworks and MITRE ATT&CK techniques.

- [ ] Track ransomware readiness and domain maturity separately from general score.

- [ ] Export findings into JSON, JSONL, CSV, SARIF, PDF, Intune, and RMM fields.

- [ ] Compare saved audits to show posture change over time.

### Export Surface Map

- [ ] Every export includes `schema_version`, `tool_version`, `timestamp`, `client`, `auditor`, `target`, and environment metadata unless the format standard forbids it.

- [ ] Every compliance framework in `$script:FrameworkMeta` appears consistently in HTML, JSON, JSONL, CSV, summary JSON, and compliance strings.

- [ ] JSON schemas are committed for structured findings, summary, Intune, JSONL events, and any future dashboard aggregate format.

- [ ] Snapshot fixtures validate JSON, JSONL, CSV headers, SARIF shape, Intune shape, and HTML framework sections.

- [ ] PDF export has automated path tests for local paths, spaces, and UNC paths.

---

### Write Surface Inventory

- [ ] `ReadOnly` currently filters scan IDs by risk tier, but it does not mean "no writes". Silent mode still writes files and registry/RMM fields, and GUI setup can modify system configuration.

- [ ] The same script contains read-only assessment, setup/configuration, RMM publishing, and report generation, but there is no central policy object that records whether each write is allowed, skipped, attempted, succeeded, or failed.

- [ ] Provider-specific RMM writes are best-effort and continue on failure, which is operationally useful, but the final summary does not include a structured write outcome table.

- [ ] Compliance string ordering is based on hashtable key enumeration. For RMM fields and dashboards, stable framework ordering would reduce noisy diffs.

- [ ] Default-checked setup actions improve onboarding but should show exact changes before execution, especially PSGallery trust, package provider install, firewall rule enables, Remote Registry start, and audit policy changes.

- [ ] RMM field schemas are documented for NinjaRMM, Datto, ConnectWise Automate, Syncro, HaloPSA, and generic registry output.

- [ ] Datto custom-field slots are configurable instead of hard-coded to `Custom1` through `Custom5`.

- [ ] Exit codes are covered by tests for grade, ransomware score, fail count, and framework threshold combinations.

- [ ] Internet access is centrally gated and offline/cache-only mode produces explicit skipped reasons.

---

- [ ] Microsoft UI Automation accessibility best practices: https://learn.microsoft.com/en-us/dotnet/framework/ui-automation/accessibility-best-practices

- [ ] Microsoft WPF UI Automation custom control guidance: https://learn.microsoft.com/en-us/dotnet/desktop/wpf/controls/ui-automation-of-a-wpf-custom-control

- [ ] W3C WCAG 2.2: https://www.w3.org/TR/WCAG22/

- [ ] Microsoft Fluent 2 accessibility guidance: https://fluent2.microsoft.design/accessibility

- [ ] Microsoft Fluent 2 color and focus-state guidance: https://fluent2.microsoft.design/color

- [ ] Preserves dark-only themes and fast scanning workflows.

- [ ] Improves keyboard focus and screen-reader metadata.

- [ ] Reduces horizontal crowding in the scan bar and check cards.

- [ ] Clarifies host-modifying setup actions before they run.

- [ ] Makes exported reports easier to read in narrow, printed, and client-facing contexts.

- [ ] Replaces rounded pill-style decorative badges with compact square or low-radius status tags where project UI rules require it.

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

- [ ] `NetworkSecurityAudit.ps1:197` through `NetworkSecurityAudit.ps1:221` detects Azure AD/Entra join and Intune enrollment locally with `dsregcmd /status` and `HKLM:\SOFTWARE\Microsoft\Enrollments`.

- [ ] `NetworkSecurityAudit.ps1:2365` through `NetworkSecurityAudit.ps1:2412` implements `IA03` as local MFA/remote-access signals: RDP NLA, installed AzureAD/Microsoft.Graph modules, ADFS service, MFA/SSO agent software, smart card policy, and Windows Hello for Business indicators.

- [ ] `NetworkSecurityAudit.ps1:2457` through `NetworkSecurityAudit.ps1:2488` implements `IA09` as local RDP/VPN posture: RDP enabled/NLA/port, VPN adapters, built-in VPN connections, split tunneling, and VPN software.

- [ ] `NetworkSecurityAudit.ps1:3850` and `NetworkSecurityAudit.ps1:3856` map `IA03` and `IA09` to MFA/Conditional Access-relevant controls even though the current evidence is local and heuristic.

- [ ] `rg` found no current `Connect-MgGraph`, `Invoke-MgGraphRequest`, `graph.microsoft`, Secure Score, Conditional Access, risky user, sign-in, Intune compliance policy, or alert API implementation in the script.

Official Microsoft references used:

- [ ] Microsoft Graph auth concepts: https://learn.microsoft.com/en-us/graph/auth/auth-concepts

- [ ] Microsoft Graph permissions overview: https://learn.microsoft.com/en-us/graph/permissions-overview

- [ ] Microsoft Graph throttling guidance: https://learn.microsoft.com/en-us/graph/throttling

- [ ] Secure Score list API: https://learn.microsoft.com/en-us/graph/api/security-list-securescores?view=graph-rest-1.0

- [ ] Conditional Access policies list API: https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0

- [ ] Conditional Access What If/evaluate API: https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-evaluate?view=graph-rest-1.0

- [ ] Authentication methods user registration details API: https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0

- [ ] Sign-ins API: https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0

- [ ] User list and `signInActivity` API notes: https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0

- [ ] Risky users API: https://learn.microsoft.com/en-us/graph/api/riskyuser-list?view=graph-rest-1.0

- [ ] Application list API: https://learn.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0

- [ ] Service principal list API: https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list?view=graph-rest-1.0

- [ ] OAuth2 permission grant resource: https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant?view=graph-rest-1.0

- [ ] Intune device compliance policies list API: https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-devicecompliancepolicy-list?view=graph-rest-1.0

- [ ] Intune managed devices list API: https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list?view=graph-rest-1.0

- [ ] Security alerts v2 list API: https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0

- [ ] Directory audits list API: https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0

- [ ] Devices list API: https://learn.microsoft.com/en-us/graph/api/device-list?view=graph-rest-1.0

- [ ] `CheckId`, `DisplayName`, `Endpoint`, `ApiVersion`, `HttpMethod`, `DefaultProfile`, `Category`, `FrameworkMap`, and `EvidenceMode`.

- [ ] Delegated scopes, application scopes, required Entra role hints, license prerequisites, national-cloud availability, beta/v1 status, paging style, and cache TTL.

- [ ] Supported result statuses: `Pass`, `Fail`, `Partial`, `Skipped`, `NotLicensed`, `NotPermitted`, `NotConfigured`, and `Error`.

- [ ] Data classification for every field: safe-to-report, tenant-sensitive, user-sensitive, secret, or redact.

The first UX should expose permission bundles instead of a raw scope wall:

- [ ] **Cloud Discovery:** tenant metadata, device join context, lightweight user/app inventory where permitted.

- [ ] **Identity Core:** Conditional Access policies, MFA registration, sign-ins, users/guests, risky users.

- [ ] **Security Core:** Secure Score, alerts, directory audit events.

- [ ] **Intune:** compliance policies and managed device compliance state.

- [ ] **Full Cloud:** all cloud checks with the widest consent prompt.

- [ ] `Connect-CloudAuditGraph` or equivalent preflight that can use delegated interactive/device-code auth first and app-only later.

- [ ] `Invoke-GraphAuditRequest` wrapper around `Invoke-MgGraphRequest` or direct REST, with `@odata.nextLink` paging, `$select`, `$filter`, `$top`, consistency headers, beta/v1 selection, and structured error classification.

- [ ] Throttling handling that honors `Retry-After` on HTTP 429 and falls back to exponential backoff when no header is returned, per Microsoft throttling guidance.

- [ ] Stable evidence envelopes for each call: `endpoint`, `api_version`, `request_window`, `source_timestamp`, `permission_scope`, `auth_mode`, `tenant`, `paging_summary`, `throttle_count`, and `redaction_summary`.

- [ ] Unit fixtures for Graph responses so cloud check logic can be tested offline without a tenant.

### Report and Export Shape

Report sections to add:

- Cloud Permission Preflight: requested scopes, granted scopes where available, role/licensing prerequisites, skipped checks, and privacy mode.
- Identity Cloud Summary: Secure Score, CA coverage, MFA registration, legacy auth, risky users, stale guests/users.
- Cloud Findings: normal check cards for `CL` IDs with the same remediation, owner, due-date, evidence, framework, and MITRE fields as local checks.
- Cloud Evidence Appendix: endpoint/source timestamps, redaction notes, API version, and status taxonomy.
- MSP-Friendly Exception Summary: not licensed, not permitted, not configured, skipped, and errors grouped separately from true failures.

- [ ] `NetworkSecurityAudit.ps1:7216` through `NetworkSecurityAudit.ps1:7247` restores saved state but does not validate schema version, tool version, check catalog version, removed/renamed checks, or unknown future fields.

- [ ] `NetworkSecurityAudit.ps1:8239` through `NetworkSecurityAudit.ps1:8310` exports one JSONL event per finding, which is close to a history event stream, but it is still a single-run export and has no `run_summary`, `delta_state`, `first_seen`, `last_seen`, `exposure_days`, or `previous_status`.

- [ ] `NetworkSecurityAudit.ps1:8664` through `NetworkSecurityAudit.ps1:8978` always produces silent-mode artifacts and RMM fields, but those fields expose only current grade/score/compliance/fail counts and output paths. They do not expose new criticals, resolved criticals, score delta, worst exposure age, baseline age, or history path.

- [ ] Microsoft Graph Secure Score API: https://learn.microsoft.com/en-us/graph/api/security-list-securescores?view=graph-rest-1.0

- [ ] CIS-CAT Pro Dashboard focuses on recent/current configuration posture rather than indefinite raw retention, recommends less than two years of dashboard history, supports exceptions/rescoring, and can alert when imported scores deviate beyond a threshold. Network Security Auditor should default to a practical retention window, expose exceptions separately from remediation, and make score-deviation alerts configurable.

- [ ] Microsoft Graph delta query uses opaque `@odata.nextLink` and `@odata.deltaLink` state tokens. Future cloud history should store token references in private state, not reports, and should handle deleted resources, eventual consistency, and "sync from now" initialization.

- [ ] Microsoft Secure Score supports retrieving score collections with `$top`, `$skip`, and `$filter`. This can seed M365 score trend cards without inventing a separate scoring history for `CL01`.

- [ ] OSCAL assessment results explicitly support assessment reports and continuous monitoring with observations, risks, findings, reviewed controls, assessment subjects, evidence, and expiration concepts. The internal history schema should align with those concepts before adding an OSCAL export.

- [ ] SARIF baseline concepts show why every compared result needs a comprehensive baseline state, not just changed findings. NSA delta exports should classify every current and baseline finding as new, unchanged, updated, or absent/resolved before deriving human-friendly labels.

- [ ] `Resolved` records `resolved_at` and should preserve the final exposure window for reporting.

- [ ] `SecurityAuditScoreDelta`

- [ ] `SecurityAuditGradePrevious`

- [ ] `SecurityAuditNewCritical`

- [ ] `SecurityAuditResolvedCritical`

- [ ] `SecurityAuditWorstExposureDays`

- [ ] `SecurityAuditBaselineAgeDays`

- [ ] `SecurityAuditHistoryPath`

- [ ] `SecurityAuditDeltaPath`

- [ ] `SecurityAuditHistoryHealth`

- [ ] Add `Convert-AuditStateToSnapshot` that normalizes GUI and silent-mode state into one snapshot object.

- [ ] Add `Get-AuditCatalogHash` and `Get-AuditPolicyHash` so history can detect check catalog/framework/threshold drift.

- [ ] Add `Get-FindingFingerprint` and text normalization for evidence/findings hashes.

- [ ] Add `Compare-AuditSnapshot` that returns a structured delta object for every current and baseline finding.

- [ ] Add `Append-AuditHistory` that writes `run_summary`, `finding_delta`, and `history_health` JSONL records with file locking/retry.

- [ ] Add `Export-DeltaJSON` and `Export-DeltaHTML` for GUI, silent mode, and dashboard ingestion.

- [ ] Refactor the GUI `Diff` button to use the same comparison engine and offer export instead of message-box-only output.

- [ ] Add silent-mode CLI flags: `-HistoryPath`, `-BaselinePath`, `-NoHistory`, `-TrendDays`, `-AlertPreview`, and later `-WebhookUrl`.

- [ ] Add migration support for current GUI save files whose `Items` object lacks history metadata.

- [ ] Add tests with two fixed snapshots to prove new/resolved/worsened/improved/unchanged/unavailable/exposure behavior.

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

- [ ] Preserve the dense tool feel, but separate "run scan", "review findings", "export/share", and "settings/integrations" as first-class zones.

- [ ] Replace misleading local screenshots with current app screenshots for GUI, HTML report, executive summary, and silent-mode output.

- [ ] GUI full audit:
   - Select client/auditor/date, target, scan profile, framework.
   - Run pre-flight.
   - Run profile.
   - Review failures, evidence, and remediation fields.
   - Export tiered report and structured data.

- [ ] RMM silent audit:
   - Run with `-Silent`.
   - Detect environment.
   - Execute profile with timeout.
   - Write files, RMM fields, registry cache, and exit code.

- [ ] Future recurring assessment:
   - Load prior baseline.
   - Run changed checks or full scan.
   - Compute deltas and exposure window.
   - Alert on score regressions or critical new failures.

- [ ] Internet errors for KEV lookup with cache status.

- [ ] Export failures with path, disk space, file lock, and browser availability for PDF.

- [ ] Progress should show current check, skipped count, timeout count, and estimated remaining checks.

- [ ] Add skeleton/loading states in WPF where long scans or report generation happen.

- [ ] Add "copy evidence" and "copy remediation" actions in report and GUI.

- [ ] Tab order across client/auditor/date/scan controls/check fields.

- [ ] Screen reader names for scan buttons, status combos, report controls, and category tabs.

- [ ] Contrast validation across all 7 dark themes.

- [ ] Focus indicators that are visible and not only color-dependent.

- [ ] Reduced-motion/no-animation compatibility where flash/highlight timers are used.

- [ ] Text wrapping for long check titles and hints.

---

- [ ] Secure Score ingestion and delta.

- [ ] Conditional Access coverage and risky exclusions.

- [ ] MFA registration and authentication methods.

- [ ] Legacy authentication/app password risk.

- [ ] Guest user lifecycle and stale guests.

- [ ] Privileged role assignment and PIM posture.

- [ ] App consent and overprivileged enterprise apps.

- [ ] Intune compliance policy coverage.

- [ ] Defender for Endpoint/Identity alert summary.

**User Stories:**

- [ ] As an MSP, I want one report that covers AD and M365 identity posture.

- [ ] As a sysadmin, I want Conditional Access gaps explained in plain language.

- [ ] As an auditor, I want Graph permission requirements documented before authentication.

**Technical Requirements:**

- [ ] Microsoft Graph module or direct REST path. Prefer a narrow `Microsoft.Graph.Authentication` / `Invoke-MgGraphRequest` integration first so the one-file distribution does not require many Graph submodules.

- [ ] `CloudPermissionManifest` for every cloud check with endpoint, API version, HTTP method, delegated/application scopes, Entra role hints, license prerequisites, national cloud support, beta/v1 flag, paging behavior, cache TTL, and privacy classification.

- [ ] Permission preflight with least-privileged permission display and profile bundles: Cloud Discovery, Identity Core, Security Core, Intune, and Full Cloud.

- [ ] Token handling that never stores access tokens, refresh tokens, device codes, client secrets, certificates, or raw auth headers in reports, state files, RMM fields, or logs.

- [ ] Cloud check IDs `CL01` through `CL12`, with framework/MITRE mapping and explicit separation from local `IA03`/`IA09` evidence.

- [ ] `Invoke-GraphAuditRequest` wrapper with `@odata.nextLink` paging, bounded `$filter` queries, `$select`, consistency headers, beta/v1 routing, `Retry-After` handling, exponential backoff fallback, and structured error classification.

- [ ] Cloud result status taxonomy: `Pass`, `Fail`, `Partial`, `Skipped`, `NotLicensed`, `NotPermitted`, `NotConfigured`, and `Error`.

- [ ] Graceful skip when tenant auth is not configured, permissions are denied, tenant licensing is absent, or an API/provider has no data.

- [ ] A CSV with host/client/site/tags can run a selected profile across multiple hosts.

- [ ] Each host produces an individual JSON and optional HTML report.

- [ ] Aggregate CSV/JSON summarizes host status, score, critical count, and skipped checks.

- [ ] Failed/offline hosts do not stop the whole batch.

- [ ] Read-only and risk-tier behavior applies per host.

**Dependencies:**
Reliable pre-flight, target identity, and runspace lifecycle.

**Risks:**
Remote execution environments differ widely. Must capture connection failures as first-class results, not generic scan failure.

- [ ] Disable LLMNR.

- [ ] Disable SMBv1.

- [ ] Require SMB signing where appropriate.

- [ ] Enforce LAPS/Windows LAPS detection-to-guidance first, then remediation where safe.

- [ ] Increase event log sizes.

- [ ] Enable PowerShell script block logging.

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

- [ ] Logo.

- [ ] Primary/accent colors.

- [ ] Prepared by / MSP contact.

- [ ] Executive summary tone selection.

- [ ] PowerPoint export.

- [ ] PDF/HTML cover page.

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

- [ ] Use a compact, readable type scale: 20-22 title, 14-16 section headers, 12-13 body, 10-11 metadata.

- [ ] Keep monospace only for console/log/evidence.

- [ ] Do not scale font size with viewport width.

- [ ] Adopt a consistent 4/8/12/16 spacing system.

- [ ] Use stable heights for scan bar, footer, score widgets, and per-check header rows.

- [ ] Keep cards at 8px radius or below; avoid nested cards.

- [ ] Preserve dark-only themes.

- [ ] Keep severity colors consistent across GUI and HTML.

- [ ] Validate contrast for every theme.

- [ ] Avoid one-note theme dominance in future report templates.

- [ ] Scan profile selector.

- [ ] Framework selector.

- [ ] Check status selector.

- [ ] Evidence/findings/notes fields.

- [ ] Remediation owner/due/status.

- [ ] Filter segmented controls.

- [ ] Report export menu instead of many adjacent export buttons.

- [ ] Icon+tooltip for Save, Load, Diff, Export, Reset, Refresh, Copy, Open report.

- [ ] Inline validation for output path, target, permissions, and Graph tenant configuration.

- [ ] Clear disabled states for unavailable checks.

- [ ] Required/optional markers for report metadata.

- [ ] Sticky headers in HTML reports.

- [ ] Sort/filter by severity, status, framework, category, owner, due date.

- [ ] Compact row density with expandable evidence.

- [ ] Use modals for scan manifest, Graph permissions, remediation preview, and export settings.

- [ ] Always show cancel/confirm and a summary of consequences for actions that write.

- [ ] Category tabs remain valid.

- [ ] Add search and saved filters.

- [ ] Add report table of contents and deep links.

- [ ] Use minimal scan progress and flash feedback.

- [ ] Avoid motion that interferes with repeated operational use.

- [ ] Respect reduced-motion settings if accessible through WPF/environment.

- [ ] Per-check "Queued", "Running", "Timed out", "Skipped", "Complete".

- [ ] Export progress for HTML/PDF/PowerPoint.

- [ ] Graph auth/loading state when cloud pack is added.

- [ ] No scan run.

- [ ] No failed findings.

- [ ] No baseline.

- [ ] No cloud auth.

- [ ] No RMM detected.

- [ ] No internet/cache for KEV.

- [ ] Visible focus states.

- [ ] Screen reader names.

- [ ] Tab-order review.

- [ ] Color-independent severity labels.

- [ ] Long text wrapping.

---

- [ ] Make releases safe and consistent.

- [ ] Establish automated validation.

- [ ] Fix visible trust/polish issues.

**Features**

- [ ] NSA-001 automated quality gate.

- [ ] NSA-002 version/branding authority.

- [ ] NSA-003 safety manifest and write controls.

- [ ] NSA-013 screenshot/docs release pipeline.

**Dependencies**

- [ ] Pester/PSScriptAnalyzer availability.

- [ ] Agreement on version constant and release flow.

**Estimated Complexity**

Medium.

**Risks**

- [ ] PSScriptAnalyzer noise.

- [ ] Existing RMM users relying on implicit registry writes.

**Definition of Done**

- [ ] CI passes.

- [ ] Parser and manifest tests run locally.

- [ ] Version strings consistent.

- [ ] Changelog date valid.

- [ ] Local screenshot reflects current app.

- [ ] README includes safety/write behavior.

- [ ] Strengthen current workflows before expanding.

- [ ] Make reports and outputs more defensible.

**Features**

- [ ] NSA-005 continuous delta assessment.

- [ ] NSA-008 evidence-grade compliance output.

- [ ] NSA-012 CISA KEV enrichment.

- [ ] Structured run log and export schemas.

**Dependencies**

- [ ] Stable result schema.

- [ ] Versioning and tests from Phase 0.

**Estimated Complexity**

Medium-high.

**Risks**

- [ ] Schema migration from existing saves.

- [ ] KEV product matching false positives/negatives.

**Definition of Done**

- [ ] Historical trend and delta report works from two saved scans.

- [ ] JSON schema is documented.

- [ ] KEV cache and schema validation exist.

- [ ] Compliance evidence has separate facts/rationale/remediation.

- [ ] Improve client-facing polish and daily operator ergonomics.

**Features**

- [ ] NSA-009 white-label executive pack.

- [ ] NSA-017 GUI IA refresh.

- [ ] Better empty/error states.

- [ ] Accessibility pass.

**Dependencies**

- [ ] Report section renderer cleanup.

- [ ] Design tokens for GUI and HTML report.

**Estimated Complexity**

Medium.

**Risks**

- [ ] WPF layout regressions.

- [ ] Report branding reducing contrast.

**Definition of Done**

- [ ] Current screenshots generated.

- [ ] HTML report has a polished executive summary and technical appendix.

- [ ] GUI search/saved filters exist.

- [ ] Contrast and tab-order checks are documented.

- [ ] Match modern hybrid-identity assessment expectations.

**Features**

- [ ] NSA-004 Entra ID and M365 Graph assessment pack.

- [ ] NSA-015 AD attack path visualization.

- [ ] D3FEND mapping.

**Dependencies**

- [ ] Graph auth/permission design.

- [ ] Cloud check IDs and framework mapping.

**Estimated Complexity**

High.

**Risks**

- [ ] Graph permission/licensing complexity.

- [ ] Tenant data sensitivity.

**Definition of Done**

- [ ] Cloud profile runs and gracefully skips unavailable/licensed endpoints.

- [ ] Secure Score and Conditional Access findings are exported.

- [ ] AD/hybrid report shows prioritized identity risks.

- [ ] Support MSP scale, SIEM/GRC workflows, and policy-as-data.

**Features**

- [ ] NSA-006 remote fleet scan mode.

- [ ] NSA-010 static multi-client dashboard.

- [ ] NSA-014 SIEM content packs.

- [ ] NSA-016 policy import/export.

**Dependencies**

- [ ] Stable result/history schema.

- [ ] Report/dashboard generator.

**Estimated Complexity**

High.

**Risks**

- [ ] Remote auth and network edge cases.

- [ ] Dashboard data leakage if published externally.

**Definition of Done**

- [ ] Fleet scan handles offline hosts.

- [ ] Dashboard processes a folder of outputs.

- [ ] Splunk/Elastic/Sentinel/Wazuh field maps documented.

- [ ] Custom policy pack can validate a simple registry check.

- [ ] Expand beyond Windows SMB audits while preserving one-file value.

**Features**

- [ ] NSA-007 remediation automation expansion.

- [ ] NSA-018 Linux/Unix sidecar.

- [ ] NSA-019 SaaS backup/cloud app coverage.

- [ ] NSA-020 GRC/ticketing integrations.

**Dependencies**

- [ ] Safety model maturity.

- [ ] Integration credentials/config strategy.

**Estimated Complexity**

High.

**Risks**

- [ ] Remediation can harm environments if not tightly controlled.

- [ ] Third-party APIs vary by licensing and tenant configuration.

**Definition of Done**

- [ ] Remediation is dry-run first with rollback.

- [ ] Linux sidecar produces normalized results.

- [ ] At least one ticketing/GRC integration works with dry-run preview.

---

- [ ] **Work top-down by priority** (P0 -> P1 -> P2 -> P3). Within a priority, group by file/subsystem so related edits share a commit and a rebuild.

- [ ] **Re-verify before fixing.** This repo has been audited many times; even in this vetted list, confirm the code still reads as described (line numbers drift) and the bug is reachable before editing. If a finding is already fixed or was a false positive, delete it from this backlog and move on — do not "fix" correct code.

- [ ] **Every fix gets a regression test.** Add/extend xUnit tests in `tests/NetworkSecurityAuditor.Tests/` (match existing style). For scoring/mapping/export bugs a test is mandatory; for pure-UI/threading bugs, add one where feasible and note in the commit if not.

- [ ] **Add the three missing structural tests early** (mapping-key parity catalog<->MITRE<->D3FEND<->Framework; technique-ID format regex; `dict.Add` duplicate-ID fail-fast). They will catch regressions while you fix the mapping items.

- [ ] **Baseline discipline:** run `dotnet build NetworkSecurityAuditor.slnx -c Release` and `dotnet test` after each batch. For PS1 changes run `.\tools\Test-NetworkSecurityAudit.ps1`. Never push red.

- [ ] **Commit discipline:** conventional commits, author `SysAdminDoc <matt_parker@outlook.com>`, no AI attribution/trailers, push to `main` directly. One logical change per commit.

- [ ] **Cross-cutting note:** many C# items share one root cause — checks are synchronous (`Task.FromResult`) and run on the UI thread. Fixing the threading model (P1 group A) changes the behavior of several progress/timeout findings; do that batch first, then re-test the dependent items.

---

- [ ] P2 — Add integrity and licensing provenance to imported benchmark/content packs
  Why: The current benchmark manifest validates source identity, version, URL, review date, staleness, supported OS/builds, and covered checks, but it cannot prove which content bytes were assessed or whether redistribution is permitted. NIST SP 800-70 Rev. 5 treats machine-readable checklists as executable verification artifacts; Scapolite research emphasizes versioned authoring/generated artifacts/tests; HardeningKitty demonstrates the value of signed/stable content.
  Evidence: `src/NetworkSecurityAuditor/Data/BenchmarkMetadata.cs:7-160,190-240`, `src/NetworkSecurityAuditor/Data/BenchmarkMetadata.json`, and PowerShell import initialization at `NetworkSecurityAudit.ps1:13692-13795`; sources: https://csrc.nist.gov/pubs/sp/800/70/r5/final, https://arxiv.org/abs/2209.08824, and https://github.com/scipag/HardeningKitty.
  Touches: `BenchmarkMetadata` model/manifest, PowerShell benchmark importer, imported STIG/CKL/JSON/CSV result metadata, export schemas, release/content tests, and documentation for embedded versus user-supplied content.
  Acceptance: Each content source records format, source/version/review date, supported targets, license/redistribution status, SHA-256 digest, and verification status. User-supplied imports compute and export the digest; a supplied manifest mismatch is rejected or clearly degraded; stale/unverified/unlicensed content never appears equivalent to the built-in verified catalog. Tamper, stale, unsupported-OS, and license-policy fixtures are covered without bundling copyrighted benchmark text.
  Complexity: M

- [ ] P2 — Add per-target single-flight locking and stale-run recovery for unattended scans
  Why: The current C# headless path and PowerShell history path can be invoked repeatedly by Task Scheduler/RMM without a shared run identity or cross-process lock, so overlapping runs can contend for the same output/history files and produce misleading baselines. Prowler's current release notes emphasize queueing/duplicate-scan control, while Guerrilla deliberately keeps cadence external and compares only completed runs.
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
  Why: The repository's 2026-08-10 package audit found no vulnerable packages but did find available patch updates for the direct `System.*` references and the test SDK. The release script runs tests and emits an SBOM, but no checked-in gate defines how vulnerability findings, patch drift, and accepted exceptions affect a local release.
  Evidence: `src/NetworkSecurityAuditor/NetworkSecurityAuditor.csproj:26-29`, `tests/NetworkSecurityAuditor.Tests/NetworkSecurityAuditor.Tests.csproj:12-15`, `tools/Publish-CSharpRelease.ps1:406-419,463-498`, and the 2026-08-10 `dotnet list ... package --vulnerable/--outdated --include-transitive` results; package source: https://www.nuget.org/packages/Microsoft.NET.Test.Sdk and lifecycle source: https://dotnet.microsoft.com/en-us/platform/support/policy.
  Touches: a new non-markdown `tools/Test-DependencyHealth.ps1`, release-tool invocation, package-version exception/allowlist format, README release instructions, and release-tool tests.
  Acceptance: The gate reports direct/transitive versions, vulnerable advisories, and patch drift in stable machine-readable output; any vulnerable package fails the release, outdated packages are warning-only locally but fail `-Release` unless a dated, named exception exists, and `--no-restore`/offline behavior is explicit. A fixture or mocked command output proves vulnerability failure, approved exception, and clean-state pass without adding CI or silently changing package versions.
  Complexity: S

- [ ] P2 — Support Windows High Contrast without changing the dark premium default
  Why: The C# application exposes only `Catppuccin Mocha` in `MainViewModel.AvailableThemes` and hard-codes its dark resource palette. The existing roadmap covers PowerShell's seven-theme contrast audit and general WPF focus/UI smoke work, but it does not cover the Windows system High Contrast contract. Microsoft's guidance requires apps to respect system contrast resources and preserve visible state/focus.
  Evidence: `src/NetworkSecurityAuditor/ViewModels/MainViewModel.cs:122,169,271-275`, `src/NetworkSecurityAuditor/Theme/Themes.xaml:4-40`, and the WPF control templates below that resource dictionary; source: https://learn.microsoft.com/en-us/windows/apps/design/accessibility/high-contrast-themes.
  Touches: `src/NetworkSecurityAuditor/Theme/Themes.xaml`, `App.xaml`, `MainViewModel`, custom button/combo/checkbox/scroll templates, status/severity templates, and headless resource/accessibility tests.
  Acceptance: When Windows High Contrast is enabled, the application switches to system foreground/background/control/focus resources (or a documented equivalent override), every interactive control retains visible keyboard focus/disabled/selected/error states, and status is conveyed by text/icon plus color. The default Catppuccin Mocha appearance and saved-theme compatibility remain unchanged; tests exercise high-contrast resource loading and all custom templates.
  Complexity: M

- [ ] P3 — Extract user-facing microcopy into a localization-neutral resource boundary
  Why: English UI/report strings are embedded throughout the 14k-line PowerShell artifact and in C# XAML/export string builders, making terminology, date/number formatting, and future translation drift difficult to control. HardeningKitty documents English-system limitations, while the project supports multilingual Windows deployments through PowerShell 5.1 and should not let localized display text alter machine contracts.
  Evidence: user-facing string generation in `NetworkSecurityAudit.ps1:7600-9305,11374-12780`, C# XAML under `src/NetworkSecurityAuditor/*.xaml`, and `src/NetworkSecurityAuditor/Export/DashboardGenerator.cs:171-283`; comparator evidence: https://github.com/scipag/HardeningKitty.
  Touches: PowerShell string/catalog sections, C# resource dictionaries or `.resx` resources, HTML/PDF/export templates, stable schema labels/IDs, and invariant-culture tests.
  Acceptance: All user-visible labels, statuses, buttons, empty/error messages, and report headings resolve through a named English resource catalog; check IDs, status enum values, JSON keys, ISO timestamps, and CSV headers remain invariant. A test switches the resource provider and proves output formatting does not change machine fields; no translation beyond the English baseline is required for this item.
  Complexity: L
