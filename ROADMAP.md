# Project Roadmap

Actionable work only. Completed work lives in CHANGELOG.md and git history; blocked work lives in Roadmap_Blocked.md. Item IDs continue the NSA-### scheme (NSA-042 was the highest ID before 2026-09-29). Evidence details for the research items are in RESEARCH.md.

Working rules:
- Re-verify each item against current code before editing. Line numbers drift, and this repo has been audited many times.
- Every fix gets a regression test: xUnit in `tests/NetworkSecurityAuditor.Tests/`, Pester in `tools/NetworkSecurityAudit.Tests.ps1`.
- After each batch run `dotnet test NetworkSecurityAuditor.slnx -c Release` and `.\tools\Test-NetworkSecurityAudit.ps1`; keep PowerShell sources ASCII-only for 5.1.
- A new check ID needs catalog, framework, ATT&CK, D3FEND and scan-profile entries on both surfaces; the structural parity tests enforce this.

## Carried Forward

The 2026-09-29 verification pass removed 234 stale lines from this file (already shipped, reference links, principles, or duplicates of Roadmap_Blocked.md). These items are the remaining open work, rewritten so each stands alone.

- [ ] P2 — NSA-044 Add the standard envelope to JSONL and CSV exports and validate PS1 output against the committed schemas
  Why: C# JSONL lacks `schema_version`, client and auditor; the C# CSV comment line carries only host, score and timestamp; PS1 JSONL uses `source_version` with no `schema_version`; PS1 CSV has no metadata; PS1 output is never validated against `schemas/exports/`.
  Evidence: `src/NetworkSecurityAuditor/Export/JsonlExporter.cs:49`, `Export/CsvExporter.cs`, `NetworkSecurityAudit.ps1:13533` (Export-FindingsJSONL), `:13938` (Export-FindingsCSV), `schemas/exports/`.
  Touches: the four exporters above, `schemas/exports/jsonl-event.schema.json`, `tests/NetworkSecurityAuditor.Tests/ExportContractTests.cs`, Pester export tests.
  Acceptance: every JSONL record and the CSV metadata comment line on both surfaces carry `schema_version`, `tool_version`, `timestamp`, `client`, `auditor` and `target` (redacted in privacy mode); a Pester test renders PS1 JSON, JSONL and SARIF fixtures and validates them against the committed schemas; CSV column headers are unchanged.
  Complexity: M

- [ ] P2 — NSA-045 Test PDF export with local, space-containing and UNC output paths
  Why: PDF export launches Edge or Chrome with a file path argument, and no test covers quoting for spaces or `\\server\share` targets.
  Evidence: `src/NetworkSecurityAuditor/Export/PdfExporter.cs`, `NetworkSecurityAudit.ps1:14411` (Export-PDF); no PDF path tests in either suite.
  Touches: `PdfExporter.cs` argument building, `Export-PDF`, new xUnit and Pester cases using a fake browser executable that records its arguments.
  Acceptance: tests prove the browser receives a correctly quoted `--print-to-pdf` target for `C:\Out\a.pdf`, `C:\Out Dir\a b.pdf` and `\\host\share\a.pdf`, without launching a real browser.
  Complexity: S

- [ ] P2 — NSA-046 Cover exit-code combinations with tests and give an unavailable profile its own code
  Why: exit-code selection is inline logic on both surfaces with no combination tests, and the empty C# Cloud profile exits 2, the same code RMM monitors read as "failures found".
  Evidence: `src/NetworkSecurityAuditor/App.xaml.cs:660-675`, `:391-395`; `Models/Enums.cs:71-82`; `NetworkSecurityAudit.ps1:15902` onward.
  Touches: extract a pure exit-code function on each surface; `Models/Enums.cs`; README Exit Codes table; CLI tests and Pester.
  Acceptance: table-driven tests cover score below 60, ransomware below 40, any Fail, framework below threshold, and their overlaps with documented precedence on both surfaces; an unavailable profile returns a usage-class code (64-series) documented in the README.
  Complexity: S

- [ ] P2 — NSA-047 Complete PS1 RMM output: delta fields for every provider, configurable Datto slots, stable framework order, documented field schema
  Why: delta fields (`ScoreDelta`, `NewCriticals`, `ResolvedCriticals`, `WorstExposureDays`, `BaselineAgeDays`) go only to the generic registry key; `GradePrevious`, `HistoryPath`, `DeltaPath` and `HistoryHealth` don't exist; Datto `Custom1-5` are hard-coded; the compliance string comes from an unordered hashtable, so field values churn between runs.
  Evidence: `NetworkSecurityAudit.ps1:15801-15806` (`$fwFlags=@{}`), `:15831-15835` (Datto), `:15881-15887` (generic delta fields); README RMM table at "RMM Integration".
  Touches: the RMM write block at `NetworkSecurityAudit.ps1:15801-15888`, a new `-DattoUdfMap` parameter or branding/config key, README RMM section.
  Acceptance: NinjaRMM, Datto, ConnectWise Automate, Syncro, HaloPSA and generic outputs all receive the delta fields when history exists; framework order in the compliance string is fixed and tested; Datto slot mapping is configurable with the current slots as default; the README lists each provider's field name, type and format.
  Complexity: M

- [ ] P2 — NSA-048 Route every network call through one internet gate with explicit skip reasons
  Why: `-NoInternet` and skip reasons exist, but each call site checks on its own, so a new outbound call can bypass offline mode.
  Evidence: `NetworkSecurityAudit.ps1:4447`, `:5619`; `src/NetworkSecurityAuditor/Checks/CommonFindings/CF02_EgressTestCheck.cs:43`, `CF08_DnsFilterTestCheck.cs:45`.
  Touches: a `Test-AuditInternetAllowed`/`InternetPolicy` helper on each surface, KEV/Graph/egress/DNS call sites, a static gate that fails on raw `Invoke-WebRequest`, `HttpClient` or socket use outside the helper.
  Acceptance: with offline mode on, every outbound path reports a `Skipped` status with reason `OfflineMode`; a static test fails if a new outbound call bypasses the helper.
  Complexity: S

- [ ] P2 — NSA-049 Show a write preview in the PS1 setup dialog and split read-only discovery from host-modifying actions
  Why: setup can trust PSGallery, install a package provider, enable firewall rules and WinRM, start Remote Registry and change audit policy, several of them default-checked, with no list of exact changes before execution.
  Evidence: `NetworkSecurityAudit.ps1:2661` (Install-AuditPrereqs), `:2712` (Enable-AuditWinRM), `:15059` (Enable-AuditPolicies), `:10562` (read-only block).
  Touches: PS1 setup window XAML and handlers, the `Register-AuditWrite` inventory at `:1164`.
  Acceptance: host-modifying actions are unchecked by default and grouped apart from discovery; before running, the dialog lists each registry key, service, firewall rule, audit subcategory and package source it will change; declining leaves the host unchanged (Pester asserts no write functions run).
  Complexity: M

- [ ] P2 — NSA-050 Finish PS1 history outputs: per-finding delta records, standalone delta export, category trends, compaction
  Why: `history.jsonl` holds only `run_summary`; there are no `finding_delta` or `history_health` records, per-finding JSONL has no `first_seen`/`previous_status`/`delta_state`, silent mode writes no standalone delta JSON or HTML, snapshots lack category scores, and `history.jsonl` grows forever.
  Evidence: `NetworkSecurityAudit.ps1:11675` (Append-HistoryLine), `:11694` (Invoke-AuditHistory), `:11787` (snapshot pruning only).
  Touches: `Append-HistoryLine`, `Invoke-AuditHistory`, `Export-FindingsJSONL`, a new delta export, retention settings.
  Acceptance: each run appends `run_summary`, one `finding_delta` per finding and a `history_health` record with bounded retry on a locked file; `-Silent` writes `*_delta.json` and a delta HTML section; category scores appear in snapshots and trends; `history.jsonl` compacts past the retention window; Pester covers two fixed snapshots.
  Complexity: M

- [ ] P2 — NSA-051 Put PS1 remediation results in reports and add a rollback restore command
  Why: `$script:RemediationResult` never reaches HTML or JSON, and the rollback manifest holds hints only, so a remediation can't be undone from the tool.
  Evidence: `NetworkSecurityAudit.ps1:1095` (Invoke-AuditRemediation), `:15651-15672` (rollback manifest).
  Touches: `Invoke-AuditRemediation`, `Export-HTMLReport`, `Export-FindingsJSON`, a new `-RestoreFromRollback <path>` path.
  Acceptance: HTML and JSON include each remediation's before value, after value, result and rollback file; `-RestoreFromRollback` with `-WhatIf` prints the restore plan and without it restores registry and service values; Pester proves a dry-run round trip on a mocked registry provider.
  Complexity: M

- [ ] P2 — NSA-052 Complete the PS1 Graph request layer and cloud manifest offline
  Why: `Invoke-GraphAuditRequest` sends no `ConsistencyLevel: eventual` header for advanced queries, doesn't route by `ApiVersion`, and the evidence envelope lacks `request_window`, `auth_mode`, `paging_summary`, `throttle_count` and `redaction_summary`; the manifest lacks HTTP method, default profile, framework map, evidence mode, delegated vs application split, national-cloud support, paging style and cache TTL; CL IDs have no framework or ATT&CK mapping.
  Evidence: `NetworkSecurityAudit.ps1:1935` (`$script:CloudCheckManifest`), `:2079` (Invoke-GraphAuditRequest), `:2201-2204`; https://learn.microsoft.com/en-us/graph/throttling.
  Touches: manifest, request wrapper, CL01/CL02/CL06/CL13 result envelopes, framework and ATT&CK maps, Graph mock fixtures in Pester.
  Acceptance: mock-fixture tests prove header, version routing, paging summary and throttle counts land in the envelope; every CL ID has framework and ATT&CK entries; no live tenant is needed.
  Complexity: M

- [ ] P2 — NSA-053 Bring the C# HTML report to the PS1 report's navigation and accessibility level
  Why: the C# report has breakpoints and overflow handling only; it has no sticky table headers, check anchors, table of contents, status legend, `:focus-visible` styles, WCAG 2.2 target sizes, or a scan-limitations section (the PS1 report has most of these).
  Evidence: `src/NetworkSecurityAuditor/Export/HtmlReportGenerator.cs`; `NetworkSecurityAudit.ps1:12217-12239`, `:12397`, `:12901`; https://www.w3.org/TR/WCAG22/.
  Touches: `HtmlReportGenerator.cs`, `CmmcReportGenerator.cs` shared CSS, HTML report tests.
  Acceptance: the report has a linked table of contents, per-check anchors, sticky headers, a status legend, visible focus styles, interactive targets of at least 24 by 24 CSS pixels, and a limitations section naming skipped, manual and errored checks; HTML tests assert each element.
  Complexity: M

- [ ] P2 — NSA-054 Verify keyboard order, focus visibility and reduced motion on both GUIs
  Why: tab order is untested on both surfaces; PS1 flash timers ignore the Windows reduced-animation setting; `tools/Test-ThemeContrast.ps1` checks text but not focus indicators.
  Evidence: `tests/NetworkSecurityAuditor.Tests/WpfUiAutomationSmokeTests.cs` (launch and names only), `NetworkSecurityAudit.ps1:9057` (flash timer), `tools/Test-ThemeContrast.ps1`.
  Touches: UIA smoke test, PS1 timer code, contrast tool.
  Acceptance: the UIA test walks Tab through client, auditor, profile, scan, filter, check list and inspector fields in a documented order; PS1 skips flash animation when `SystemParameters.ClientAreaAnimation` is false; the contrast tool reports focus-indicator contrast of at least 3:1 for all seven PS1 themes and the C# theme.
  Complexity: M

- [ ] P3 — NSA-055 Show per-check scan states and skipped/timeout counts during a scan
  Why: the C# GUI shows percent and the running row only; operators can't see queued, timed-out or skipped checks until the scan ends, and exports show no progress.
  Evidence: `src/NetworkSecurityAuditor/ViewModels/MainViewModel.cs`, `ViewModels/CheckItemViewModel.cs`.
  Touches: `CheckItemViewModel` state property, `MainWindow.xaml` row template, status bar, export commands.
  Acceptance: each row shows Queued, Running, Timed out, Skipped or Complete with text plus color; the status bar shows skipped and timeout counts and remaining checks; HTML and PDF export show a busy state with the file name.
  Complexity: M

- [ ] P3 — NSA-056 Add review ergonomics to the C# workstation
  Why: there are no copy-evidence or copy-remediation actions, no sort by owner or due date, no saved filters (the remaining part of NSA-017), no "no failures" or "no baseline" empty states, and no required-field markers or inline validation on report metadata.
  Evidence: `src/NetworkSecurityAuditor/MainWindow.xaml` (search box at line 825), `ViewModels/MainViewModel.cs`.
  Touches: inspector toolbar, check list sorting, filter persistence in user settings, empty-state templates, metadata fields.
  Acceptance: copy buttons place evidence or remediation text on the clipboard with a toast; the list sorts by severity, status, owner and due date; a named filter survives restart; empty states explain what to do next; client and auditor show required markers with inline messages; icon buttons carry tooltips and automation names.
  Complexity: M

- [ ] P3 — NSA-057 Make the C# window usable at 1000 px wide and 150 percent scaling
  Why: `MinWidth` is 1180, so the layout can't reach the 1000 px width that small laptops at 150 percent scaling present.
  Evidence: `src/NetworkSecurityAuditor/MainWindow.xaml` (`MinWidth`).
  Touches: `MainWindow.xaml` grid definitions, command bar wrapping, inspector collapse behavior, screenshot render test.
  Acceptance: at 1000 by 700 logical pixels every command stays reachable without horizontal clipping; a `--render-screenshot` test at that size shows no truncated labels.
  Complexity: M

- [ ] P3 — NSA-058 Add remediation status and GUI branding fields to the C# workstation
  Why: C# tracks owner and due date but no remediation status (PS1 has it), and branding is CLI config only.
  Evidence: `NetworkSecurityAudit.ps1:8335` (`RemStatusCombos`); `src/NetworkSecurityAuditor/Models/BrandingConfig.cs`.
  Touches: `Models/CheckResult.cs`, audit-state schema with migration, inspector, a branding panel, exports.
  Acceptance: status (Open, In progress, Fixed, Accepted) saves, loads older state files, and appears in HTML, JSON, CSV and POA&M; branding can be set and previewed in the GUI and round-trips to the config JSON.
  Complexity: M

- [ ] P3 — NSA-059 Export an executive PowerPoint deck from one scan
  Why: MSPs present results in QBRs; the deck is the one tiered deliverable neither surface produces.
  Evidence: old roadmap Phase 3 (NSA-009 white-label executive pack); Network Detective positions reports as client deliverables (RESEARCH.md, Competitive Landscape).
  Touches: new C# exporter using Open XML SDK or a minimal hand-built package, branding config, `--export-pptx` flag.
  Acceptance: the deck contains title with branding, overall and ransomware scores, top five risks, compliance gaps, and phased remediation; it opens in PowerPoint and LibreOffice without repair prompts; tool version and scan limitations appear on the last slide.
  Complexity: L

- [ ] P3 — NSA-060 Send the existing alert payload to a webhook on request
  Why: `-AlertPreview` builds the payload but nothing can send it; recurring-scan users wire external scripts (the PingCastle-Notify pattern).
  Evidence: `NetworkSecurityAudit.ps1:11616` (Get-AuditAlertPayload); https://github.com/LuccaSA/PingCastle-Notify.
  Touches: new `-WebhookUrl` parameter, the internet gate from NSA-048, Teams and Slack payload shapes.
  Acceptance: with `-WebhookUrl` the run posts once per run only when new criticals or score regressions exist; privacy mode redacts identities; failures are logged and never change the audit exit code; offline mode skips the send with a reason.
  Complexity: S

- [ ] P3 — NSA-061 Explain export failures with disk space and file-lock details
  Why: diagnostics cover output path and PDF browser discovery, but a failed export doesn't say whether the disk was full or the file was open elsewhere.
  Evidence: `src/NetworkSecurityAuditor/Services/DiagnosticsReport.cs:113,123`.
  Touches: `AtomicFileWriter` error mapping, PS1 export catch blocks.
  Acceptance: a locked target reports the file name and "in use by another process"; insufficient space reports free bytes; tests simulate both.
  Complexity: S

- [ ] P3 — NSA-062 Gate CHANGELOG heading dates and version order
  Why: nothing checks that release headings have valid ISO dates in descending order, and the current Unreleased section sits above an unreleased version heading.
  Evidence: `CHANGELOG.md` head; `tools/Test-NetworkSecurityAudit.ps1` version-surface checks.
  Touches: `tools/Test-NetworkSecurityAudit.ps1`.
  Acceptance: the gate fails on an invalid date, a date later than today, or out-of-order versions.
  Complexity: S

- [ ] P3 — NSA-063 Share design tokens between the WPF theme and the HTML reports
  Why: the dashboard and HTML reports hard-code a Catppuccin-like palette separate from `Theme/Themes.xaml`, so severity colors can drift between GUI and report.
  Evidence: `src/NetworkSecurityAuditor/Export/DashboardGenerator.cs`, `Export/HtmlReportGenerator.cs`, `Theme/Themes.xaml`.
  Touches: a token source (C# constants or JSON) consumed by XAML resources and report CSS, contrast tests.
  Acceptance: severity and status colors come from one source; a test asserts GUI and report tokens match.
  Complexity: M

- [ ] P3 — NSA-064 Trend Microsoft Secure Score from CL01 history
  Why: CL01 reads Secure Score but history has no Secure Score series, so trend cards can't show it.
  Evidence: `NetworkSecurityAudit.ps1:2289-2511` (CL checks), history snapshot fields.
  Touches: CL01 result envelope, snapshot schema, dashboard trend rendering, mock fixtures.
  Acceptance: two mock Secure Score responses on different dates produce a delta and a trend point; no tenant is needed for tests.
  Complexity: S

## Research-Driven Additions

### P0

### P1

- [ ] P1 — NSA-076 Update IA11 for Kerberos RC4 enforcement (CVE-2026-20833)
  Why: accounts without `msDS-SupportedEncryptionTypes` fall back to the DC default, which changed in 2026, but IA11 counts them without failing, reads the domain object's etype attribute as if meaningful, and skips computer and gMSA accounts.
  Evidence: `src/NetworkSecurityAuditor/Checks/IdentityAccess/IA11_KerberosEncryptionCheck.cs:123-156`; https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication/; https://4sysops.com/archives/windows-kerberos-rc4-deprecation-what-will-break-in-active-directory-and-how-to-fix-it/.
  Touches: `IA11_KerberosEncryptionCheck.cs`, PS1 IA11 block (`NetworkSecurityAudit.ps1:3801-3823`), NSA-073 fixtures.
  Acceptance: the check reads `DefaultDomainSupportedEncTypes` and `RC4DefaultDisablementPhase` on each reachable DC, evaluates user, computer and gMSA accounts with SPNs against that effective value, fails RC4-only or DES accounts, and summarizes KDC events 201-209 when readable; fixtures cover unset, AES-only and RC4-only accounts. Needs live validation on a DC with the 2026 updates.
  Complexity: M

- [ ] P1 — NSA-078 Resolve privileged groups by SID and nested membership
  Why: IA01, IA02, CF04 and IA12 match English group names and direct membership only, so non-English domains and nested admins give wrong results.
  Evidence: `IA01_PrivilegedGroupsCheck.cs:55`, `IA02_ServiceAccountCheck.cs:76`, `CF04_FormerEmployeeCheck.cs:77`, `IA12_DmsaCheck.cs:121-124`.
  Touches: a shared well-known-SID resolver (domain SID plus RID 512, 518, 519, 544 and others), `LDAP_MATCHING_RULE_IN_CHAIN` membership queries, the four checks, PS1 equivalents.
  Acceptance: groups resolve from domain SID and RID; nested members appear with their path; a fixture with localized group names (for example "Domänen-Admins") produces the same result as the English fixture.
  Complexity: M

- [ ] P1 — NSA-080 Port the PS1 AD attack-indicator checks to C#
  Why: DCSync rights for non-default principals, AdminSDHolder ACL tampering, Protected Users coverage of Tier 0 and unconstrained delegation exist only in the PS1; C# EP03 labels the LSA `AllowTgtSessionKey` value as "Kerberos delegation".
  Evidence: `NetworkSecurityAudit.ps1:3524-3530`, `:3538-3553`, `:3596-3606`; `src/NetworkSecurityAuditor/Checks/EndpointSecurity/EP03_SmbNtlmCheck.cs:286-295`.
  Touches: IA01 or a new IA check for AD attack indicators, EP03 label fix, mappings, NSA-073 fixtures.
  Acceptance: C# reports the same four indicators as the PS1 on shared fixtures, using SIDs; EP03 no longer describes `AllowTgtSessionKey` as delegation; framework and ATT&CK mappings are added.
  Complexity: M

- [ ] P1 — NSA-081 Evaluate AD CS templates and CAs for the ESC catalog
  Why: C# CF01 only lists CAs and prints "Review templates for ESC1-ESC8"; the PS1 covers ESC1, 6, 8, 9, 10, 11, 13, 15 and 16 but not ESC2, 3, 4, 5, 7 or 14; certificate-based domain takeover is a top AD path.
  Evidence: `src/NetworkSecurityAuditor/Checks/CommonFindings/CF01_DaServiceAccountsCheck.cs:380-404`; `NetworkSecurityAudit.ps1:5080-5220`; https://github.com/ly4k/Certipy/releases; https://github.com/jakehildreth/Locksmith2; https://learn.microsoft.com/en-us/defender-for-identity/prevent-certificate-enrollment-esc15.
  Touches: a new AD CS check reading `CN=Certificate Templates` and `CN=Enrollment Services` in the configuration partition, CA flags via remote registry when reachable, both surfaces, NSA-073 fixtures.
  Acceptance: templates are flagged for ESC1 (enrollee-supplied subject with client auth), ESC2 (any purpose or no EKU), ESC3 (enrollment agent), ESC4 (write rights for non-Tier-0 SIDs), ESC9 (no security extension), ESC13 (issuance policy group link) and ESC15 (schema v1 with enrollee subject); CAs are flagged for ESC6, ESC7 (ManageCA or ManageCertificates held by non-Tier-0), ESC8 (web enrollment over HTTP without EPA) and ESC16 (security extension disabled CA-wide); weak `altSecurityIdentities` mappings are reported (ESC14); every finding names the template or CA and the principal; fixtures cover each ESC.
  Complexity: L

- [ ] P1 — NSA-082 Publish a versioned release with the PowerShell script attached and current screenshots
  Why: the latest GitHub release is v5.3.1 (2026-07-09) while code has been 5.4.0/4.12.0 since 2026-08-12; releases since v4.10.1 don't attach `NetworkSecurityAudit.ps1`, so the README points at the unversioned `blob/main` file with no checksum to compare; the README screenshot is from v5.3.1.
  Evidence: `gh release list` and `gh release view v5.3.1` on 2026-09-29; README "Download" section; CHANGELOG Unreleased notes.
  Touches: `tools/Publish-CSharpRelease.ps1` (add the PS1 and its hash to `SHA256SUMS.txt`), README download link to `releases/latest/download/NetworkSecurityAudit.ps1`, screenshots for GUI, HTML report, executive summary and silent-mode console, CHANGELOG release heading.
  Acceptance: after NSA-065, a release exists with the C# ZIP, SBOM, manifest, `NetworkSecurityAudit.ps1` and one `SHA256SUMS.txt` covering all of them; the README download link resolves (HTTP 200) and the documented hash command matches; screenshots show the released version.
  Complexity: S

- [ ] P1 — NSA-116 Stop IA01, IA02, IA07 and CF04 from failing every real domain
  Why: converting the AD checks to recorded fixtures (NSA-073) showed results no real domain can pass, apart from the nested-group and non-English cases NSA-078 covers. IA01's orphaned-adminCount test flags `krbtgt`, which always has adminCount=1. IA02's SPN filter includes `krbtgt` and disabled accounts, so every domain has a "kerberoastable" account, and an account matching two name patterns is counted twice. IA07's "admin" pattern matches the built-in Administrator. CF04 treats `(!(lastLogonTimestamp=*))` as a former employee, so a hire created yesterday is CRITICAL, and it requests `whenCreated` without using it.
  Evidence: `Checks/IdentityAccess/IA01_PrivilegedGroupsCheck.cs` orphan loop; `IA02_ServiceAccountCheck.cs` filter and pattern count; `IA07_SharedAccountsCheck.cs` pattern list; `Checks/CommonFindings/CF04_FormerEmployeeCheck.cs` filter; fixtures under `tests/NetworkSecurityAuditor.Tests/Fixtures/Directory/`.
  Touches: the four checks, their fixtures and tests, and the PS1 counterparts where they share the logic.
  Acceptance: a fixture domain with `krbtgt`, a disabled account with an SPN, the built-in Administrator and a week-old account that never logged on passes IA01, IA02, IA07 and CF04; a real orphaned adminCount account, an enabled user with an SPN, a shared "frontdesk" account and a 200-day-idle account still fail; IA02 counts each account once.
  Complexity: M

- [ ] P1 — NSA-118 Stop CF01 passing when the directory can't be read
  Why: CF01 writes every LDAP failure to evidence and carries on, so with the DC unreachable it returns Pass with "No critical service account issues detected". IA08 fails an account whose `accountExpires` is out of range without saying why, because the CRITICAL count only includes "Never".
  Evidence: `Checks/CommonFindings/CF01_DaServiceAccountsCheck.cs` catch blocks around each search; `IA08_VendorAccountsCheck.cs` Invalid versus Never handling.
  Touches: CF01, IA08 and their tests.
  Acceptance: CF01 with an unreachable directory is Error (or Not assessed with the reason), never Pass; IA08 names the invalid-expiry accounts in the findings.
  Complexity: S

### P2

- [ ] P2 — NSA-084 Add an LDAP signing and channel binding check for domain controllers
  Why: C# has no LDAP signing or channel binding check and the PS1 reads only the local DC registry; Server 2025 DCs require signing by default while channel binding stays "when supported", so unconfigured means different things by OS.
  Evidence: `NetworkSecurityAudit.ps1:5226-5231`; `src/NetworkSecurityAuditor/Checks/EndpointSecurity/EP03_SmbNtlmCheck.cs:52`; https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/ldap-channel-binding-and-ldap-signing-requirements---server-2025-updates/921536.
  Touches: new IA check, remote registry reads of `NTDS\Parameters\LDAPServerIntegrity` and `LdapEnforceChannelBinding` per DC when permitted, Directory Service events 2887 and 2889, mappings, fixtures.
  Acceptance: each reachable DC reports signing and channel-binding effective state with OS-aware defaults; unsigned-bind event counts appear when readable; unreachable DCs are `NotAssessed` with the reason.
  Complexity: M

- [ ] P2 — NSA-085 Detect RBCD, MachineAccountQuota, Pre-Windows 2000 Compatible Access and DnsAdmins exposure
  Why: neither surface checks these common AD privilege-escalation preconditions.
  Evidence: coverage grep 2026-09-29 (absent on both surfaces); PingCastle and Purple Knight indicator catalogs (RESEARCH.md, Competitive Landscape).
  Touches: new or extended IA checks, both surfaces, NSA-073 fixtures.
  Acceptance: the check reports `ms-DS-MachineAccountQuota` above 0, members of Pre-Windows 2000 Compatible Access beyond the defaults (Authenticated Users or Everyone flagged), non-default DnsAdmins members, and computers or DCs with `msDS-AllowedToActOnBehalfOfOtherIdentity` set, each with the principal SID and name.
  Complexity: M

- [ ] P2 — NSA-086 Evaluate SMB, NTLM and Credential Guard state against OS-specific defaults
  Why: 24H2 and Server 2025 require SMB signing and enable Credential Guard, HVCI and LSA protection by default, but EP03/EP08 read policy keys only; `RestrictSendingNTLMTraffic` is recorded but not scored; NTLMv1-derived SSO blocking (`BlockNtlmv1SSO`) moves from audit to enforce in 2026-10.
  Evidence: `EP03_SmbNtlmCheck.cs:83-113,170-172`, `EP08_CredentialGuardCheck.cs:84-170`; https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening; https://support.microsoft.com/en-us/topic/upcoming-changes-to-ntlmv1-in-windows-11-version-24h2-and-windows-server-2025-c0554217-cdbc-420f-b47c-e02b2db49b2e.
  Touches: EP03, EP08, PS1 equivalents, a build-aware defaults table, tests.
  Acceptance: effective state comes from `Get-SmbServerConfiguration`/`Get-SmbClientConfiguration` and `Win32_DeviceGuard` running services, with policy keys as secondary evidence; unconfigured 24H2/Server 2025 hosts are not failed for defaults they enforce; `BlockNtlmv1SSO` and NTLM operational events 4024/4025 appear in evidence; HVCI is scored.
  Complexity: M

- [ ] P2 — NSA-087 Make LM03 read effective audit and logging state
  Why: PowerShell v2 detection tests a registry key that can exist after v2 is removed; a CBS lookup uses a wildcard path that never matches; event log size is read only from policy; SMB is checked via `EnableSecuritySignature` instead of `RequireSecuritySignature`; PS1 LM03 flags only "No Auditing" instead of comparing to a baseline.
  Evidence: `LM03_AuditPolicyCheck.cs:38-43,74-77,149,156,254-260`; `NetworkSecurityAudit.ps1:4842-4885`.
  Touches: LM03 on both surfaces.
  Acceptance: PowerShell v2 state comes from the `MicrosoftWindowsPowerShellV2Root` optional feature; event log size uses the effective log configuration; audit settings are compared by subcategory GUID to a documented baseline with per-subcategory results.
  Complexity: M

- [ ] P2 — NSA-088 Detect the domain controller role correctly and check Print Spooler on DCs
  Why: the PS1 treats any domain-joined Server SKU as a DC (`Caption -match 'Server'`), and C# has no Print Spooler on DC check.
  Evidence: `NetworkSecurityAudit.ps1:6660-6670`.
  Touches: a shared role helper (`Win32_ComputerSystem.DomainRole` 4 or 5 locally; DC list from the domain for remote queries), PS1 spooler block, a C# check or EP06 extension.
  Acceptance: member servers are never reported as DCs; each reachable DC reports Spooler state, and a running Spooler on a DC fails.
  Complexity: S

- [ ] P2 — NSA-089 Replace English command-output parsing with locale-independent sources
  Why: `auditpol`, `net share`, `net localgroup`, `netstat`, `rasdial`, `netsh wlan`, `netsh advfirewall` and `route print` output is parsed with English strings, so checks misreport on non-English Windows.
  Evidence: `LM03:149,156`, `CF05:18,128,136`, `CF07:210`, `NP02:54`, `NP03:123`, `NA03:211-223`, `NA07:157-163`, `NP01:127-151`, `NP05:170-193`, `NP06:139-151`, `NA02:156`, `EP06:275-279`; PS1 `:4576`, `:4865-4868`, `:6219-6222`.
  Touches: each call site above; prefer WMI/CIM (`Win32_Share`, `MSFT_NetFirewallRule`, `MSFT_NetRoute`, `MSFT_NetTCPConnection`), `auditpol /r` GUID columns, SID-based group reads, WLAN profile XML export (already preferred in NA03).
  Acceptance: no check depends on a localized English literal; a test harness replays German and French command-output fixtures where a CLI must remain; results match the English fixtures. Needs live validation on one non-English host.
  Complexity: L

- [ ] P2 — NSA-090 Move catalog compliance references to NIST CSF 2.0 and add CSF 2.0 as a framework
  Why: 51 catalog lines cite CSF 1.1 categories (PR.IP, PR.AC, PR.PT, PR.DS) that CSF 2.0 restructured, and CSF 2.0 isn't one of the 11 frameworks although CIS Controls v8.1 and CISA CPG 2.0 align to it.
  Evidence: `src/NetworkSecurityAuditor/Data/CheckCatalog.cs` compliance strings; https://www.nist.gov/cyberframework; https://www.cisa.gov/sites/default/files/2025-12/CPG_Report_2.0_508c.pdf.
  Touches: catalog strings, `Data/FrameworkMappings.cs`, PS1 `$script:FrameworkMap` and `$script:FrameworkMeta`, framework summaries and exports, structural tests.
  Acceptance: every check maps to CSF 2.0 subcategory IDs (for example PR.PS-01) including GV where applicable; CSF 2.0 appears in HTML, JSON, JSONL, CSV and compliance summary on both surfaces; no CSF 1.1 IDs remain.
  Complexity: M

- [ ] P2 — NSA-091 Map checks to NIST SP 800-171 Rev 3 using NIST's r2-to-r3 analysis
  Why: `NIST_R3` fields are empty; the blocker was the lack of verified Rev 3 IDs, and NIST publishes an official Rev 2 to Rev 3 analysis spreadsheet. CMMC stays on Rev 2 by DoD class deviation, so Rev 2 remains the CMMC default.
  Evidence: `src/NetworkSecurityAuditor/Data/FrameworkMappings.cs` (no `NIST_R3 =` entries); https://csrc.nist.gov/files/pubs/sp/800/171/r3/final/docs/sp800-171r2-to-r3-analysis.xlsx.
  Touches: `FrameworkMappings.cs`, PS1 framework map, report framework selector, a test that every Rev 3 ID exists in a committed ID list derived from the spreadsheet.
  Acceptance: each check with a Rev 2 mapping carries the corresponding Rev 3 requirement IDs from the NIST analysis, or an explicit "withdrawn/merged" note; Rev 3 is a selectable framework labelled as non-CMMC; the ID-list test passes.
  Complexity: M

- [ ] P2 — NSA-092 Keep the PS1 Graph path working when Graph PowerShell v3 drops Windows PowerShell 5.1
  Why: the PS1 calls `Invoke-MgGraphRequest` from `Microsoft.Graph.Authentication`; Graph PowerShell v3, planned for Q4 2026, drops Windows PowerShell 5.1 (Likely).
  Evidence: `NetworkSecurityAudit.ps1:2160-2170`, `:15154`; https://endpointweekly.com/blog/microsoft-graph-powershell-v3-drops-windows-powershell-5-1-support.html.
  Touches: `Invoke-GraphAuditRequest`, diagnostics Graph readiness, README requirements.
  Acceptance: diagnostics report the loaded Graph module version and warn when a 5.1 host has v3 or later; the README documents the supported 2.x range for 5.1; running under PowerShell 7 with v3 still works (Pester with mocked cmdlets).
  Complexity: S

- [ ] P2 — NSA-093 Report the installed .NET Desktop Runtime against the minimum patched version
  Why: the C# build is framework-dependent, so runtime CVE fixes (10.0.12 fixed seven on 2026-09-08) only reach users through their installed runtime, and nothing states a minimum.
  Evidence: `src/NetworkSecurityAuditor/NetworkSecurityAuditor.csproj`; `tools/Publish-CSharpRelease.ps1` manifest; https://devblogs.microsoft.com/dotnet/dotnet-and-dotnet-framework-september-2026-servicing-updates/.
  Touches: `Services/DiagnosticsReport.cs`, `release-manifest.json` (`minimum_runtime`), README requirements.
  Acceptance: diagnostics show `Environment.Version` and warn below the manifest minimum; the release manifest and README state the minimum patched runtime; `Verify-CSharpRelease.ps1` checks the field exists.
  Complexity: S

- [ ] P2 — NSA-094 Evaluate share permissions by SID in CF05
  Why: CF05 parses English `net share` output and looks for the string "Everyone", missing Authenticated Users, Domain Users, Domain Computers and BUILTIN\Users grants and failing on localized systems.
  Evidence: `src/NetworkSecurityAuditor/Checks/CommonFindings/CF05_OpenSharesCheck.cs:18,119,128,136`; https://github.com/NetSPI/PowerHuntShares.
  Touches: CF05 (share list from `Win32_Share`, ACL from `Win32_LogicalShareSecuritySetting` or `Get-SmbShareAccess`), PS1 equivalent, tests.
  Acceptance: shares granting write or full control to S-1-1-0, S-1-5-11, S-1-5-32-545, domain RID 513 or 515 fail; read-only grants are Partial; administrative shares are ignored; tests use SID fixtures.
  Complexity: M

- [ ] P2 — NSA-095 Add automated Group Policy hygiene checks
  Why: the Policies & Standards category is entirely questionnaire-based, while GPO problems are machine-checkable.
  Evidence: `src/NetworkSecurityAuditor/Checks/PoliciesStandards/`; https://github.com/EvotecIT/GPOZaurr; GPP cpassword detection already exists in `CF01:304-305`.
  Touches: a new PS07 check using `groupPolicyContainer` objects and SYSVOL `GPT.INI`, mappings, fixtures.
  Acceptance: the check reports unlinked GPOs, GPOs whose AD and SYSVOL versions differ, GPOs missing Authenticated Users or Domain Computers read, and SYSVOL folders without a matching GPO; each item names the GPO GUID and display name.
  Complexity: M

- [ ] P2 — NSA-096 Export remediation items as ticket-ready files
  Why: MSPs move findings into PSA or issue trackers; M365-Assess exports GitHub Issues markdown and Jira CSV, while this tool offers POA&M and DefectDojo only. A file export needs no credentials, so it can land before the blocked NSA-020 integrations.
  Evidence: https://github.com/Galvnyz/M365-Assess; `Roadmap_Blocked.md` NSA-020.
  Touches: new C# exporter and PS1 function, `--export-tickets` flag.
  Acceptance: one CSV row (Jira and generic PSA columns) and one markdown block per failed or partial check, with title, severity, evidence summary, remediation, owner and due date; privacy mode redacts identities; formula-injection guarding matches the existing CSV exporter.
  Complexity: S

- [ ] P2 — NSA-097 Report Windows LAPS policy details and flag legacy-only deployments
  Why: Windows LAPS is the supported path and legacy LAPS no longer installs on current Windows 11; IA06 doesn't read local Windows LAPS policy (backup directory, password age, complexity or passphrase, automatic account management).
  Evidence: https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview; `IA06_PamCheck.cs`.
  Touches: IA06 local evidence from `HKLM\Software\Microsoft\Policies\LAPS` and the CSP key, PS1 equivalent.
  Acceptance: local evidence shows the effective LAPS policy; domains with legacy-only coverage on hosts that support Windows LAPS are Partial with migration guidance.
  Complexity: S

- [ ] P2 — NSA-098 Write PS1 exports atomically and accept any output path
  Why: PS1 exports use non-atomic `Set-Content`, so an interrupted run can leave truncated files that the dashboard later ingests; save-state lacks `-LiteralPath`, so paths with brackets fail.
  Evidence: `NetworkSecurityAudit.ps1:11881`, `:12984`, `:13526`, `:14356`.
  Touches: a PS1 `Write-AuditFileAtomic` helper (temp file plus `[IO.File]::Replace`), every export function, save-state.
  Acceptance: all PS1 exports go through the helper; a Pester test writes to a path containing `[x]` and verifies no partial file remains after a simulated failure.
  Complexity: S

- [ ] P2 — NSA-111 Verify or replace the PS1 DISA STIG V-IDs
  Why: the PS1 `$stigMap` gives most checks sequential IDs (V-254247 through V-254300), which don't look like real rule IDs from one STIG. IA11, IA12 and EP11 already use plain descriptions instead.
  Evidence: `NetworkSecurityAudit.ps1` `$stigMap`; `BenchmarkMetadata.json` source `disa-windows-server-2025-stig` covers only IA11 and IA12.
  Touches: PS1 `$stigMap`, the C# STIG mapping if one exists, README STIG row, tests.
  Acceptance: every STIG reference names a real rule from a named STIG release (checked against the published XCCDF) or says plainly that no rule maps; a test pins the source release.
  Complexity: M

- [ ] P2 — NSA-115 Bring the PS1 status model in line with the app (questionnaires, Error, Pass-only thresholds)
  Why: NSA-072 changed the app only. The PS1's questionnaire checks still return `Partial` when they find nothing (NA04, BR02, BR04, BR05, BR07, CF03, PS01 to PS03 return nothing else), so an unanswered question earns half credit in `Get-FrameworkScores` and the risk score. Some also return Pass or Fail from local hints (PS04, NA07, NP10, BR03, BR08, PS06), which the app treats as questionnaire answers the operator gives. A check whose runspace throws still has no Error state.
  Evidence: PS1 check blocks for the 16 IDs in `CheckCatalog.QuestionnaireIds`; `Get-FrameworkScores` counts `Partial` as 0.5 and everything else as Not Assessed; app behavior in `StatusModelTests`.
  Touches: PS1 questionnaire check blocks, the status combo values, `Get-FrameworkScores`, risk score, HTML and JSON coverage fields, Pester.
  Acceptance: the 16 questionnaire checks return Not Assessed from the scan on the PS1 (hints go in the findings text); a thrown or timed-out check shows as Error, earns nothing and is listed in the report; the PS1 exit code's framework threshold counts only Pass; a Pester parity test checks the questionnaire set against the app's.
  Complexity: M

- [ ] P2 — NSA-120 Fix EP04 KEV false hits and misses found while porting it to the app
  Why: the C# port copies the PS1's KEV rules to keep the two in step, so both share these faults. On this PC both flag CVE-2019-1068 on SQL Server 2019, which shipped with that fix, because the old-CVE rule can only clear a fix by binary date (2019-09-24). Edge is never detected, since its version is read from HKLM\SOFTWARE\Microsoft\Edge\BLBeacon and only HKCU has that key. Entries whose product is just "Microsoft" are skipped, so CVE-2026-42897 (an Exchange XSS) can't match. Hits are capped at 15 before ransomware-linked ones are counted, so an older overdue ransomware entry can drop off. And when no hotfix has a parseable date, the app's EP04 passes where the PS1 fails.
  Evidence: `NetworkSecurityAudit.ps1` EP04 block (`Get-Ep04KevFamily`, the BLBeacon read near :4686, the hit cap near :4522); `Checks/EndpointSecurity/KevMatcher.cs`, `KevProductInventory.cs`, `EP04_PatchComplianceCheck.cs`.
  Touches: both EP04 surfaces, `Fixtures/Kev/ep04-kev-scenarios.json` (the shared scenarios keep them in step).
  Acceptance: a SQL Server build that includes a fix clears that KEV entry by version; Edge is detected from the HKLM or per-user key; an Exchange entry listed under vendor-only "Microsoft" matches on its name; ransomware-linked hits are counted before the display cap; both surfaces give the same status when hotfix dates are missing; each case is a shared scenario run by xUnit and Pester.
  Complexity: M

- [ ] P2 — NSA-121 Make the remaining event-log reads honest about caps and read failures
  Why: NSA-083 bounded the app's event-log checks, and it turned up gaps it didn't cover. The app's LM05 returns Pass ("No failed logon events") when the Security log can't be read. In the PS1, IA06 cuts its list to 20 events before testing `-gt 50`, so that branch can never fire. LM05 always prints "N+" even under the cap. BR02, BR06 and CF03 filter on message text, which formats every event, and none says "at least" when `-MaxEvents` cut the result. The app's NP03 records a split tunnel in evidence only, where the PS1 marks it Partial.
  Evidence: `Checks/LoggingMonitoring/LM05_FailedLogonCheck.cs` (`QueryFailedLogons` catch); `NetworkSecurityAudit.ps1` IA06 (near :6577-6581), LM05 (near :5531), BR02 (near :7744), BR06 (near :7867), CF03 (near :7965); `Checks/NetworkPerimeter/NP03_VpnCheck.cs`.
  Touches: app LM05 and NP03, PS1 IA06, LM05, BR02, BR06 and CF03, their tests.
  Acceptance: an unreadable Security log makes the app's LM05 Partial or Error with the reason, never Pass; the PS1 IA06 threshold is tested on the full count; every capped PS1 query says "at least N" only when the cap was hit; BR02, BR06 and CF03 filter by event ID or XPath before formatting messages; NP03 gives the same status for a split tunnel on both surfaces.
  Complexity: M

- [ ] P2 — NSA-122 Stop IA09 counting Windows' built-in WAN Miniport and RAS adapters as VPN adapters
  Why: the app's IA09 treats every PPP-type adapter as a VPN, and every Windows install has "WAN Miniport (PPPOE)" and "RAS Async Adapter". On this PC IA09 reported both as VPN adapters although no VPN is configured.
  Evidence: `Checks/IdentityAccess/IA09_RemoteAccessCheck.cs` (`nic.Type == NetworkInterfaceType.Ppp`); the PS1 IA09 block matches descriptions only and doesn't have the fault.
  Touches: IA09 adapter test, IA09RemoteAccessCheckTests.
  Acceptance: an adapter fixture with "WAN Miniport (PPPOE)" and "RAS Async Adapter" reports no VPN adapters; a PPP adapter with a VPN vendor description and a WireGuard tunnel still count.
  Complexity: S

### P3

- [ ] P3 — NSA-099 Report Sysmon configuration maturity, not just presence
  Why: "Sysmon installed with default or empty config" is a common gap; LM06 and LM07 detect the service only.
  Evidence: `LM06_FimCheck.cs:18-186`, `LM07_LogRetentionCheck.cs:128-184`; https://github.com/SwiftOnSecurity/sysmon-config; https://github.com/olafhartong/sysmon-modular.
  Touches: LM06 evidence from the SysmonDrv `Rules` registry value (schema version, hash, rule count) and the Sysmon operational log size.
  Acceptance: evidence shows Sysmon version, config hash and schema version; an empty or missing rule set is Partial.
  Complexity: S

- [ ] P3 — NSA-100 Migrate the C# tests to xunit v3 on Microsoft.Testing.Platform
  Why: xunit 2.9.3 is the legacy line; `xunit.runner.visualstudio` 4.x and `xunit.analyzers` 2.x now track v3, so the dependency gate will keep carrying exceptions until the suite moves.
  Evidence: https://xunit.net/docs/getting-started/v3/microsoft-testing-platform; https://learn.microsoft.com/en-us/dotnet/core/testing/migrating-vstest-microsoft-testing-platform.
  Touches: `tests/NetworkSecurityAuditor.Tests/NetworkSecurityAuditor.Tests.csproj`, test code using v2-only APIs, README test commands.
  Acceptance: the suite runs on xunit.v3 with the same test count; the NSA-065 xunit exceptions are removed.
  Complexity: M

- [ ] P3 — NSA-101 Run the PowerShell quality suite under Pester 6 and PSScriptAnalyzer 1.25
  Why: Pester 6.0.1 and PSScriptAnalyzer 1.25.0 are current and the harness targets Pester 5.9.0.
  Evidence: `tools/NetworkSecurityAudit.Tests.ps1`; https://www.powershellgallery.com/packages/PSScriptAnalyzer/1.25.0.
  Touches: Pester syntax that Pester 6 removed (for example `-Pending`), README validation commands.
  Acceptance: the suite passes under Pester 6 on both Windows PowerShell 5.1 and PowerShell 7, with a documented minimum version.
  Complexity: S

- [ ] P3 — NSA-102 Emit a CycloneDX 1.6 or later SBOM
  Why: the release emits CycloneDX 1.5 while 1.7 is the current ECMA-424 edition; newer versions add provenance and distribution-constraint fields useful for a security tool.
  Evidence: `tools/Publish-CSharpRelease.ps1`, `tools/Verify-CSharpRelease.ps1`; https://cyclonedx.org/specification/overview/.
  Touches: SBOM generation and verifier spec-version checks.
  Acceptance: the SBOM declares 1.6 or 1.7 and validates against the official schema; the verifier accepts it.
  Complexity: S

- [ ] P3 — NSA-103 Remove dead check and option code
  Why: `StubCheck` is unreachable, and `NoRmmWrite`, `NoRegistryWrite`, `ExportJSON`, `ExportCSV` and `ExportJSONL` in `AuditOptions` are never read, which misleads readers about C# RMM support.
  Evidence: `src/NetworkSecurityAuditor/Checks/StubCheck.cs`, `Checks/CheckRegistry.cs:111-115`, `Checks/CheckRunner.cs:38-44`, `Models/AuditOptions.cs:12-19`.
  Touches: the files above and tests that reference them.
  Acceptance: the unused types and properties are gone; the registry-count test still passes; no behavior changes.
  Complexity: S

- [ ] P3 — NSA-104 State plainly in the README that MSP and consultant use is free
  Why: PingCastle and Purple Knight restrict free use to your own environment, so "free for auditing client environments" is the main reason an MSP would choose this tool.
  Evidence: https://www.pingcastle.com/terms-and-conditions/; https://www.capterra.com/p/10052219/PingCastle/; README "Why This Exists".
  Touches: README "Why This Exists".
  Acceptance: the README says the MIT license allows auditing client and third-party environments at no cost, without naming competitors' prices.
  Complexity: S

- [ ] P3 — NSA-105 Replace the box-drawing banner comments in the PS1 with ASCII
  Why: `NetworkSecurityAudit.ps1` is BOM-less UTF-8 and the repo rule is ASCII-only for Windows PowerShell 5.1, yet 158 section-banner comments use U+2500 (`# ── ... ──`); 5.1 decodes them through the ANSI code page. Harmless while they stay in comments, but it hides real non-ASCII regressions from a simple scan. Found 2026-09-30 during NSA-066.
  Evidence: `NetworkSecurityAudit.ps1:374` and 157 similar lines (`Select-String -Pattern '[^\x00-\x7F]'`).
  Touches: `NetworkSecurityAudit.ps1` comments, a Pester test that fails on any non-ASCII byte in the PS1.
  Acceptance: the PS1 has zero non-ASCII characters; a Pester test enforces it on both hosts.
  Complexity: S
