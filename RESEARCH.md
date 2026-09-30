# Research — Network Security Auditor
Date: 2026-09-29. Replaces all prior research (previous pass: 2026-08-10).

Confidence labels: **Verified** (checked against the code or a primary source on 2026-09-29), **Likely** (secondary source, consistent with primary guidance), **Needs live validation** (needs a DC, tenant, RMM endpoint or specific Windows build).

## Executive Summary

Network Security Auditor is a local, read-only, no-telemetry Windows endpoint and Active Directory posture auditor with two surfaces: the production single-file `NetworkSecurityAudit.ps1` (v4.12.0, Windows PowerShell 5.1, RMM/fleet/history/Graph) and the .NET 10 WPF rewrite (v5.4.0, 69 checks, 11 frameworks, ATT&CK/D3FEND, OSCAL/SARIF/OCSF/DefectDojo exports). Its strongest shape is breadth of evidence plus machine-readable output that no MSP-facing commercial product sells at any price, delivered free under MIT while PingCastle and Purple Knight charge for third-party (MSP) audits. That makes verdict accuracy the product. This pass found that accuracy has fallen behind: several checks return the same verdict on nearly every host, 2025-2026 platform changes (Secure Boot CA expiry, Kerberos RC4 enforcement, 24H2/Server 2025 secure defaults, Windows 10 end of support) have outpaced check logic, and the release pipeline currently fails its own dependency gate.

Top opportunities, in priority order:

1. Unblock releases. `tools/Test-DependencyHealth.ps1 -Release` exits 3 on 2026-09-29 (16 outdated, 1 exception still matching), and no GitHub release has shipped since v5.3.1 on 2026-07-09. Refresh packages, then publish v5.4.x with the PowerShell script attached.
2. Fix checks with near-constant verdicts: LM02 always passes, NP02 fails nearly every host, EP01 always "detects" Defender for Endpoint, IA06 reports "no LAPS" to any non-privileged auditor.
3. Add a correct Secure Boot 2023 certificate check. Windows Production PCA 2011 expires 2026-10-19; the PowerShell logic misreads the status value and C# has no check.
4. Refresh lifecycle data. EP04 treats Windows 10 22H2 as a current build, EP10 never runs on workgroup hosts, and Windows 10 ESU year 1 plus Server 2012 R2 ESU end 2026-10-13.
5. Stop unanswered questionnaire checks from earning credit (16 checks always return `Partial` = half credit) and stop the exit-code threshold from counting `Partial` as passing.
6. Revalidate ATT&CK mappings for the v19 Defense Evasion split and correct the claimed "19.1" version.
7. Update IA11 for CVE-2026-20833 RC4 enforcement and IA12 for the real BadSuccessor precondition, after adding an AD test seam (every AD check is currently untested).
8. Bring C# to parity on AD CS ESC coverage, AD attack indicators, and CISA KEV (EP04 is labelled KEV but has none), and add LDAP signing/channel binding.
9. Make identity and command-output evaluation locale-independent (English group names and English `auditpol`/`netstat`/`net`/`netsh` parsing).
10. Migrate the catalog's NIST CSF 1.1 references to CSF 2.0 and map NIST SP 800-171 Rev 3 from NIST's published r2-to-r3 analysis.

## Product Map

### Core workflows
- Technician runs `NetworkSecurityAudit.ps1` interactively or with `-Silent` through RMM or a scheduled task; outputs HTML/PDF/JSON/JSONL/CSV/SARIF/OSCAL plus RMM custom fields, history deltas and exit codes.
- MSP runs fleet mode (`-TargetsCsv`, WinRM) and builds the static multi-client dashboard from a folder of findings exports.
- Workstation user runs the C# WPF app, reviews evidence in the inspector, edits notes/owner/due date, saves state, applies waivers, exports tiered reports and GRC formats (OSCAL POA&M, DefectDojo, CMMC/SPRS).
- Release operator runs `tools/Publish-CSharpRelease.ps1`, which gates dependencies, builds the ZIP, CycloneDX 1.5 SBOM, `SHA256SUMS.txt` and manifest, and self-verifies with `tools/Verify-CSharpRelease.ps1`.

### Personas
- MSP technician or vCISO producing prospect and client assessments (the free "prospect scan" is an active market category: Syncro/CyberDrain Snapshot launched 2025-12-02, Network Detective markets itself for opening sales conversations).
- Windows/AD administrator who needs local evidence without an agent.
- Compliance auditor (CMMC/SPRS, HIPAA, PCI, Essential Eight, Cyber Essentials) who needs framework mapping and portable evidence.

### Platforms and distribution
- Windows 10/11 and Server; PS1 targets Windows PowerShell 5.1; C# targets `net10.0-windows` framework-dependent (needs the .NET 10 Desktop Runtime).
- Verified 2026-09-29: latest GitHub release is v5.3.1 (2026-07-09); code has carried 5.4.0/4.12.0 since 2026-08-12 unreleased; releases since v4.10.1 do not attach `NetworkSecurityAudit.ps1`, so the README download link points at the unversioned `blob/main` file with no matching checksum; the GitHub repo description still says 67 checks and 7 frameworks.

### Integrations and data flows
- Collectors: WMI, registry, services, event logs, LDAP/ADSI, `auditpol`, `netsh`, `net`, `netstat`, `dsregcmd`, Defender/BitLocker cmdlets.
- PS1-only: WinRM fleet, NinjaRMM/Datto/ConnectWise Automate/Syncro/HaloPSA fields, Microsoft Graph via `Invoke-MgGraphRequest` (`NetworkSecurityAudit.ps1:2160`), CISA KEV feed with cache (`:4462-4520`), HardeningKitty/Policy Analyzer/STIG CKL import (`:14720`), remediation with rollback manifest (`:1095`).
- C#-only: waiver lifecycle store, OSCAL POA&M, DefectDojo, CMMC/SPRS report (`Scoring/SprsScoreEngine.cs`, `Export/CmmcReportGenerator.cs`).

## Competitive Landscape

**PingCastle (Netwrix).** 4.0.0.20 (2026-08-11) added `--json` healthcheck export and fixed Protected Users enumeration truncating at 1,500 members. Free use is limited to auditing your own domain; service-provider licensing is about $3,449/year (Likely, Capterra) and a licensing-clarity issue has been open since 2025-06-24. Learn: rule-based healthcheck with maturity levels and JSON output. Avoid: the third-party-use license wall, which is exactly where this project wins.

**Semperis Purple Knight and Forest Druid.** Purple Knight scans 185+ indicators across AD, Entra ID and Okta, point-in-time, as the on-ramp to paid DSP; third-party consulting use needs a paid license (Likely). Forest Druid does inside-out Tier-0 path discovery. Learn: indicator breadth and Tier-0 framing. Avoid: closed binaries and lead-gen gating.

**Certipy 5.1.0, Locksmith2, PSPKIAudit.** Certipy (2026-06-23) defines the working ESC1-ESC16 catalog including ESC15 (EKUwu, CVE-2024-49019) and ESC16 (CA-wide security-extension disable). Locksmith2 (build 2026-09-07) pairs each ESC finding with fix and revert scripts. Learn: adopt the ESC matrix for C# CF01, which today only lists CAs. Avoid: auto-remediation of PKI by default.

**Testimo and GPOZaurr (Evotec, both released 2026-09-20).** Pester-based AD health checks and GPO hygiene (orphaned GPOs, SYSVOL/AD version drift, missing Authenticated Users read, GPP content). Learn: automated GPO hygiene for the Policies category, which is currently all questionnaire. Avoid: module-dependency sprawl for the 5.1 artifact.

**ADeleg, PowerHuntShares, Adalanche, BloodHound CE v9.7.0 (2026-09-10).** ADeleg diffs ACEs against `defaultSecurityDescriptor` to surface only real delegations; PowerHuntShares defines excessive share ACEs by principal (Everyone, Authenticated Users, BUILTIN\Users, Domain Users, Domain Computers). Learn: low-noise ACL analysis and SID-based share rules. Avoid: building a graph product before check accuracy is fixed.

**PrivescCheck (2026-09-27) and Seatbelt.** Local misconfiguration catalogs (service ACLs, unquoted paths, credential files). Learn: endpoint check ideas. Avoid: offensive framing in client reports.

**Monkey365 v1.0.0 (2026-09-25), Maester 2.2.x, ScubaGear, M365-Assess, Zero Trust Assessment, CIPP 10.7.0.** The M365 side is crowded and PowerShell 7-leaning. M365-Assess exports remediation as GitHub Issues markdown and Jira CSV; CIPP's standards engine defines a baseline once and re-checks every tenant; Monkey365 is moving rules into data (issue #133). Learn: file-based remediation ticket export and per-client drift since last run. Avoid: tenant write actions and PS7-only module requirements in the 5.1 artifact.

**Kaseya RapidFire Network Detective Pro and Compliance Manager GRC.** Closest MSP assessment competitor: agentless collectors, branded reports, quote-only pricing. Verified reviews cite 12+ hour reports on large clients, false positives, and QA decline after acquisition. Learn: the prospect-to-client report workflow. Avoid: collector sprawl and per-seat pricing.

**ConnectSecure, Galactic Scan, Huntress ISPM, Tenable Nessus/Identity Exposure, CIS-CAT Pro.** Identity posture, ransomware readiness and multi-framework scoring are paywalled across the board (Huntress ISPM $4/identity/month, Nessus Professional $4,790/year, CIS SecureSuite from $3,600/year). None of the MSP-facing products surfaced OSCAL, SARIF or OCSF export. Learn: report cards and recurring-scan deliverables. Avoid: redistributing CIS benchmark text.

**Microsoft Secure Score, Exposure Management, Defender for Identity.** Defender for Identity added dMSA object auditing and an ESC15 posture assessment; its assessment list is a useful checklist source. Learn: check ideas. Avoid: dependence on Microsoft licensing for local checks.

## Reported Issues

The repository has no open or closed issues, no pull requests, and an empty Discussions tab (checked 2026-09-29 with `gh issue list`, `gh pr list`, `gh api .../discussions`). Real-world signal therefore comes from the code, the git history and the failing gates:

- Last 200 commits: fix commits concentrate in `ViewModels/MainViewModel.cs` (24), `App.xaml.cs` (20), `NetworkSecurityAudit.ps1` (16) and `Data/FrameworkMappings.cs` (7). Recurring themes are mapping drift (a 2026-07-08 burst of realign commits and 36626ed removing fabricated STIG scoring), escaping/privacy fixes (11 commits), OSCAL/SARIF validity (4), scoring-formula churn (7) and check-parsing false positives (12). The false-positive theme continues: see Security, Privacy, and Reliability.
- Release trust: the README banner and quick-start links 404ed until the 2026-09-28 docs fixes (89928ae, 3e98966) because v5.4.0 was never published.

## Security, Privacy, and Reliability

### Wrong or constant verdicts (Verified in code)
- `Checks/LoggingMonitoring/LM02_SiemCheck.cs:30-35`: the agent list includes `EventLog`, `Wecsvc` and `Sense`, which exist on every Windows host, so LM02 passes everywhere.
- `Checks/NetworkPerimeter/NP02_OpenPortsCheck.cs:15-31`: 135, 445 and 5985 are "high risk" and listen by default, and `:54` matches the English `LISTENING`. NP02 fails nearly every host, including hosts that fleet mode itself needs WinRM on.
- `Checks/EndpointSecurity/EP01_AvEdrCheck.cs:191-192`: the `Windows Advanced Threat Protection` key exists on all Windows 10+ systems and `Palo Alto Networks` may be GlobalProtect only; passive-mode Defender next to third-party AV is reported as a failure (`:53-60`).
- `Checks/IdentityAccess/IA06_PamCheck.cs:58-95`: LAPS coverage filters on confidential attributes (`msLAPS-EncryptedPassword=*`, `ms-Mcs-AdmPwd=*`), which return nothing to readers without the control-access right; the `catch` turns access-denied into "not deployed"; `Math.Max` is used as a union.
- `Checks/EndpointSecurity/EP04_PatchComplianceCheck.cs:18-28`: build 19045 (Windows 10 22H2, end of support 2025-10-14) is listed as current and 26200 (Windows 11 25H2) is missing. EP04 is catalogued as "Patch compliance + CISA KEV" but has no KEV logic.
- `Data/CheckCatalog.cs` EP10 is `CheckType.AD`, so `CheckRunner.cs:144` skips its local end-of-life logic on workgroup hosts; the lifecycle list stops at Server 2012 R2.
- `IA11_KerberosEncryptionCheck.cs:123-156`: accounts with no `msDS-SupportedEncryptionTypes` are counted but never failed, the domain object's etype attribute is read as if meaningful, computer and gMSA accounts are skipped.
- `IA12_DmsaCheck.cs:162-169`: BadSuccessor risk is gated on domain functional level, but the precondition is a single Server 2025 DC; only the Managed Service Accounts container ACL is inspected, with English group names.
- `CF01` (C#) lists AD CS CAs and prints "Review templates for ESC1-ESC8" without evaluating any template (`CF01:380-404`). `EP03:286-295` labels the LSA `AllowTgtSessionKey` value as "Kerberos delegation".
- PS1 `NetworkSecurityAudit.ps1:6001-6004`: `UEFICA2023Status` is switched on integers although Microsoft documents string states (NotStarted, InProgress, Updated), and `AvailableUpdates` is read from a `Servicing\WindowsUEFICA2023` subkey instead of `HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot`.
- PS1 `:15067-15078` (and `:10860-10873`): `Enable-AuditPolicies` passes category names ("Account Logon", "System", ...) to `auditpol /set /subcategory:`, so six of seven calls fail.
- PS1 `:6664`: Print Spooler "on DC" uses `Caption -match 'Server'` instead of the domain role.

### Scoring integrity (Verified)
- 16 questionnaire checks (BR02-BR05, BR07, BR08, CF03, NA04, NA07, NP10, PS01-PS06) always return `Partial`, which earns 0.5 credit in `Scoring/RiskScoreEngine.cs:22-26`, so Policies & Standards is always 50% in headless runs.
- `App.xaml.cs:706-707` counts `Partial` as passing in the framework exit-code threshold, contradicting the repo rule that Partial is not Met. The PS1 can exclude manual evidence (`:7799-7812`); C# cannot.
- Errors and timeouts still collapse to `NA` (`Models/Enums.cs` has no Error state), which removes failing checks from denominators.
- Catalog `EvidenceMode` tags are exported but not used, and some are wrong (IA04 InterviewRequired, NP01/NP02 ExternalRequired, all automated).

### Resource use and cancellation (Verified)
- Unbounded event log reads with message formatting: `LM05:115`, `BR03:115`, `BR06:95,150` (`maxEvents: 0`, `EventLogQueryHelper.cs:32,57`).
- Headless runs pass `CancellationToken.None` (`App.xaml.cs:440`); timed-out synchronous checks are abandoned, not stopped (`CheckRunner.cs:70-83`); LDAP searches set no `ServerTimeLimit`/`ClientTimeout`.
- `NP03:133` runs `rasphone -h`, a GUI binary, during unattended scans. PS1 PDF export waits without a timeout (`:14438`).
- PS1 exports use non-atomic `Set-Content` (`:12984`, `:13526`, `:14356`), and save-state lacks `-LiteralPath` (`:11881`).

### Locale dependence (Verified)
English group names without RID or nesting in IA01 (`:55`), IA02 (`:76`), CF04 (`:77`), IA12 (`:121-124`). English output parsing in `LM03:149,156`, `CF05:18,128,136`, `CF07:210`, `NP02:54`, `NP03:123`, `NA03:211-223`, `NA07:157-163`, `NP01/NP05/NP06` netsh fallbacks, `NA02:156`, `EP06:275-279`, and PS1 `:4576`, `:4865-4868`, `:6219-6222`.

### Supply chain (Verified unless marked)
- Dependency gate fails on 2026-09-29: System.* packages 10.0.9 vs 10.0.12, Microsoft.NET.Test.Sdk and TestPlatform 18.7.0 vs 18.10.1, coverlet.collector 10.0.1 vs 10.1.0, Newtonsoft.Json 13.0.3 vs 13.0.4, xunit.runner.visualstudio 3.1.5 vs 4.0.0, xunit.analyzers 1.18.0 vs 2.1.0. Exceptions in `tools/dependency-health-exceptions.json` pin an exact `latest_version`, so they stopped matching when upstream shipped the next patch, before their 2026-09-30 expiry.
- .NET 10.0.12 (2026-09-08) fixed seven CVEs in the shared runtime. The C# build is framework-dependent, so the patch only reaches users through their installed Desktop Runtime; nothing in diagnostics or the release manifest states a minimum runtime.
- `xunit.runner.visualstudio` 4.x and `xunit.analyzers` 2.x belong to the xunit v3 line; bumping them independently of a v3 migration is not safe (Likely, xunit.net).
- No Authenticode signature. Microsoft Artifact Signing is $9.99/month for 5,000 signatures and accepts individual developers; SignPath Foundation signs OSI projects free under its own certificate; EV no longer grants instant SmartScreen reputation since 2024-08 (Likely).
- PS1 Graph calls depend on `Microsoft.Graph.Authentication` (`:2160`, `:15154`); Graph PowerShell v3, planned for Q4 2026, drops Windows PowerShell 5.1 (Likely, endpointweekly.com).

### Platform deadlines driving check updates
| Change | Date | Affects | Confidence |
|---|---|---|---|
| Microsoft KEK CA 2011 / UEFI CA 2011 / Windows Production PCA 2011 expiry; `UEFICA2023Status` string states; events 1808 success, 1801 failure | 2026-06-24 / 2026-06-27 / 2026-10-19 | new Secure Boot check | Verified |
| DC default assumed etypes change for accounts without `msDS-SupportedEncryptionTypes` (CVE-2026-20833) | mid-2026 (Verified); audit 2026-01, default 2026-04, enforcement 2026-07 with `RC4DefaultDisablementPhase` and KDC events 201-209 (Likely) | IA11 | Verified/Likely |
| Certificate strong mapping full enforcement, `StrongCertificateBindingEnforcement` ignored | 2025-09-09 | AD CS checks | Likely |
| NTLMv1 removed in 24H2/Server 2025; `BlockNtlmv1SSO` audit to enforce, events 4024/4025 | enforce 2026-10 (Likely) | EP03 | Likely |
| Server 2025 DCs require LDAP signing by default; channel binding still "when supported" | Server 2025 GA | new LDAP check | Likely |
| 24H2/Server 2025 SMB signing required; Credential Guard, HVCI and LSA protection on by default | 24H2 GA | EP03, EP08, LM03 | Likely |
| ATT&CK v19: Defense Evasion split into Stealth (TA0005) and Defense Impairment (TA0112); current v19.2 | 2026-04-28 | `Data/MitreMappings.cs` (14 TA0005 references) | Verified |
| Windows 10 ESU year 1 and Server 2012 R2 ESU end; SQL Server 2016 ended 2026-07-14; Office and Exchange 2016/2019 ended 2025-10-14 | 2026-10-13 | EP04, EP10 | Likely |
| CMMC Phase 2 (C3PAO assessments from 2026-11-10) suspended; Level 1/2 self-assessment requirements remain | 2026-07-13 | CMMC report wording | Verified |

### Recovery and rollback needs
- PS1 `Update-ExposureWindows` (`:11596`) carries only Fail entries forward, so one errored run resets exposure age; `resolved_at` is never written.
- PS1 remediation rollback manifests contain hints but there is no restore command, and remediation results never reach HTML/JSON.

## Architecture Assessment

- **AD logic is untestable.** 51 check classes have no test reference, including every AD check; only EP06, CF02 and CF08 have injectable seams. An `IDirectoryReader` (LDAP search, ACL read, RootDSE) and an `ICommandRunner`/event-log seam with recorded fixtures should land before the IA11/IA12/IA06/AD CS fixes so each fix ships with a regression test (repo rule).
- **Status model is too small.** `CheckStatus` needs explicit non-scoring states (unanswered questionnaire, error, timeout) so scoring, exit codes, KPIs and exports stop inferring meaning from `Partial` and `NA`. The existing denominator-safe KPI work (v5.4.0) already has the vocabulary.
- **Catalog metadata drifts from behavior.** `EvidenceMode` should either drive status handling or be validated by a structural test. Catalog compliance strings cite CSF 1.1 categories in 51 lines (`PR.IP`, `PR.AC`, `PR.PT`, `PR.DS`), which CSF 2.0 restructured.
- **External version constants are centralized** in `Export/ExternalVersions.cs` (OCSF 1.8.0, OSCAL 1.2.2, ATT&CK 19.1). ATT&CK should read 19.2 after revalidation; OSCAL 1.2.3 (2026-08-07) is a patch with no model changes; OSCAL 1.2.0 added a Control Mapping model that could later carry framework crosswalks.
- **Parity.** PS1-only: fleet, RMM writes, history/delta, Graph, remediation, KEV, attack paths, AD attack indicators (DCSync, AdminSDHolder ACL, Protected Users, unconstrained delegation), benchmark import, MSP KPIs, manual-evidence exclusion. C#-only: DefectDojo, OSCAL POA&M, CMMC/SPRS, waivers. Neither surface checks RBCD, MachineAccountQuota, Pre-Windows 2000 Compatible Access, DnsAdmins, or LDAP channel binding on remote DCs.
- **Dead code.** `Checks/StubCheck.cs` is unreachable; `Models/AuditOptions.cs:12-19` options `NoRmmWrite`, `NoRegistryWrite`, `ExportJSON`, `ExportCSV`, `ExportJSONL` are never read; the empty Cloud profile exits with code 2, the same code as "failures found".
- **Test stack.** xunit 2.9.3 is the legacy line (v3 plus Microsoft.Testing.Platform is mainstream); Pester 6.0.1 and PSScriptAnalyzer 1.25.0 are current while the harness targets Pester 5.9.0.
- **Category coverage.** Security, testing, reliability, accessibility, i18n (locale parsing), observability (diagnostics, progress states), docs and distribution (release assets, screenshots) and migration/upgrade (status-model change needs save-state migration; ATT&CK tactic split needs mapping migration) all have roadmap items. Plugin ecosystem, mobile and multi-user remain intentionally excluded (see Rejected Ideas); offline behavior is already gated by `-NoInternet` and gets a central gate item.

## Rejected Ideas

- Bumping `xunit.analyzers` to 2.x or `xunit.runner.visualstudio` to 4.x without an xunit v3 migration: they pair with v3 (xunit.net docs). Record dated exceptions instead.
- EV certificate purchase for SmartScreen: EV stopped granting instant reputation in 2024-08 (todesktop.com).
- GitHub artifact attestations: creation needs GitHub Actions, which the repo does not use for builds (docs.github.com).
- Local cosign key-pair signatures: same trust root as `SHA256SUMS.txt` on the same release page; revisit only with a keyless identity or real code signing.
- Executive-summary tone selection (old roadmap): no demand signal in any source.
- Network-wide SMB share sweeping in the PowerHuntShares style: that is a Probing risk tier and conflicts with the read-only local default; fleet mode already covers multiple hosts.
- Automatic AD CS remediation (Locksmith2 style) by default: keep detection plus guidance; existing opt-in remediation rules apply.
- ADRecon-style Excel export: CSV and HTML cover the use case; ADRecon has been inactive since 2024-10-15.
- CIPP-style scheduled standards enforcement across clients: write actions contradict the read-only model.
- Six additional WPF themes in C#: Catppuccin Mocha plus automatic Windows High Contrast is the documented design (README, v5.4.0 CHANGELOG).
- Runtime-loaded community rule packs (Monkey365 issue #133 pattern): supply-chain risk; keep data-only benchmark imports.
- Quick Machine Recovery and Sudo for Windows posture checks: weak mapping to the supported frameworks; low value.
- WMIC removal work: neither surface calls `wmic.exe` (Verified).
- DefectDojo boolean-coercion change (DefectDojo PR #16043): the exporter does not emit `known_exploited`, `fix_available` or `ransomware_used` (Verified).
- Cyber Essentials remap to v3.3 and ISO 27001:2013 cleanup: mappings already say v3.3 and no 2013 references exist (Verified).
- European Accessibility Act work: applies to commercial products and services sold in the EU, not a free desktop tool (levelaccess.com).
- Mobile clients, SaaS storage, default telemetry, PowerShell 7-only production: reaffirmed from the 2026-08-10 pass.

## Sources

### OSS competitors and adjacent tools
- https://github.com/netwrix/pingcastle/releases/tag/4.0.0.20
- https://github.com/netwrix/pingcastle/issues/291
- https://github.com/ly4k/Certipy/releases
- https://github.com/jakehildreth/Locksmith2
- https://github.com/GhostPack/PSPKIAudit
- https://github.com/EvotecIT/Testimo
- https://github.com/EvotecIT/GPOZaurr
- https://github.com/mtth-bfft/adeleg
- https://github.com/NetSPI/PowerHuntShares
- https://github.com/lkarlslund/Adalanche
- https://github.com/SpecterOps/BloodHound/releases/tag/v9.7.0
- https://github.com/itm4n/PrivescCheck
- https://github.com/GhostPack/Seatbelt
- https://github.com/silverhack/monkey365/releases/tag/v1.0.0
- https://github.com/silverhack/monkey365/issues/133
- https://github.com/maester365/maester
- https://github.com/cisagov/ScubaGear/pull/2310
- https://github.com/Galvnyz/M365-Assess
- https://github.com/KelvinTegelaar/CIPP
- https://github.com/microsoft/zerotrustassessment
- https://github.com/LuccaSA/PingCastle-Notify
- https://github.com/SwiftOnSecurity/sysmon-config
- https://github.com/olafhartong/sysmon-modular
- https://github.com/palantir/osquery-configuration

### Commercial products and pricing
- https://www.semperis.com/purple-knight/
- https://www.semperis.com/forest-druid/
- https://www.pingcastle.com/terms-and-conditions/
- https://www.capterra.com/p/10052219/PingCastle/
- https://www.rapidfiretools.com/products/network-assessment/
- https://www.capterra.com/p/194232/Network-Detective/reviews/
- https://www.capterra.com/p/194233/Compliance-Manager/reviews/
- https://connectsecure.com/pricing
- https://www.businesswire.com/news/home/20251202055893/en/Syncro-and-CyberDrain-Launch-Snapshot-a-Free-Microsoft-Tenant-Security-Assessment-for-MSPs
- https://www.cisecurity.org/cis-securesuite/pricing-and-categories
- https://underdefense.com/blog/huntress-pricing-guide/
- https://www.totem.tech/free-tools/
- https://petri.com/purple-knight-vs-pingcastle/

### Windows and Active Directory platform
- https://support.microsoft.com/en-us/servicing/os/secure-boot/2025/06/windows-secure-boot-certificate-expiration-and-ca-updates
- https://techcommunity.microsoft.com/blog/windows-itpro-blog/secure-boot-playbook-for-certificates-expiring-in-2026/4469235
- https://media.defense.gov/2025/Dec/11/2003841096/-1/-1/0/CSI_UEFI_SECURE_BOOT.PDF
- https://www.microsoft.com/en-us/windows-server/blog/2025/12/03/beyond-rc4-for-windows-authentication/
- https://4sysops.com/archives/windows-kerberos-rc4-deprecation-what-will-break-in-active-directory-and-how-to-fix-it/
- https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- https://support.microsoft.com/en-us/topic/upcoming-changes-to-ntlmv1-in-windows-11-version-24h2-and-windows-server-2025-c0554217-cdbc-420f-b47c-e02b2db49b2e
- https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/ldap-channel-binding-and-ldap-signing-requirements---server-2025-updates/921536
- https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening
- https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview
- https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch
- https://www.microsoft.com/en-us/windows-server/blog/2025/12/09/microsofts-guidance-to-help-mitigate-critical-threats-to-active-directory-domain-services-in-2025/
- https://learn.microsoft.com/en-us/defender-for-identity/prevent-certificate-enrollment-esc15
- https://techcommunity.microsoft.com/blog/microsoft-security-baselines/windows-11-version-25h2-security-baseline/4456231
- https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-baseline-for-windows-server-2025-version-2602/4496468
- https://www.cisecurity.org/insights/blog/cis-benchmarks-september-2026-update
- https://stigaview.com/products/winserv2025/v1r1/
- https://learn.microsoft.com/en-us/windows/whats-new/extended-security-updates
- https://www.microsoft.com/en-us/sql-server/blog/2026/07/14/sql-server-2016-end-of-support-is-here-plan-your-next-steps/
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog

### Standards and frameworks
- https://attack.mitre.org/resources/versions/
- https://attack.mitre.org/resources/updates/updates-april-2026/
- https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md
- https://d3fend.mitre.org/version/
- https://github.com/usnistgov/OSCAL/releases
- https://www.oasis-open.org/2023/09/22/approved-errata-for-static-analysis-results-interchange-format-sarif-v2-1-0-oasis-standard-published/
- https://csrc.nist.gov/files/pubs/sp/800/171/r3/final/docs/sp800-171r2-to-r3-analysis.xlsx
- https://www.nist.gov/cyberframework
- https://www.cisa.gov/sites/default/files/2025-12/CPG_Report_2.0_508c.pdf
- https://federalnewsnetwork.com/cybersecurity/2026/07/pentagon-suspends-cmmc-phase-two-requirements-launches-review-of-program/
- https://www.acq.osd.mil/asda/dpc/cp/cyber/docs/safeguarding/NIST-SP-800-171-Assessment-Methodology-Version-1.2.1-6.24.2020.pdf
- https://iasme.co.uk/articles/upcoming-changes-to-the-cyber-essentials-scheme-april-2026-update/
- https://owasp.org/www-community/attacks/CSV_Injection

### Dependencies, signing and supply chain
- https://devblogs.microsoft.com/dotnet/dotnet-and-dotnet-framework-september-2026-servicing-updates/
- https://www.nuget.org/packages/microsoft.net.test.sdk
- https://www.nuget.org/packages/CommunityToolkit.Mvvm
- https://xunit.net/docs/getting-started/v3/microsoft-testing-platform
- https://learn.microsoft.com/en-us/dotnet/core/testing/migrating-vstest-microsoft-testing-platform
- https://devblogs.microsoft.com/powershell/announcing-powershell-7-6/
- https://www.powershellgallery.com/packages/PSScriptAnalyzer/1.25.0
- https://endpointweekly.com/blog/microsoft-graph-powershell-v3-drops-windows-powershell-5-1-support.html
- https://azure.microsoft.com/en-us/pricing/details/artifact-signing/
- https://signpath.org/about
- https://www.todesktop.com/blog/posts/windows-apps-psa-ev-certs-do-not-grant-immediate-reputation-anymore
- https://docs.github.com/en/actions/concepts/security/artifact-attestations
- https://cyclonedx.org/specification/overview/

## Open Questions

- Code signing: subscribe to Microsoft Artifact Signing ($9.99/month, identity validation in the owner's name) or apply to SignPath Foundation (free, signs under SignPath's certificate)? This is a spend and identity decision for the owner, and it gates the signing item in `Roadmap_Blocked.md`.
- Which environments are available for live validation (a Server 2025 DC with AD CS, a non-English Windows host, an RMM-managed endpoint, a tenant)? Fixtures cover the default gate, but the AD CS, LDAP, RC4 and locale items need at least one real target before claiming field accuracy.
