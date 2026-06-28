# Research - Network Security Auditor

## Executive Summary

Network Security Auditor is strongest as an MSP-friendly Windows security assessment tool: broad local/AD checks, compliance exports, white-label reporting, and a low-friction PowerShell artifact already put it in a useful gap between AD-only tools and cloud-only posture platforms. The current repo is now a dual-track product: the mature `NetworkSecurityAudit.ps1` path and a .NET 9/WPF C# rewrite under `src/NetworkSecurityAuditor`. The highest-value direction is to make the C# rewrite honest and release-ready before expanding: fix the broken `Cloud` profile behavior, remove stale README/workflow claims, close parity gaps with PowerShell v4.11 automation features, and add external schema/export contracts so downstream MSP/SIEM/GRC consumers can trust upgrades. Top opportunities: fix `ScanProfileType.Cloud` resolving to all 69 local checks; update README release/CI/single-file claims after workflow removal; port C# MSP automation parity for RMM writes, remote fleet mode, history/delta, benchmark import, cloud-assessment import, and remediation dry-run; add GUI export parity for SIEM/CMMC and real theme selection; add Graph-backed Entra/M365 checks using Secure Score, Conditional Access, authentication methods, sign-in activity, and MDE signals; publish JSON schemas and contract fixtures; add benchmark/lifecycle update strategy; add a signed local release artifact flow.

## Product Map

- Core workflows: interactive WPF audit; silent CLI scan and exports; PowerShell single-file RMM deployment; report/dashboard generation; audit state save/load; waiver-based accepted-risk annotation.
- User personas: MSP technician, internal Windows/domain sysadmin, security consultant, CMMC/compliance assessor, security engineer feeding SIEM/GRC/ticketing systems.
- Platforms and distribution: Windows 10/11 and Server, PowerShell 5.1 legacy artifact, .NET 9 WPF rewrite, local builds only, GitHub Releases for installable artifacts.
- Key integrations and data flows: WMI/registry/EventLog/AD/Windows services into `ISecurityCheck`; `CheckResult` into scoring engines; exporters to HTML, JSON, CSV, JSONL, SARIF, OCSF, OSCAL, Intune, DefectDojo, SIEM content packs, CMMC reports, PDF.

## Competitive Landscape

- PingCastle: strong AD risk scoring, Entra ID menu, multi-report console, cartography, and current hotfix-scanner fixes. Learn from its focused health-check flow and report aggregation. Avoid its AD-only center of gravity and non-profit/open-source license limits for MSP monetization.
- Purple Knight: strong closed-source AD/Entra/Okta posture assessment and government-cloud positioning. Learn from hybrid identity breadth and clear remediation workflow. Avoid registration/closed-source friction and lack of white-label MSP reporting.
- Maester: strong open-source M365/Entra test automation with Pester-style custom tests, notifications, multi-tenant reporting, MDE, Azure DevOps, and newer M365 workload coverage. Learn from permission-aware Graph tests and multi-tenant report UX. Avoid becoming cloud-only or requiring hosted workflow execution.
- Prowler: strong multi-provider compliance engine with dashboards, scheduled scans, OCSF/SARIF output, API/UI, and attack paths. Learn from provider matrices, scheduled scan state, and schema-first integrations. Avoid its infrastructure weight for a Windows endpoint/domain tool.
- HardeningKitty: strong CSV/list-driven Windows hardening audit/remediation with backup and GPO generation concepts. Learn from benchmark lists, filters, and reversible hardening manifests. Avoid stale baseline coverage and language/locale fragility.
- Seatbelt: strong modular C# host-survey architecture, remote WMI-capable command groups, and JSON output. Learn from command grouping and remote-safe collection boundaries. Avoid offensive artifact collection that would alarm MSP/client environments.
- Wazuh SCA/CIS-CAT/STIG tools: strong policy-as-data and benchmark evidence models. Learn from explicit expected/actual values and versioned benchmark imports. Avoid requiring agents or licensed benchmark content for the core value path.

## Security, Privacy, and Reliability

- Verified: `src/NetworkSecurityAuditor/Data/ScanProfiles.cs` marks `Cloud` as an empty placeholder, then `Resolve()` treats all empty profiles as all checks. Selecting Cloud in the C# GUI/CLI currently runs local/AD checks, not Graph cloud checks. `tests/NetworkSecurityAuditor.Tests/ScanProfileTests.cs` omits `ScanProfileType.Cloud`, so this false behavior is unguarded.
- Verified: README claims the primary project is a single-file PowerShell tool and includes GitHub Actions badges/workflow examples, while `src/NetworkSecurityAuditor` is now active and commit `3419bcf` removed workflows for local-build-only policy. This is a trust/release documentation bug, not just polish.
- Verified: WPF GUI exports omit SIEM content packs and CMMC reports even though silent CLI supports `--export-siem` and `--export-cmmc`; see `src/NetworkSecurityAuditor/MainWindow.xaml` and `src/NetworkSecurityAuditor/App.xaml.cs`.
- Verified: WPF theme selection is only `"Catppuccin Mocha"` in `src/NetworkSecurityAuditor/ViewModels/MainViewModel.cs`, while the PowerShell README/CLAUDE notes still describe 7 dark themes.
- Verified: `StartScanAsync()` in `src/NetworkSecurityAuditor/ViewModels/MainViewModel.cs` sets every selected profile item `IsRunning = true` in a pre-run loop, so the GUI can show all selected checks as scanning at once rather than the current check.
- Verified: `src/NetworkSecurityAuditor/Export/DashboardGenerator.cs` lists every `*_findings.json` file as a row and has no latest-per-client collapse or trend series, while README promises each client's latest score and score trend.
- Verified: `dotnet list NetworkSecurityAuditor.slnx package --vulnerable` found no vulnerable packages from NuGet. `dotnet list ... --outdated` shows newer CommunityToolkit.Mvvm, Microsoft extension, xUnit, test SDK, and coverlet versions, so dependency drift is maintenance work, not emergency security work.

## Architecture Assessment

- Strong boundaries: `Models`, `Data`, `Checks`, `Scoring`, `Export`, `Services`, and `ViewModels` are cleanly separated; `CheckRunner` has async timeout/cancellation; export classes are isolated and testable.
- Main boundary improvement: profile resolution needs explicit dynamic-profile semantics. Empty arrays currently mean too many things: all checks, AD/local filtered, and cloud placeholder.
- C# parity gaps: `App.xaml.cs` CLI lacks PowerShell v4.11 features such as RMM write manifest/field writes, `-TargetsCsv`, `-BenchmarkImportPath`, `-CloudAssessmentPath`, remediation dry-run, continuous history/delta, `-NoRmmWrite`, `-NoRegistryWrite`, and `-WriteManifestOnly`.
- Export gap: machine-readable output is broad, but there are no committed JSON schemas or golden fixtures for JSON/JSONL/OCSF/OSCAL/SIEM content packs. Export consumers need stable contracts before more fields land.
- UI gap: WPF has useful dense check cards, but export buttons are crowded, no export menu/settings flow exists, SIEM/CMMC are absent, theme selector is not functional, and scan progress state is misleading.
- Test gap: 131 tests pass, but profile tests do not include Cloud semantics, GUI progress state has no unit test, dashboard latest/trend behavior has no fixture, and C# parity flags are not contract-tested.
- Documentation gap: README, roadmap, and research history mix PowerShell-era facts with C# rewrite facts. Future docs should distinguish supported PowerShell artifact behavior from C# rewrite behavior until parity is real.

## Rejected Ideas

- Restore GitHub Actions workflows: rejected because repo policy now requires local builds/tests/releases only; source was commit `3419bcf` and repo instructions.
- Make the C# rewrite cross-platform: rejected because WPF and the audited surfaces are Windows-specific; source was `net9.0-windows` in the csproj.
- Replace the PowerShell artifact immediately: rejected because the PowerShell path still has production MSP features that the C# rewrite lacks.
- Add Okta before Entra/M365: rejected because current code, README, and target MSP use case are Microsoft-first; Purple Knight/Prowler already cover Okta better today.
- Add a Neo4j/BloodHound-style graph backend now: rejected because Prowler/BloodHound show graph value, but this repo first needs correct C# profile/export contracts and lightweight attack-path summaries.
- Native AOT for WPF: rejected because WPF publishing should stay framework-dependent or single-file only when deployment requires it.
- Runtime plugin loading: rejected for now because inspectability and predictable MSP deployment matter more; data-driven benchmark/policy packs are a better first extension point.

## Sources

Competitors:
- https://github.com/netwrix/pingcastle
- https://api.github.com/repos/netwrix/pingcastle/releases/latest
- https://www.semperis.com/purple-knight/
- https://github.com/maester365/maester
- https://api.github.com/repos/maester365/maester/releases/latest
- https://github.com/prowler-cloud/prowler
- https://api.github.com/repos/prowler-cloud/prowler/releases/latest
- https://github.com/scipag/HardeningKitty
- https://api.github.com/repos/scipag/HardeningKitty/releases/latest
- https://github.com/GhostPack/Seatbelt

Standards and platform:
- https://learn.microsoft.com/en-us/graph/api/resources/securescore?view=graph-rest-1.0
- https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy?view=graph-rest-1.0
- https://learn.microsoft.com/en-us/graph/api/resources/authenticationmethods-overview?view=graph-rest-1.0
- https://learn.microsoft.com/en-us/windows-server/get-started/whats-new-windows-server-2025
- https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing
- https://attack.mitre.org/resources/versions/
- https://d3fend.mitre.org/
- https://schema.ocsf.io/classes/compliance_finding
- https://pages.nist.gov/OSCAL/
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- https://www.cisecurity.org/cis-benchmarks
- https://public.cyber.mil/stigs/

Dependencies:
- https://www.nuget.org/packages/CommunityToolkit.Mvvm/8.4.0
- https://www.nuget.org/packages/System.Management/
- https://www.nuget.org/packages/Microsoft.NET.Test.Sdk/
- https://www.nuget.org/packages/xunit/

## Open Questions

- Should the C# rewrite be positioned as an experimental v5 line until PowerShell v4.11 parity is closed, or should README make PowerShell the production artifact and C# a preview?
- What release artifact is intended for the C# rewrite: framework-dependent publish folder, self-contained zip, single-file exe, MSI, or both zip and installer?
