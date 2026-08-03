# Research — Network Security Auditor
Date: 2026-07-09 — replaces all prior research.

## Executive Summary
Network Security Auditor is a Windows security assessment product for MSPs, consultants, and internal administrators, with a mature PowerShell artifact (`NetworkSecurityAudit.ps1`) and a .NET/WPF C# rewrite under `src/NetworkSecurityAuditor` at v5.2.6 on 2026-07-09. Verified highest-value direction: make the C# rewrite durable before treating it as the primary artifact by moving off .NET 9 before its 2026-11-10 support end, restoring C# parity for Cloud and benchmark workflows that already exist or are promised in the PowerShell path, and tightening release/audit evidence so MSP, SIEM, and GRC consumers can trust outputs across upgrades. Top opportunities: .NET 10 LTS migration; C# Graph cloud posture pack; C# benchmark/import parity; release SBOM/provenance; OSCAL POA&M export; Intune STIG baseline import; non-intrusive WPF UI/accessibility smoke tests; completion of already-tracked parser/export/atomic-write defects in `ROADMAP.md`.

## Product Map
- Core workflows: WPF-guided audit, silent CLI scan/export, PowerShell RMM deployment, dashboard/history review, waiver/accepted-risk annotation, CMMC/compliance reporting.
- User personas: MSP technician, Windows/domain administrator, security consultant, CMMC assessor, security engineer feeding SIEM/GRC/ticketing systems.
- Platforms and distribution: Windows 10/11 and Windows Server; PowerShell 5.1 production artifact v4.11.0; .NET 9 WPF rewrite v5.2.6; local build/release flow via `tools/Publish-CSharpRelease.ps1`; GitHub Releases for distributable artifacts.
- Key integrations and data flows: registry/WMI/EventLog/AD/service checks into `ISecurityCheck`; `CheckResult` into scoring engines; exporters to HTML, PDF, JSON, CSV, JSONL, SARIF, OCSF, OSCAL, Intune, DefectDojo, SIEM content packs, and CMMC HTML/JSON; PowerShell imports HardeningKitty, Policy Analyzer, and DISA CKL evidence through `-BenchmarkImportPath`.

## Competitive Landscape
- PingCastle: does focused AD/Entra risk scoring, maturity views, and executive-friendly posture reports well. Learn from opinionated risk categories and fast health-check posture. Avoid AD-only product gravity and licensing friction for MSP/commercial use.
- Purple Knight: does hybrid AD/Entra/Okta posture, clear remediation, and government-cloud messaging well. Learn from permission-aware identity breadth and concise risk communication. Avoid closed-source registration friction and opaque collection behavior.
- Maester and CISA ScubaGear: do Microsoft 365/Entra baseline automation and Graph-backed test evidence well. Learn from Graph permission modeling, cloud skip/not-licensed states, and test-as-policy structure. Avoid making cloud checks depend on hosted CI or forcing cloud-only workflows.
- Prowler: does multi-provider compliance scanning, scheduled scans, schema-first outputs, and OCSF/SARIF-style integrations well. Learn from provider separation, compliance folders, and dashboard/API patterns. Avoid adding infrastructure weight that conflicts with a local Windows/MSP tool.
- HardeningKitty, CIS-CAT, Microsoft Security Compliance Toolkit, Wazuh SCA, Tenable, and Qualys: do policy-as-data, expected/actual evidence, exceptions, and benchmark drift tracking well. Learn from versioned baseline imports and explicit evidence provenance. Avoid bundling copyrighted benchmark content or requiring agents/licensed feeds for core value.
- Seatbelt and PrivescCheck: do modular local Windows enumeration and concise host posture collection well. Learn from collector boundaries and command grouping. Avoid offensive artifact framing or noisy collection that would reduce client trust.
- OSCAL, OCSF, and SARIF ecosystems: do machine-readable evidence, finding lineage, and downstream automation well. Learn from stable schemas and false-positive/risk-adjustment fields. Avoid exporting broad JSON without contract tests and versioned schemas.

## Security, Privacy, and Reliability
- Verified: `src/NetworkSecurityAuditor/NetworkSecurityAuditor.csproj` and `tests/NetworkSecurityAuditor.Tests/NetworkSecurityAuditor.Tests.csproj` target `net9.0-windows`; Microsoft documents .NET 9 as STS with support ending 2026-11-10, while .NET 10 LTS runs until 2028-11-14. The release tool also emits `windows-net9` packages and `.NET 9 Desktop Runtime` install text.
- Verified: `dotnet list NetworkSecurityAuditor.slnx package --vulnerable` reported no vulnerable NuGet packages on 2026-07-09. `dotnet list ... package --outdated` showed package drift: 2026-07-09 available versions include CommunityToolkit.Mvvm 8.4.2, System.* 10.0.9, Microsoft.NET.Test.Sdk 18.7.0, xUnit 2.9.3/runner 3.1.5, and coverlet.collector 10.0.1.
- Verified: `src/NetworkSecurityAuditor/Data/ScanProfiles.cs` intentionally resolves the C# `Cloud` profile to no checks, and tests guard that it must not expand to local/AD checks. This is safer than the prior false-positive behavior but leaves a major C# parity gap versus PowerShell cloud assessment/import work and competitors.
- Verified: `tools/Publish-CSharpRelease.ps1` cleans artifacts, runs tests unless skipped, publishes framework-dependent WPF output, signs if a local certificate exists, zips, hashes, and writes `release-manifest.json`; it does not generate an SBOM or disclose runtime support status in the manifest.
- Verified: `ROADMAP.md` as read on 2026-07-09 still contains stale research logs and completed-history sections, but this research pass preserved the user's append-only rule and added only new incomplete work. Existing P3 items already cover parser bugs, locale-sensitive `netsh` parsing, dsregcmd timeout/leak, Intune enrollment detection, atomic artifact writes, output filename sanitization, culture-invariant export dates, PDF stale-output/deadlock risk, and several PowerShell fleet/privacy defects; new roadmap additions do not duplicate them.
- Likely: any live Graph/Intune/Defender implementation will need explicit privacy classes for tenant IDs, user principal names, device IDs, source paths, and token-like values, because README and PowerShell tests already enforce cloud provenance redaction under `-PrivacyMode`.
- Likely: imported benchmark/STIG evidence needs source/version/provenance fields to remain auditor-grade; bundled exact CIS/STIG benchmark content would create licensing and maintenance risk.

## Architecture Assessment
- Strong boundaries: `Models`, `Data`, `Checks`, `Scoring`, `Export`, `Services`, `Theme`, and `ViewModels` are cleanly separated; 289 xUnit tests passed on 2026-07-09 and `tools/Test-NetworkSecurityAudit.ps1` validated the PowerShell artifact's 69-check contract.
- Main lifecycle risk: the C# rewrite is release-tooling-complete enough to publish, but its target framework and package family are on an STS track close to maintenance end. Migration should land before more C# feature work expands the retest surface.
- Main product boundary gap: Cloud is intentionally disabled in the C# scan profile rather than backed by `CLxx` Graph checks. A new Graph service boundary with offline fixtures is needed before enabling Cloud in GUI or silent CLI.
- Main parity gap: PowerShell v4.11 supports benchmark import, cloud assessment provenance, RMM/fleet workflows, and remediation/dry-run flows that the C# rewrite does not yet fully expose. C# parity should prefer shared structured models and fixture-driven importers over one-off report sections.
- Export/GRC gap: OSCAL assessment-results output exists, but POA&M is not generated as a first-class artifact. CMMC users need a remediation task/risk artifact linked to failed or partial findings, waivers, owners, due dates, and evidence.
- Release trust gap: the C# release manifest has checksums and optional Authenticode status, but no SBOM/SPDX/CycloneDX artifact, no package license inventory, and no runtime lifecycle metadata.
- UI verification gap: static XAML tests exist, and the app supports a test-only `--uia-background` mode, but there is no live WPF UI Automation smoke test that verifies focusable controls, accessible names, scan/export affordances, or non-foreground launch behavior.
- Documentation gap: README distinguishes the production PowerShell artifact from the C# preview, but subsequent C# parity work must keep setup, release, runtime, export, and cloud-permission docs synchronized with actual behavior.

## Rejected Ideas
- Restore GitHub Actions workflows: rejected because repo rules explicitly require local builds/tests/releases and no CI workflow files.
- Replace the PowerShell artifact immediately: rejected because PowerShell v4.11.0 remains the production MSP/RMM path and has automation features the C# rewrite lacks.
- Make the C# app cross-platform: rejected because WPF, Windows security APIs, registry/WMI/EventLog/AD checks, and target users are Windows-specific.
- Import GPL/AGPL code from SharpHound, BloodHound collectors, or ADRecon: rejected because license compatibility and offensive-collection optics conflict with the repo's MIT, MSP-friendly posture.
- Ship bundled full CIS/STIG benchmark catalogs: rejected because licensing/provenance risk is higher than importing user-provided or vendor-exported evidence.
- Add Okta/Google Workspace before Entra/M365: rejected because code/docs as read on 2026-07-09 and the target customers are Microsoft-first; Purple Knight and ScubaGear show those can be later adjacent tracks after Graph parity.
- Add runtime arbitrary plugins before data-driven packs: rejected because deterministic local deployment and inspectability matter more; data-driven import/policy packs are the safer extension route.
- Build a hosted multi-tenant SaaS dashboard before local/offline parity is complete: rejected because the product's trust model is local/offline-friendly reporting for MSPs and admins, not centralized custody of client findings.
- Build a mobile companion app: rejected because the audited evidence sources are Windows registry/WMI/EventLog/AD/WPF surfaces in `NetworkSecurityAudit.ps1` and `src/NetworkSecurityAuditor/NetworkSecurityAuditor.csproj`; mobile would add distribution complexity without improving evidence quality.

## Sources
Competitors and analogous projects:
- https://github.com/netwrix/pingcastle
- https://www.semperis.com/purple-knight/
- https://github.com/SpecterOps/BloodHound
- https://github.com/GhostPack/Seatbelt
- https://github.com/itm4n/PrivescCheck
- https://github.com/scipag/HardeningKitty
- https://github.com/maester365/maester
- https://maester.dev/
- https://github.com/cisagov/ScubaGear
- https://github.com/prowler-cloud/prowler
- https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/index.html
- https://learn.cisecurity.org/cis-cat-lite
- https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10
- https://www.tenable.com/audits
- https://www.qualys.com/apps/security-configuration-assessment

Standards, APIs, and platform:
- https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core
- https://learn.microsoft.com/en-us/graph/api/security-list-securescores?view=graph-rest-1.0
- https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-evaluate?view=graph-rest-1.0
- https://learn.microsoft.com/en-us/graph/api/resources/authenticationmethods-overview?view=graph-rest-1.0
- https://learn.microsoft.com/en-us/intune/device-security/security-baselines/stig-audit-baseline
- https://learn.microsoft.com/en-us/defender-endpoint/api/get-assessment-secure-config
- https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-results/
- https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/poam/
- https://schema.ocsf.io/classes/compliance_finding
- https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
- https://github.com/microsoft/sbom-tool
- https://github.com/CycloneDX/cyclonedx-dotnet

Community signal:
- https://github.com/decalage2/awesome-security-hardening
- https://github.com/PaulSec/awesome-windows-domain-hardening
- https://www.reddit.com/r/activedirectory/comments/1r6kwvd/ad_security_checker_scriptstools/

## Open Questions
- For C# Graph checks, the implementation can proceed with offline fixtures first, but live-mode prioritization still needs a product decision between delegated device-code auth and app-only certificate auth as the first supported tenant connection model.
- For STIG expansion beyond IA11/IA12, the project should decide whether C# remains import-only for authoritative STIG evidence or adds a licensed/operator-supplied STIG catalog path.
