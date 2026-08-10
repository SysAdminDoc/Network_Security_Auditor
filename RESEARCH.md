# Research — Network Security Auditor
Date: 2026-08-10 — replaces all prior research.

## Executive Summary

Network Security Auditor is a Windows-first, read-only security posture tool with two deliberately different delivery surfaces: a dependency-light PowerShell 5.1 artifact for RMM/jumpbox use and a .NET 10 WPF/MVVM workstation application for guided scans, state, history, and rich exports. Its strongest shape is local execution with broad evidence collection, privacy-mode export sanitization, fleet/reporting foundations, and a growing normalized export surface. The highest-value direction is to make every result explainable and repeatable across prerequisites, benchmark provenance, privacy handling, exceptions, and successive runs before expanding check count or adding a hosted service.

Priority opportunities, excluding work already present in the active roadmap:

1. Finish the open 2026-08-10 correctness, fleet, export, Graph-retry, and accessibility findings already listed in `ROADMAP.md`.
2. Turn the existing GUI-only preflight and scattered CLI status into a non-invasive diagnostic profile that explains exactly why a check is ready, degraded, or blocked.
3. Make data handling, benchmark provenance, and exception disposition visible and machine-verifiable in every export.
4. Complete the existing Graph, continuous-history, fleet, remediation, and schema initiatives with denominator-safe metrics and single-flight unattended-run behavior.
5. Harden local releases with an independently executable verifier and a package-freshness/vulnerability gate; the current release script already emits CycloneDX, checksums, and a manifest, so the gap is verification and policy rather than SBOM generation.
6. Preserve the dark premium default while supporting Windows high-contrast resources and a localization-neutral string boundary.

The current local baseline is healthy: on 2026-08-10, `dotnet test .\\NetworkSecurityAuditor.slnx --no-restore -c Release` passed 384 tests, the Pester suite passed 63 tests, the release gate passed 69 checks, and `dotnet list ... package --vulnerable --include-transitive` reported no vulnerable packages. The same package inspection reported patch drift: the three direct `System.*` 10.0.9 references have 10.0.10 available, and `Microsoft.NET.Test.Sdk` 18.7.0 has 18.8.1 available. That makes release discipline and regression fixtures more urgent than a wholesale architecture rewrite.

## Product Map

### Core workflows

- A technician launches the PowerShell artifact locally or through RMM, selects a profile, and receives HTML/JSON/CSV/SARIF/OSCAL/SIEM-style outputs plus optional history, RMM, fleet, benchmark, and cloud-import data.
- A workstation user opens the WPF application, runs local checks, reviews category/check evidence, edits notes and remediation ownership, saves/loads state, compares runs, and exports reports.
- An MSP or auditor imports multiple result files, benchmark/STIG/cloud artifacts, or fleet targets and produces client-facing summaries and dashboards.
- A release operator builds the C# artifact locally with `tools/Publish-CSharpRelease.ps1`, which runs tests and produces a Windows/.NET 10 package, CycloneDX SBOM, checksum file, and release manifest.

### User personas

- MSP technician or vCISO: needs quick, repeatable, privacy-safe client posture and trend outputs from a jumpbox.
- Windows/AD administrator: needs local evidence, explicit prerequisites, and remediation guidance without an agent or default write behavior.
- Security/compliance auditor: needs benchmark version, source, framework mapping, evidence, exception/disposition history, and portable OSCAL/SARIF/CSV/JSON artifacts.
- Release/support operator: needs deterministic diagnostics, bounded failures, dependency visibility, and artifact verification without a hosted control plane.

### Platforms and distribution

- Windows 10/11 and Windows Server are the supported operating systems in `README.md`.
- The legacy production surface is one `NetworkSecurityAudit.ps1` file targeting Windows PowerShell 5.1; the C# rewrite targets `net10.0-windows` and requires the .NET 10 Desktop Runtime.
- Distribution is local and offline-friendly by design. There is no `.github` workflow or hosted service in this repository; local PowerShell/.NET gates and the release script are the operational path.

### Key integrations and data flows

- Local collectors cross WMI, registry, services, event logs, Defender, BitLocker, SMB, AD/RSAT, `dsregcmd`, and PowerShell command output.
- Remote/fleet paths use WinRM/PowerShell remoting and write per-target plus aggregate artifacts.
- Import paths accept benchmark, STIG/Intune, cloud-assessment, saved-state, and prior-result files; all are trust boundaries and require bounded parsing and explicit degraded states.
- Export paths fan one normalized result set into HTML/PDF/JSON/JSONL/CSV/SARIF/Navigator/OCSF/OSCAL/POA&M/Intune/DefectDojo/CMMC/SIEM and dashboard formats.
- Microsoft Graph is a planned/partial PowerShell cloud path with an active `CL01`–`CL12` design in `ROADMAP.md`; the C# cloud profile is intentionally not yet enabled.

## Competitive Landscape

### PingCastle

PingCastle demonstrates the value of a fast domain healthcheck, maturity/context framing, report history, consolidation, and a management-facing explanation of risk. Network Security Auditor should adopt durable posture context and source-aware trend views while retaining its local one-file deployment. It should avoid copying a commercial centralized-service model or implying that a score replaces evidence.

### Maester and CISA SCuBA/ScubaGear

Maester treats Microsoft 365 security as test automation: checks are customizable, results are exportable, notifications and CI are supported, and the 2026 native-test RFC explicitly calls for structured prerequisites, license/cloud metadata, skip reasons, parallelism, and migration compatibility. ScubaGear supplies an authoritative M365-baseline orientation. Network Security Auditor should keep check metadata close to execution and make prerequisites/skip reasons first-class, but should not require PowerShell 7 modules or a hosted CI service for its Windows PowerShell 5.1 artifact.

### Prowler

Prowler shows the product value of versioned check/compliance catalogs, a local dashboard, bounded scan queueing, cross-provider output, and release-level SBOM/provenance attestations. The local tool should borrow catalog versioning, single-flight behavior, and verifiable artifacts. It should avoid expanding into a cloud SaaS control plane or adopting provider breadth that does not fit Windows/AD evidence.

### Wazuh, HardeningKitty, Security Compliance Toolkit, and OpenSCAP

These tools establish the machine-readable policy pattern: an expected setting, observed value, applicability, evidence, source, and remediation can be represented as data and tested independently of UI. HardeningKitty also exposes the operational importance of signed/stable content and language/platform caveats. Network Security Auditor should strengthen its existing benchmark metadata/import path with integrity and licensing provenance; it should keep automatic hardening opt-in and preserve its read-only default.

### CIS-CAT Pro, Qualys SCA, and Tenable compliance

Commercial products make benchmark version/revision, target prerequisites, exceptions, history, remediation, and report provenance visible to operators. They also warn that credentials, audit-file scope, and oversized policy sets affect completeness. Network Security Auditor should expose these facts in diagnostics, findings, exceptions, and exports without requiring a server, scheduler SaaS, or proprietary benchmark redistribution.

### M365-Assess, Guerrilla, and Microsoft Zero Trust Assessment

These adjacent tools are the clearest model for this repository’s audience: read-only execution, self-contained reports, explicit authentication/permission matrices, compatibility and troubleshooting documentation, sovereign-cloud guidance, PII-scrubbed examples, and local/no-telemetry posture. Guerrilla’s comparison semantics are especially relevant: a check that becomes unavailable must not look unchanged, and partial/crashed runs must not poison the baseline. Network Security Auditor should add those guarantees to its existing Graph/history work while keeping a Windows PowerShell 5.1-compatible deployment path.

### BloodHound/OpenGraph

BloodHound demonstrates the leap from independent settings to relationships and paths across identity, directory, cloud, and code systems. This is a Later opportunity for a bounded relationship-evidence export, not an immediate attack-path replacement: the current catalog produces findings and framework mappings, not a graph of subjects, edges, and reachability claims.

## Security, Privacy, and Reliability

- The current C# waiver model in `src/NetworkSecurityAuditor/Models/RiskWaiver.cs` stores one active record per check with justification, approver, and expiration, but no immutable approval/revocation history or recertification state. The POA&M exporter can carry waiver properties, but disposition governance is not yet a lifecycle.
- `src/NetworkSecurityAuditor/Services/PreflightChecker.cs` returns seven GUI-oriented pass/details rows. `App.xaml.cs:315-342` prints a small environment summary in silent mode, but there is no bounded diagnostic artifact that explains runtime, output, browser/PDF, remoting, Graph, or import readiness.
- C# privacy redaction is centralized at `App.xaml.cs:446-454` and `Export/PrivacyExportSanitizer.cs`; the PowerShell artifact has `ConvertTo-PrivacySafeObject`, `ConvertTo-RedactedText`, and exporter-specific redaction. The design is materially safer after the recent hardening, but the output contract does not yet declare a uniform data classification/redaction manifest to the consumer.
- `Data/BenchmarkMetadata.cs` validates schema, source URL, version, review date, stale period, supported OS/builds, and covered check IDs. It does not represent a digest, signature/verification status, license/redistribution status, or the exact imported content bytes.
- `tools/Publish-CSharpRelease.ps1` emits a ZIP, CycloneDX 1.5 SBOM, `SHA256SUMS.txt`, and `release-manifest.json`, and can Authenticode-sign PE files when a local certificate exists. It does not provide a separate supported verifier that checks the bundle end-to-end or distinguishes local signing from an external attestation.
- Microsoft Graph requires least-privilege permission selection, and app-only access is broader/more powerful than delegated access. The active Graph roadmap already specifies permission bundles and throttling; implementation must retain that boundary and never persist tokens, headers, device codes, or client secrets.
- There is no default telemetry or hosted multi-tenant datastore. That is a product strength for sensitive audits and should remain explicit in documentation and tests.

Recovery priorities are: prevent partial runs from becoming baselines, preserve migration paths for existing state/history, bound import and crash-log storage, make lock/timeout outcomes explicit, and ensure every export can be tied to a catalog/policy/content version and privacy mode.

## Architecture Assessment

- The C# rewrite has useful boundaries (`Checks`, `Data`, `Services`, `Export`, `ViewModels`) and substantial xUnit coverage. `MainViewModel` still contains many dialog-specific export/save methods, while `App.xaml.cs` owns headless orchestration; the active audit findings already cover the immediate busy/error and shutdown defects. New work should add shared contracts around those boundaries rather than move code for its own sake.
- The PowerShell artifact remains a very large single file containing collectors, UI, importers, exporters, scoring, history, and RMM behavior. Preserve the single-file release promise; future policy/content and string catalogs should be generated or embedded without introducing arbitrary runtime code loading.
- Check metadata is split between C# catalog classes/JSON, PowerShell hashtables, framework/MITRE maps, and imported benchmark data. The existing roadmap’s catalog/schema work should be extended with provenance and compatibility validation, not replaced by a second plugin system.
- The current dashboard (`Export/DashboardGenerator.cs`) computes latest client/host rows, score, ransomware score, critical/fail counts, stale state, and score trend. It has no denominator-safe coverage/remediation-aging KPI model and currently renders a Catppuccin-like hard-coded HTML palette separate from the WPF resource dictionary and PowerShell themes.
- Testing is strongest for deterministic C# check/export logic and PowerShell static/fixture behavior. There is no live tenant, real WinRM fleet, enterprise browser/PDF matrix, or signed-release verification fixture in the repository. Add recorded/mock boundary fixtures and headless tests; do not make credentials or network availability part of the default gate.
- `.NET 10` is the correct LTS target through 2028-11-14. Dependency freshness should be handled as a repeatable local release gate because the repository currently has patch drift but no reported vulnerable packages.
- Observability is presently console/GUI logging plus the emerging history/delta model; diagnostics, run locks, KPI denominators, and structured run records should become the support contract. Documentation and distribution should stay in `README.md`, the local release scripts, and machine-readable manifests rather than a hosted operations portal.
- Offline/resilience, migration, and upgrade strategy are first-class constraints: imports need bounded degraded states, existing state/history/waiver formats need versioned migration, and content/catalog hashes must prevent false deltas after an upgrade. Multi-user SaaS, mobile, and runtime plugin ecosystems are intentionally excluded; MSP multi-target operation remains a local batch/reporting workflow.

## Rejected Ideas

- Mobile or cross-platform desktop clients: WPF, WMI, registry, Windows services, RSAT, and PowerShell 5.1 are core constraints; a mobile client would duplicate a different product rather than improve the supported workflow.
- Hosted SaaS/multi-tenant storage and default telemetry: conflicts with the local, privacy-safe, one-file/RMM philosophy and creates a new custody boundary for audit evidence.
- Arbitrary runtime plugins that execute third-party PowerShell or assemblies: increases supply-chain and trust risk; prefer signed/data-only policy packs and explicit built-in adapters.
- Automatic remediation as the default: the repository’s read-only safety model and the risk of domain-managed settings require explicit selection, dry run, before/after evidence, and rollback; existing remediation items remain opt-in.
- Bundling proprietary CIS/STIG benchmark text or silently redistributing licensed content: use source/version/license metadata and user-supplied imports unless redistribution rights are established.
- A full BloodHound replacement in the next cycle: a relationship graph is a different data model and needs carefully bounded identity/edge semantics; only a later, privacy-aware relationship evidence export is recommended.
- PowerShell 7-only production support: adjacent tools benefit from modern modules, but the legacy artifact’s Windows PowerShell 5.1/RMM compatibility is a stated differentiator. PowerShell 7 compatibility can be tested opportunistically, not made a prerequisite.

## Sources

### Direct OSS competitors and adjacent projects

- https://github.com/maester365/maester
- https://github.com/cisagov/ScubaGear
- https://github.com/prowler-cloud/prowler
- https://github.com/prowler-cloud/prowler/releases
- https://github.com/specterops/bloodhound
- https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/index.html
- https://github.com/scipag/HardeningKitty
- https://github.com/openscap/openscap
- https://github.com/Galvnyz/M365-Assess
- https://guerrilla.army/
- https://github.com/PaulSec/awesome-windows-domain-hardening
- https://learn.microsoft.com/en-us/security/zero-trust/assessment/get-started

### Commercial assessment products

- https://www.pingcastle.com/documentation/
- https://www.pingcastle.com/services/enterprise/
- https://www.cisecurity.org/cybersecurity-tools/cis-cat-pro
- https://ciscat-pro-dashboard.docs.cisecurity.org/en/latest/source/Dashboard%20User%27s%20Guide/
- https://docs.tenable.com/nessus/10_9/Content/Compliance.htm
- https://docs.tenable.com/nessus/compliance-checks-reference/Content/CustomItems.htm
- https://www.qualys.com/apps/security-configuration-assessment
- https://docs.qualys.com/en/pa/latest/policies/manage_policies.htm

### Standards and platform guidance

- https://csrc.nist.gov/pubs/sp/800/70/r5/final
- https://csrc.nist.gov/Projects/security-content-automation-protocol/SCAP-Releases/scap-1-3
- https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10
- https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/poam/
- https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-results/
- https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
- https://schema.ocsf.io/classes/compliance_finding
- https://www.w3.org/TR/wcag/
- https://learn.microsoft.com/en-us/windows/apps/design/accessibility/high-contrast-themes
- https://learn.microsoft.com/en-us/graph/permissions-overview
- https://learn.microsoft.com/en-us/graph/throttling
- https://learn.microsoft.com/en-us/entra/identity-platform/app-only-access-primer
- https://cyclonedx.org/specification/overview/
- https://github.com/CycloneDX/cyclonedx-dotnet
- https://github.com/CycloneDX/sbom-utility
- https://dotnet.microsoft.com/en-us/platform/support/policy

### Community, issue, and discussion signals

- https://github.com/maester365/maester/issues/1802
- https://github.com/maester365/maester/discussions/2050
- https://www.reddit.com/r/msp/comments/xg9hd1
- https://www.reddit.com/r/msp/comments/1rus9f2
- https://www.reddit.com/r/sysadmin/comments/1i9rh9n
- https://www.reddit.com/r/sysadmin/comments/1snz0i2
- https://www.reddit.com/r/PowerShell/comments/1sqdmg6
- https://www.reddit.com/r/MAESTER/comments/1v8p6fe
- https://www.reddit.com/r/MAESTER/comments/1v9qxtn

### Academic and engineering research

- https://arxiv.org/abs/2209.08936
- https://arxiv.org/abs/2209.08824
- https://arxiv.org/abs/2112.13175
- https://arxiv.org/abs/2608.02336
- https://arxiv.org/abs/2512.11316

### Dependency, lifecycle, and supply-chain references

- https://github.com/CommunityToolkit/dotnet/releases
- https://www.nuget.org/packages/Microsoft.NET.Test.Sdk
- https://www.nuget.org/packages/System.Management/10.0.0
- https://www.nuget.org/packages/CommunityToolkit.Mvvm
- https://xunit.net/releases/v2/2.9.3
- https://learn.microsoft.com/en-us/powershell/scripting/install/powershell-support-lifecycle?view=powershell-7.6
- https://github.com/GitHub/advisory-database
- https://www.cisa.gov/topics/cyber-threats-and-advisories/sbom/sbomresourceslibrary
- https://www.cisa.gov/sites/default/files/2024-08/SECURING_THE_SOFTWARE_SUPPLY_CHAIN_RECOMMENDED_PRACTICES_FOR_SOFTWARE_BILL_OF_MATERIALS_CONSUMPTION-508.pdf

## Open Questions

- Which Graph authentication boundary is acceptable for the first production cloud release: delegated interactive/device code, app-only, or a separately documented MSP/partner mode? This changes consent UX and permission risk.
- Which benchmark sources may be redistributed as embedded content, versus metadata-only or user-supplied imports? This requires an owner/licensing decision, not more technical research.
- Is a code-signing certificate and/or repository attestation provider available for releases? The verifier can validate unsigned local bundles, but mandatory authenticity claims require that authority.
- Which representative tenant, WinRM fleet, PDF-browser, and RMM environments can be used for opt-in integration validation? Deterministic mocks cover the default gate, but they cannot prove enterprise boundary behavior.
