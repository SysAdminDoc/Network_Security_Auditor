namespace NetworkSecurityAuditor.Checks.EndpointSecurity;

using System.Text;
using System.Text.RegularExpressions;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>
/// EP10 - End-of-life software: the local OS, local SQL Server, Office and Exchange installs, and
/// (when domain-joined) the operating systems of enabled AD computers, all judged against the dated
/// <see cref="LifecycleTable"/>. Runs on every host; the AD sweep is added only on domain members.
/// </summary>
public sealed class EP10_EolOsCheck : ISecurityCheck
{
    public string Id => "EP10";

    internal const string AdComputerFilter = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
    private const int MaxEolComputersListed = 20;

    private static readonly string[] UninstallRoots =
    [
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ];
    private static readonly string[] SqlRoots =
    [
        @"HKLM\SOFTWARE\Microsoft\Microsoft SQL Server",
        @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server",
    ];
    private const string ExchangeSetupKey = @"HKLM\SOFTWARE\Microsoft\ExchangeServer\v15\Setup";
    /// <summary>Exchange Server Subscription Edition RTM is 15.2.2562; earlier 15.2 builds are Exchange 2019.</summary>
    internal const int ExchangeSeFirstBuild = 2562;

    internal sealed record InstalledProduct(string Product, string Detail);

    internal sealed record AdComputer(string Name, string? OperatingSystem, string? OperatingSystemVersion);

    internal sealed record EolSnapshot
    {
        public string OsCaption { get; init; } = "";
        public int OsBuild { get; init; }
        /// <summary>Windows 10 ESU license state; only read on Windows 10 22H2.</summary>
        public EsuEnrollment Windows10Esu { get; init; } = EsuEnrollment.NotApplicable;
        public DateOnly? EsuCoversUntil { get; init; }
        public string? EsuDetail { get; init; }
        public IReadOnlyList<InstalledProduct> Products { get; init; } = [];
        public bool DomainJoined { get; init; }
        /// <summary>Null when the directory wasn't queried or the query failed.</summary>
        public IReadOnlyList<AdComputer>? AdComputers { get; init; }
        public string? AdError { get; init; }
    }

    internal sealed record EolAssessment(CheckStatus Status, string Findings, string Evidence);

    public Task<CheckResult> ExecuteAsync(EnvironmentInfo env, AuditOptions options, CancellationToken ct)
    {
        try
        {
            var assessment = Assess(CollectSnapshot(env, ct), DateOnly.FromDateTime(DateTime.Now));
            return Task.FromResult(new CheckResult
            {
                Status = assessment.Status,
                Findings = assessment.Findings,
                Evidence = assessment.Evidence
            });
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.FromError(Id, ex));
        }
    }

    internal static EolAssessment Assess(EolSnapshot snapshot, DateOnly today)
    {
        var sb = new StringBuilder();
        var evidence = new StringBuilder();
        var failures = 0;
        var partials = 0;

        void Count(LifecycleVerdict v, int n = 1)
        {
            if (v.State == LifecycleState.EndOfSupport) failures += n;
            else if (v.State is LifecycleState.EsuCovered or LifecycleState.EsuEligible) partials += n;
        }

        evidence.AppendLine($"[Lifecycle Table] source={LifecycleTable.Source} reviewed={LifecycleVerdict.Format(LifecycleTable.Reviewed)} entries={LifecycleTable.Entries.Count} evaluated={LifecycleVerdict.Format(today)}");
        if (today.DayNumber - LifecycleTable.Reviewed.DayNumber > 365)
            sb.AppendLine($"INFO: The lifecycle table was last reviewed {LifecycleVerdict.Format(LifecycleTable.Reviewed)}. Releases after that date aren't in it.");

        // 1. Local OS
        evidence.AppendLine("\n[Local OS Lifecycle]");
        evidence.AppendLine($"  Caption: {snapshot.OsCaption}");
        evidence.AppendLine($"  Build: {snapshot.OsBuild}");
        var osEntry = LifecycleTable.FindOs(snapshot.OsCaption, snapshot.OsBuild);
        var esu = osEntry?.Key == "win10-22h2" ? snapshot.Windows10Esu : EsuEnrollment.Unknown;
        var osVerdict = LifecycleTable.Evaluate(osEntry, today, esu, snapshot.EsuCoversUntil);
        Count(osVerdict);
        if (snapshot.EsuDetail is not null)
            evidence.AppendLine($"  ESU license: {snapshot.EsuDetail}");
        evidence.AppendLine($"  Verdict: {osVerdict.State}");
        sb.AppendLine(osVerdict.State switch
        {
            LifecycleState.EndOfSupport => $"FAIL: Local OS {osVerdict.Describe(today)}. It gets no security updates.",
            LifecycleState.EsuCovered => $"PARTIAL: Local OS {osVerdict.Describe(today)}. Plan the upgrade before ESU ends.",
            LifecycleState.EsuEligible => $"PARTIAL: Local OS {osVerdict.Describe(today)}.",
            LifecycleState.EndingSoon => $"WARNING: Local OS {osVerdict.Describe(today)}. Plan the upgrade.",
            LifecycleState.Supported => $"Local OS {osVerdict.Describe(today)}.",
            _ => $"INFO: Local OS {snapshot.OsCaption} (build {snapshot.OsBuild}) isn't in the lifecycle table. Confirm it's supported on Microsoft's lifecycle pages.",
        });
        if (osEntry?.Key == "win10-22h2" && osVerdict.State == LifecycleState.EndOfSupport && today <= osEntry.EsuEnd)
            sb.AppendLine("  No Windows 10 ESU license is active. Consumer ESU enrollment through a Microsoft account leaves no license this check can read; if this PC is enrolled that way, record a waiver.");

        // 2. Server and Office products installed on this host
        evidence.AppendLine("\n[Local Products]");
        if (snapshot.Products.Count == 0)
            evidence.AppendLine("  No SQL Server, Office 2016/2019 or Exchange installs found.");
        foreach (var product in snapshot.Products)
        {
            var entry = LifecycleTable.FindProduct(product.Product);
            var verdict = LifecycleTable.Evaluate(entry, today);
            Count(verdict);
            evidence.AppendLine($"  {product.Product} ({product.Detail}): {verdict.State}");
            var line = verdict.State switch
            {
                LifecycleState.EndOfSupport => $"FAIL: {verdict.Describe(today)} ({product.Detail}).",
                LifecycleState.EsuEligible => $"PARTIAL: {verdict.Describe(today)} ({product.Detail}).",
                LifecycleState.EndingSoon => $"WARNING: {verdict.Describe(today)} ({product.Detail}).",
                _ => null,
            };
            if (line is not null)
                sb.AppendLine(line);
        }

        // 3. Enabled AD computers
        evidence.AppendLine("\n[AD Computer OS Distribution]");
        if (!snapshot.DomainJoined)
        {
            evidence.AppendLine("  Skipped: this computer isn't domain-joined.");
        }
        else if (snapshot.AdComputers is null)
        {
            evidence.AppendLine($"  Query failed: {snapshot.AdError ?? "unknown error"}");
            sb.AppendLine("INFO: Couldn't query AD computer objects, so only this host was evaluated.");
        }
        else
        {
            AssessDirectory(snapshot.AdComputers, today, sb, evidence, Count);
        }

        var status = failures > 0 ? CheckStatus.Fail : partials > 0 ? CheckStatus.Partial : CheckStatus.Pass;
        return new EolAssessment(status, sb.ToString().TrimEnd(), evidence.ToString().TrimEnd());
    }

    private static void AssessDirectory(IReadOnlyList<AdComputer> computers, DateOnly today, StringBuilder sb,
        StringBuilder evidence, Action<LifecycleVerdict, int> count)
    {
        var groups = computers
            .Select(c => (Computer: c, Build: LifecycleTable.ParseAdBuild(c.OperatingSystemVersion)))
            .GroupBy(x => (Os: string.IsNullOrWhiteSpace(x.Computer.OperatingSystem) ? "Unknown" : x.Computer.OperatingSystem!, x.Build))
            .Select(g => (g.Key.Os, g.Key.Build, Items: g.Select(x => x.Computer).ToList(),
                Verdict: LifecycleTable.Evaluate(LifecycleTable.FindOs(g.Key.Os, g.Key.Build), today)))
            .OrderByDescending(g => g.Items.Count)
            .ToList();

        evidence.AppendLine($"  Enabled computers: {computers.Count}");
        foreach (var g in groups)
            evidence.AppendLine($"    {g.Items.Count,4} x {g.Os}{(g.Build > 0 ? $" ({g.Build})" : "")}: {g.Verdict.State}");

        var eol = groups.Where(g => g.Verdict.State == LifecycleState.EndOfSupport).ToList();
        var eligible = groups.Where(g => g.Verdict.State == LifecycleState.EsuEligible).ToList();
        var soon = groups.Where(g => g.Verdict.State == LifecycleState.EndingSoon).ToList();
        foreach (var g in groups)
            count(g.Verdict, g.Items.Count);

        sb.AppendLine($"AD: {computers.Count} enabled computers evaluated.");
        if (eol.Count > 0)
        {
            sb.AppendLine($"FAIL: {eol.Sum(g => g.Items.Count)} enabled computer(s) run software past end of support:");
            foreach (var g in eol)
                sb.AppendLine($"  {g.Items.Count} x {g.Verdict.Describe(today)}");
            evidence.AppendLine($"  End-of-support computers (first {MaxEolComputersListed}):");
            foreach (var c in eol.SelectMany(g => g.Items).Take(MaxEolComputersListed))
                evidence.AppendLine($"    {c.Name} | {c.OperatingSystem}");
        }
        if (eligible.Count > 0)
        {
            sb.AppendLine($"PARTIAL: {eligible.Sum(g => g.Items.Count)} enabled computer(s) are past end of support but inside an Extended Security Updates window. Confirm each one is enrolled:");
            foreach (var g in eligible)
                sb.AppendLine($"  {g.Items.Count} x {g.Verdict.Describe(today)}");
        }
        foreach (var g in soon)
            sb.AppendLine($"WARNING: {g.Items.Count} x {g.Verdict.Describe(today)}.");

        var win10 = computers.Count(c => c.OperatingSystem?.Contains("Windows 10", StringComparison.OrdinalIgnoreCase) == true);
        var win11 = computers.Count(c => c.OperatingSystem?.Contains("Windows 11", StringComparison.OrdinalIgnoreCase) == true);
        if (win10 + win11 > 0)
            sb.AppendLine($"Windows 10 to 11 migration: {win11 * 100 / (win10 + win11)}% ({win11}/{win10 + win11} workstations on Windows 11).");
    }

    internal static EolSnapshot CollectSnapshot(EnvironmentInfo env, CancellationToken ct)
    {
        var osEntry = LifecycleTable.FindOs(env.OSCaption, env.OSBuild);
        var esu = EsuEnrollment.NotApplicable;
        DateOnly? coversUntil = null;
        string? esuDetail = null;
        if (osEntry?.Key == "win10-22h2")
            (esu, coversUntil, esuDetail) = EsuLicenseReader.ReadWindows10Esu(ct);

        ct.ThrowIfCancellationRequested();
        var products = CollectProducts();

        IReadOnlyList<AdComputer>? adComputers = null;
        string? adError = null;
        if (env.IsDomainJoined)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                adComputers = QueryAdComputers(ct);
            }
            catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or UnauthorizedAccessException or InvalidOperationException)
            {
                adError = ex.Message.Trim();
            }
        }

        return new EolSnapshot
        {
            OsCaption = env.OSCaption,
            OsBuild = env.OSBuild,
            Windows10Esu = esu,
            EsuCoversUntil = coversUntil,
            EsuDetail = esuDetail,
            Products = products,
            DomainJoined = env.IsDomainJoined,
            AdComputers = adComputers,
            AdError = adError,
        };
    }

    private static List<AdComputer> QueryAdComputers(CancellationToken ct)
    {
        using var entry = new System.DirectoryServices.DirectoryEntry("LDAP://RootDSE");
        var defaultNamingContext = entry.Properties["defaultNamingContext"]?.Value?.ToString();
        if (string.IsNullOrEmpty(defaultNamingContext))
            throw new InvalidOperationException("RootDSE returned no defaultNamingContext.");

        using var searchRoot = new System.DirectoryServices.DirectoryEntry($"LDAP://{defaultNamingContext}");
        using var adSearcher = new System.DirectoryServices.DirectorySearcher(searchRoot)
        {
            Filter = AdComputerFilter,
            PageSize = 1000,
        };
        adSearcher.PropertiesToLoad.AddRange(["name", "operatingSystem", "operatingSystemVersion"]);

        var computers = new List<AdComputer>();
        using var results = adSearcher.FindAll();
        foreach (System.DirectoryServices.SearchResult result in results)
        {
            ct.ThrowIfCancellationRequested();
            computers.Add(new AdComputer(
                First(result, "name") ?? result.Path,
                First(result, "operatingSystem"),
                First(result, "operatingSystemVersion")));
        }
        return computers;
    }

    private static string? First(System.DirectoryServices.SearchResult result, string property) =>
        result.Properties[property] is { Count: > 0 } values ? values[0]?.ToString() : null;

    private static List<InstalledProduct> CollectProducts()
    {
        var products = new List<InstalledProduct>();

        foreach (var root in SqlRoots)
        {
            var instances = $@"{root}\Instance Names\SQL";
            foreach (var instance in RegistryHelper.GetValueNames(instances))
            {
                var id = RegistryHelper.GetValue<string>(instances, instance);
                if (string.IsNullOrWhiteSpace(id)) continue;
                var version = RegistryHelper.GetValue<string>($@"{root}\{id}\Setup", "Version");
                var product = SqlProductName(id, version);
                if (product is not null)
                    products.Add(new InstalledProduct(product, $"instance {instance}, {version ?? id}"));
            }
        }

        var office = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in UninstallRoots)
        {
            foreach (var sub in RegistryHelper.GetSubKeyNames(root))
            {
                var name = RegistryHelper.GetValue<string>($@"{root}\{sub}", "DisplayName");
                if (OfficeProductName(name) is { } officeProduct && office.Add(officeProduct))
                    products.Add(new InstalledProduct(officeProduct, name!));
            }
        }

        var exchange = ExchangeProductName(
            RegistryHelper.GetValue<int>(ExchangeSetupKey, "MsiProductMajor", -1),
            RegistryHelper.GetValue<int>(ExchangeSetupKey, "MsiProductMinor", -1),
            RegistryHelper.GetValue<int>(ExchangeSetupKey, "MsiBuildMajor", -1));
        if (exchange is not null)
            products.Add(new InstalledProduct(exchange, "ExchangeServer\\v15\\Setup"));

        return products;
    }

    /// <summary>Maps a SQL Server instance ID (MSSQL13.MSSQLSERVER) or version (13.0.6300.2) to a product name.</summary>
    internal static string? SqlProductName(string instanceId, string? version)
    {
        var major = 0;
        if (!string.IsNullOrWhiteSpace(version) && int.TryParse(version.Split('.')[0], out var v))
            major = v;
        else if (Regex.Match(instanceId, @"^MSSQL(\d+)\.", RegexOptions.IgnoreCase) is { Success: true } m)
            major = int.Parse(m.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);

        return major switch
        {
            <= 0 => null,
            < 12 => "SQL Server 2012 or older",
            12 => "SQL Server 2014",
            13 => "SQL Server 2016",
            14 => "SQL Server 2017",
            15 => "SQL Server 2019",
            16 => "SQL Server 2022",
            _ => $"SQL Server (version {major})",
        };
    }

    /// <summary>Maps an Uninstall DisplayName to "Office 2016" or "Office 2019"; add-ons and language packs don't count.</summary>
    internal static string? OfficeProductName(string? displayName)
    {
        if (string.IsNullOrWhiteSpace(displayName)) return null;
        var m = Regex.Match(displayName, @"^Microsoft Office\b.*\b(2016|2019)\b", RegexOptions.IgnoreCase);
        if (!m.Success) return null;
        if (Regex.IsMatch(displayName, @"Language Pack|Proofing|MUI|Interop|Shared|Web Components|Update", RegexOptions.IgnoreCase))
            return null;
        return $"Office {m.Groups[1].Value}";
    }

    internal static string? ExchangeProductName(int major, int minor, int build) => (major, minor) switch
    {
        (15, 1) => "Exchange Server 2016",
        (15, 2) when build < 0 => "Exchange Server 2019 or Subscription Edition (build unknown)",
        (15, 2) when build < ExchangeSeFirstBuild => "Exchange Server 2019",
        (15, 2) => "Exchange Server Subscription Edition",
        _ => null,
    };
}
