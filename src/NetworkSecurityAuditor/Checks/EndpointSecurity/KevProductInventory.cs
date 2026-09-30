namespace NetworkSecurityAuditor.Checks.EndpointSecurity;

using System.IO;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using NetworkSecurityAuditor.Services;

/// <summary>Separately serviced Microsoft products on this host, with the binary dates EP04 compares KEV entries against.</summary>
internal sealed record KevProductInventory
{
    public bool ExchangeInstalled { get; init; }
    public DateTime? ExchangeServiceBinaryDate { get; init; }
    /// <summary>Default and named SQL Server engine instances (MSSQLSERVER and MSSQL$*).</summary>
    public int SqlInstanceCount { get; init; }
    /// <summary>The least recently updated instance's sqlservr.exe date.</summary>
    public DateTime? SqlOldestServiceBinaryDate { get; init; }
    public bool IisInstalled { get; init; }
    public bool DotNetFrameworkInstalled { get; init; }
    public bool OfficeInstalled { get; init; }
    public IReadOnlyList<DateTime> OfficeClickToRunBinaryDates { get; init; } = [];
    public bool EdgeInstalled { get; init; }
    public DateTime? EdgeBinaryDate { get; init; }
}

/// <summary>
/// Reads <see cref="KevProductInventory"/> the way the PowerShell EP04 check does: services for Exchange, SQL Server
/// and IIS, the .NET Framework 4 setup key, Office's Click-to-Run configuration or version keys, and Edge's
/// BLBeacon. Server products replace their service binary with each update, so its date is their update date.
/// </summary>
internal sealed class KevProductInventoryReader
{
    internal const string DotNetFrameworkKey = @"HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full";
    internal const string ClickToRunKey = @"HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration";
    internal const string OfficeKey = @"HKLM\SOFTWARE\Microsoft\Office";
    internal const string EdgeBeaconKey = @"HKLM\SOFTWARE\Microsoft\Edge\BLBeacon";
    internal const string ServicesKey = @"HKLM\SYSTEM\CurrentControlSet\Services";

    private static readonly string[] ClickToRunApps = ["WINWORD.EXE", "EXCEL.EXE", "OUTLOOK.EXE", "POWERPNT.EXE"];
    private static readonly Regex OfficeVersionKey = new(@"^\d+\.\d+$", RegexOptions.CultureInvariant);
    private static readonly Regex QuotedImage = new("^\\s*\"([^\"]+)\"", RegexOptions.CultureInvariant);
    private static readonly Regex BareImage = new(@"^\s*(\S+\.exe)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private readonly IRegistryReader _registry;
    private readonly Func<IReadOnlyList<string>> _serviceNames;
    private readonly Func<string, DateTime?> _fileDate;
    private readonly Func<string, string?> _environment;

    internal KevProductInventoryReader(
        IRegistryReader? registry = null,
        Func<IReadOnlyList<string>>? serviceNames = null,
        Func<string, DateTime?>? fileDate = null,
        Func<string, string?>? environment = null)
    {
        _registry = registry ?? SystemRegistryReader.Instance;
        _serviceNames = serviceNames ?? InstalledServiceNames;
        _fileDate = fileDate ?? FileDate;
        _environment = environment ?? Environment.GetEnvironmentVariable;
    }

    public KevProductInventory Read()
    {
        var services = _serviceNames();
        var exchange = services.Where(n => n.Equals("MSExchangeIS", StringComparison.OrdinalIgnoreCase)).ToList();
        var sql = services.Where(IsSqlEngineService).ToList();

        var clickToRun = _registry.KeyExists(ClickToRunKey);
        var officeVersions = _registry.GetSubKeyNames(OfficeKey).Any(OfficeVersionKey.IsMatch);
        var clickToRunDates = new List<DateTime>();
        var installPath = clickToRun ? _registry.GetValue<string>(ClickToRunKey, "InstallationPath") : null;
        if (!string.IsNullOrWhiteSpace(installPath))
        {
            foreach (var app in ClickToRunApps)
            {
                if (_fileDate(Path.Combine(installPath, "root", "Office16", app)) is DateTime date)
                    clickToRunDates.Add(date.Date);
            }
        }

        var edgeVersion = _registry.GetValue<string>(EdgeBeaconKey, "version");
        DateTime? edgeDate = null;
        if (!string.IsNullOrEmpty(edgeVersion))
        {
            foreach (var root in new[] { _environment("ProgramFiles(x86)"), _environment("ProgramFiles") })
            {
                if (string.IsNullOrEmpty(root))
                    continue;
                if (_fileDate(Path.Combine(root, "Microsoft", "Edge", "Application", "msedge.exe")) is DateTime date)
                {
                    edgeDate = date.Date;
                    break;
                }
            }
        }

        return new KevProductInventory
        {
            ExchangeInstalled = exchange.Count > 0,
            ExchangeServiceBinaryDate = OldestServiceBinaryDate(exchange),
            SqlInstanceCount = sql.Count,
            SqlOldestServiceBinaryDate = OldestServiceBinaryDate(sql),
            IisInstalled = services.Any(n => n.Equals("W3SVC", StringComparison.OrdinalIgnoreCase)),
            // Matches the PowerShell Get-ChildItem test, which lists the key's subkeys (1033 and the like).
            DotNetFrameworkInstalled = _registry.GetSubKeyNames(DotNetFrameworkKey).Length > 0,
            OfficeInstalled = clickToRun || officeVersions,
            OfficeClickToRunBinaryDates = clickToRunDates,
            EdgeInstalled = !string.IsNullOrEmpty(edgeVersion),
            EdgeBinaryDate = edgeDate,
        };
    }

    /// <summary>The default instance (MSSQLSERVER) and named instances (MSSQL$NAME).</summary>
    internal static bool IsSqlEngineService(string name) =>
        name.Equals("MSSQLSERVER", StringComparison.OrdinalIgnoreCase)
        || name.StartsWith("MSSQL$", StringComparison.OrdinalIgnoreCase);

    /// <summary>The executable in a service ImagePath: the quoted path, or the first token ending in .exe.</summary>
    internal static string? ExecutableFromImagePath(string? imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath))
            return null;
        var quoted = QuotedImage.Match(imagePath);
        if (quoted.Success)
            return quoted.Groups[1].Value;
        var bare = BareImage.Match(imagePath);
        return bare.Success ? bare.Groups[1].Value : null;
    }

    private DateTime? OldestServiceBinaryDate(IEnumerable<string> services)
    {
        DateTime? oldest = null;
        foreach (var name in services)
        {
            var exe = ExecutableFromImagePath(_registry.GetValue<string>($@"{ServicesKey}\{name}", "ImagePath"));
            if (exe is null)
                continue;
            if (_fileDate(Environment.ExpandEnvironmentVariables(exe)) is DateTime date && (oldest is null || date.Date < oldest))
                oldest = date.Date;
        }
        return oldest;
    }

    private static IReadOnlyList<string> InstalledServiceNames()
    {
        ServiceController[] services;
        try
        {
            services = ServiceController.GetServices();
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return [];
        }
        try
        {
            return services.Select(s => s.ServiceName).ToList();
        }
        finally
        {
            ServiceControllerDisposal.DisposeAll(services);
        }
    }

    private static DateTime? FileDate(string path)
    {
        try
        {
            return File.Exists(path) ? File.GetLastWriteTime(path).Date : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }
}
