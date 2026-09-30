namespace NetworkSecurityAuditor.Services;

using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;

/// <summary>One CISA Known Exploited Vulnerabilities entry, trimmed to the fields EP04 reads.</summary>
internal sealed record KevEntry(
    string CveId,
    string VendorProject,
    string Product,
    string VulnerabilityName,
    DateTime? DateAdded,
    DateTime? DueDate,
    string KnownRansomwareCampaignUse);

internal sealed record KevCatalog(string? CatalogVersion, IReadOnlyList<KevEntry> Entries);

/// <summary>
/// The outcome of loading the KEV feed. <see cref="Catalog"/> is null when neither the feed nor a cache
/// could be read. <see cref="SkipReason"/> is <see cref="KevCatalogService.OfflineMode"/> when the run
/// doesn't allow internet access (a cache may still be in use), or <see cref="KevCatalogService.FeedUnavailable"/>
/// when the download failed and there was no cache to fall back on.
/// </summary>
internal sealed record KevCatalogLoad
{
    public KevCatalog? Catalog { get; init; }
    public string Source { get; init; } = "none";
    public string? SkipReason { get; init; }
    public string? Detail { get; init; }
    public double? CacheAgeHours { get; init; }
    public string CachePath { get; init; } = "";
    /// <summary>The catalog had too few entries to be the real feed, so it isn't used.</summary>
    public bool Rejected { get; init; }
    public int MinimumEntries { get; init; } = KevCatalogService.DefaultMinimumEntries;
}

/// <summary>
/// Downloads and caches the CISA KEV JSON feed for EP04. Mirrors the PowerShell EP04 check: a cache younger
/// than 24 hours is used as is, otherwise the feed is downloaded (30 second timeout) and cached when it
/// looks complete. A failed download falls back to the cache whatever its age. With internet access off,
/// nothing is downloaded and the cache is used when one exists. The cache lives under
/// %LOCALAPPDATA%\NetworkSecurityAuditor next to the crash log.
/// </summary>
internal sealed class KevCatalogService
{
    public const string FeedUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    public const string OfflineMode = "OfflineMode";
    public const string FeedUnavailable = "FeedUnavailable";
    public const string CacheFileName = "cisa-kev-cache.json";

    /// <summary>The real feed has well over a thousand entries; fewer than this means a truncated or wrong document.</summary>
    internal const int DefaultMinimumEntries = 100;
    /// <summary>The feed is about 2 MB. Anything past this is refused rather than read into memory.</summary>
    internal const int MaxFeedBytes = 16 * 1024 * 1024;
    internal static readonly TimeSpan DownloadTimeout = TimeSpan.FromSeconds(30);
    internal static readonly TimeSpan CacheFreshFor = TimeSpan.FromHours(24);

    private static readonly Lazy<HttpClient> s_http = new(() => new HttpClient(new SocketsHttpHandler
    {
        AutomaticDecompression = DecompressionMethods.All,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
    })
    {
        Timeout = Timeout.InfiniteTimeSpan,
    });

    private readonly Func<CancellationToken, Task<string>> _download;
    private readonly Func<DateTime> _utcNow;
    private readonly int _minimumEntries;

    public KevCatalogService() : this(null, null, null) { }

    internal KevCatalogService(
        Func<CancellationToken, Task<string>>? download,
        string? cacheDirectory,
        Func<DateTime>? utcNow,
        int minimumEntries = DefaultMinimumEntries)
    {
        _download = download ?? DownloadAsync;
        CachePath = Path.Combine(cacheDirectory ?? DefaultCacheDirectory(), CacheFileName);
        _utcNow = utcNow ?? (() => DateTime.UtcNow);
        _minimumEntries = minimumEntries;
    }

    public string CachePath { get; }

    internal static string DefaultCacheDirectory()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return string.IsNullOrWhiteSpace(localAppData)
            ? Path.Combine(Path.GetTempPath(), "NetworkSecurityAuditor")
            : Path.Combine(localAppData, "NetworkSecurityAuditor");
    }

    public async Task<KevCatalogLoad> LoadAsync(bool offline, CancellationToken ct)
    {
        var cacheAge = CacheAgeHours();

        if (offline)
        {
            var cached = cacheAge is null ? null : TryReadCache();
            return cached is null
                ? Result(null, "none", OfflineMode, "no local KEV cache", cacheAge)
                : Result(cached, $"cache ({FormatHours(cacheAge!.Value)} hours old)", OfflineMode, null, cacheAge);
        }

        if (cacheAge is not null && cacheAge.Value < CacheFreshFor.TotalHours)
        {
            var fresh = TryReadCache();
            if (fresh is not null)
                return Result(fresh, $"cache ({FormatHours(cacheAge.Value)} hours old)", null, null, cacheAge);
        }

        string failure;
        try
        {
            var raw = await _download(ct).ConfigureAwait(false);
            var catalog = Parse(raw);
            if (catalog.Entries.Count >= _minimumEntries)
                TryWriteCache(raw);
            return Result(catalog, "live download", null, null, cacheAge);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            failure = $"download timed out after {DownloadTimeout.TotalSeconds:0}s";
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or JsonException or InvalidDataException or UnauthorizedAccessException)
        {
            failure = ex.Message.Trim();
        }

        var stale = cacheAge is null ? null : TryReadCache();
        return stale is null
            ? Result(null, "none", FeedUnavailable, failure, cacheAge)
            : Result(stale, $"stale cache ({FormatHours(cacheAge!.Value)} hours, download failed)", null, failure, cacheAge);
    }

    private KevCatalogLoad Result(KevCatalog? catalog, string source, string? skipReason, string? detail, double? cacheAge) => new()
    {
        Catalog = catalog,
        Source = source,
        SkipReason = skipReason,
        Detail = detail,
        CacheAgeHours = cacheAge,
        CachePath = CachePath,
        Rejected = catalog is not null && catalog.Entries.Count < _minimumEntries,
        MinimumEntries = _minimumEntries,
    };

    /// <summary>Hours since the cache was written, or null when there is no cache file.</summary>
    private double? CacheAgeHours()
    {
        try
        {
            if (!File.Exists(CachePath))
                return null;
            var hours = (_utcNow() - File.GetLastWriteTimeUtc(CachePath)).TotalHours;
            return Math.Max(0, hours);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private KevCatalog? TryReadCache()
    {
        try
        {
            var info = new FileInfo(CachePath);
            if (!info.Exists || info.Length > MaxFeedBytes)
                return null;
            return Parse(File.ReadAllText(CachePath, Encoding.UTF8));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
        {
            return null;
        }
    }

    private void TryWriteCache(string raw)
    {
        try
        {
            AtomicFileWriter.WriteAllText(CachePath, raw);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The cache only saves a download next time; the check still has the live feed.
        }
    }

    /// <summary>Hours rounded to one decimal the way PowerShell's [math]::Round prints them.</summary>
    internal static string FormatHours(double hours) =>
        Math.Round(hours, 1).ToString(CultureInfo.InvariantCulture);

    /// <summary>Parses the feed document. Throws <see cref="JsonException"/> or <see cref="InvalidDataException"/> when it isn't one.</summary>
    internal static KevCatalog Parse(string json)
    {
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16 });
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("vulnerabilities", out var list)
            || list.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("The KEV document has no vulnerabilities list.");
        }

        var entries = new List<KevEntry>(list.GetArrayLength());
        foreach (var item in list.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object)
                continue;
            entries.Add(new KevEntry(
                Text(item, "cveID"),
                Text(item, "vendorProject"),
                Text(item, "product"),
                Text(item, "vulnerabilityName"),
                Date(item, "dateAdded"),
                Date(item, "dueDate"),
                Text(item, "knownRansomwareCampaignUse")));
        }

        var version = root.TryGetProperty("catalogVersion", out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        return new KevCatalog(version, entries);
    }

    private static string Text(JsonElement item, string name) =>
        item.TryGetProperty(name, out var value) ? value.ValueKind switch
        {
            JsonValueKind.String => value.GetString() ?? "",
            JsonValueKind.Null or JsonValueKind.Undefined => "",
            _ => value.ToString(),
        } : "";

    /// <summary>Feed dates are yyyy-MM-dd; like PowerShell's [datetime] cast they become midnight of that day.</summary>
    internal static DateTime? ParseDate(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        if (DateTime.TryParseExact(value.Trim(), "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var exact))
            return exact.Date;
        return DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed) ? parsed.Date : null;
    }

    private static DateTime? Date(JsonElement item, string name) => ParseDate(Text(item, name));

    private static async Task<string> DownloadAsync(CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(DownloadTimeout);
        using var request = new HttpRequestMessage(HttpMethod.Get, FeedUrl);
        request.Headers.UserAgent.ParseAdd($"NetworkSecurityAuditor/{VersionInfo.Version}");
        request.Headers.Accept.ParseAdd("application/json");
        using var response = await s_http.Value.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength is long length && length > MaxFeedBytes)
            throw new InvalidDataException($"The KEV feed is {length} bytes, over the {MaxFeedBytes} byte limit.");
        await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        return await ReadBoundedAsync(stream, MaxFeedBytes, timeout.Token).ConfigureAwait(false);
    }

    /// <summary>Reads a UTF-8 body, refusing one longer than <paramref name="maxBytes"/>.</summary>
    internal static async Task<string> ReadBoundedAsync(Stream stream, int maxBytes, CancellationToken ct)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = await stream.ReadAsync(chunk, ct).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > maxBytes)
                throw new InvalidDataException($"The KEV feed is over the {maxBytes} byte limit.");
            buffer.Write(chunk, 0, read);
        }
        var text = Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
        return text.Length > 0 && text[0] == ByteOrderMark ? text[1..] : text;
    }

    private const char ByteOrderMark = (char)0xFEFF;
}
