namespace NetworkSecurityAuditor.Services;

using System.Diagnostics.Eventing.Reader;
using System.Globalization;

/// <summary>The event log reads a check makes, so tests can answer them without a live log.</summary>
internal interface IEventLogReader
{
    /// <inheritdoc cref="EventLogQueryHelper.Query"/>
    EventLogReadResult Query(
        string logName,
        string xPathQuery,
        int maxEvents,
        Func<EventLogRecordSnapshot, bool>? formatMessage,
        CancellationToken ct);
}

/// <summary>Reads the local machine's event logs through <see cref="EventLogQueryHelper"/>.</summary>
internal sealed class SystemEventLogReader : IEventLogReader
{
    public static readonly SystemEventLogReader Instance = new();

    private SystemEventLogReader() { }

    public EventLogReadResult Query(
        string logName,
        string xPathQuery,
        int maxEvents,
        Func<EventLogRecordSnapshot, bool>? formatMessage,
        CancellationToken ct) =>
        EventLogQueryHelper.Query(logName, xPathQuery, maxEvents, formatMessage, ct);
}

internal static class EventLogQueryHelper
{
    /// <summary>
    /// The most records one query reads. A busy server can log hundreds of thousands of events in the
    /// lookback window, so every query stops here, newest first, and the check reports its counts as
    /// "at least N" once the cap is reached. A caller may ask for fewer, never more.
    /// </summary>
    public const int MaxEventsPerQuery = 10_000;

    public static string RecentEventsQuery(TimeSpan lookback, string? systemPredicate = null)
    {
        long milliseconds = (long)Math.Ceiling(lookback.TotalMilliseconds);
        string timePredicate = $"TimeCreated[timediff(@SystemTime) <= {milliseconds}]";
        string combinedPredicate = string.IsNullOrWhiteSpace(systemPredicate)
            ? timePredicate
            : $"{timePredicate} and ({systemPredicate})";

        return $"*[System[{combinedPredicate}]]";
    }

    /// <summary>
    /// Reads up to <paramref name="maxEvents"/> records (at most <see cref="MaxEventsPerQuery"/>; zero or less
    /// means the cap), newest first. Messages are rendered only for the records <paramref name="formatMessage"/>
    /// picks, since rendering loads the publisher's message resources. It sees each record once, in read order,
    /// with an empty <see cref="EventLogRecordSnapshot.Message"/>. Every other record keeps an empty message.
    /// </summary>
    public static EventLogReadResult Query(
        string logName,
        string xPathQuery,
        int maxEvents,
        Func<EventLogRecordSnapshot, bool>? formatMessage,
        CancellationToken ct)
    {
        var query = new EventLogQuery(logName, PathType.LogName, xPathQuery)
        {
            ReverseDirection = true
        };

        using var reader = new EventLogReader(query);
        return Collect(reader.ReadEvent, Snapshot, TryFormatDescription, maxEvents, formatMessage, ct);
    }

    /// <summary>Reads without rendering any message. Kept for callers that only need IDs, times and properties.</summary>
    public static List<EventLogRecordSnapshot> Read(
        string logName,
        string xPathQuery,
        int maxEvents,
        CancellationToken ct)
    {
        return [.. Query(logName, xPathQuery, maxEvents, formatMessage: null, ct).Records];
    }

    /// <summary>The read loop, apart from the event log API so tests can drive it with fake records.</summary>
    internal static EventLogReadResult Collect<TRecord>(
        Func<TRecord?> readNext,
        Func<TRecord, EventLogRecordSnapshot> snapshot,
        Func<TRecord, string> formatDescription,
        int maxEvents,
        Func<EventLogRecordSnapshot, bool>? formatMessage,
        CancellationToken ct)
        where TRecord : class, IDisposable
    {
        int cap = EffectiveCap(maxEvents);
        var records = new List<EventLogRecordSnapshot>();

        while (records.Count < cap)
        {
            ct.ThrowIfCancellationRequested();
            using TRecord? record = readNext();
            if (record is null)
                return new EventLogReadResult(records, CapReached: false, cap);

            var item = snapshot(record);
            if (formatMessage?.Invoke(item) == true)
                item = item with { Message = formatDescription(record) };
            records.Add(item);
        }

        // One more read tells a log that holds exactly the cap apart from one that holds more.
        ct.ThrowIfCancellationRequested();
        using TRecord? extra = readNext();
        return new EventLogReadResult(records, CapReached: extra is not null, cap);
    }

    internal static int EffectiveCap(int maxEvents) =>
        maxEvents <= 0 ? MaxEventsPerQuery : Math.Min(maxEvents, MaxEventsPerQuery);

    private static EventLogRecordSnapshot Snapshot(EventRecord record)
    {
        object?[] properties = record.Properties
            .Select(property => property.Value)
            .ToArray();

        return new EventLogRecordSnapshot(
            record.TimeCreated ?? DateTime.MinValue,
            record.ProviderName ?? string.Empty,
            record.Id,
            record.Level,
            record.LevelDisplayName ?? string.Empty,
            string.Empty,
            properties);
    }

    private static string TryFormatDescription(EventRecord record)
    {
        try
        {
            return record.FormatDescription() ?? string.Empty;
        }
        catch (EventLogException)
        {
            return string.Empty;
        }
    }
}

/// <summary>
/// What one query read. <see cref="CapReached"/> means the log held more matching records than
/// <see cref="Cap"/>, so any count taken from <see cref="Records"/> is a lower bound.
/// </summary>
internal sealed record EventLogReadResult(IReadOnlyList<EventLogRecordSnapshot> Records, bool CapReached, int Cap)
{
    /// <summary>"at least N" when the cap cut the read short, otherwise N.</summary>
    public string CountText(int count) => CapReached
        ? $"at least {count.ToString(CultureInfo.InvariantCulture)}"
        : count.ToString(CultureInfo.InvariantCulture);

    /// <summary>An evidence line saying the read stopped at the cap, or null when it didn't.</summary>
    public string? CapNote(string logName) => CapReached
        ? $"  Read cap reached: the {logName} log held more than {Cap.ToString(CultureInfo.InvariantCulture)} matching events, so only the newest {Cap.ToString(CultureInfo.InvariantCulture)} were read and the counts are lower bounds."
        : null;
}

internal sealed record EventLogRecordSnapshot(
    DateTime TimeCreated,
    string ProviderName,
    int Id,
    byte? Level,
    string LevelDisplayName,
    string Message,
    IReadOnlyList<object?> Properties);
