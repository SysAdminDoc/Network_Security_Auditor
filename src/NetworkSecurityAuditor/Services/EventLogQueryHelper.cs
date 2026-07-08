namespace NetworkSecurityAuditor.Services;

using System.Diagnostics.Eventing.Reader;

internal static class EventLogQueryHelper
{
    public static string RecentEventsQuery(TimeSpan lookback, string? systemPredicate = null)
    {
        long milliseconds = (long)Math.Ceiling(lookback.TotalMilliseconds);
        string timePredicate = $"TimeCreated[timediff(@SystemTime) <= {milliseconds}]";
        string combinedPredicate = string.IsNullOrWhiteSpace(systemPredicate)
            ? timePredicate
            : $"{timePredicate} and ({systemPredicate})";

        return $"*[System[{combinedPredicate}]]";
    }

    public static List<EventLogRecordSnapshot> Read(
        string logName,
        string xPathQuery,
        int maxEvents,
        CancellationToken ct)
    {
        var query = new EventLogQuery(logName, PathType.LogName, xPathQuery)
        {
            ReverseDirection = true
        };

        using var reader = new EventLogReader(query);
        var records = new List<EventLogRecordSnapshot>();

        while (maxEvents <= 0 || records.Count < maxEvents)
        {
            ct.ThrowIfCancellationRequested();
            using EventRecord? record = reader.ReadEvent();
            if (record is null)
                break;

            records.Add(Snapshot(record));
        }

        return records;
    }

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
            TryFormatDescription(record),
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

internal sealed record EventLogRecordSnapshot(
    DateTime TimeCreated,
    string ProviderName,
    int Id,
    byte? Level,
    string LevelDisplayName,
    string Message,
    IReadOnlyList<object?> Properties);
