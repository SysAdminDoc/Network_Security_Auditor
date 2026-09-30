namespace NetworkSecurityAuditor.Tests;

using NetworkSecurityAuditor.Services;

/// <summary>
/// Answers event log queries from in-memory records, newest first, through the production read loop
/// (<see cref="EventLogQueryHelper.Collect{TRecord}"/>), so the cap and the message rendering rules under test
/// are the real ones. Counts how many records were read and how many messages were rendered.
/// Of the XPath it honors only <c>Level=N</c> (any listed level) and <c>Level!=N</c> terms, the one filter
/// checks add to the time window, so a check that splits its reads by level is tested as it runs.
/// </summary>
internal sealed class FakeEventLogReader : IEventLogReader
{
    private readonly Dictionary<string, List<FakeEventRecord>> _logs = new(StringComparer.OrdinalIgnoreCase);

    public List<(string LogName, string XPath, int MaxEvents)> Queries { get; } = [];

    public int RecordsRead { get; private set; }

    public int MessagesFormatted { get; private set; }

    public FakeEventLogReader Add(string logName, params FakeEventRecord[] records)
    {
        if (!_logs.TryGetValue(logName, out var list))
            _logs[logName] = list = [];
        list.AddRange(records);
        return this;
    }

    public FakeEventLogReader AddMany(string logName, int count, Func<int, FakeEventRecord> create) =>
        Add(logName, [.. Enumerable.Range(0, count).Select(create)]);

    public EventLogReadResult Query(
        string logName,
        string xPathQuery,
        int maxEvents,
        Func<EventLogRecordSnapshot, bool>? formatMessage,
        CancellationToken ct)
    {
        Queries.Add((logName, xPathQuery, maxEvents));
        var records = (_logs.TryGetValue(logName, out var list) ? list : []).Where(r => MatchesLevel(xPathQuery, r.Snapshot.Level)).ToList();
        int next = 0;

        return EventLogQueryHelper.Collect(
            () =>
            {
                if (next >= records.Count)
                    return null;
                RecordsRead++;
                return records[next++];
            },
            record => record.Snapshot,
            record =>
            {
                MessagesFormatted++;
                return record.Message;
            },
            maxEvents,
            formatMessage,
            ct);
    }

    private static bool MatchesLevel(string xPath, byte? level)
    {
        var terms = System.Text.RegularExpressions.Regex.Matches(xPath, @"Level(!?=)(\d+)");
        var wanted = terms.Where(t => t.Groups[1].Value == "=").Select(t => byte.Parse(t.Groups[2].Value)).ToList();
        var excluded = terms.Where(t => t.Groups[1].Value == "!=").Select(t => byte.Parse(t.Groups[2].Value)).ToList();
        return (wanted.Count == 0 || (level is { } l && wanted.Contains(l))) && !(level is { } x && excluded.Contains(x));
    }

    public static FakeEventRecord FailedLogon(string user, string domain = "CONTOSO") =>
        new(new EventLogRecordSnapshot(
            DateTime.UtcNow, "Microsoft-Windows-Security-Auditing", 4625, 0, "Information", "",
            [null, null, null, null, null, user, domain]),
            $"An account failed to log on: {domain}\\{user}");

    public static FakeEventRecord Event(string provider, byte level, string message, int id = 1) =>
        new(new EventLogRecordSnapshot(DateTime.UtcNow, provider, id, level, LevelName(level), "", []), message);

    private static string LevelName(byte level) => level switch
    {
        1 => "Critical",
        2 => "Error",
        3 => "Warning",
        _ => "Information"
    };
}

internal sealed class FakeEventRecord(EventLogRecordSnapshot snapshot, string message) : IDisposable
{
    public EventLogRecordSnapshot Snapshot { get; } = snapshot;

    public string Message { get; } = message;

    public int Disposals { get; private set; }

    public void Dispose() => Disposals++;
}
