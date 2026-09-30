namespace NetworkSecurityAuditor.Tests;

using NetworkSecurityAuditor.Checks.LoggingMonitoring;
using NetworkSecurityAuditor.Services;

public sealed class EventLogQueryHelperTests
{
    [Fact]
    public void RecentEventsQuery_Includes_Time_Window_And_System_Predicate()
    {
        string query = EventLogQueryHelper.RecentEventsQuery(TimeSpan.FromDays(7), "EventID=4625");

        Assert.Contains("timediff(@SystemTime)", query);
        Assert.Contains("604800000", query);
        Assert.Contains("EventID=4625", query);
    }

    [Fact]
    public void FailedLogonAccount_Uses_Target_User_And_Domain_Properties()
    {
        object?[] properties =
        [
            null,
            null,
            null,
            null,
            null,
            "alice",
            "CONTOSO"
        ];

        string? account = LM05_FailedLogonCheck.ExtractFailedLogonAccount(properties);

        Assert.Equal(@"CONTOSO\alice", account);
    }

    [Theory]
    [InlineData("src", "NetworkSecurityAuditor", "Checks", "BackupRecovery", "BR03_RestoreTestCheck.cs")]
    [InlineData("src", "NetworkSecurityAuditor", "Checks", "BackupRecovery", "BR06_BackupMonitoringCheck.cs")]
    [InlineData("src", "NetworkSecurityAuditor", "Checks", "LoggingMonitoring", "LM05_FailedLogonCheck.cs")]
    public void Event_Log_Checks_Do_Not_Use_Com_Entries_Indexer(params string[] segments)
    {
        string source = ReadSourceFile(segments);

        Assert.DoesNotContain(".Entries", source);
        Assert.Contains("EventLogQueryHelper", source);
    }

    [Theory]
    [InlineData("src", "NetworkSecurityAuditor", "Checks", "BackupRecovery", "BR03_RestoreTestCheck.cs")]
    [InlineData("src", "NetworkSecurityAuditor", "Checks", "BackupRecovery", "BR06_BackupMonitoringCheck.cs")]
    [InlineData("src", "NetworkSecurityAuditor", "Checks", "LoggingMonitoring", "LM05_FailedLogonCheck.cs")]
    public void Event_Log_Checks_Read_Through_The_Capped_Reader(params string[] segments)
    {
        string source = ReadSourceFile(segments);

        Assert.DoesNotContain("maxEvents: 0", source);
        Assert.DoesNotContain("EventLogQueryHelper.Read(", source);
        Assert.Contains("_events.Query(", source);
        Assert.Contains("RecentEventsQuery(", source);
    }

    [Fact]
    public void Cap_Is_A_Single_Documented_Constant()
    {
        Assert.Equal(10_000, EventLogQueryHelper.MaxEventsPerQuery);
        Assert.Equal(EventLogQueryHelper.MaxEventsPerQuery, EventLogQueryHelper.EffectiveCap(0));
        Assert.Equal(EventLogQueryHelper.MaxEventsPerQuery, EventLogQueryHelper.EffectiveCap(-1));
        Assert.Equal(EventLogQueryHelper.MaxEventsPerQuery, EventLogQueryHelper.EffectiveCap(1_000_000));
        Assert.Equal(50, EventLogQueryHelper.EffectiveCap(50));
    }

    [Fact]
    public void Collect_Stops_At_The_Cap_And_Reports_At_Least()
    {
        var reader = new FakeEventLogReader()
            .AddMany("Application", 25, i => FakeEventLogReader.Event("Veeam", 4, $"message {i}"));

        var result = reader.Query("Application", "*", maxEvents: 10, formatMessage: null, CancellationToken.None);

        Assert.Equal(10, result.Records.Count);
        Assert.True(result.CapReached);
        Assert.Equal(10, result.Cap);
        // Ten records plus the one read that proves there are more. The other fourteen are never touched.
        Assert.Equal(11, reader.RecordsRead);
        Assert.Equal("at least 10", result.CountText(result.Records.Count));
        Assert.Equal("at least 3", result.CountText(3));
        Assert.Contains("more than 10 matching events", result.CapNote("Application"));
    }

    [Fact]
    public void Collect_Does_Not_Flag_A_Log_That_Holds_Exactly_The_Cap()
    {
        var reader = new FakeEventLogReader()
            .AddMany("Application", 10, i => FakeEventLogReader.Event("Veeam", 4, $"message {i}"));

        var result = reader.Query("Application", "*", maxEvents: 10, formatMessage: null, CancellationToken.None);

        Assert.Equal(10, result.Records.Count);
        Assert.False(result.CapReached);
        Assert.Equal("10", result.CountText(result.Records.Count));
        Assert.Null(result.CapNote("Application"));
    }

    [Fact]
    public void Collect_Renders_Only_The_Messages_It_Is_Asked_For()
    {
        var reader = new FakeEventLogReader()
            .AddMany("System", 40, i => FakeEventLogReader.Event(i % 2 == 0 ? "VSS" : "Disk", 2, $"message {i}"));
        int sampled = 0;

        var result = reader.Query(
            "System", "*", EventLogQueryHelper.MaxEventsPerQuery,
            formatMessage: e => e.ProviderName == "VSS" && sampled++ < 3,
            CancellationToken.None);

        Assert.Equal(40, result.Records.Count);
        Assert.Equal(3, reader.MessagesFormatted);
        Assert.Equal(new[] { "message 0", "message 2", "message 4" }, result.Records.Where(r => r.Message.Length > 0).Select(r => r.Message));
        Assert.All(result.Records.Skip(5), r => Assert.Equal("", r.Message));
    }

    [Fact]
    public void Collect_Disposes_Every_Record_It_Reads()
    {
        var records = Enumerable.Range(0, 6).Select(i => FakeEventLogReader.Event("Veeam", 4, $"m{i}")).ToArray();
        var reader = new FakeEventLogReader().Add("Application", records);

        reader.Query("Application", "*", maxEvents: 4, formatMessage: _ => true, CancellationToken.None);

        Assert.All(records.Take(5), r => Assert.Equal(1, r.Disposals));
        Assert.Equal(0, records[5].Disposals);
    }

    [Fact]
    public void Collect_Stops_When_Cancelled()
    {
        using var cts = new CancellationTokenSource();
        var reader = new FakeEventLogReader()
            .AddMany("Security", 100, _ => FakeEventLogReader.FailedLogon("alice"));
        cts.Cancel();

        Assert.ThrowsAny<OperationCanceledException>(() =>
            reader.Query("Security", "*", EventLogQueryHelper.MaxEventsPerQuery, null, cts.Token));
        Assert.Equal(0, reader.RecordsRead);
    }

    private static string ReadSourceFile(params string[] segments)
    {
        string[] pathSegments = new string[segments.Length + 1];
        pathSegments[0] = FindRepoRoot();
        segments.CopyTo(pathSegments, 1);
        return File.ReadAllText(Path.Combine(pathSegments));
    }

    private static string FindRepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "NetworkSecurityAuditor.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("Could not locate repository root.");
    }
}
