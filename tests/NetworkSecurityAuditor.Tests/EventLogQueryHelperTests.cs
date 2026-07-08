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
