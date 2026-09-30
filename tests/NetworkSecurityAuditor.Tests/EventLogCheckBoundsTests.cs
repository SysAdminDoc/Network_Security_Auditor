namespace NetworkSecurityAuditor.Tests;

using NetworkSecurityAuditor.Checks.BackupRecovery;
using NetworkSecurityAuditor.Checks.LoggingMonitoring;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

/// <summary>LM05, BR03 and BR06 read a bounded number of events and render only the messages they show.</summary>
public sealed class EventLogCheckBoundsTests
{
    private static readonly EnvironmentInfo Admin = new() { IsAdmin = true };

    [Fact]
    public async Task LM05_Stops_At_The_Cap_And_Reports_At_Least()
    {
        var reader = new FakeEventLogReader()
            .AddMany("Security", EventLogQueryHelper.MaxEventsPerQuery + 500, _ => FakeEventLogReader.FailedLogon("alice"));

        var result = await new LM05_FailedLogonCheck(reader).ExecuteAsync(Admin, new AuditOptions(), CancellationToken.None);

        Assert.Equal(EventLogQueryHelper.MaxEventsPerQuery + 1, reader.RecordsRead);
        Assert.Equal(0, reader.MessagesFormatted);
        Assert.Contains($"Found at least {EventLogQueryHelper.MaxEventsPerQuery} failed logon events", result.Findings);
        Assert.Contains("lower bounds", result.Findings);
        Assert.Contains($"4625 events returned by XPath query: at least {EventLogQueryHelper.MaxEventsPerQuery}", result.Evidence);
        Assert.Contains("Read cap reached", result.Evidence);
        Assert.Equal(CheckStatus.Fail, result.Status);
        var query = Assert.Single(reader.Queries);
        Assert.Contains("timediff(@SystemTime)", query.XPath);
        Assert.Contains("EventID=4625", query.XPath);
    }

    [Theory]
    [InlineData(12, CheckStatus.Pass, "[ELEVATED]")]
    [InlineData(60, CheckStatus.Fail, "[BRUTE FORCE SUSPECT]")]
    public async Task LM05_Keeps_Its_Thresholds_Under_The_Cap(int failures, CheckStatus expected, string flag)
    {
        var reader = new FakeEventLogReader()
            .AddMany("Security", failures, _ => FakeEventLogReader.FailedLogon("bob"));

        var result = await new LM05_FailedLogonCheck(reader).ExecuteAsync(Admin, new AuditOptions(), CancellationToken.None);

        Assert.Equal(expected, result.Status);
        Assert.Contains($"Found {failures} failed logon events across 1 account(s)", result.Findings);
        Assert.Contains(flag, result.Findings);
        Assert.DoesNotContain("at least", result.Findings);
        Assert.DoesNotContain("Read cap reached", result.Evidence);
    }

    [Fact]
    public async Task BR06_Renders_Only_The_Shown_Error_Samples()
    {
        var reader = new FakeEventLogReader()
            .AddMany("Application", 8, i => FakeEventLogReader.Event("Veeam Backup", 2, $"Job {i} failed"))
            .AddMany("Application", 300, i => FakeEventLogReader.Event("Microsoft-Windows-Winlogon", 4, $"noise {i}"))
            .AddMany("Application", 4, i => FakeEventLogReader.Event("Veeam Backup", 4, $"Job {i} finished"))
            .AddMany("System", 6, i => FakeEventLogReader.Event("VSS", 2, $"VSS error {i}"))
            .AddMany("System", 50, i => FakeEventLogReader.Event("Disk", 2, $"disk {i}"));

        var result = await new BR06_BackupMonitoringCheck(reader).ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        // Five backup error samples and three VSS samples, out of 368 records read.
        Assert.Equal(8, reader.MessagesFormatted);
        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("Job 0 failed", result.Evidence);
        Assert.Contains("Job 4 failed", result.Evidence);
        Assert.DoesNotContain("Job 5 failed", result.Evidence);
        Assert.DoesNotContain("noise", result.Evidence);
        Assert.Contains("Last 7 days: 8 errors, 0 warnings, 4 info", result.Evidence);
        Assert.Contains("VSS errors in last 7 days: 6", result.Evidence);
        Assert.Contains("VSS error 2", result.Evidence);
        Assert.DoesNotContain("VSS error 3", result.Evidence);
        Assert.All(reader.Queries, q => Assert.Contains("timediff(@SystemTime)", q.XPath));
    }

    [Fact]
    public async Task BR06_Reports_At_Least_When_The_Application_Log_Hits_The_Cap()
    {
        var reader = new FakeEventLogReader()
            .AddMany("Application", 3, i => FakeEventLogReader.Event("Datto Backup Agent", 2, $"Backup {i} failed"))
            .AddMany("Application", EventLogQueryHelper.MaxEventsPerQuery, i => FakeEventLogReader.Event("Service Control Manager", 4, $"noise {i}"));

        var result = await new BR06_BackupMonitoringCheck(reader).ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Fail, result.Status);
        Assert.Contains("WARNING: at least 3 backup error event(s)", result.Findings);
        Assert.Contains("Last 7 days: at least 3 errors", result.Evidence);
        Assert.Contains("Read cap reached: the Application log", result.Evidence);
        Assert.Equal(3, reader.MessagesFormatted);
    }

    [Fact]
    public async Task BR06_Stays_Partial_Without_Backup_Errors()
    {
        var reader = new FakeEventLogReader()
            .AddMany("Application", 5, i => FakeEventLogReader.Event("Acronis", 4, $"ok {i}"));

        var result = await new BR06_BackupMonitoringCheck(reader).ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.Partial, result.Status);
        Assert.Equal(0, reader.MessagesFormatted);
        Assert.StartsWith("Backup activity detected with no recent failures.", result.Findings);
    }

    [Fact]
    public async Task BR03_Samples_Five_Messages_And_Flags_A_Full_Backup_Log()
    {
        var reader = new FakeEventLogReader()
            .AddMany("Microsoft-Windows-Backup", 30, i => FakeEventLogReader.Event("Microsoft-Windows-Backup", 4, $"Backup run {i}", id: 4))
            .AddMany("Application", 12, i => FakeEventLogReader.Event("Veeam Agent", 4, $"Veeam job {i}"))
            .AddMany("Application", 200, i => FakeEventLogReader.Event("Office", 4, $"noise {i}"));

        var result = await new BR03_RestoreTestCheck(reader).ExecuteAsync(new EnvironmentInfo(), new AuditOptions(), CancellationToken.None);

        Assert.Equal(CheckStatus.NotAssessed, result.Status);
        Assert.Equal(10, reader.MessagesFormatted);
        Assert.Contains("Recent backup events (last 30 days): at least 10", result.Evidence);
        Assert.Contains("Windows Backup events found: at least 10 in last 30 days.", result.Findings);
        Assert.Contains("Backup-related application events (last 30 days): 12", result.Evidence);
        Assert.Contains("Backup run 4", result.Evidence);
        Assert.DoesNotContain("Backup run 5", result.Evidence);
        Assert.Contains("Veeam job 4", result.Evidence);
        Assert.DoesNotContain("Veeam job 5", result.Evidence);
        Assert.Contains(reader.Queries, q => q.LogName == "Microsoft-Windows-Backup" && q.MaxEvents == 10);
        Assert.Contains(reader.Queries, q => q.LogName == "Application" && q.MaxEvents == EventLogQueryHelper.MaxEventsPerQuery);
    }
}
