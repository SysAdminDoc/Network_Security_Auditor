namespace NetworkSecurityAuditor.Checks.EndpointSecurity;

using System.Runtime.InteropServices;

/// <summary>
/// Reads successful installs from the Windows Update Agent history (Microsoft.Update.Session), which
/// records hotpatches and cumulative updates whether or not they appear in Win32_QuickFixEngineering.
/// Readable without elevation.
/// </summary>
internal static class UpdateHistoryReader
{
    private const int MaxEntries = 1000;
    private const int OperationInstallation = 1;
    private const int ResultSucceeded = 2;
    private const int ResultSucceededWithErrors = 3;

    public static (IReadOnlyList<EP04_PatchComplianceCheck.UpdateHistoryEntry>? Entries, string? Error) ReadInstalls(CancellationToken ct)
    {
        var sessionType = Type.GetTypeFromProgID("Microsoft.Update.Session");
        if (sessionType is null)
            return (null, "Windows Update Agent isn't registered.");

        object? session = null;
        try
        {
            session = Activator.CreateInstance(sessionType);
            dynamic searcher = ((dynamic)session!).CreateUpdateSearcher();
            int total = searcher.GetTotalHistoryCount();
            var entries = new List<EP04_PatchComplianceCheck.UpdateHistoryEntry>();
            if (total <= 0)
                return (entries, null);

            dynamic history = searcher.QueryHistory(0, Math.Min(total, MaxEntries));
            int count = history.Count;
            for (var i = 0; i < count; i++)
            {
                ct.ThrowIfCancellationRequested();
                dynamic item = history.Item(i);
                int operation = item.Operation;
                int result = item.ResultCode;
                if (operation != OperationInstallation || (result != ResultSucceeded && result != ResultSucceededWithErrors))
                    continue;
                string title = item.Title ?? string.Empty;
                DateTime date = item.Date;
                entries.Add(new EP04_PatchComplianceCheck.UpdateHistoryEntry(title, date.Kind == DateTimeKind.Utc ? date.ToLocalTime() : date));
            }
            return (entries, null);
        }
        catch (Exception ex) when (ex is COMException or UnauthorizedAccessException or InvalidCastException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
        {
            return (null, ex.Message.Trim());
        }
        finally
        {
            if (session is not null && Marshal.IsComObject(session))
                Marshal.FinalReleaseComObject(session);
        }
    }
}
