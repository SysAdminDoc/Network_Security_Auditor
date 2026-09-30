namespace NetworkSecurityAuditor.Services;

using System.ComponentModel;
using System.Globalization;
using System.IO;

internal enum HeadlessStopReason
{
    None,
    CancelKey,
    Deadline
}

/// <summary>
/// Stops a headless scan early. The first Ctrl+C cancels the scan and lets the run write its partial reports;
/// a second Ctrl+C is left to Windows, which ends the process. An optional deadline cancels the same way.
/// </summary>
internal sealed class HeadlessRunCancellation : IDisposable
{
    private readonly CancellationTokenSource _cts = new();
    private readonly TimeSpan? _deadline;
    private int _cancelKeyPresses;
    private int _reason;
    private bool _consoleHooked;

    public HeadlessRunCancellation(TimeSpan? deadline)
    {
        _deadline = deadline;
        if (deadline is { } limit)
            _cts.CancelAfter(limit);
    }

    public CancellationToken Token => _cts.Token;

    /// <summary>
    /// Whichever stopped the run first, or None when nothing did. Ctrl+C records itself before it cancels,
    /// so a cancelled token with nothing recorded means the deadline fired.
    /// </summary>
    public HeadlessStopReason Reason
    {
        get
        {
            var recorded = (HeadlessStopReason)Volatile.Read(ref _reason);
            if (recorded != HeadlessStopReason.None)
                return recorded;
            return _cts.IsCancellationRequested ? HeadlessStopReason.Deadline : HeadlessStopReason.None;
        }
    }

    /// <summary>
    /// Handles one Ctrl+C. Returns true when the process should stay alive (the first press, which cancels the
    /// scan) and false for every later press, so Windows ends the process as it normally would.
    /// </summary>
    public bool HandleCancelKeyPress()
    {
        if (Interlocked.Increment(ref _cancelKeyPresses) != 1)
            return false;

        // A press after the deadline fired doesn't change why the run stopped.
        if (!_cts.IsCancellationRequested)
            Interlocked.CompareExchange(ref _reason, (int)HeadlessStopReason.CancelKey, (int)HeadlessStopReason.None);
        _cts.Cancel();
        return true;
    }

    /// <summary>Listens for Ctrl+C on the console the process is attached to. Returns false when there's none to hook.</summary>
    public bool HookConsole(TextWriter errorWriter)
    {
        try
        {
            Console.CancelKeyPress += OnCancelKeyPress;
            _consoleHooked = true;
            return true;
        }
        catch (Exception ex) when (ex is Win32Exception or IOException or PlatformNotSupportedException)
        {
            errorWriter.WriteLine($"WARNING: Ctrl+C handling is unavailable ({ex.Message}).");
            return false;
        }
    }

    /// <summary>The words that finish "did not finish because ...".</summary>
    public string DescribeStop() => Reason switch
    {
        HeadlessStopReason.CancelKey => "the run was cancelled with Ctrl+C",
        HeadlessStopReason.Deadline when _deadline is { } limit => $"the run reached its {FormatDeadline(limit)} deadline",
        _ => "the run was cancelled"
    };

    internal static string FormatDeadline(TimeSpan limit) => limit.TotalMinutes >= 1 && limit.TotalMinutes == Math.Floor(limit.TotalMinutes)
        ? $"{limit.TotalMinutes.ToString(CultureInfo.InvariantCulture)}-minute"
        : $"{limit.TotalSeconds.ToString("0.###", CultureInfo.InvariantCulture)}-second";

    private void OnCancelKeyPress(object? sender, ConsoleCancelEventArgs e)
    {
        e.Cancel = HandleCancelKeyPress();
        if (e.Cancel)
            Console.Error.WriteLine("Cancelling: finishing up and writing partial results. Press Ctrl+C again to quit now.");
    }

    public void Dispose()
    {
        if (_consoleHooked)
        {
            Console.CancelKeyPress -= OnCancelKeyPress;
            _consoleHooked = false;
        }

        _cts.Dispose();
    }
}
