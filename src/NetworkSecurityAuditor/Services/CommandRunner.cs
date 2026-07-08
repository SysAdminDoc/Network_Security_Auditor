namespace NetworkSecurityAuditor.Services;

using System.Diagnostics;

internal static class CommandRunner
{
    public static CommandResult Run(string fileName, string arguments, TimeSpan timeout, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(fileName, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start {fileName}");

        using var registration = ct.Register(static state =>
        {
            try
            {
                ((Process)state!).Kill(entireProcessTree: true);
            }
            catch
            {
                // The process may already have exited.
            }
        }, process);

        Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync(ct);
        Task<string> stderrTask = process.StandardError.ReadToEndAsync(ct);

        bool exited = process.WaitForExit((int)timeout.TotalMilliseconds);
        if (!exited)
        {
            TryKill(process);
            process.WaitForExit(2_000);
        }

        string stdout = ReadCompletedStream(stdoutTask);
        string stderr = ReadCompletedStream(stderrTask);
        ct.ThrowIfCancellationRequested();

        return new CommandResult(stdout, stderr, exited ? process.ExitCode : null, !exited);
    }

    public static string RunForOutput(string fileName, string arguments, TimeSpan timeout, CancellationToken ct)
    {
        return Run(fileName, arguments, timeout, ct).StandardOutput;
    }

    private static string ReadCompletedStream(Task<string> streamTask)
    {
        try
        {
            return streamTask.Wait(2_000) ? streamTask.Result : string.Empty;
        }
        catch (AggregateException ex) when (ex.InnerExceptions.All(e => e is OperationCanceledException or ObjectDisposedException or InvalidOperationException))
        {
            return string.Empty;
        }
        catch (OperationCanceledException)
        {
            return string.Empty;
        }
        catch (ObjectDisposedException)
        {
            return string.Empty;
        }
        catch (InvalidOperationException)
        {
            return string.Empty;
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch
        {
            // The process may already have exited.
        }
    }
}

internal sealed record CommandResult(string StandardOutput, string StandardError, int? ExitCode, bool TimedOut);
