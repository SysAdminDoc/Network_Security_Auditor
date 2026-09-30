using System.Runtime.ExceptionServices;
using Microsoft.Win32;

namespace NetworkSecurityAuditor.Services;

/// <summary>Reads HKLM values on another host (for example a domain controller's patch level). Tests swap in a fixture.</summary>
public interface IRemoteRegistryReader
{
    /// <summary>
    /// Reads one value under HKLM\<paramref name="subKey"/> on <paramref name="host"/>. Returns null when the key or
    /// value is missing, and throws when the host's registry can't be opened (unreachable, access denied, timeout).
    /// </summary>
    object? ReadMachineValue(string host, string subKey, string valueName, CancellationToken ct);
}

/// <summary>Remote registry over RPC, bounded by a timeout so an unreachable host can't stall a scan.</summary>
public sealed class RemoteRegistryReader(TimeSpan timeout) : IRemoteRegistryReader
{
    public RemoteRegistryReader() : this(TimeSpan.FromSeconds(15)) { }

    public object? ReadMachineValue(string host, string subKey, string valueName, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var read = Task.Run(() =>
        {
            using var hive = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, host, RegistryView.Registry64);
            using var key = hive.OpenSubKey(subKey, writable: false);
            return key?.GetValue(valueName);
        }, ct);

        try
        {
            if (!read.Wait(timeout, ct))
                throw new TimeoutException($"Remote registry on {host} didn't answer within {timeout.TotalSeconds:0} seconds.");
        }
        catch (AggregateException ex) when (ex.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
        }
        return read.Result;
    }
}
