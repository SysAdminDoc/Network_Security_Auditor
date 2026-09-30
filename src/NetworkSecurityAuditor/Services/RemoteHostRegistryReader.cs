namespace NetworkSecurityAuditor.Services;

using System.Globalization;
using System.Runtime.ExceptionServices;
using Microsoft.Win32;

/// <summary>
/// Reads another machine's HKLM through the Remote Registry service, as an <see cref="IRegistryReader"/> for checks
/// that read several values from one host. <see cref="Connect"/> opens the hive within a timeout, so an unreachable
/// host or a refused connection throws there instead of stalling a scan. After that a missing key or value returns
/// the default, and a key the caller may not open throws, so a check can tell "not configured" from "not readable".
/// </summary>
public sealed class RemoteHostRegistryReader : IRegistryReader, IDisposable
{
    private const string Prefix = @"HKLM\";
    private readonly RegistryKey _hklm;

    private RemoteHostRegistryReader(string host, RegistryKey hklm)
    {
        Host = host;
        _hklm = hklm;
    }

    public string Host { get; }

    /// <summary>Opens <paramref name="host"/>'s HKLM, throwing <see cref="TimeoutException"/> when it doesn't answer in time.</summary>
    public static RemoteHostRegistryReader Connect(string host, TimeSpan timeout)
    {
        var open = Task.Run(() => RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, host, RegistryView.Registry64));
        try
        {
            if (!open.Wait(timeout))
            {
                // Dispose the hive if the connection completes after we gave up on it.
                open.ContinueWith(t => t.Result.Dispose(), TaskContinuationOptions.OnlyOnRanToCompletion);
                throw new TimeoutException($"Remote registry on {host} didn't answer within {timeout.TotalSeconds:0} seconds.");
            }
        }
        catch (AggregateException ex) when (ex.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
        }
        return new RemoteHostRegistryReader(host, open.Result);
    }

    public T? GetValue<T>(string keyPath, string valueName, T? defaultValue = default)
    {
        using var key = _hklm.OpenSubKey(SubKey(keyPath), writable: false);
        var raw = key?.GetValue(valueName);
        if (raw is null)
            return defaultValue;
        if (raw is T typed)
            return typed;
        try
        {
            return (T)Convert.ChangeType(raw, Nullable.GetUnderlyingType(typeof(T)) ?? typeof(T), CultureInfo.InvariantCulture);
        }
        catch (Exception ex) when (ex is InvalidCastException or FormatException or OverflowException)
        {
            return defaultValue;
        }
    }

    public bool KeyExists(string keyPath)
    {
        using var key = _hklm.OpenSubKey(SubKey(keyPath), writable: false);
        return key is not null;
    }

    public string[] GetSubKeyNames(string keyPath)
    {
        using var key = _hklm.OpenSubKey(SubKey(keyPath), writable: false);
        return key?.GetSubKeyNames() ?? [];
    }

    public void Dispose() => _hklm.Dispose();

    private static string SubKey(string keyPath) =>
        keyPath.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase)
            ? keyPath[Prefix.Length..].TrimEnd('\\')
            : throw new ArgumentException($"Only HKLM paths can be read remotely: {keyPath}", nameof(keyPath));
}
