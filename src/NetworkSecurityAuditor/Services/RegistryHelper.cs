namespace NetworkSecurityAuditor.Services;

using Microsoft.Win32;

public static class RegistryHelper
{
    /// <summary>
    /// Reads a registry value safely, returning <paramref name="defaultValue"/> on any failure.
    /// <paramref name="keyPath"/> must start with HKLM\ or HKCU\ (case-insensitive).
    /// </summary>
    public static T? GetValue<T>(string keyPath, string valueName, T? defaultValue = default)
    {
        try
        {
            var (hive, subKey) = ParsePath(keyPath);
            using var key = hive.OpenSubKey(subKey, writable: false);
            if (key is null) return defaultValue;

            object? raw = key.GetValue(valueName);
            if (raw is null) return defaultValue;

            if (raw is T typed) return typed;

            // Handle numeric conversions (DWORD stored as int, caller wants bool, etc.)
            return (T)Convert.ChangeType(raw, typeof(T));
        }
        catch
        {
            return defaultValue;
        }
    }

    /// <summary>
    /// Returns true if the registry key exists (does not check values).
    /// </summary>
    public static bool KeyExists(string keyPath)
    {
        try
        {
            var (hive, subKey) = ParsePath(keyPath);
            using var key = hive.OpenSubKey(subKey, writable: false);
            return key is not null;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Enumerates value names under a key. Returns empty array on failure.
    /// </summary>
    public static string[] GetValueNames(string keyPath)
    {
        try
        {
            var (hive, subKey) = ParsePath(keyPath);
            using var key = hive.OpenSubKey(subKey, writable: false);
            return key?.GetValueNames() ?? [];
        }
        catch
        {
            return [];
        }
    }

    /// <summary>
    /// Enumerates subkey names under a key. Returns empty array on failure.
    /// </summary>
    public static string[] GetSubKeyNames(string keyPath)
    {
        try
        {
            var (hive, subKey) = ParsePath(keyPath);
            using var key = hive.OpenSubKey(subKey, writable: false);
            return key?.GetSubKeyNames() ?? [];
        }
        catch
        {
            return [];
        }
    }

    private static (RegistryKey hive, string subKey) ParsePath(string keyPath)
    {
        if (keyPath.StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase))
            return (Registry.LocalMachine, keyPath[5..]);
        if (keyPath.StartsWith(@"HKCU\", StringComparison.OrdinalIgnoreCase))
            return (Registry.CurrentUser, keyPath[5..]);
        if (keyPath.StartsWith(@"HKCR\", StringComparison.OrdinalIgnoreCase))
            return (Registry.ClassesRoot, keyPath[5..]);
        throw new ArgumentException($"Unsupported registry hive in path: {keyPath}");
    }
}
