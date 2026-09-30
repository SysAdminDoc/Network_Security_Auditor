using NetworkSecurityAuditor.Services;

namespace NetworkSecurityAuditor.Tests;

/// <summary>An in-memory registry for check tests. Keys exist once a value or child is set under them.</summary>
internal sealed class FixtureRegistryReader : IRegistryReader
{
    private readonly Dictionary<string, Dictionary<string, object>> _keys = new(StringComparer.OrdinalIgnoreCase);

    public const string Uninstall = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    public FixtureRegistryReader Set(string keyPath, string valueName, object value)
    {
        AddKey(keyPath)[valueName] = value;
        return this;
    }

    /// <summary>Adds an Add/Remove Programs entry with this display name.</summary>
    public FixtureRegistryReader Installed(string displayName) =>
        Set($@"{Uninstall}\{{{Guid.NewGuid()}}}", "DisplayName", displayName);

    public Dictionary<string, object> AddKey(string keyPath)
    {
        var path = keyPath.TrimEnd('\\');
        if (!_keys.TryGetValue(path, out var values))
        {
            values = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            _keys[path] = values;
            var parent = path.LastIndexOf('\\');
            if (parent > 4)
                AddKey(path[..parent]);
        }
        return values;
    }

    public T? GetValue<T>(string keyPath, string valueName, T? defaultValue = default)
    {
        if (!_keys.TryGetValue(keyPath.TrimEnd('\\'), out var values) || !values.TryGetValue(valueName, out var raw))
            return defaultValue;
        if (raw is T typed)
            return typed;
        try
        {
            return (T)Convert.ChangeType(raw, typeof(T));
        }
        catch
        {
            return defaultValue;
        }
    }

    public bool KeyExists(string keyPath) => _keys.ContainsKey(keyPath.TrimEnd('\\'));

    public string[] GetSubKeyNames(string keyPath)
    {
        var prefix = keyPath.TrimEnd('\\') + "\\";
        return _keys.Keys
            .Where(key => key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && key.IndexOf('\\', prefix.Length) < 0)
            .Select(key => key[prefix.Length..])
            .ToArray();
    }
}
