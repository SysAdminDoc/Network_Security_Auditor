namespace NetworkSecurityAuditor.Services;

/// <summary>The registry reads a check makes, so tests can answer them from a fixture.</summary>
public interface IRegistryReader
{
    /// <inheritdoc cref="RegistryHelper.GetValue{T}"/>
    T? GetValue<T>(string keyPath, string valueName, T? defaultValue = default);

    /// <inheritdoc cref="RegistryHelper.KeyExists"/>
    bool KeyExists(string keyPath);

    /// <inheritdoc cref="RegistryHelper.GetSubKeyNames"/>
    string[] GetSubKeyNames(string keyPath);
}

/// <summary>Reads the local machine's registry through <see cref="RegistryHelper"/>.</summary>
public sealed class SystemRegistryReader : IRegistryReader
{
    public static readonly SystemRegistryReader Instance = new();

    private SystemRegistryReader() { }

    public T? GetValue<T>(string keyPath, string valueName, T? defaultValue = default) =>
        RegistryHelper.GetValue(keyPath, valueName, defaultValue);

    public bool KeyExists(string keyPath) => RegistryHelper.KeyExists(keyPath);

    public string[] GetSubKeyNames(string keyPath) => RegistryHelper.GetSubKeyNames(keyPath);
}
