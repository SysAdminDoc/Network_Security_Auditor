using System.Reflection;

namespace NetworkSecurityAuditor;

public static class VersionInfo
{
    public static string Version { get; } = GetVersion();

    private static string GetVersion()
    {
        var assembly = typeof(VersionInfo).Assembly;
        var informationalVersion = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion;

        if (!string.IsNullOrWhiteSpace(informationalVersion))
            return informationalVersion.Split('+', 2)[0];

        return assembly.GetName().Version?.ToString(3) ?? "0.0.0";
    }
}
