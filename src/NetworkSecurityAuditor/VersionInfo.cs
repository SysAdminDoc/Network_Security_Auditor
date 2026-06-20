using System.Reflection;

namespace NetworkSecurityAuditor;

public static class VersionInfo
{
    public static string Version { get; } =
        typeof(VersionInfo).Assembly.GetName().Version?.ToString(3) ?? "5.0.0";
}
