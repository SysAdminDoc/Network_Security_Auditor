using System.Text.Json;
using NetworkSecurityAuditor.Services;

namespace NetworkSecurityAuditor.Tests;

/// <summary>
/// Answers remote registry reads from the "remoteRegistry" section of a directory fixture:
/// <code>
/// "remoteRegistry": {
///   "dc01.corp.example": { "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion": { "UBR": 4946 } },
///   "dc02.corp.example": { "$error": { "hresult": "0x80070005", "message": "Access is denied." } }
/// }
/// </code>
/// A host that isn't listed throws the way an unreachable host does. <see cref="Hosts"/> records every host read.
/// </summary>
internal sealed class FixtureRemoteRegistryReader : IRemoteRegistryReader
{
    private readonly JsonElement _root;

    public List<string> Hosts { get; } = [];

    private FixtureRemoteRegistryReader(JsonElement root) => _root = root;

    public static FixtureRemoteRegistryReader Load(string fileName)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "NetworkSecurityAuditor.slnx")))
            dir = dir.Parent;
        var path = Path.Combine(dir?.FullName ?? throw new DirectoryNotFoundException("Repo root not found."),
            "tests", "NetworkSecurityAuditor.Tests", "Fixtures", "Directory", fileName);
        return FromJson(File.ReadAllText(path));
    }

    public static FixtureRemoteRegistryReader FromJson(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return new FixtureRemoteRegistryReader(doc.RootElement.Clone());
    }

    public object? ReadMachineValue(string host, string subKey, string valueName, CancellationToken ct)
    {
        Hosts.Add(host);
        if (!_root.TryGetProperty("remoteRegistry", out var hosts) || !hosts.TryGetProperty(host, out var keys))
            throw new IOException($"The network path was not found. ({host})");

        if (keys.TryGetProperty("$error", out var error))
        {
            var message = error.GetProperty("message").GetString();
            throw error.GetProperty("hresult").GetString() == "0x80070005"
                ? new UnauthorizedAccessException(message)
                : new IOException(message);
        }

        if (!keys.TryGetProperty(subKey, out var values) || !values.TryGetProperty(valueName, out var value))
            return null;
        return value.ValueKind == JsonValueKind.Number ? value.GetInt32() : value.GetString();
    }
}
