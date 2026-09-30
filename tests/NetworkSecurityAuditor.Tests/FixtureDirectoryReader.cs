using System.DirectoryServices;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Services;

namespace NetworkSecurityAuditor.Tests;

/// <summary>
/// Answers directory reads from a recorded fixture under Fixtures/Directory. Searches match on base and exact
/// filter, or on a "filterPattern" regex where the filter embeds a timestamp; an unmatched read throws so a
/// changed filter can't pass silently.
/// </summary>
/// <remarks>
/// Fixture shape:
/// <code>
/// {
///   "entries":  { "(domain)": { "attr": [values] }, "RootDSE": { ... }, "CN=...,DC=...": { ... } },
///   "searches": [ { "base": "CN=...", "filter": "(...)", "results": [ { "$path": "...", "attr": [values] } ] } ],
///   "acls":     { "CN=...": [ { "identity": "CORP\\Helpdesk", "sid": "S-1-5-21-...-1110", "rights": "CreateChild", "type": "Allow" } ] },
///   "owners":   { "CN=...": { "sid": "S-1-5-21-...-1105", "identity": "CORP\\jdoe" } }
/// }
/// </code>
/// Any entry, search or ACL can carry "$error": { "hresult": "0x80070005", "message": "..." } instead, which throws a
/// <see cref="COMException"/> the way the provider does. Values: strings, integers (as long), booleans, and objects
/// {"$fileTimeDaysAgo": n}, {"$daysAgo": n} (DateTime UTC), {"$bytes": "base64"}, {"$sid": "S-1-5-..."}.
/// An ACL rule can also carry "objectType" (a GUID), "inherited" and "inheritOnly" (booleans).
/// </remarks>
internal sealed class FixtureDirectoryReader : IDirectoryReader
{
    /// <summary>A domain member, so the AD checks don't return N/A.</summary>
    public static EnvironmentInfo DomainMember => new() { IsDomainJoined = true, DomainName = "corp.example" };

    private const string DomainKey = "(domain)";
    private readonly JsonElement _root;
    private readonly DateTime _now = DateTime.UtcNow;

    public List<DirectoryQuery> Queries { get; } = [];

    /// <summary>Every distinguishedName passed to <see cref="ReadEntry"/>, in order (null is the domain root).</summary>
    public List<string?> EntryReads { get; } = [];

    private FixtureDirectoryReader(JsonElement root) => _root = root;

    public static FixtureDirectoryReader Load(string fileName)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "NetworkSecurityAuditor.slnx")))
            dir = dir.Parent;
        var path = Path.Combine(dir?.FullName ?? throw new DirectoryNotFoundException("Repo root not found."),
            "tests", "NetworkSecurityAuditor.Tests", "Fixtures", "Directory", fileName);
        return FromJson(File.ReadAllText(path));
    }

    /// <summary>A fixture written inline in a test, in the same shape as the files.</summary>
    public static FixtureDirectoryReader FromJson(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return new FixtureDirectoryReader(doc.RootElement.Clone());
    }

    public IReadOnlyList<DirectoryRecord> Search(DirectoryQuery query, CancellationToken ct)
    {
        Queries.Add(query);
        if (_root.TryGetProperty("searches", out var searches))
        {
            foreach (var search in searches.EnumerateArray())
            {
                if (!Matches(search, query))
                    continue;
                ThrowIfError(search);
                var records = search.GetProperty("results").EnumerateArray()
                    .Select(result => Requested(ToRecord(result, "LDAP://" + (query.SearchBase ?? DomainKey)), query.Properties))
                    .ToList();
                return query.SizeLimit > 0 ? records.Take(query.SizeLimit).ToList() : records;
            }
        }

        throw new InvalidOperationException($"No fixture search for base '{query.SearchBase ?? DomainKey}' and filter '{query.Filter}'.");
    }

    public DirectoryRecord ReadEntry(string? distinguishedName, IReadOnlyList<string> properties, CancellationToken ct)
    {
        EntryReads.Add(distinguishedName);
        // A serverless RootDSE read answers from the same recorded RootDSE entry.
        var key = distinguishedName == DirectoryReader.RootDseServerless
            ? DirectoryReader.RootDse
            : distinguishedName ?? DomainKey;
        if (_root.TryGetProperty("entries", out var entries) && entries.TryGetProperty(key, out var entry))
        {
            ThrowIfError(entry);
            var record = ToRecord(entry, "LDAP://" + key);
            var requested = properties.ToDictionary(p => p, p => record.Values(p), StringComparer.OrdinalIgnoreCase);
            return new DirectoryRecord(record.Path, requested.Where(kv => kv.Value.Count > 0).ToDictionary(kv => kv.Key, kv => kv.Value));
        }

        // 0x80072030: "There is no such object on the server."
        throw new COMException($"There is no such object on the server. ({key})", unchecked((int)0x80072030));
    }

    public IReadOnlyList<DirectoryAccessRule> ReadAccessRules(string distinguishedName, CancellationToken ct)
    {
        if (!_root.TryGetProperty("acls", out var acls) || !acls.TryGetProperty(distinguishedName, out var rules))
            throw new COMException($"There is no such object on the server. ({distinguishedName})", unchecked((int)0x80072030));

        if (rules.ValueKind == JsonValueKind.Object)
        {
            ThrowIfError(rules);
        }

        return rules.EnumerateArray().Select(rule => new DirectoryAccessRule(
            rule.GetProperty("identity").GetString()!,
            Enum.Parse<ActiveDirectoryRights>(rule.GetProperty("rights").GetString()!),
            Enum.Parse<AccessControlType>(rule.TryGetProperty("type", out var type) ? type.GetString()! : "Allow"),
            rule.TryGetProperty("objectType", out var objectType) ? Guid.Parse(objectType.GetString()!) : Guid.Empty,
            rule.TryGetProperty("inherited", out var inherited) && inherited.GetBoolean(),
            rule.TryGetProperty("sid", out var sid) ? sid.GetString() : null,
            rule.TryGetProperty("inheritOnly", out var inheritOnly) && inheritOnly.GetBoolean())).ToList();
    }

    /// <summary>The "acls" rules plus the object's owner from "owners": { "DN": { "sid": "...", "identity": "..." } }.</summary>
    public DirectoryAcl ReadAcl(string distinguishedName, CancellationToken ct)
    {
        var rules = ReadAccessRules(distinguishedName, ct);
        if (_root.TryGetProperty("owners", out var owners) && owners.TryGetProperty(distinguishedName, out var owner))
        {
            return new DirectoryAcl(
                owner.GetProperty("sid").GetString(),
                owner.TryGetProperty("identity", out var identity) ? identity.GetString() : null,
                rules);
        }
        return new DirectoryAcl(null, null, rules);
    }

    // A real search returns only the attributes it loaded (plus adspath, which it always returns), so a check that
    // reads an attribute its query didn't request must fail here as it would against a DC. No properties loads all.
    private static DirectoryRecord Requested(DirectoryRecord record, IReadOnlyList<string> properties)
    {
        if (properties.Count == 0)
            return record;
        var requested = properties.Append("adspath")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(name => record.Has(name))
            .ToDictionary(name => name, name => record.Values(name), StringComparer.OrdinalIgnoreCase);
        return new DirectoryRecord(record.Path, requested);
    }

    private static bool Matches(JsonElement search, DirectoryQuery query)
    {
        var fixtureBase = search.TryGetProperty("base", out var b) && b.ValueKind == JsonValueKind.String ? b.GetString() : null;
        if (!string.Equals(fixtureBase, query.SearchBase, StringComparison.OrdinalIgnoreCase))
            return false;
        if (search.TryGetProperty("filter", out var filter))
            return string.Equals(filter.GetString(), query.Filter, StringComparison.Ordinal);
        return search.TryGetProperty("filterPattern", out var pattern) &&
            Regex.IsMatch(query.Filter, "^" + pattern.GetString() + "$");
    }

    private static void ThrowIfError(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty("$error", out var error))
            return;
        var hresult = Convert.ToInt32(error.GetProperty("hresult").GetString(), 16);
        throw new COMException(error.GetProperty("message").GetString(), hresult);
    }

    private DirectoryRecord ToRecord(JsonElement element, string fallbackPath)
    {
        var path = fallbackPath;
        var attributes = new Dictionary<string, IReadOnlyList<object>>(StringComparer.OrdinalIgnoreCase);
        foreach (var property in element.EnumerateObject())
        {
            if (property.Name == "$path")
            {
                path = property.Value.GetString()!;
                continue;
            }
            if (property.Name.StartsWith('$'))
                continue;

            attributes[property.Name] = property.Value.ValueKind == JsonValueKind.Array
                ? property.Value.EnumerateArray().Select(Decode).ToList()
                : [Decode(property.Value)];
        }
        return new DirectoryRecord(path, attributes);
    }

    private object Decode(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString()!,
        JsonValueKind.Number => value.GetInt64(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Object when value.TryGetProperty("$fileTimeDaysAgo", out var days) => _now.AddDays(-days.GetDouble()).ToFileTimeUtc(),
        JsonValueKind.Object when value.TryGetProperty("$daysAgo", out var days) => _now.AddDays(-days.GetDouble()),
        JsonValueKind.Object when value.TryGetProperty("$bytes", out var bytes) => Convert.FromBase64String(bytes.GetString()!),
        JsonValueKind.Object when value.TryGetProperty("$sid", out var sid) => SidBytes(sid.GetString()!),
        _ => throw new InvalidDataException($"Unsupported fixture value: {value}")
    };

    private static byte[] SidBytes(string sid)
    {
        var identifier = new SecurityIdentifier(sid);
        var bytes = new byte[identifier.BinaryLength];
        identifier.GetBinaryForm(bytes, 0);
        return bytes;
    }
}
