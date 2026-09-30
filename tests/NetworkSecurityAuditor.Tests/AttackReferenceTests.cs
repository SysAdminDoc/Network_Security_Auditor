using System.Text.Json;
using System.Text.RegularExpressions;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Export;

namespace NetworkSecurityAuditor.Tests;

/// <summary>
/// Checks both surfaces' ATT&amp;CK mappings against the Enterprise release pinned by tools/Update-AttackReference.ps1.
/// </summary>
public partial class AttackReferenceTests
{
    private static readonly Lazy<AttackReference> s_reference = new(LoadReference);
    private static readonly Lazy<string> s_script = new(() => File.ReadAllText(Path.Combine(FindRepoRoot(), "NetworkSecurityAudit.ps1")));

    [Fact]
    public void Pinned_Release_Is_The_Exported_Version()
    {
        Assert.Equal(ExternalVersions.AttackEnterprise, s_reference.Value.Version);
        Assert.Equal(ExternalVersions.AttackEnterprise, ScriptExternalVersion("AttackEnterprise"));
        Assert.Equal(ExternalVersions.Oscal, ScriptExternalVersion("OSCAL"));
        Assert.Equal(ExternalVersions.Ocsf, ScriptExternalVersion("OCSF"));
    }

    [Fact]
    public void Every_Mapped_Technique_Is_Current_In_The_Pinned_Release()
    {
        var problems = MitreMappings.All
            .SelectMany(kv => kv.Value.Techniques.Select(t => (Check: kv.Key, Technique: t)))
            .Select(x => Problem(x.Technique) is { } p ? $"{x.Check} {x.Technique}: {p}" : null)
            .OfType<string>()
            .ToList();

        Assert.True(problems.Count == 0, string.Join(Environment.NewLine, problems));
    }

    [Fact]
    public void Mapped_Tactics_Match_Their_Techniques()
    {
        var reference = s_reference.Value;
        var problems = new List<string>();
        foreach (var (id, mapping) in MitreMappings.All)
        {
            var carried = mapping.Techniques
                .Where(reference.Techniques.ContainsKey)
                .SelectMany(t => reference.Techniques[t].Tactics)
                .ToHashSet();
            foreach (var tactic in mapping.Tactics)
            {
                if (!reference.TacticNames.ContainsKey(tactic))
                    problems.Add($"{id}: {tactic} isn't an ATT&CK {reference.Version} tactic.");
                else if (!carried.Contains(tactic))
                    problems.Add($"{id}: none of its techniques is under {tactic} ({reference.TacticNames[tactic]}).");
            }
            foreach (var technique in mapping.Techniques.Where(reference.Techniques.ContainsKey))
            {
                var tactics = reference.Techniques[technique].Tactics;
                if (!tactics.Intersect(mapping.Tactics).Any())
                    problems.Add($"{id}: {technique} is under {string.Join(", ", tactics)}, none of which the check lists.");
            }
        }

        Assert.True(problems.Count == 0, string.Join(Environment.NewLine, problems));
    }

    [Fact]
    public void Script_Map_Is_Identical_To_The_App_Map()
    {
        var script = ScriptMap();

        Assert.Equal(MitreMappings.All.Keys.Order(StringComparer.Ordinal), script.Keys.Order(StringComparer.Ordinal));
        foreach (var (id, mapping) in MitreMappings.All)
        {
            var (tactics, techniques, description) = script[id];
            Assert.True(mapping.Tactics.SequenceEqual(tactics), $"{id} tactics differ: app {string.Join(",", mapping.Tactics)}, script {string.Join(",", tactics)}");
            Assert.True(mapping.Techniques.SequenceEqual(techniques), $"{id} techniques differ: app {string.Join(",", mapping.Techniques)}, script {string.Join(",", techniques)}");
            Assert.Equal(mapping.Description, description);
        }
    }

    [Fact]
    public void Script_Tactic_Table_Follows_The_Pinned_Matrix()
    {
        var block = Block(s_script.Value, @"\$script:MitreTactics = \[ordered\]@\{");
        var table = TacticRow().Matches(block).Select(m => (m.Groups["id"].Value, m.Groups["name"].Value)).ToList();

        Assert.Equal(s_reference.Value.Tactics, table);
    }

    [Fact]
    public void Script_Attack_Paths_Cite_Current_Techniques()
    {
        var body = Block(s_script.Value, @"function Get-AttackPaths \{");
        var cited = TechniqueId().Matches(body).Select(m => m.Value).Distinct().ToList();
        var problems = cited.Select(t => Problem(t) is { } p ? $"{t}: {p}" : null).OfType<string>().ToList();

        Assert.NotEmpty(cited);
        Assert.True(problems.Count == 0, string.Join(Environment.NewLine, problems));
    }

    [Fact]
    public void Problem_Names_The_Replacement_For_A_Revoked_Technique()
    {
        // Positive control: the gate above would catch the IDs the v19 split retired.
        Assert.Equal("revoked, use T1685", Problem("T1562.001"));
        Assert.Equal("revoked, use T1685.005", Problem("T1070.001"));
        Assert.Equal("not in the pinned release", Problem("T9999"));
        Assert.Null(Problem("T1685"));
    }

    private static string? Problem(string technique)
    {
        var reference = s_reference.Value;
        if (reference.Techniques.ContainsKey(technique)) return null;
        if (reference.Revoked.TryGetValue(technique, out var replacement))
            return replacement is null ? "revoked" : $"revoked, use {replacement}";
        return reference.Deprecated.Contains(technique) ? "deprecated" : "not in the pinned release";
    }

    private static Dictionary<string, (string[] Tactics, string[] Techniques, string Description)> ScriptMap()
    {
        var block = Block(s_script.Value, @"\$script:MitreMap = @\{");
        return ScriptMapRow().Matches(block).ToDictionary(
            m => m.Groups["id"].Value,
            m => (Quoted(m.Groups["tactics"].Value), Quoted(m.Groups["techniques"].Value), m.Groups["desc"].Value.Replace("''", "'")),
            StringComparer.Ordinal);
    }

    private static string ScriptExternalVersion(string key)
    {
        var block = Block(s_script.Value, @"\$script:ExternalVersions = \[ordered\]@\{");
        return Regex.Match(block, $@"(?m)^\s*{key}\s*=\s*'([^']*)'").Groups[1].Value;
    }

    private static string[] Quoted(string list) => Regex.Matches(list, "'([^']*)'").Select(m => m.Groups[1].Value).ToArray();

    // From the opening line to the first line that is only a closing brace.
    private static string Block(string text, string startPattern)
    {
        var start = Regex.Match(text, startPattern);
        Assert.True(start.Success, $"{startPattern} not found in NetworkSecurityAudit.ps1");
        var end = Regex.Match(text[start.Index..], @"(?m)^\}\s*$");
        Assert.True(end.Success);
        return text.Substring(start.Index, end.Index);
    }

    [GeneratedRegex(@"(?m)^\s*'(?<id>[A-Z]{2}\d{2})' = @\{ Tactics=@\((?<tactics>[^)]*)\); Techniques=@\((?<techniques>[^)]*)\); Desc='(?<desc>(?:[^']|'')*)' \}\s*$")]
    private static partial Regex ScriptMapRow();

    [GeneratedRegex(@"(?m)^\s*'(?<id>TA\d{4})' = @\{ Name='(?<name>[^']*)'")]
    private static partial Regex TacticRow();

    [GeneratedRegex(@"\bT\d{4}(?:\.\d{3})?\b")]
    private static partial Regex TechniqueId();

    private sealed record AttackReference(
        string Version,
        List<(string Id, string Name)> Tactics,
        Dictionary<string, string> TacticNames,
        Dictionary<string, (string Name, string[] Tactics)> Techniques,
        Dictionary<string, string?> Revoked,
        HashSet<string> Deprecated);

    private static AttackReference LoadReference()
    {
        var path = Path.Combine(FindRepoRoot(), "tests", "NetworkSecurityAuditor.Tests", "Fixtures", "Attack", "enterprise-attack.json");
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var root = doc.RootElement;
        var tactics = root.GetProperty("tactics").EnumerateArray()
            .Select(t => (t.GetProperty("id").GetString()!, t.GetProperty("name").GetString()!))
            .ToList();
        return new AttackReference(
            root.GetProperty("version").GetString()!,
            tactics,
            tactics.ToDictionary(t => t.Item1, t => t.Item2),
            root.GetProperty("techniques").EnumerateObject().ToDictionary(
                p => p.Name,
                p => (p.Value.GetProperty("name").GetString()!, p.Value.GetProperty("tactics").EnumerateArray().Select(t => t.GetString()!).ToArray())),
            root.GetProperty("revoked").EnumerateObject().ToDictionary(p => p.Name, p => p.Value.ValueKind == JsonValueKind.Null ? null : p.Value.GetString()),
            root.GetProperty("deprecated").EnumerateArray().Select(t => t.GetString()!).ToHashSet());
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "NetworkSecurityAuditor.slnx")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new DirectoryNotFoundException("Repository root not found.");
    }
}
