using System.Text.Json;
using System.Text.RegularExpressions;
using NetworkSecurityAuditor.Data;

namespace NetworkSecurityAuditor.Tests;

/// <summary>
/// Checks both surfaces' D3FEND mappings against the release pinned by tools/Update-D3fendReference.ps1.
/// </summary>
public partial class D3fendReferenceTests
{
    private static readonly Lazy<D3fendReference> s_reference = new(LoadReference);
    private static readonly Lazy<string> s_script = new(() => File.ReadAllText(Path.Combine(FindRepoRoot(), "NetworkSecurityAudit.ps1")));

    [Fact]
    public void Pinned_Release_Is_The_Script_Version()
    {
        var block = Block(s_script.Value, @"\$script:ExternalVersions = \[ordered\]@\{");
        Assert.Equal(s_reference.Value.Version, Regex.Match(block, @"(?m)^\s*D3FEND\s*=\s*'([^']*)'").Groups[1].Value);
    }

    [Fact]
    public void Every_Mapped_Technique_Exists_With_Its_D3fend_Label()
    {
        var problems = new List<string>();
        foreach (var (id, mapping) in D3FendMappings.All)
        {
            Assert.Equal(mapping.Techniques.Length, mapping.Labels.Length);
            for (var i = 0; i < mapping.Techniques.Length; i++)
            {
                if (Problem(mapping.Techniques[i], mapping.Labels[i]) is { } problem)
                    problems.Add($"{id} {mapping.Techniques[i]}: {problem}");
            }
        }

        Assert.True(problems.Count == 0, string.Join(Environment.NewLine, problems));
    }

    [Fact]
    public void No_Technique_Carries_Two_Labels()
    {
        var conflicts = D3FendMappings.All
            .SelectMany(kv => kv.Value.Techniques.Zip(kv.Value.Labels, (t, l) => (Technique: t, Label: l)))
            .GroupBy(x => x.Technique, StringComparer.Ordinal)
            .Where(g => g.Select(x => x.Label).Distinct(StringComparer.Ordinal).Count() > 1)
            .Select(g => $"{g.Key}: {string.Join(" / ", g.Select(x => x.Label).Distinct(StringComparer.Ordinal))}")
            .ToList();

        Assert.True(conflicts.Count == 0, string.Join(Environment.NewLine, conflicts));
    }

    [Fact]
    public void Stages_Are_The_Techniques_Own_Stages()
    {
        var reference = s_reference.Value;
        foreach (var (id, mapping) in D3FendMappings.All)
        {
            var expected = reference.Stages
                .Where(stage => mapping.Techniques.Any(t => reference.Techniques.TryGetValue(t, out var tech) && tech.Stage == stage))
                .ToArray();
            Assert.True(expected.SequenceEqual(mapping.Stages), $"{id} stages {string.Join(",", mapping.Stages)}, its techniques give {string.Join(",", expected)}");
        }
    }

    [Fact]
    public void Script_Map_Is_Identical_To_The_App_Map()
    {
        var block = Block(s_script.Value, @"\$script:D3FendMap = @\{");
        var script = ScriptRow().Matches(block).ToDictionary(m => m.Groups["id"].Value, m => m, StringComparer.Ordinal);

        Assert.Equal(D3FendMappings.All.Keys.Order(StringComparer.Ordinal), script.Keys.Order(StringComparer.Ordinal));
        foreach (var (id, mapping) in D3FendMappings.All)
        {
            var row = script[id];
            Assert.True(mapping.Stages.SequenceEqual(Quoted(row.Groups["stages"].Value)), $"{id} stages differ");
            Assert.True(mapping.Techniques.SequenceEqual(Quoted(row.Groups["techniques"].Value)), $"{id} techniques differ");
            Assert.True(mapping.Labels.SequenceEqual(Quoted(row.Groups["labels"].Value)), $"{id} labels differ");
            Assert.Equal(mapping.Description, row.Groups["desc"].Value.Replace("''", "'"));
        }
    }

    [Fact]
    public void Problem_Catches_The_Old_Backup_Label_And_Invented_Ids()
    {
        // Positive control: the table used to label Bootloader Authentication as "Backup" and cite IDs D3FEND doesn't have.
        Assert.Equal("D3FEND calls it \"Bootloader Authentication\"", Problem("D3-BA", "Backup"));
        Assert.Equal("not in D3FEND 1.6.0", Problem("D3-SIEM", "SIEM Event Correlation"));
        Assert.Null(Problem("D3-RF", "Restore File"));
    }

    private static string? Problem(string technique, string label)
    {
        var reference = s_reference.Value;
        if (!reference.Techniques.TryGetValue(technique, out var tech)) return $"not in D3FEND {reference.Version}";
        return tech.Label == label ? null : $"D3FEND calls it \"{tech.Label}\"";
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

    [GeneratedRegex(@"(?m)^\s*'(?<id>[A-Z]{2}\d{2})' = @\{ Stages=@\((?<stages>[^)]*)\); Techniques=@\((?<techniques>[^)]*)\); Labels=@\((?<labels>[^)]*)\); Desc='(?<desc>(?:[^']|'')*)' \}\s*$")]
    private static partial Regex ScriptRow();

    private sealed record D3fendReference(string Version, string[] Stages, Dictionary<string, (string Label, string Stage)> Techniques);

    private static D3fendReference LoadReference()
    {
        var path = Path.Combine(FindRepoRoot(), "tests", "NetworkSecurityAuditor.Tests", "Fixtures", "D3fend", "d3fend.json");
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var root = doc.RootElement;
        return new D3fendReference(
            root.GetProperty("version").GetString()!,
            root.GetProperty("stages").EnumerateArray().Select(s => s.GetString()!).ToArray(),
            root.GetProperty("techniques").EnumerateObject().ToDictionary(
                p => p.Name,
                p => (p.Value.GetProperty("label").GetString()!, p.Value.GetProperty("stage").GetString()!),
                StringComparer.Ordinal));
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "NetworkSecurityAuditor.slnx")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new DirectoryNotFoundException("Repository root not found.");
    }
}
