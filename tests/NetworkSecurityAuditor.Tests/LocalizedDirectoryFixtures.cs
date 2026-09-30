using System.Text.RegularExpressions;

namespace NetworkSecurityAuditor.Tests;

/// <summary>
/// The "-de" directory fixtures are their English twins with the well-known groups carrying German names, the way
/// a German domain controller creates them. A check that finds groups by SID gives both the same answer.
/// </summary>
internal static class LocalizedDirectoryFixtures
{
    private static readonly (string German, string English)[] s_names =
    [
        ("Domänen-Admins", "Domain Admins"),
        ("Organisations-Admins", "Enterprise Admins"),
        ("Schema-Admins", "Schema Admins"),
        ("Administratoren", "Administrators"),
        ("Konten-Operatoren", "Account Operators"),
        ("Server-Operatoren", "Server Operators"),
        ("Sicherungs-Operatoren", "Backup Operators"),
        ("Remotedesktopbenutzer", "Remote Desktop Users"),
    ];

    public static IEnumerable<string> EnglishNames => s_names.Select(n => n.English);

    /// <summary>Maps the German group names in a result (or a fixture) back to English.</summary>
    public static string Delocalize(string text)
    {
        foreach (var (german, english) in s_names)
            text = text.Replace(german, english, StringComparison.Ordinal);
        return text;
    }

    public static string Read(string fileName)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "NetworkSecurityAuditor.slnx")))
            dir = dir.Parent;
        return File.ReadAllText(Path.Combine(dir!.FullName, "tests", "NetworkSecurityAuditor.Tests", "Fixtures", "Directory", fileName));
    }
}

public class LocalizedDirectoryFixtureTests
{
    [Theory]
    [InlineData("IA01-pass")]
    [InlineData("IA01-fail")]
    [InlineData("IA01-nested")]
    [InlineData("IA02-fail")]
    [InlineData("CF04-fail")]
    [InlineData("CF04-nested")]
    public void German_Fixture_Is_The_English_Domain_With_Localized_Group_Names(string fixture)
    {
        var english = LocalizedDirectoryFixtures.Read(fixture + ".json");
        var german = LocalizedDirectoryFixtures.Read(fixture + "-de.json");

        Assert.Contains("Domänen-Admins", german);
        foreach (var name in LocalizedDirectoryFixtures.EnglishNames)
            Assert.DoesNotMatch(new Regex($"CN={Regex.Escape(name)},|\"sAMAccountName\": \"{Regex.Escape(name)}\""), german);
        Assert.Equal(english, LocalizedDirectoryFixtures.Delocalize(german));
    }
}
