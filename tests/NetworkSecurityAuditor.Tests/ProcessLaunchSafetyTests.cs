namespace NetworkSecurityAuditor.Tests;

using System.Text.RegularExpressions;

/// <summary>
/// Headless runs happen under RMM agents and scheduled tasks, often on a desktop someone is using. No check may
/// open a window there, so checks start processes only through CommandRunner (which hides the window), and only
/// console tools.
/// </summary>
public sealed partial class ProcessLaunchSafetyTests
{
    /// <summary>Console tools the checks run hidden, with redirected output.</summary>
    private static readonly HashSet<string> AllowedConsoleTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "arp", "auditpol", "dsregcmd", "net", "netsh", "rasdial", "route", "winrm"
    };

    /// <summary>Binaries that open a window or a dialog when started.</summary>
    private static readonly string[] GuiBinaries =
    [
        "rasphone", "mmc", "explorer", "notepad", "control", "rundll32", "mstsc", "eventvwr",
        "regedit", "taskmgr", "msinfo32", "mshta", "wscript", "calc", "ncpa.cpl", "rasdlg", "perfmon", "wf.msc"
    ];

    /// <summary>Files that start processes, and why each is safe.</summary>
    private static readonly Dictionary<string, string> ProcessStarters = new(StringComparer.OrdinalIgnoreCase)
    {
        // Hidden console launchers: each must set CreateNoWindow = true and UseShellExecute = false.
        ["Services/CommandRunner.cs"] = "hidden",
        ["Services/EnvironmentDetector.cs"] = "hidden",
        ["Export/PdfExporter.cs"] = "hidden",
        // Interactive GUI only: self-elevation is skipped for --silent and --dashboard, and opening a
        // finished report happens from a button in the window.
        ["App.xaml.cs"] = "interactive",
        ["ViewModels/MainViewModel.cs"] = "interactive"
    };

    [Fact]
    public void No_Check_Starts_A_Process_Directly()
    {
        var offenders = SourceFiles()
            .Where(file => file.Relative.StartsWith("Checks/", StringComparison.OrdinalIgnoreCase))
            .Where(file => file.Text.Contains("Process.Start", StringComparison.Ordinal) ||
                           file.Text.Contains("ProcessStartInfo", StringComparison.Ordinal) ||
                           file.Text.Contains("UseShellExecute", StringComparison.Ordinal))
            .Select(file => file.Relative)
            .ToList();

        Assert.Empty(offenders);
    }

    [Fact]
    public void Every_Process_Launch_Is_Known_And_Hidden()
    {
        foreach (var file in SourceFiles())
        {
            bool starts = file.Text.Contains("Process.Start(", StringComparison.Ordinal) ||
                          file.Text.Contains("ProcessStartInfo", StringComparison.Ordinal);
            if (!starts)
                continue;

            Assert.True(ProcessStarters.TryGetValue(file.Relative, out var kind),
                $"{file.Relative} starts a process but isn't reviewed in ProcessLaunchSafetyTests.");
            if (kind == "hidden")
            {
                Assert.Contains("CreateNoWindow = true", file.Text);
                Assert.Contains("UseShellExecute = false", file.Text);
            }
        }
    }

    [Fact]
    public void Commands_Are_Console_Tools_Only()
    {
        var launched = SourceFiles()
            .SelectMany(file => LaunchTarget().Matches(file.Text).Select(match => (file.Relative, Tool: match.Groups["tool"].Value)))
            .ToList();

        Assert.NotEmpty(launched);
        var unexpected = launched
            .Where(launch => !AllowedConsoleTools.Contains(Path.GetFileNameWithoutExtension(launch.Tool)))
            .Select(launch => $"{launch.Relative}: {launch.Tool}")
            .ToList();
        Assert.Empty(unexpected);
    }

    [Fact]
    public void No_Gui_Binary_Is_Named_Anywhere_In_Source()
    {
        // A string literal that is exactly a GUI binary's name, with or without .exe, anywhere in the app.
        var guiLiteral = new Regex(
            "\"(?<value>(?:" + string.Join("|", GuiBinaries.Select(Regex.Escape)) + @")(?:\.exe)?)""",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        // Localization holds display text only ("Control" is a table header), and nothing there is launched.
        var offenders = SourceFiles()
            .Where(file => !file.Relative.StartsWith("Localization/", StringComparison.OrdinalIgnoreCase))
            .SelectMany(file => guiLiteral.Matches(file.Text).Select(match => $"{file.Relative}: {match.Groups["value"].Value}"))
            .ToList();

        Assert.Empty(offenders);
    }

    [Fact]
    public void Command_Runner_Hides_Every_Window()
    {
        var runner = SourceFiles().Single(file => file.Relative == "Services/CommandRunner.cs");

        Assert.Contains("CreateNoWindow = true", runner.Text);
        Assert.Contains("RedirectStandardOutput = true", runner.Text);
        Assert.Contains("UseShellExecute = false", runner.Text);
    }

    // The first string argument of every launch helper: CommandRunner.Run/RunForOutput, the checks' RunCommand
    // wrappers and injected _runCommand delegates, and ProcessStartInfo(fileName, ...).
    [GeneratedRegex(@"(?:\bRunCommand|\b_runCommand|\bRunForOutput|CommandRunner\.Run|new\s+ProcessStartInfo)\(\s*""(?<tool>[^""]+)""")]
    private static partial Regex LaunchTarget();

    private static IEnumerable<(string Relative, string Text)> SourceFiles()
    {
        string root = Path.Combine(FindRepoRoot(), "src", "NetworkSecurityAuditor");
        return Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories)
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase) &&
                           !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase))
            .Select(path => (Path.GetRelativePath(root, path).Replace('\\', '/'), File.ReadAllText(path)))
            .ToList();
    }

    private static string FindRepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "NetworkSecurityAuditor.slnx")))
            directory = directory.Parent;

        return directory?.FullName ?? throw new InvalidOperationException("Could not locate repository root.");
    }
}
