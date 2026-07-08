namespace NetworkSecurityAuditor.Tests;

public class MainWindowXamlTests
{
    [Fact]
    public void Main_Window_Binds_Security_Color_Surfaces()
    {
        var xaml = File.ReadAllText(Path.Combine(FindRepoRoot(), "src", "NetworkSecurityAuditor", "MainWindow.xaml"));

        Assert.Contains("Foreground=\"{Binding GradeColor}\"", xaml);
        Assert.Contains("Background=\"{Binding SeverityColor}\"", xaml);
        Assert.Contains("Background=\"{Binding StatusColor}\"", xaml);
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "NetworkSecurityAuditor.slnx")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new DirectoryNotFoundException("Could not locate NetworkSecurityAuditor.slnx from test output directory.");
    }
}
