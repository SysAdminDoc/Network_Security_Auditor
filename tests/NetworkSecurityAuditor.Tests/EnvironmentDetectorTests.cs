using NetworkSecurityAuditor.Services;

namespace NetworkSecurityAuditor.Tests;

public class EnvironmentDetectorTests
{
    [Theory]
    [InlineData("IsDeviceManaged : NO\r\nEnrollmentType : none", false)]
    [InlineData("IsDeviceManaged : NO\r\nEnrollmentType : unknown", false)]
    [InlineData("IsDeviceManaged : NO\r\nEnrollmentType : 0", false)]
    [InlineData("IsDeviceManaged : YES\r\nEnrollmentType : none", true)]
    [InlineData("IsDeviceManaged : NO\r\nEnrollmentType : mdm", true)]
    public void Intune_Management_Detection_Requires_Managed_State_Or_Real_Enrollment(string dsregOutput, bool expected)
    {
        Assert.Equal(expected, EnvironmentDetector.IsIntuneManagedFromDsregOutput(dsregOutput));
    }

    [Fact]
    public void Environment_Detector_Avoids_System_Drive_Hardcoded_Module_And_Laps_Paths()
    {
        var source = ReadSourceFile("src", "NetworkSecurityAuditor", "Services", "EnvironmentDetector.cs");

        Assert.DoesNotContain(@"C:\Windows\System32\WindowsPowerShell", source);
        Assert.DoesNotContain(@"C:\Program Files\LAPS", source);
        Assert.Contains("Environment.SpecialFolder.Windows", source);
        Assert.Contains("Environment.SpecialFolder.ProgramFiles", source);
        Assert.Contains("Path.Combine(moduleRoot", source);
    }

    [Fact]
    public void Dsregcmd_Output_Is_Read_After_Timeout_Guard()
    {
        var source = ReadSourceFile("src", "NetworkSecurityAuditor", "Services", "EnvironmentDetector.cs");

        Assert.Contains("var outputTask = proc.StandardOutput.ReadToEndAsync();", source);
        Assert.Contains("if (!proc.WaitForExit(5000))", source);
        Assert.Contains("proc.Kill(entireProcessTree: true)", source);
        Assert.DoesNotContain("proc.StandardOutput.ReadToEnd();", source);
    }

    private static string ReadSourceFile(params string[] segments)
    {
        var pathSegments = new string[segments.Length + 1];
        pathSegments[0] = FindRepoRoot();
        Array.Copy(segments, 0, pathSegments, 1, segments.Length);
        return File.ReadAllText(Path.Combine(pathSegments));
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
