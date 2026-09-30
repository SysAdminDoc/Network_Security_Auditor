namespace NetworkSecurityAuditor.Tests;

public sealed class ResourceDisposalTests
{
    [Fact]
    public void EolOsCheck_Disposes_Ldap_Search_Result_Collections()
    {
        var source = ReadSourceFile("src", "NetworkSecurityAuditor", "Checks", "EndpointSecurity", "EP10_EolOsCheck.cs");

        Assert.DoesNotContain("ManagementObjectSearcher", source);
        Assert.DoesNotContain("foreach (System.DirectoryServices.SearchResult result in adSearcher.FindAll())", source);
        // EP10 searches through IDirectoryReader now; the LDAP reader owns and disposes the result collection.
        Assert.DoesNotContain("FindAll()", source);
        Assert.Contains("directory.Search(query, ct)", source);

        var reader = ReadSourceFile("src", "NetworkSecurityAuditor", "Services", "DirectoryReader.cs");
        Assert.DoesNotContain("in searcher.FindAll())", reader);
        Assert.Contains("using var results = searcher.FindAll();", reader);
    }

    [Theory]
    [InlineData("LM06_FimCheck.cs", 1)]
    [InlineData("LM07_LogRetentionCheck.cs", 1)]
    [InlineData("LM08_AlertingCheck.cs", 2)]
    public void Logging_Checks_Dispose_Service_Controller_Arrays(string fileName, int expectedServiceEnumerations)
    {
        var source = ReadSourceFile("src", "NetworkSecurityAuditor", "Checks", "LoggingMonitoring", fileName);

        Assert.Equal(expectedServiceEnumerations, CountOccurrences(source, "ServiceController.GetServices()"));
        Assert.Equal(expectedServiceEnumerations, CountOccurrences(source, "ServiceControllerDisposal.DisposeAll(services);"));
    }

    private static int CountOccurrences(string source, string value)
    {
        int count = 0;
        int index = 0;
        while ((index = source.IndexOf(value, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += value.Length;
        }

        return count;
    }

    private static string ReadSourceFile(params string[] segments)
    {
        string[] pathSegments = new string[segments.Length + 1];
        pathSegments[0] = FindRepoRoot();
        segments.CopyTo(pathSegments, 1);
        return File.ReadAllText(Path.Combine(pathSegments));
    }

    private static string FindRepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "NetworkSecurityAuditor.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("Could not locate repository root.");
    }
}
