using NetworkSecurityAuditor.Services;

namespace NetworkSecurityAuditor.Tests;

public class IntuneStigAuditImporterTests
{
    [Fact]
    public async Task LoadAsync_Rejects_Oversized_Import_File()
    {
        var path = Path.Combine(Path.GetTempPath(), "nsa-intune-large-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            using (var stream = File.OpenWrite(path))
            {
                stream.SetLength(IntuneStigAuditImporter.MaxImportBytes + 1);
            }

            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => IntuneStigAuditImporter.LoadAsync(path));

            Assert.Contains("Intune STIG audit import file", ex.Message);
            Assert.Contains("maximum supported size", ex.Message);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task LoadAsync_Handles_CaseInsensitive_Containers_And_Skips_Malformed_Json_Rows()
    {
        var path = Path.Combine(Path.GetTempPath(), "nsa-intune-json-" + Guid.NewGuid().ToString("N") + ".json");
        await File.WriteAllTextAsync(path, """
        {
          "Results": [
            {"SETTINGID":"STIG-1", "STATUS":"Passed", "ReferenceId":"V-1000"},
            "not an object",
            {"Status":"Failed"}
          ]
        }
        """);

        try
        {
            var import = await IntuneStigAuditImporter.LoadAsync(path);

            Assert.Equal("Partial", import.ImportStatus);
            Assert.Single(import.Findings);
            Assert.Equal("STIG-1", import.Findings[0].SettingId);
            Assert.Equal(2, import.SkippedRowCount);
            Assert.Contains(import.ImportWarnings, warning => warning.Contains("unsupported value kind", StringComparison.Ordinal));
            Assert.Contains(import.ImportWarnings, warning => warning.Contains("neither", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task LoadAsync_Normalizes_Duplicate_And_Blank_Csv_Headers()
    {
        var path = Path.Combine(Path.GetTempPath(), "nsa-intune-csv-" + Guid.NewGuid().ToString("N") + ".csv");
        await File.WriteAllTextAsync(path, "SettingId,settingid,,Reference ID\nSTIG-2,ignored,,V-2000\n, , ,\n");

        try
        {
            var import = await IntuneStigAuditImporter.LoadAsync(path);

            Assert.Equal("Partial", import.ImportStatus);
            Assert.Single(import.Findings);
            Assert.Equal("STIG-2", import.Findings[0].SettingId);
            Assert.Equal("V-2000", import.Findings[0].ReferenceId);
            Assert.Equal(2, import.SkippedHeaderCount);
            Assert.True(import.SkippedRowCount >= 1);
            Assert.Contains(import.ImportWarnings, warning => warning.Contains("Duplicate CSV header", StringComparison.Ordinal));
            Assert.Contains(import.ImportWarnings, warning => warning.Contains("Blank CSV header", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
