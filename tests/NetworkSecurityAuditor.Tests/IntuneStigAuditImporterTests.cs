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
}
