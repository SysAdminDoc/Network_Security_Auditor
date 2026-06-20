using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class AuditStateTests
{
    [Fact]
    public void Serialize_Deserialize_Roundtrip()
    {
        var original = new AuditState
        {
            SchemaVersion = "1.0",
            Client = "TestClient",
            Auditor = "jsmith",
            ScanProfile = "Full",
            Theme = "Catppuccin Mocha",
            OverallScore = 75,
            Grade = "C",
            RansomwareScore = 60,
            RansomwareGrade = "D",
            DomainMaturityScore = 80,
            DomainMaturityGrade = "B",
            Checks =
            [
                new CheckState
                {
                    Id = "EP01",
                    Status = CheckStatus.Pass,
                    Findings = "AV is running",
                    Evidence = "Defender active",
                    Notes = "Verified manually",
                    RemediationAssignee = "admin",
                    RemediationDueDate = "2026-12-31"
                },
                new CheckState
                {
                    Id = "IA05",
                    Status = CheckStatus.Fail,
                    Findings = "Weak password policy",
                    Evidence = "MinLength=8",
                    Notes = "",
                    RemediationAssignee = "",
                    RemediationDueDate = null
                },
                new CheckState
                {
                    Id = "BR01",
                    Status = CheckStatus.NA,
                    Findings = "",
                    Evidence = "",
                    Notes = "Not applicable",
                    RemediationAssignee = "",
                    RemediationDueDate = null
                }
            ]
        };

        var json = original.Serialize();
        var deserialized = AuditState.Deserialize(json);

        Assert.NotNull(deserialized);
        Assert.Equal(original.SchemaVersion, deserialized.SchemaVersion);
        Assert.Equal(original.Client, deserialized.Client);
        Assert.Equal(original.Auditor, deserialized.Auditor);
        Assert.Equal(original.ScanProfile, deserialized.ScanProfile);
        Assert.Equal(original.Theme, deserialized.Theme);
        Assert.Equal(original.OverallScore, deserialized.OverallScore);
        Assert.Equal(original.Grade, deserialized.Grade);
        Assert.Equal(original.RansomwareScore, deserialized.RansomwareScore);
        Assert.Equal(original.RansomwareGrade, deserialized.RansomwareGrade);
        Assert.Equal(original.DomainMaturityScore, deserialized.DomainMaturityScore);
        Assert.Equal(original.DomainMaturityGrade, deserialized.DomainMaturityGrade);

        Assert.Equal(3, deserialized.Checks.Count);

        var ep01 = deserialized.Checks.First(c => c.Id == "EP01");
        Assert.Equal(CheckStatus.Pass, ep01.Status);
        Assert.Equal("AV is running", ep01.Findings);
        Assert.Equal("admin", ep01.RemediationAssignee);
        Assert.Equal("2026-12-31", ep01.RemediationDueDate);

        var ia05 = deserialized.Checks.First(c => c.Id == "IA05");
        Assert.Equal(CheckStatus.Fail, ia05.Status);
        Assert.Null(ia05.RemediationDueDate);

        var br01 = deserialized.Checks.First(c => c.Id == "BR01");
        Assert.Equal(CheckStatus.NA, br01.Status);
    }

    [Fact]
    public void ToolVersion_Reads_From_Assembly()
    {
        var state = new AuditState();
        Assert.False(string.IsNullOrEmpty(state.ToolVersion));
        Assert.NotEqual("5.0.0", state.ToolVersion);
    }

    [Fact]
    public void Deserialize_Throws_On_Invalid_Json()
    {
        Assert.ThrowsAny<System.Text.Json.JsonException>(() => AuditState.Deserialize("not valid json"));
    }

    [Fact]
    public void Deserialize_Empty_Object()
    {
        var result = AuditState.Deserialize("{}");
        Assert.NotNull(result);
        Assert.Empty(result.Checks);
    }
}
