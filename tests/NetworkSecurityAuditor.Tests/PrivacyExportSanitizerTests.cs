using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Export;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Tests;

public class PrivacyExportSanitizerTests
{
    [Fact]
    public void Redacts_Environment_Operator_Fields_And_Client_File_Segment()
    {
        var env = new EnvironmentInfo
        {
            ComputerName = "WORKSTATION1",
            DomainName = "CONTOSO.LOCAL",
            OSCaption = "Windows 11 Enterprise for CONTOSO.LOCAL",
            TenantName = "ContosoTenant"
        };
        var check = CheckItemViewModel.FromMetadata(CheckCatalog.All["EP01"]);
        check.Findings = "WORKSTATION1 reported endpoint gaps for CONTOSO.LOCAL";
        check.Evidence = "Agent connected from 192.168.1.10";
        check.Notes = "Accepted by admin.user for Acme Client";
        check.RemediationAssignee = "admin.user";
        check.DurationMs = 1234.5;

        var redactor = PrivacyExportSanitizer.CreateRedactor(
            true,
            env,
            "admin.user",
            "Acme Client");
        var redactedEnv = PrivacyExportSanitizer.RedactEnvironment(env, redactor);
        var redactedCheck = PrivacyExportSanitizer.RedactChecks([check], redactor).Single();
        var clientSegment = App.SafeFileNameSegment(redactor.Redact("Acme Client"), "Client");

        Assert.DoesNotContain("WORKSTATION1", redactedEnv.ComputerName, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("CONTOSO.LOCAL", redactedEnv.DomainName, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ContosoTenant", redactedEnv.TenantName, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("WORKSTATION1", redactedCheck.Findings, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("192.168.1.10", redactedCheck.Evidence, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("admin.user", redactedCheck.Notes, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("admin.user", redactedCheck.RemediationAssignee, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(1234.5, redactedCheck.DurationMs);
        Assert.DoesNotContain("Acme Client", clientSegment, StringComparison.OrdinalIgnoreCase);
        Assert.Matches(@"\[CLIENT-[0-9a-f]{8}\]", clientSegment);
    }
}
