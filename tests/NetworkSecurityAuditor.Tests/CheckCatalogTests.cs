using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;

namespace NetworkSecurityAuditor.Tests;

public class CheckCatalogTests
{
    [Fact]
    public void Catalog_Contains_69_Checks()
    {
        Assert.Equal(69, CheckCatalog.All.Count);
    }

    [Fact]
    public void All_Checks_Have_Required_Fields()
    {
        foreach (var (id, meta) in CheckCatalog.All)
        {
            Assert.False(string.IsNullOrWhiteSpace(meta.Id), $"{id} has empty Id");
            Assert.False(string.IsNullOrWhiteSpace(meta.Label), $"{id} has empty Label");
            Assert.False(string.IsNullOrWhiteSpace(meta.Category), $"{id} has empty Category");
            Assert.False(string.IsNullOrWhiteSpace(meta.Hint), $"{id} has empty Hint");
            Assert.True(meta.Weight > 0, $"{id} has zero weight");
        }
    }

    [Fact]
    public void Check_Ids_Match_Dictionary_Keys()
    {
        foreach (var (key, meta) in CheckCatalog.All)
        {
            Assert.Equal(key, meta.Id);
        }
    }

    [Theory]
    [InlineData("Identity & Access", 12)]
    [InlineData("Endpoint Security", 10)]
    [InlineData("Logging & Monitoring", 8)]
    [InlineData("Network Architecture", 7)]
    [InlineData("Network Perimeter", 10)]
    [InlineData("Backup & Recovery", 8)]
    [InlineData("Common Findings", 8)]
    [InlineData("Policies & Standards", 6)]
    public void Category_Has_Expected_Count(string category, int expected)
    {
        var count = CheckCatalog.All.Values.Count(m => m.Category == category);
        Assert.Equal(expected, count);
    }

    [Fact]
    public void All_Categories_Are_Known()
    {
        var known = new HashSet<string>
        {
            "Identity & Access", "Endpoint Security", "Logging & Monitoring",
            "Network Architecture", "Network Perimeter", "Backup & Recovery",
            "Common Findings", "Policies & Standards"
        };

        foreach (var meta in CheckCatalog.All.Values)
        {
            Assert.Contains(meta.Category, known);
        }
    }

    [Theory]
    [InlineData("NA03", "Wireless security", "wireless", "Wireless Filtering", "3.1.16, 3.1.17", "AC.L2-3.1.16, AC.L2-3.1.17")]
    [InlineData("NA04", "Network documentation", "diagram", "Access Modeling", "3.4.1, 3.4.2", "CM.L2-3.4.1, CM.L2-3.4.2")]
    [InlineData("NA05", "802.1X/NAC", "802.1X", "Credential Transmission Scoping", "3.1.1, 3.1.2, 3.1.20", "AC.L2-3.1.1, AC.L2-3.1.2, AC.L2-3.1.20")]
    [InlineData("NA06", "Management interface isolation", "management", "Inbound/Outbound Port Restriction", "3.13.1, 3.13.5, 3.13.6", "SC.L2-3.13.1, SC.L2-3.13.5, SC.L2-3.13.6")]
    [InlineData("NA07", "Guest network isolation", "guest", "Wireless Filtering", "3.13.1, 3.13.2", "SC.L2-3.13.1, SC.L2-3.13.2")]
    public void Network_Architecture_Mappings_Match_Current_Catalog(
        string id,
        string expectedLabel,
        string expectedDescriptionTerm,
        string expectedDefendLabel,
        string expectedNist,
        string expectedCmmc)
    {
        var catalog = CheckCatalog.All[id];
        var attack = MitreMappings.All[id];
        var defend = D3FendMappings.All[id];
        var framework = FrameworkMappings.All[id];
        var staleTerms = new[] { "DMZ", "VPN", "IDS", "DNS filtering" };

        Assert.Equal(expectedLabel, catalog.Label);
        Assert.True(attack.Description.Contains(expectedDescriptionTerm, StringComparison.OrdinalIgnoreCase),
            $"{id} ATT&CK description should describe {expectedLabel}.");
        Assert.True(defend.Description.Contains(expectedDescriptionTerm, StringComparison.OrdinalIgnoreCase),
            $"{id} D3FEND description should describe {expectedLabel}.");
        Assert.Contains(expectedDefendLabel, defend.Labels);
        Assert.Equal(expectedNist, framework.NIST);
        Assert.Equal(expectedCmmc, framework.CMMC);

        foreach (var staleTerm in staleTerms)
        {
            Assert.False(attack.Description.Contains(staleTerm, StringComparison.OrdinalIgnoreCase),
                $"{id} ATT&CK description still contains stale term {staleTerm}.");
            Assert.False(defend.Description.Contains(staleTerm, StringComparison.OrdinalIgnoreCase),
                $"{id} D3FEND description still contains stale term {staleTerm}.");
        }
    }

    [Theory]
    [InlineData("BR03", "Restore testing", "restore", "File Verification", "3.6.1, 3.6.3", "IR.L2-3.6.1, IR.L2-3.6.3")]
    [InlineData("BR04", "RTO/RPO documentation", "RTO/RPO", "Access Modeling", "3.6.1", "IR.L2-3.6.1")]
    [InlineData("BR05", "Backup encryption", "encrypt", "Disk Encryption", "3.8.1, 3.8.6, 3.13.11", "MP.L2-3.8.1, MP.L2-3.8.6, SC.L2-3.13.11")]
    [InlineData("BR06", "Backup monitoring", "monitor", "Platform Monitoring", "3.6.1, 3.6.2", "IR.L2-3.6.1, IR.L2-3.6.2")]
    [InlineData("BR07", "DR plan", "DR plan", "Access Modeling", "3.6.1, 3.6.2", "IR.L2-3.6.1, IR.L2-3.6.2")]
    public void Backup_Recovery_Mappings_Match_Current_Catalog(
        string id,
        string expectedLabel,
        string expectedDescriptionTerm,
        string expectedDefendLabel,
        string expectedNist,
        string expectedCmmc)
    {
        var catalog = CheckCatalog.All[id];
        var attack = MitreMappings.All[id];
        var defend = D3FendMappings.All[id];
        var framework = FrameworkMappings.All[id];

        Assert.Equal(expectedLabel, catalog.Label);
        Assert.True(attack.Description.Contains(expectedDescriptionTerm, StringComparison.OrdinalIgnoreCase),
            $"{id} ATT&CK description should describe {expectedLabel}.");
        Assert.True(defend.Description.Contains(expectedDescriptionTerm, StringComparison.OrdinalIgnoreCase),
            $"{id} D3FEND description should describe {expectedLabel}.");
        Assert.Contains(expectedDefendLabel, defend.Labels);
        Assert.Equal(expectedNist, framework.NIST);
        Assert.Equal(expectedCmmc, framework.CMMC);
    }

    [Theory]
    [InlineData("PS01", "Security policies", "ID.GV-1", "164.308(a)(1)(i), 164.308(a)(1)(ii)(A), 164.316(b)(1)", "PL-1, PL-2, PM-1")]
    [InlineData("PS02", "Acceptable use policy", "PR.AT-1", "164.308(a)(5)(i), 164.316(b)(1)", "AT-1, AT-2, PL-4")]
    [InlineData("PS03", "Incident response plan", "RS.RP-1", "164.308(a)(6)(i), 164.308(a)(6)(ii), 164.316(b)(1)", "IR-1, IR-4, IR-8")]
    [InlineData("PS04", "Compliance monitoring", "ID.GV-3", "164.308(a)(1)(ii)(D), 164.316(b)(2)(iii)", "CA-2, CA-7, PM-10")]
    [InlineData("PS05", "Risk assessment", "ID.RA-1", "164.308(a)(1)(ii)(A), 164.308(a)(1)(ii)(B)", "RA-1, RA-3, RA-5")]
    [InlineData("PS06", "Security training", "PR.AT-1", "164.308(a)(5)(i), 164.308(a)(5)(ii)(A)", "AT-1, AT-2, AT-3")]
    public void Policies_Standards_Mappings_Avoid_Physical_Security_Citations(
        string id,
        string expectedLabel,
        string expectedCsfTerm,
        string expectedHipaa,
        string expectedFedramp)
    {
        var catalog = CheckCatalog.All[id];
        var framework = FrameworkMappings.All[id];

        Assert.Equal(expectedLabel, catalog.Label);
        Assert.Contains(expectedCsfTerm, catalog.Compliance);
        Assert.Equal(expectedHipaa, framework.HIPAA);
        Assert.Equal(expectedFedramp, framework.FedRAMP);
        Assert.DoesNotContain("164.310", catalog.Compliance);
        Assert.DoesNotContain("164.310", framework.HIPAA);
        Assert.DoesNotContain("PE-", framework.FedRAMP);
    }

    [Fact]
    public void Stig_Mappings_Do_Not_Use_Fabricated_Vulnerability_Ids()
    {
        var stigMappedIds = FrameworkMappings.All
            .Where(kv => kv.Value.STIG is not null)
            .Select(kv => kv.Key)
            .Order()
            .ToArray();

        Assert.Equal(new[] { "IA11", "IA12" }, stigMappedIds);
        Assert.DoesNotContain(FrameworkMappings.All.Values, mapping =>
            mapping.STIG?.Contains("V-254", StringComparison.OrdinalIgnoreCase) == true);
        Assert.DoesNotContain(FrameworkDefinitions.All, framework =>
            framework.Name.Equals("DISA STIG", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Ep10_Mapping_Matches_Eol_Operating_Systems()
    {
        var catalog = CheckCatalog.All["EP10"];
        var attack = MitreMappings.All["EP10"];
        var defend = D3FendMappings.All["EP10"];
        var framework = FrameworkMappings.All["EP10"];

        Assert.Equal("EOL operating systems", catalog.Label);
        Assert.Contains("T1190", attack.Techniques);
        Assert.Contains("T1210", attack.Techniques);
        Assert.DoesNotContain("T1091", attack.Techniques);
        Assert.DoesNotContain("T1052", attack.Techniques);
        Assert.Contains("Software Update", defend.Labels);
        Assert.Contains("end-of-life", defend.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("SI-2, CM-8", framework.FedRAMP);
    }

    [Fact]
    public void Cf03_Mapping_Matches_Security_Awareness_Training()
    {
        var catalog = CheckCatalog.All["CF03"];
        var framework = FrameworkMappings.All["CF03"];
        var e8Ids = ScanProfiles.Resolve(ScanProfileType.E8);

        Assert.Equal("Security awareness training", catalog.Label);
        Assert.Equal("NIST CSF PR.AT-1, PR.AT-2 | CIS Control 14.1, 14.2 | HIPAA 164.308(a)(5)(i), 164.308(a)(5)(ii)(A)", catalog.Compliance);
        Assert.Equal("14.1, 14.2", framework.CIS);
        Assert.Equal("164.308(a)(5)(i), 164.308(a)(5)(ii)(A)", framework.HIPAA);
        Assert.Equal("AT-1, AT-2, AT-3", framework.FedRAMP);
        Assert.Null(framework.E8);
        Assert.DoesNotContain("11.4", framework.FormatAll());
        Assert.DoesNotContain("11.5", framework.FormatAll());
        Assert.DoesNotContain("164.308(a)(7", catalog.Compliance);
        Assert.DoesNotContain("Regular Backups", framework.FormatAll());
        Assert.DoesNotContain("CF03", e8Ids);
    }

    [Fact]
    public void Severity_Weights_Match_Enum_Values()
    {
        foreach (var meta in CheckCatalog.All.Values)
        {
            Assert.True(meta.Weight >= (int)Severity.Low && meta.Weight <= (int)Severity.Critical,
                $"{meta.Id} has weight {meta.Weight} outside valid range [{(int)Severity.Low}-{(int)Severity.Critical}]");
        }
    }
}
