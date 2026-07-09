using System.IO;
using NetworkSecurityAuditor.Data;
using NetworkSecurityAuditor.Models;
using NetworkSecurityAuditor.Scoring;
using NetworkSecurityAuditor.ViewModels;

namespace NetworkSecurityAuditor.Tests;

public class WaiverStoreTests
{
    [Fact]
    public void Add_Waiver_And_GetActive()
    {
        var store = new WaiverStore();
        store.Add(new RiskWaiver
        {
            CheckId = "EP01",
            Justification = "Third-party AV in use",
            ApprovedBy = "CISO",
            ApprovedDate = DateTime.UtcNow,
            ExpirationDate = DateTime.UtcNow.AddDays(90)
        });

        var active = store.GetActive("EP01");
        Assert.NotNull(active);
        Assert.Equal("Third-party AV in use", active.Justification);
    }

    [Fact]
    public void Add_Replaces_Existing_By_CheckId()
    {
        var store = new WaiverStore();
        store.Add(new RiskWaiver
        {
            CheckId = "EP01",
            Justification = "old",
            ApprovedBy = "admin",
            ApprovedDate = DateTime.UtcNow
        });
        store.Add(new RiskWaiver
        {
            CheckId = "EP01",
            Justification = "new",
            ApprovedBy = "admin",
            ApprovedDate = DateTime.UtcNow
        });

        Assert.Single(store.Waivers);
        Assert.Equal("new", store.Waivers[0].Justification);
    }

    [Fact]
    public void GetActive_CaseInsensitive()
    {
        var store = new WaiverStore();
        store.Add(new RiskWaiver
        {
            CheckId = "EP01",
            Justification = "test",
            ApprovedBy = "admin",
            ApprovedDate = DateTime.UtcNow
        });

        Assert.NotNull(store.GetActive("ep01"));
        Assert.NotNull(store.GetActive("Ep01"));
    }

    [Fact]
    public void GetActive_Returns_Null_For_Expired()
    {
        var store = new WaiverStore();
        store.Add(new RiskWaiver
        {
            CheckId = "EP01",
            Justification = "expired waiver",
            ApprovedBy = "admin",
            ApprovedDate = DateTime.UtcNow.AddDays(-100),
            ExpirationDate = DateTime.UtcNow.AddDays(-1)
        });

        Assert.Null(store.GetActive("EP01"));
    }

    [Fact]
    public void GetExpired_Returns_Expired_Waivers()
    {
        var store = new WaiverStore();
        store.Add(new RiskWaiver
        {
            CheckId = "EP01",
            Justification = "expired",
            ApprovedBy = "admin",
            ApprovedDate = DateTime.UtcNow.AddDays(-100),
            ExpirationDate = DateTime.UtcNow.AddDays(-1)
        });
        store.Add(new RiskWaiver
        {
            CheckId = "EP02",
            Justification = "active",
            ApprovedBy = "admin",
            ApprovedDate = DateTime.UtcNow,
            ExpirationDate = DateTime.UtcNow.AddDays(90)
        });

        var expired = store.GetExpired();
        Assert.Single(expired);
        Assert.Equal("EP01", expired[0].CheckId);
    }

    [Fact]
    public void No_Expiration_Means_Permanent()
    {
        var waiver = new RiskWaiver
        {
            CheckId = "EP01",
            Justification = "permanent",
            ApprovedBy = "admin",
            ApprovedDate = DateTime.UtcNow,
            ExpirationDate = null
        };

        Assert.True(waiver.IsActive);
        Assert.False(waiver.IsExpired);
    }

    [Fact]
    public void ExpirationDate_UnspecifiedKind_Uses_DateOnly_Semantics()
    {
        var waiver = new RiskWaiver
        {
            CheckId = "EP01",
            Justification = "expires today",
            ApprovedBy = "admin",
            ApprovedDate = DateTime.UtcNow.AddDays(-1),
            ExpirationDate = DateTime.SpecifyKind(DateTime.UtcNow.Date, DateTimeKind.Unspecified)
        };

        Assert.False(waiver.IsExpired);
        Assert.True(waiver.IsActive);
    }

    [Fact]
    public void ExpirationDate_UnspecifiedKind_Yesterday_Is_Expired()
    {
        var waiver = new RiskWaiver
        {
            CheckId = "EP01",
            Justification = "expired yesterday",
            ApprovedBy = "admin",
            ApprovedDate = DateTime.UtcNow.AddDays(-2),
            ExpirationDate = DateTime.SpecifyKind(DateTime.UtcNow.Date.AddDays(-1), DateTimeKind.Unspecified)
        };

        Assert.True(waiver.IsExpired);
        Assert.False(waiver.IsActive);
    }

    [Fact]
    public void Remove_Waiver()
    {
        var store = new WaiverStore();
        store.Add(new RiskWaiver
        {
            CheckId = "EP01",
            Justification = "test",
            ApprovedBy = "admin",
            ApprovedDate = DateTime.UtcNow
        });

        store.Remove("EP01");
        Assert.Empty(store.Waivers);
    }

    [Fact]
    public void Serialize_Deserialize_Roundtrip()
    {
        var store = new WaiverStore();
        store.Add(new RiskWaiver
        {
            CheckId = "EP01",
            Justification = "accepted risk",
            ApprovedBy = "CISO",
            ApprovedDate = new DateTime(2026, 1, 15, 0, 0, 0, DateTimeKind.Utc),
            ExpirationDate = new DateTime(2026, 7, 15, 0, 0, 0, DateTimeKind.Utc)
        });

        var json = store.Serialize();
        var restored = WaiverStore.Deserialize(json);

        Assert.Single(restored.Waivers);
        Assert.Equal("EP01", restored.Waivers[0].CheckId);
        Assert.Equal("accepted risk", restored.Waivers[0].Justification);
        Assert.Equal("CISO", restored.Waivers[0].ApprovedBy);
    }

    [Fact]
    public async Task LoadFromFile_MissingFile_ReturnsEmptyStore()
    {
        var store = await WaiverStore.LoadFromFileAsync(@"C:\nonexistent\waivers.json");
        Assert.NotNull(store);
        Assert.Empty(store.Waivers);
    }

    [Fact]
    public async Task SaveAndLoad_Roundtrip()
    {
        var store = new WaiverStore();
        store.Add(new RiskWaiver
        {
            CheckId = "IA05",
            Justification = "policy exception",
            ApprovedBy = "admin",
            ApprovedDate = DateTime.UtcNow
        });

        var path = Path.GetTempFileName();
        try
        {
            await store.SaveToFileAsync(path);
            var loaded = await WaiverStore.LoadFromFileAsync(path);

            Assert.Single(loaded.Waivers);
            Assert.Equal("IA05", loaded.Waivers[0].CheckId);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Active_Waived_Fail_Is_Excluded_From_Effective_Scoring()
    {
        var checks = new[]
        {
            Check("EP01", CheckStatus.Fail),
            Check("EP02", CheckStatus.Pass)
        };

        var scoredChecks = App.ExcludeWaivedChecksFromScoring(
            checks,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "EP01" });

        Assert.DoesNotContain(scoredChecks, check => check.Id == "EP01");
        Assert.Contains(scoredChecks, check => check.Id == "EP02");
        var (score, grade) = RiskScoreEngine.Calculate(scoredChecks);
        Assert.Equal(100, score);
        Assert.Equal("A", grade);
    }

    [Fact]
    public void Active_Waived_Pass_Remains_In_Effective_Scoring()
    {
        var checks = new[]
        {
            Check("EP01", CheckStatus.Fail),
            Check("EP02", CheckStatus.Pass)
        };

        var scoredChecks = App.ExcludeWaivedChecksFromScoring(
            checks,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "EP02" });

        Assert.Contains(scoredChecks, check => check.Id == "EP01");
        Assert.Contains(scoredChecks, check => check.Id == "EP02");
    }

    private static CheckItemViewModel Check(string id, CheckStatus status)
    {
        var vm = CheckItemViewModel.FromMetadata(CheckCatalog.All[id]);
        vm.Status = status;
        return vm;
    }
}
