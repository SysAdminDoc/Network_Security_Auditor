using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkSecurityAuditor.Services;

namespace NetworkSecurityAuditor.Models;

public sealed class RiskWaiver
{
    public required string CheckId { get; set; }
    public required string Justification { get; set; }
    public required string ApprovedBy { get; set; }
    public required DateTime ApprovedDate { get; set; }
    public DateTime? ExpirationDate { get; set; }

    [JsonIgnore]
    public bool IsExpired => ExpirationDate.HasValue &&
        ToUtcDate(ExpirationDate.Value) < DateOnly.FromDateTime(DateTime.UtcNow);

    [JsonIgnore]
    public bool IsActive => !IsExpired;

    internal static DateOnly ToUtcDate(DateTime value)
    {
        return value.Kind switch
        {
            DateTimeKind.Local => DateOnly.FromDateTime(value.ToUniversalTime()),
            DateTimeKind.Utc => DateOnly.FromDateTime(value),
            _ => DateOnly.FromDateTime(value.Date)
        };
    }
}

public sealed class WaiverStore
{
    public string SchemaVersion { get; set; } = "1.0";
    public List<RiskWaiver> Waivers { get; set; } = [];

    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public void Add(RiskWaiver waiver)
    {
        Waivers.RemoveAll(w => w.CheckId.Equals(waiver.CheckId, StringComparison.OrdinalIgnoreCase));
        Waivers.Add(waiver);
    }

    public void Remove(string checkId)
    {
        Waivers.RemoveAll(w => w.CheckId.Equals(checkId, StringComparison.OrdinalIgnoreCase));
    }

    public RiskWaiver? GetActive(string checkId)
    {
        return Waivers.FirstOrDefault(w =>
            w.CheckId.Equals(checkId, StringComparison.OrdinalIgnoreCase) && w.IsActive);
    }

    public IReadOnlyList<RiskWaiver> GetExpired()
    {
        return Waivers.Where(w => w.IsExpired).ToList();
    }

    public string Serialize() => JsonSerializer.Serialize(this, Options);

    public static WaiverStore Deserialize(string json)
        => JsonSerializer.Deserialize<WaiverStore>(json, Options) ?? new WaiverStore();

    public static async Task<WaiverStore> LoadFromFileAsync(string path)
    {
        if (!File.Exists(path)) return new WaiverStore();
        var json = await File.ReadAllTextAsync(path);
        return Deserialize(json);
    }

    public async Task SaveToFileAsync(string path)
    {
        await AtomicFileWriter.WriteAllTextAsync(path, Serialize());
    }
}
