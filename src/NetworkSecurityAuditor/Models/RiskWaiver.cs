using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkSecurityAuditor.Services;

namespace NetworkSecurityAuditor.Models;

public enum WaiverDispositionState
{
    Proposed,
    Approved,
    Rejected,
    Revoked,
    Expired
}

public sealed class WaiverEvent
{
    public required string EventType { get; init; }
    public required WaiverDispositionState FromStatus { get; init; }
    public required WaiverDispositionState ToStatus { get; init; }
    public required string Actor { get; init; }
    public required DateTime OccurredAt { get; init; }
    public required string Reason { get; init; }
}

public sealed class RiskWaiver
{
    public required string CheckId { get; set; }
    public required string Justification { get; set; }
    public required string ApprovedBy { get; set; }
    public required DateTime ApprovedDate { get; set; }
    public DateTime? ExpirationDate { get; set; }
    public string Scope { get; set; } = "check";
    public DateTime? RecertificationDate { get; set; }
    public WaiverDispositionState Status { get; set; } = WaiverDispositionState.Approved;
    public List<WaiverEvent> Events { get; set; } = [];

    [JsonIgnore]
    public WaiverDispositionState EffectiveStatus => IsExpiredByDate ? WaiverDispositionState.Expired : Status;

    [JsonIgnore]
    public bool IsExpired => Status == WaiverDispositionState.Expired || IsExpiredByDate;

    [JsonIgnore]
    public bool IsActive => EffectiveStatus == WaiverDispositionState.Approved;

    [JsonIgnore]
    internal bool IsExpiredByDate => ExpirationDate.HasValue &&
        ToUtcDate(ExpirationDate.Value) < DateOnly.FromDateTime(DateTime.UtcNow);

    [JsonIgnore]
    internal DateTime LastActivityDate => Events.Count == 0
        ? ApprovedDate
        : Events.Max(e => e.OccurredAt);

    public void Transition(
        WaiverDispositionState nextStatus,
        string actor,
        string reason,
        DateTime? occurredAt = null)
    {
        if (string.IsNullOrWhiteSpace(actor))
            throw new ArgumentException("A waiver lifecycle event requires an actor.", nameof(actor));
        if (string.IsNullOrWhiteSpace(reason))
            throw new ArgumentException("A waiver lifecycle event requires a reason.", nameof(reason));
        if (nextStatus == Status)
            throw new InvalidOperationException($"Waiver {CheckId} is already {Status}.");
        if (!IsValidTransition(Status, nextStatus))
            throw new InvalidOperationException($"Waiver {CheckId} cannot transition from {Status} to {nextStatus}.");

        var at = occurredAt ?? DateTime.UtcNow;
        Events.Add(new WaiverEvent
        {
            EventType = "DispositionChanged",
            FromStatus = Status,
            ToStatus = nextStatus,
            Actor = actor.Trim(),
            OccurredAt = at.Kind == DateTimeKind.Utc ? at : at.ToUniversalTime(),
            Reason = reason.Trim()
        });
        Status = nextStatus;
    }

    internal void EnsureLifecycleHistory()
    {
        if (Events.Count > 0)
            return;

        Events.Add(new WaiverEvent
        {
            EventType = "LegacyImported",
            FromStatus = WaiverDispositionState.Proposed,
            ToStatus = Status,
            Actor = string.IsNullOrWhiteSpace(ApprovedBy) ? "legacy-import" : ApprovedBy,
            OccurredAt = ApprovedDate.Kind == DateTimeKind.Utc ? ApprovedDate : ApprovedDate.ToUniversalTime(),
            Reason = "Migrated from the version 1 waiver record without changing its justification, approver, or dates."
        });
    }

    private static bool IsValidTransition(WaiverDispositionState from, WaiverDispositionState to) =>
        (from, to) switch
        {
            (WaiverDispositionState.Proposed, WaiverDispositionState.Approved or WaiverDispositionState.Rejected) => true,
            (WaiverDispositionState.Approved, WaiverDispositionState.Revoked or WaiverDispositionState.Expired) => true,
            (WaiverDispositionState.Rejected, WaiverDispositionState.Proposed) => true,
            (WaiverDispositionState.Revoked, WaiverDispositionState.Proposed) => true,
            (WaiverDispositionState.Expired, WaiverDispositionState.Proposed) => true,
            _ => false
        };

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
    public const long MaxImportBytes = ImportFileGuard.MaxWaiverStoreBytes;
    public const string CurrentSchemaVersion = "2.0";

    public string SchemaVersion { get; set; } = CurrentSchemaVersion;
    public List<RiskWaiver> Waivers { get; set; } = [];

    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public void Add(RiskWaiver waiver)
    {
        if (string.IsNullOrWhiteSpace(waiver.CheckId))
            throw new ArgumentException("A waiver requires a check ID.", nameof(waiver));
        if (string.IsNullOrWhiteSpace(waiver.Justification))
            throw new ArgumentException("A waiver requires a justification.", nameof(waiver));

        waiver.CheckId = waiver.CheckId.Trim().ToUpperInvariant();
        waiver.Scope = string.IsNullOrWhiteSpace(waiver.Scope) ? "check" : waiver.Scope.Trim();
        waiver.EnsureLifecycleHistory();
        Waivers.Add(waiver);
    }

    public void Remove(string checkId)
    {
        Revoke(checkId, "system", "Waiver removed by the operator.");
    }

    public bool Revoke(string checkId, string actor, string reason)
    {
        var active = GetLatest(checkId);
        if (active is null || !active.IsActive)
            return false;

        active.Transition(WaiverDispositionState.Revoked, actor, reason);
        return true;
    }

    public RiskWaiver? GetActive(string checkId)
    {
        var latest = GetLatest(checkId);
        return latest is not null && latest.IsActive ? latest : null;
    }

    public RiskWaiver? GetLatest(string checkId)
    {
        return Waivers
            .Where(w => w.CheckId.Equals(checkId, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(w => w.LastActivityDate)
            .FirstOrDefault();
    }

    public IReadOnlyList<RiskWaiver> GetExpired()
    {
        return Waivers.Where(w => w.IsExpired).ToList();
    }

    public string Serialize() => JsonSerializer.Serialize(this, Options);

    public static WaiverStore Deserialize(string json)
    {
        var store = JsonSerializer.Deserialize<WaiverStore>(json, Options) ?? new WaiverStore();
        if (!VersionIsSupported(store.SchemaVersion))
            throw new InvalidDataException($"Unsupported waiver schema version '{store.SchemaVersion}'.");

        foreach (var waiver in store.Waivers)
        {
            waiver.CheckId = waiver.CheckId.Trim().ToUpperInvariant();
            waiver.Scope = string.IsNullOrWhiteSpace(waiver.Scope) ? "check" : waiver.Scope.Trim();
            waiver.EnsureLifecycleHistory();
        }

        store.SchemaVersion = CurrentSchemaVersion;
        return store;
    }

    public static async Task<WaiverStore> LoadFromFileAsync(string path)
    {
        if (!File.Exists(path)) return new WaiverStore();
        ImportFileGuard.EnsureWithinSizeLimit(path, MaxImportBytes, "Risk waiver");
        var json = await File.ReadAllTextAsync(path);
        return Deserialize(json);
    }

    public async Task SaveToFileAsync(string path)
    {
        await AtomicFileWriter.WriteAllTextAsync(path, Serialize());
    }

    private static bool VersionIsSupported(string? version)
    {
        if (string.IsNullOrWhiteSpace(version))
            return true;
        return Version.TryParse(version, out var parsed) && parsed.Major <= 2;
    }
}
