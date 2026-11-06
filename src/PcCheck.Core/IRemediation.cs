namespace PcCheck.Core;

// Plan splits a finding into concrete targets: ST-COUNT, for example, becomes one target per startup entry,
// each approved separately.
public interface IRemediation
{
    string Id { get; }
    RiskLevel Risk { get; }
    bool Reversible { get; }
    IReadOnlyList<RemediationTarget> Plan(Finding f);
    Task<ActionRecord> ApplyAsync(RemediationTarget target, CancellationToken ct);
    Task UndoAsync(ActionRecord record, CancellationToken ct);
}

public sealed record RemediationTarget(
    string RemediationId, string FindingId, string Target, string Title, IReadOnlyDictionary<string, string> Data);

public sealed record ActionRecord
{
    public int Seq { get; init; }
    public required string RemediationId { get; init; }
    public required string FindingId { get; init; }
    public required string Target { get; init; }
    public IReadOnlyDictionary<string, string> Before { get; init; } = new Dictionary<string, string>();
    public IReadOnlyDictionary<string, string> After { get; init; } = new Dictionary<string, string>();
    public bool Reversible { get; init; }
    public ActionStatus Status { get; init; }
    public string? Error { get; init; }
    public string? Title { get; init; }
    public DateTimeOffset? AppliedAt { get; init; }
    public DateTimeOffset? UndoneAt { get; init; }
}

public sealed record RestorePointInfo(bool Created, string Description, string? Error = null);

public sealed record ActionLog
{
    public int Version { get; init; } = 1;
    public DateTimeOffset CreatedAt { get; init; }
    public string? ScanDir { get; init; }
    public RestorePointInfo? RestorePoint { get; init; }
    public List<ActionRecord> Actions { get; init; } = [];
}
