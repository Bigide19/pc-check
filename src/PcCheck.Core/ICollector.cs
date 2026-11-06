using PcCheck.Core.Config;

namespace PcCheck.Core;

public interface ICollector
{
    string Id { get; }

    // Sampling collectors must outlive their sampling window, so the timeout is per collector.
    TimeSpan GetTimeout(CollectContext ctx) => ctx.DefaultTimeout;

    Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct);
}

public enum DefenderScanType { None, Quick, Full }

public sealed record ScanOptions(bool Quick = false, DefenderScanType DefenderScan = DefenderScanType.None, bool VirusTotal = false);

public sealed record CollectorProgress(string CollectorId, string Message, double? Fraction = null);

public sealed class CollectContext
{
    public required PcCheckConfig Config { get; init; }
    public required ScanOptions Options { get; init; }
    public TimeSpan DefaultTimeout { get; init; } = TimeSpan.FromSeconds(60);
    public IProgress<CollectorProgress>? Progress { get; init; }

    public TimeSpan SamplingDuration => TimeSpan.FromSeconds(
        Options.Quick ? Config.Rules.Sampling.QuickDurationSec : Config.Rules.Sampling.DurationSec);
}

public sealed record CollectorResult
{
    public required string CollectorId { get; init; }
    public CollectorStatus Status { get; init; } = CollectorStatus.Ok;
    public IReadOnlyList<Finding> Findings { get; init; } = [];
    public string? Error { get; init; }
    public TimeSpan Elapsed { get; init; }

    // Structured data other than findings (machine info, top processes); the pipeline picks the types it knows.
    public object? Payload { get; init; }

    public static CollectorResult Ok(string id, IReadOnlyList<Finding> findings, object? payload = null) =>
        new() { CollectorId = id, Findings = findings, Payload = payload };

    public static CollectorResult Fail(string id, string error) =>
        new() { CollectorId = id, Status = CollectorStatus.Failed, Error = error };
}
