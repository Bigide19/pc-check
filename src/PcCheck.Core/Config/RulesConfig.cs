namespace PcCheck.Core.Config;

// Property initializers are the built-in defaults; rules.json is merged on top (populate mode),
// so a file that sets only one threshold keeps every other default.
public sealed class RulesConfig
{
    public int Version { get; set; } = 1;
    public SamplingConfig Sampling { get; set; } = new();
    public CollectorTimeouts Collectors { get; set; } = new();

    public Dictionary<Severity, int> SeverityScore { get; set; } = new()
    {
        [Severity.Critical] = 40,
        [Severity.High] = 15,
        [Severity.Medium] = 5,
        [Severity.Low] = 1,
        [Severity.Info] = 0,
    };

    public ThresholdsConfig Thresholds { get; set; } = new();
    public VerdictConfig Verdict { get; set; } = new();

    public int ScoreOf(Severity s) => SeverityScore.TryGetValue(s, out var v) ? v : 0;
}

public sealed class SamplingConfig
{
    public int DurationSec { get; set; } = 120;
    public int QuickDurationSec { get; set; } = 30;
    public int IntervalSec { get; set; } = 2;
    public int TopProcesses { get; set; } = 5;
}

public sealed class CollectorTimeouts
{
    public int DefaultTimeoutSec { get; set; } = 60;
    public int SamplingGraceSec { get; set; } = 30;
    public int DefenderQuickScanTimeoutSec { get; set; } = 900;
    public int DefenderFullScanTimeoutSec { get; set; } = 10800;
}

public sealed class Level
{
    public double? Low { get; set; }
    public double? Medium { get; set; }
    public double? High { get; set; }
}

public sealed class ThresholdsConfig
{
    public Level DiskFreePercent { get; set; } = new() { Medium = 15, High = 5 };
    public Level RamGb { get; set; } = new() { High = 4, Medium = 8 };
    public Level CpuAvgPercent { get; set; } = new() { Medium = 60, High = 85 };
    public Level MemAvailableMb { get; set; } = new() { High = 1024 };
    public Level MemCommittedPercent { get; set; } = new() { High = 90 };
    public Level DiskIdlePercent { get; set; } = new() { High = 20 };
    public Level DiskQueueLength { get; set; } = new() { High = 2 };
    public Level StartupCount { get; set; } = new() { Medium = 15 };
    public Level DefenderSignatureAgeDays { get; set; } = new() { Medium = 7 };
    public Level LastUpdateAgeDays { get; set; } = new() { Medium = 60 };
    public Level UnexpectedShutdowns7d { get; set; } = new() { Medium = 3 };
    public Level TempSizeGb { get; set; } = new() { Low = 2 };
    public Level UptimeDays { get; set; } = new() { Low = 14 };
    public int RecentInstallDays { get; set; } = 30;
}

public sealed class VerdictConfig
{
    public int FormatSuspectHighCount { get; set; } = 5;
    public int FormatSoftwareScore { get; set; } = 80;
    public int CleanupSoftwareScore { get; set; } = 10;
}
