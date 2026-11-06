namespace PcCheck.Core;

// Shape of findings.json; also what the result screen binds to.
public sealed record ScanReport
{
    public int Version { get; init; } = 1;
    public DateTimeOffset ScannedAt { get; init; }
    public int SamplingSec { get; init; }
    public required MachineInfo Machine { get; init; }
    public required VerdictResult Verdict { get; init; }
    public required ScoreSummary Scores { get; init; }
    public IReadOnlyList<Finding> Findings { get; init; } = [];
    public TopProcesses? TopProcesses { get; init; }
    public IReadOnlyList<CollectorError> CollectorErrors { get; init; } = [];
}

public sealed record MachineInfo
{
    public string Name { get; init; } = "";
    public string Os { get; init; } = "";
    public string Cpu { get; init; } = "";
    public double RamGb { get; init; }
    public string SystemDisk { get; init; } = "Unknown";
    public string User { get; init; } = "";
    public bool IsAdmin { get; init; }
}

public sealed record VerdictResult(Verdict Primary, Verdict? Secondary, IReadOnlyList<string> Basis, IReadOnlyList<string>? SecondaryBasis = null);

public sealed record ScoreSummary
{
    public int Hardware { get; init; }
    public int Software { get; init; }
    public IReadOnlyDictionary<string, int> ByCategory { get; init; } = new Dictionary<string, int>();
}

public sealed record ProcessSample(string Name, int Pid, double Value);

public sealed record TopProcesses(
    IReadOnlyList<ProcessSample> Cpu,
    IReadOnlyList<ProcessSample> Memory,
    IReadOnlyList<ProcessSample> Disk);

public sealed record CollectorError(string CollectorId, CollectorStatus Status, string Message);
