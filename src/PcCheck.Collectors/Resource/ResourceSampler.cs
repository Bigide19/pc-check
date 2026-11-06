using System.Diagnostics;
using PcCheck.Core;

namespace PcCheck.Collectors.Resource;

public sealed record Series(double Avg, double P95, int Count)
{
    public static Series Of(IReadOnlyList<double> values)
    {
        if (values.Count == 0) return new Series(0, 0, 0);
        var sorted = values.Order().ToArray();
        var idx = (int)Math.Ceiling(0.95 * sorted.Length) - 1;
        return new Series(values.Average(), sorted[Math.Clamp(idx, 0, sorted.Length - 1)], values.Count);
    }
}

public sealed record ResourceSnapshot(
    int DurationSec, Series Cpu, Series MemAvailableMb, Series MemCommittedPercent,
    Series DiskIdlePercent, Series DiskQueue, TopProcesses Top);

public interface IResourceSampler
{
    Task<ResourceSnapshot> GetAsync(CollectContext ctx, CancellationToken ct);
}

// One sampling run per scan, shared by RES-CPU, RES-MEM and RES-DISK.
public sealed class ResourceSampler : IResourceSampler
{
    public static readonly string[] CollectorIds = ["RES-CPU", "RES-MEM", "RES-DISK"];

    private readonly object _gate = new();
    private Task<ResourceSnapshot>? _task;
    private readonly CancellationTokenSource _cts = new();

    public Task<ResourceSnapshot> GetAsync(CollectContext ctx, CancellationToken ct)
    {
        lock (_gate)
        {
            _task ??= Task.Run(() => Sample(ctx, _cts.Token));
        }
        ct.Register(() => _cts.Cancel());
        return _task.WaitAsync(ct);
    }

    private static ResourceSnapshot Sample(CollectContext ctx, CancellationToken ct)
    {
        var s = ctx.Config.Rules.Sampling;
        var duration = ctx.SamplingDuration;
        var interval = TimeSpan.FromSeconds(Math.Max(1, s.IntervalSec));
        var cores = Environment.ProcessorCount;

        using var cpu = new PerformanceCounter("Processor", "% Processor Time", "_Total", readOnly: true);
        using var avail = new PerformanceCounter("Memory", "Available MBytes", readOnly: true);
        using var commit = new PerformanceCounter("Memory", "% Committed Bytes In Use", readOnly: true);
        using var idle = new PerformanceCounter("PhysicalDisk", "% Idle Time", "_Total", readOnly: true);
        using var queue = new PerformanceCounter("PhysicalDisk", "Avg. Disk Queue Length", "_Total", readOnly: true);
        var processCategory = new PerformanceCounterCategory("Process");

        var cpuV = new List<double>(); var availV = new List<double>(); var commitV = new List<double>();
        var idleV = new List<double>(); var queueV = new List<double>();
        var procs = new Dictionary<int, ProcAccumulator>();
        Dictionary<string, (CounterSample cpu, CounterSample io)>? prev = null;

        // Rate counters need a first read to establish a baseline.
        cpu.NextValue(); idle.NextValue(); queue.NextValue(); commit.NextValue();
        prev = ReadProcesses(processCategory, null, procs, cores);

        var sw = Stopwatch.StartNew();
        while (sw.Elapsed < duration)
        {
            ct.WaitHandle.WaitOne(interval);
            ct.ThrowIfCancellationRequested();

            cpuV.Add(cpu.NextValue());
            availV.Add(avail.NextValue());
            commitV.Add(commit.NextValue());
            // % Idle Time can exceed 100 on multi-disk systems with _Total.
            idleV.Add(Math.Min(100, idle.NextValue()));
            queueV.Add(queue.NextValue());
            prev = ReadProcesses(processCategory, prev, procs, cores);

            var fraction = Math.Min(1, sw.Elapsed / duration);
            var left = duration - sw.Elapsed;
            foreach (var id in CollectorIds)
                ctx.Progress?.Report(new CollectorProgress(id, $"샘플링 중, {Math.Max(0, left.TotalSeconds):0}초 남음", fraction));
        }

        var n = s.TopProcesses;
        static List<ProcessSample> Top(IEnumerable<ProcAccumulator> all, Func<ProcAccumulator, double> sel, int n) =>
            all.Where(p => p.Samples > 0).OrderByDescending(sel).Take(n)
                .Select(p => new ProcessSample(p.Name, p.Pid, Math.Round(sel(p), 1))).ToList();

        var top = new TopProcesses(
            Top(procs.Values, p => p.Cpu / p.Samples, n),
            Top(procs.Values, p => p.MemMb / p.Samples, n),
            Top(procs.Values, p => p.IoMbps / p.Samples, n));

        return new ResourceSnapshot((int)duration.TotalSeconds, Series.Of(cpuV), Series.Of(availV), Series.Of(commitV),
            Series.Of(idleV), Series.Of(queueV), top);
    }

    private sealed class ProcAccumulator(string name, int pid)
    {
        public string Name { get; } = name;
        public int Pid { get; } = pid;
        public double Cpu, MemMb, IoMbps;
        public int Samples;
    }

    // ReadCategory fetches every process instance in one call; per-process PerformanceCounter objects are far slower.
    private static Dictionary<string, (CounterSample cpu, CounterSample io)> ReadProcesses(
        PerformanceCounterCategory category, Dictionary<string, (CounterSample cpu, CounterSample io)>? prev,
        Dictionary<int, ProcAccumulator> acc, int cores)
    {
        var data = category.ReadCategory();
        var cpuData = data["% Processor Time"];
        var ioData = data["IO Data Bytes/sec"];
        var wsData = data["Working Set - Private"];
        var pidData = data["ID Process"];
        var now = new Dictionary<string, (CounterSample, CounterSample)>();

        foreach (InstanceData inst in pidData.Values)
        {
            var name = inst.InstanceName;
            if (name is "_Total" or "Idle") continue;
            var pid = (int)inst.RawValue;
            var c = cpuData[name]?.Sample ?? CounterSample.Empty;
            var io = ioData[name]?.Sample ?? CounterSample.Empty;
            now[name] = (c, io);

            if (prev is null || !prev.TryGetValue(name, out var before)) continue;
            if (!acc.TryGetValue(pid, out var a))
                acc[pid] = a = new ProcAccumulator(name.Split('#')[0], pid);
            a.Cpu += CounterSample.Calculate(before.cpu, c) / cores;
            a.IoMbps += CounterSample.Calculate(before.io, io) / 1024 / 1024;
            a.MemMb += (wsData[name]?.RawValue ?? 0) / 1024d / 1024;
            a.Samples++;
        }
        return now;
    }
}
