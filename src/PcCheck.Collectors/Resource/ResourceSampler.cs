using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using PcCheck.Core;

namespace PcCheck.Collectors.Resource;

public sealed record Series(double Avg, double P95, int Count)
{
    public static Series? Of(IReadOnlyList<double> values)
    {
        if (values.Count == 0) return null;
        var sorted = values.Order().ToArray();
        var idx = (int)Math.Ceiling(0.95 * sorted.Length) - 1;
        return new Series(values.Average(), sorted[Math.Clamp(idx, 0, sorted.Length - 1)], values.Count);
    }
}

// Any series is null when its source could not be read on this PC; the matching collector then
// reports a failure for itself instead of taking the other two down with it.
public sealed record ResourceSnapshot(
    int DurationSec, Series? Cpu, Series? MemAvailableMb, Series? MemCommittedPercent,
    Series? DiskIdlePercent, Series? DiskQueue, TopProcesses Top)
{
    public IReadOnlyList<string> CounterProblems { get; init; } = [];
    public IReadOnlyList<string> DisabledCounterSets { get; init; } = [];
}

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

    private static PerformanceCounter? TryCounter(string category, string counter, string? instance, List<string> problems)
    {
        try
        {
            var c = instance is null ? new PerformanceCounter(category, counter, readOnly: true) : new PerformanceCounter(category, counter, instance, readOnly: true);
            c.NextValue();
            return c;
        }
        catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException or Win32Exception or FormatException)
        {
            problems.Add($@"{category}\{counter}{(instance is null ? "" : $"({instance})")}: {ex.Message}");
            return null;
        }
    }

    // Optimizers set "Disable Performance Counters" under these keys, which empties the categories.
    public static IReadOnlyList<string> DisabledSets()
    {
        var list = new List<string>();
        foreach (var svc in new[] { "PerfOS", "PerfDisk", "PerfProc" })
        {
            using var k = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{svc}\Performance");
            if (k?.GetValue("Disable Performance Counters") is int v && v != 0) list.Add(svc);
        }
        return list;
    }

    private static ResourceSnapshot Sample(CollectContext ctx, CancellationToken ct)
    {
        var s = ctx.Config.Rules.Sampling;
        var duration = ctx.SamplingDuration;
        var interval = TimeSpan.FromSeconds(Math.Max(1, s.IntervalSec));
        var cores = Environment.ProcessorCount;
        var problems = new List<string>();

        // "Processor Information" is the newer set; either has _Total when counters are healthy.
        using var cpu = TryCounter("Processor", "% Processor Time", "_Total", problems)
                        ?? TryCounter("Processor Information", "% Processor Time", "_Total", problems);
        using var avail = TryCounter("Memory", "Available MBytes", null, problems);
        using var commit = TryCounter("Memory", "% Committed Bytes In Use", null, problems);
        using var idle = TryCounter("PhysicalDisk", "% Idle Time", "_Total", problems);
        using var queue = TryCounter("PhysicalDisk", "Avg. Disk Queue Length", "_Total", problems);

        PerformanceCounterCategory? processCategory = null;
        try { processCategory = new PerformanceCounterCategory("Process"); processCategory.ReadCategory(); }
        catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException or Win32Exception)
        {
            problems.Add($"Process: {ex.Message}");
            processCategory = null;
        }

        var cpuV = new List<double>(); var availV = new List<double>(); var commitV = new List<double>();
        var idleV = new List<double>(); var queueV = new List<double>();
        var procs = new Dictionary<int, ProcAccumulator>();
        Dictionary<string, (CounterSample cpu, CounterSample io)>? prev = null;
        var fallback = new ProcessFallback();

        var lastTimes = SystemTimes();
        if (processCategory is not null) prev = ReadProcesses(processCategory, null, procs, cores);
        else fallback.Sample(procs, cores);

        var sw = Stopwatch.StartNew();
        while (sw.Elapsed < duration)
        {
            ct.WaitHandle.WaitOne(interval);
            ct.ThrowIfCancellationRequested();

            if (cpu is not null) cpuV.Add(cpu.NextValue());
            else if (SystemTimes() is { } now && lastTimes is { } then)
            {
                // GetSystemTimes fallback: kernel time includes idle time.
                var busy = (now.Kernel - then.Kernel) + (now.User - then.User) - (now.Idle - then.Idle);
                var total = (now.Kernel - then.Kernel) + (now.User - then.User);
                if (total > 0) cpuV.Add(Math.Clamp(100.0 * busy / total, 0, 100));
                lastTimes = now;
            }

            if (avail is not null) availV.Add(avail.NextValue());
            if (commit is not null) commitV.Add(commit.NextValue());
            if ((avail is null || commit is null) && MemoryStatus() is { } ms)
            {
                if (avail is null) availV.Add(ms.AvailPhys / 1024d / 1024);
                if (commit is null && ms.TotalPageFile > 0) commitV.Add(100.0 * (ms.TotalPageFile - ms.AvailPageFile) / ms.TotalPageFile);
            }
            // % Idle Time can exceed 100 on multi-disk systems with _Total.
            if (idle is not null) idleV.Add(Math.Min(100, idle.NextValue()));
            if (queue is not null) queueV.Add(queue.NextValue());

            if (processCategory is not null) prev = ReadProcesses(processCategory, prev, procs, cores);
            else fallback.Sample(procs, cores);

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
            processCategory is null ? [] : Top(procs.Values, p => p.IoMbps / p.Samples, n));

        return new ResourceSnapshot((int)duration.TotalSeconds, Series.Of(cpuV), Series.Of(availV), Series.Of(commitV),
            Series.Of(idleV), Series.Of(queueV), top)
        {
            CounterProblems = problems,
            DisabledCounterSets = DisabledSets(),
        };
    }

    private sealed class ProcAccumulator(string name, int pid)
    {
        public string Name { get; } = name;
        public int Pid { get; } = pid;
        public double Cpu, MemMb, IoMbps;
        public int Samples;
    }

    // Used when the Process counter set is unavailable: CPU time deltas and working sets, no I/O.
    private sealed class ProcessFallback
    {
        private Dictionary<int, (TimeSpan cpu, DateTime at)> _prev = new();

        public void Sample(Dictionary<int, ProcAccumulator> acc, int cores)
        {
            var now = new Dictionary<int, (TimeSpan, DateTime)>();
            foreach (var p in Process.GetProcesses())
            {
                using (p)
                {
                    try
                    {
                        var t = p.TotalProcessorTime;
                        var at = DateTime.UtcNow;
                        now[p.Id] = (t, at);
                        if (!_prev.TryGetValue(p.Id, out var before)) continue;
                        var wall = (at - before.at).TotalMilliseconds;
                        if (wall <= 0) continue;
                        if (!acc.TryGetValue(p.Id, out var a)) acc[p.Id] = a = new ProcAccumulator(p.ProcessName, p.Id);
                        a.Cpu += (t - before.cpu).TotalMilliseconds / wall * 100 / cores;
                        a.MemMb += p.WorkingSet64 / 1024d / 1024;
                        a.Samples++;
                    }
                    catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException) { }
                }
            }
            _prev = now;
        }
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
        if (pidData is null || cpuData is null) return now;

        foreach (InstanceData inst in pidData.Values)
        {
            var name = inst.InstanceName;
            if (name is "_Total" or "Idle") continue;
            var pid = (int)inst.RawValue;
            var c = cpuData[name]?.Sample ?? CounterSample.Empty;
            var io = ioData?[name]?.Sample ?? CounterSample.Empty;
            now[name] = (c, io);

            if (prev is null || !prev.TryGetValue(name, out var before)) continue;
            if (!acc.TryGetValue(pid, out var a))
                acc[pid] = a = new ProcAccumulator(name.Split('#')[0], pid);
            a.Cpu += CounterSample.Calculate(before.cpu, c) / cores;
            a.IoMbps += CounterSample.Calculate(before.io, io) / 1024 / 1024;
            a.MemMb += (wsData?[name]?.RawValue ?? 0) / 1024d / 1024;
            a.Samples++;
        }
        return now;
    }

    private readonly record struct Times(long Idle, long Kernel, long User);

    private static Times? SystemTimes() =>
        GetSystemTimes(out var idle, out var kernel, out var user) ? new Times(idle, kernel, user) : null;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSystemTimes(out long idle, out long kernel, out long user);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint Length, MemoryLoad;
        public ulong TotalPhys, AvailPhys, TotalPageFile, AvailPageFile, TotalVirtual, AvailVirtual, AvailExtendedVirtual;
    }

    private readonly record struct Mem(ulong AvailPhys, ulong TotalPageFile, ulong AvailPageFile);

    private static Mem? MemoryStatus()
    {
        var m = new MEMORYSTATUSEX { Length = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
        return GlobalMemoryStatusEx(ref m) ? new Mem(m.AvailPhys, m.TotalPageFile, m.AvailPageFile) : null;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX buffer);
}
