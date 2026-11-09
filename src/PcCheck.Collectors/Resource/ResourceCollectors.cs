using PcCheck.Collectors.Infra;
using PcCheck.Core;
using PcCheck.Core.Config;

namespace PcCheck.Collectors.Resource;

public abstract class ResourceCollectorBase(IResourceSampler sampler) : ICollector
{
    public abstract string Id { get; }

    public TimeSpan GetTimeout(CollectContext ctx) =>
        ctx.SamplingDuration + TimeSpan.FromSeconds(ctx.Config.Rules.Collectors.SamplingGraceSec);

    public async Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        var snap = await sampler.GetAsync(ctx, ct);
        if (!HasData(snap))
            return CollectorResult.Fail(Id, Strings.Res_CountersFailed + string.Join(" / ", snap.CounterProblems.Take(2)));
        var findings = Evaluate(snap, ctx.Config.Rules).ToList();
        // Counter health and top processes ride on RES-CPU only, so the report gets them once.
        if (Id == "RES-CPU") findings.AddRange(PerfCounterHealth.Check(snap));
        return CollectorResult.Ok(Id, findings, Id == "RES-CPU" ? snap.Top : null);
    }

    protected abstract bool HasData(ResourceSnapshot s);
    protected abstract IReadOnlyList<Finding> Evaluate(ResourceSnapshot s, RulesConfig rules);

    protected static string Pct(double v) => v.ToString("0.#");
}

public static class PerfCounterHealth
{
    public static IReadOnlyList<Finding> Check(ResourceSnapshot s)
    {
        if (s.CounterProblems.Count == 0 && s.DisabledCounterSets.Count == 0) return [];
        var ev = new List<(string, object?)>();
        if (s.DisabledCounterSets.Count > 0) ev.Add(("disabled", string.Join(", ", s.DisabledCounterSets)));
        ev.AddRange(s.CounterProblems.Take(8).Select((p, i) => ($"problem{i + 1}", (object?)p)));
        return [F.Make("SYS-PERF", Categories.System, Severity.Low, Strings.Perf_Title,
            s.DisabledCounterSets.Count > 0
                ? Strings.Perf_DisabledDetail
                : Strings.Perf_PartialDetail,
            "ADV-PERFCOUNTER", ev.ToArray())];
    }
}

public sealed class CpuCollector(IResourceSampler sampler) : ResourceCollectorBase(sampler)
{
    public override string Id => "RES-CPU";

    protected override bool HasData(ResourceSnapshot s) => s.Cpu is not null;
    protected override IReadOnlyList<Finding> Evaluate(ResourceSnapshot s, RulesConfig rules) => Check(s, rules);

    public static IReadOnlyList<Finding> Check(ResourceSnapshot s, RulesConfig rules)
    {
        if (s.Cpu is not { } cpu) return [];
        var sev = F.Above(cpu.Avg, rules.Thresholds.CpuAvgPercent);
        if (sev is null) return [];
        var top = string.Join(", ", s.Top.Cpu.Take(3).Select(p => $"{p.Name} {p.Value}%"));
        return [F.Make("RES-CPU", Categories.Resource, sev.Value, string.Format(Strings.Cpu_Title, Pct(cpu.Avg)),
            string.Format(Strings.Cpu_Detail, s.DurationSec, top), "ADV-CPU",
            ("avgPercent", Pct(cpu.Avg)), ("p95Percent", Pct(cpu.P95)), ("samples", cpu.Count))];
    }
}

public sealed class MemoryCollector(IResourceSampler sampler) : ResourceCollectorBase(sampler)
{
    public override string Id => "RES-MEM";

    protected override bool HasData(ResourceSnapshot s) => s.MemAvailableMb is not null || s.MemCommittedPercent is not null;
    protected override IReadOnlyList<Finding> Evaluate(ResourceSnapshot s, RulesConfig rules) => Check(s, rules);

    public static IReadOnlyList<Finding> Check(ResourceSnapshot s, RulesConfig rules)
    {
        var t = rules.Thresholds;
        var lowAvail = t.MemAvailableMb.High is { } a && s.MemAvailableMb is { } av && av.Avg < a;
        var highCommit = t.MemCommittedPercent.High is { } c && s.MemCommittedPercent is { } cm && cm.Avg > c;
        if (!lowAvail && !highCommit) return [];
        return [F.Make("RES-MEM", Categories.Resource, Severity.High, Strings.Mem_Title,
            string.Format(Strings.Mem_Detail, s.MemAvailableMb?.Avg, Pct(s.MemCommittedPercent?.Avg ?? 0)), "ADV-MEM",
            ("availableAvgMb", s.MemAvailableMb?.Avg.ToString("0")), ("availableP95Mb", s.MemAvailableMb?.P95.ToString("0")),
            ("committedAvgPercent", s.MemCommittedPercent is { } x ? Pct(x.Avg) : null),
            ("committedP95Percent", s.MemCommittedPercent is { } y ? Pct(y.P95) : null))];
    }
}

public sealed class DiskIoCollector(IResourceSampler sampler) : ResourceCollectorBase(sampler)
{
    public override string Id => "RES-DISK";

    protected override bool HasData(ResourceSnapshot s) => s.DiskIdlePercent is not null || s.DiskQueue is not null;
    protected override IReadOnlyList<Finding> Evaluate(ResourceSnapshot s, RulesConfig rules) => Check(s, rules);

    public static IReadOnlyList<Finding> Check(ResourceSnapshot s, RulesConfig rules)
    {
        var t = rules.Thresholds;
        var lowIdle = t.DiskIdlePercent.High is { } i && s.DiskIdlePercent is { } id && id.Avg < i;
        var longQueue = t.DiskQueueLength.High is { } q && s.DiskQueue is { } dq && dq.Avg > q;
        if (!lowIdle && !longQueue) return [];
        return [F.Make("RES-DISK", Categories.Resource, Severity.High, Strings.DiskIo_Title,
            string.Format(Strings.DiskIo_Detail, Pct(s.DiskIdlePercent?.Avg ?? 100), s.DiskQueue?.Avg ?? 0), "ADV-DISK-IO",
            ("idleAvgPercent", s.DiskIdlePercent is { } a ? Pct(a.Avg) : null), ("idleP95Percent", s.DiskIdlePercent is { } b ? Pct(b.P95) : null),
            ("queueAvg", s.DiskQueue?.Avg.ToString("0.0")), ("queueP95", s.DiskQueue?.P95.ToString("0.0")))];
    }
}
