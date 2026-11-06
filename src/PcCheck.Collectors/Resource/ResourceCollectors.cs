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
        // Top processes ride on RES-CPU only, so the report gets them once.
        return CollectorResult.Ok(Id, Evaluate(snap, ctx.Config.Rules), Id == "RES-CPU" ? snap.Top : null);
    }

    protected abstract IReadOnlyList<Finding> Evaluate(ResourceSnapshot s, RulesConfig rules);

    protected static string Pct(double v) => v.ToString("0.#");
}

public sealed class CpuCollector(IResourceSampler sampler) : ResourceCollectorBase(sampler)
{
    public override string Id => "RES-CPU";

    protected override IReadOnlyList<Finding> Evaluate(ResourceSnapshot s, RulesConfig rules) => Check(s, rules);

    public static IReadOnlyList<Finding> Check(ResourceSnapshot s, RulesConfig rules)
    {
        var sev = F.Above(s.Cpu.Avg, rules.Thresholds.CpuAvgPercent);
        if (sev is null) return [];
        var top = string.Join(", ", s.Top.Cpu.Take(3).Select(p => $"{p.Name} {p.Value}%"));
        return [F.Make("RES-CPU", Categories.Resource, sev.Value, $"CPU 사용률 평균 {Pct(s.Cpu.Avg)}%",
            $"{s.DurationSec}초 동안 CPU가 계속 바빴습니다. 상위: {top}", "ADV-CPU",
            ("avgPercent", Pct(s.Cpu.Avg)), ("p95Percent", Pct(s.Cpu.P95)), ("samples", s.Cpu.Count))];
    }
}

public sealed class MemoryCollector(IResourceSampler sampler) : ResourceCollectorBase(sampler)
{
    public override string Id => "RES-MEM";

    protected override IReadOnlyList<Finding> Evaluate(ResourceSnapshot s, RulesConfig rules) => Check(s, rules);

    public static IReadOnlyList<Finding> Check(ResourceSnapshot s, RulesConfig rules)
    {
        var t = rules.Thresholds;
        var lowAvail = t.MemAvailableMb.High is { } a && s.MemAvailableMb.Avg < a;
        var highCommit = t.MemCommittedPercent.High is { } c && s.MemCommittedPercent.Avg > c;
        if (!lowAvail && !highCommit) return [];
        return [F.Make("RES-MEM", Categories.Resource, Severity.High, "메모리 압박",
            $"가용 메모리 평균 {s.MemAvailableMb.Avg:0}MB, 커밋 {Pct(s.MemCommittedPercent.Avg)}%입니다. 디스크로 페이지 교체가 자주 일어납니다.", "ADV-MEM",
            ("availableAvgMb", s.MemAvailableMb.Avg.ToString("0")), ("availableP95Mb", s.MemAvailableMb.P95.ToString("0")),
            ("committedAvgPercent", Pct(s.MemCommittedPercent.Avg)), ("committedP95Percent", Pct(s.MemCommittedPercent.P95)))];
    }
}

public sealed class DiskIoCollector(IResourceSampler sampler) : ResourceCollectorBase(sampler)
{
    public override string Id => "RES-DISK";

    protected override IReadOnlyList<Finding> Evaluate(ResourceSnapshot s, RulesConfig rules) => Check(s, rules);

    public static IReadOnlyList<Finding> Check(ResourceSnapshot s, RulesConfig rules)
    {
        var t = rules.Thresholds;
        var lowIdle = t.DiskIdlePercent.High is { } i && s.DiskIdlePercent.Avg < i;
        var longQueue = t.DiskQueueLength.High is { } q && s.DiskQueue.Avg > q;
        if (!lowIdle && !longQueue) return [];
        return [F.Make("RES-DISK", Categories.Resource, Severity.High, "디스크 병목",
            $"샘플링 중 디스크 Idle 평균 {Pct(s.DiskIdlePercent.Avg)}%, 큐 길이 평균 {s.DiskQueue.Avg:0.0}입니다.", "ADV-DISK-IO",
            ("idleAvgPercent", Pct(s.DiskIdlePercent.Avg)), ("idleP95Percent", Pct(s.DiskIdlePercent.P95)),
            ("queueAvg", s.DiskQueue.Avg.ToString("0.0")), ("queueP95", s.DiskQueue.P95.ToString("0.0")))];
    }
}
