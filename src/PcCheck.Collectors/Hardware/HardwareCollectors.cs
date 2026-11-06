using PcCheck.Collectors.Infra;
using PcCheck.Core;
using PcCheck.Core.Config;

namespace PcCheck.Collectors.Hardware;

public sealed record SystemDiskPayload(string Kind);

public sealed class DiskTypeCollector(StorageSource source) : ICollector
{
    public string Id => "HW-DISK-TYPE";

    public async Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        var s = await source.Info.GetAsync(ct);
        return CollectorResult.Ok(Id, Evaluate(s), new SystemDiskPayload(s.Kind));
    }

    public static IReadOnlyList<Finding> Evaluate(StorageInfo s) => s.Kind switch
    {
        "HDD" => [F.Make("HW-DISK-TYPE", Categories.Hardware, Severity.High, "시스템 드라이브가 HDD",
            $"C: 드라이브가 HDD({s.BusType})입니다. SSD로 바꾸면 체감 속도가 크게 좋아집니다.", "ADV-DISK-SSD",
            ("mediaType", s.MediaType), ("busType", s.BusType), ("model", s.Model), ("spindleSpeed", s.SpindleSpeed))],
        "Unknown" => [F.Make("HW-DISK-TYPE", Categories.Hardware, Severity.Info, "시스템 드라이브 종류를 판별하지 못함",
            "디스크가 매체 종류를 알려 주지 않습니다 (가상 디스크, RAID 등).", null,
            ("mediaType", s.MediaType), ("busType", s.BusType), ("model", s.Model))],
        _ => [],
    };
}

public sealed class DiskHealthCollector(StorageSource source) : ICollector
{
    public string Id => "HW-DISK-HEALTH";

    public async Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        var s = await source.Info.GetAsync(ct);
        if (s.HealthStatus.Length == 0 && s.PredictFailure is null)
            return CollectorResult.Fail(Id, "디스크 상태(Storage cmdlet, SMART)를 조회할 수 없습니다.");
        return CollectorResult.Ok(Id, Evaluate(s));
    }

    public static IReadOnlyList<Finding> Evaluate(StorageInfo s)
    {
        (string, object?)[] ev =
        [
            ("healthStatus", s.HealthStatus), ("operationalStatus", s.OperationalStatus), ("predictFailure", s.PredictFailure),
            ("predictFailureInstance", s.PredictFailureInstance), ("readErrorsTotal", s.ReadErrorsTotal),
            ("readErrorsUncorrected", s.ReadErrorsUncorrected), ("wear", s.Wear), ("model", s.Model),
        ];
        if (s.PredictFailure == true || s.HealthStatus.Equals("Unhealthy", StringComparison.OrdinalIgnoreCase))
            return [F.Make("HW-DISK-HEALTH", Categories.Hardware, Severity.Critical, "디스크 고장 예측",
                "디스크가 고장 직전 상태를 보고했습니다. 자료를 즉시 백업하고 디스크를 교체하세요.", "ADV-DISK-HEALTH", ev)];
        if (s.ReadErrorsUncorrected > 0 || s.ReadErrorsTotal > 0 || s.HealthStatus.Equals("Warning", StringComparison.OrdinalIgnoreCase))
            return [F.Make("HW-DISK-HEALTH", Categories.Hardware, Severity.High, "디스크 읽기 오류 누적",
                "디스크에서 읽기 오류가 기록되어 있습니다. 백업을 먼저 하고 교체를 검토하세요.", "ADV-DISK-HEALTH", ev)];
        return [];
    }
}

public sealed record VolumeInfo(double SizeGb, double FreeGb)
{
    public double FreePercent => SizeGb > 0 ? FreeGb / SizeGb * 100 : 100;
}

public sealed class DiskFreeCollector(IWmi wmi) : ICollector
{
    public string Id => "HW-DISK-FREE";

    public Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        var row = wmi.Query(@"root\cimv2", "SELECT Size, FreeSpace FROM Win32_LogicalDisk WHERE DeviceID='C:'").FirstOrDefault();
        if (row is null) return Task.FromResult(CollectorResult.Fail(Id, "C: 드라이브 정보를 읽지 못했습니다."));
        var v = new VolumeInfo(Convert.ToDouble(row["Size"]) / 1e9, Convert.ToDouble(row["FreeSpace"]) / 1e9);
        return Task.FromResult(CollectorResult.Ok(Id, Evaluate(v, ctx.Config.Rules)));
    }

    public static IReadOnlyList<Finding> Evaluate(VolumeInfo v, RulesConfig rules)
    {
        var sev = F.Below(v.FreePercent, rules.Thresholds.DiskFreePercent);
        return sev is null ? [] :
        [
            F.Make("HW-DISK-FREE", Categories.Hardware, sev.Value, $"C: 여유 공간 {v.FreePercent:0}%",
                $"전체 {v.SizeGb:0}GB 중 {v.FreeGb:0.0}GB가 남았습니다.", "ADV-DISK-FREE",
                ("sizeGb", Math.Round(v.SizeGb, 1)), ("freeGb", Math.Round(v.FreeGb, 1)), ("freePercent", Math.Round(v.FreePercent, 1))),
        ];
    }
}

public sealed class RamCollector(IWmi wmi) : ICollector
{
    public string Id => "HW-RAM";

    public Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        var gb = InstalledRamGb(wmi);
        if (gb is null) return Task.FromResult(CollectorResult.Fail(Id, "메모리 용량을 읽지 못했습니다."));
        return Task.FromResult(CollectorResult.Ok(Id, Evaluate(gb.Value, ctx.Config.Rules)));
    }

    // Installed modules first; TotalPhysicalMemory is lower than installed because of hardware reservations.
    public static double? InstalledRamGb(IWmi wmi)
    {
        var modules = wmi.Query(@"root\cimv2", "SELECT Capacity FROM Win32_PhysicalMemory")
            .Sum(r => Convert.ToDouble(r["Capacity"] ?? 0));
        if (modules > 0) return Math.Round(modules / 1024 / 1024 / 1024, 1);
        var total = wmi.Query(@"root\cimv2", "SELECT TotalPhysicalMemory FROM Win32_ComputerSystem").FirstOrDefault()?["TotalPhysicalMemory"];
        return total is null ? null : Math.Round(Convert.ToDouble(total) / 1024 / 1024 / 1024, 1);
    }

    public static IReadOnlyList<Finding> Evaluate(double gb, RulesConfig rules)
    {
        var t = rules.Thresholds.RamGb;
        Severity? sev = t.High is { } h && gb <= h ? Severity.High : t.Medium is { } m && gb < m ? Severity.Medium : null;
        return sev is null ? [] :
        [
            F.Make("HW-RAM", Categories.Hardware, sev.Value, $"메모리 {gb:0.#}GB",
                sev == Severity.High ? "메모리가 부족합니다. 요즘 브라우저와 업무 프로그램을 함께 쓰기 어렵습니다." : "메모리가 넉넉하지 않습니다.",
                "ADV-RAM", ("totalGb", gb)),
        ];
    }
}
