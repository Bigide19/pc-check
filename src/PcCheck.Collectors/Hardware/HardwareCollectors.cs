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
        "HDD" => [F.Make("HW-DISK-TYPE", Categories.Hardware, Severity.High, Strings.DiskType_HddTitle,
            string.Format(Strings.DiskType_HddDetail, s.BusType), "ADV-DISK-SSD",
            ("mediaType", s.MediaType), ("busType", s.BusType), ("model", s.Model), ("spindleSpeed", s.SpindleSpeed))],
        "Unknown" => [F.Make("HW-DISK-TYPE", Categories.Hardware, Severity.Info, Strings.DiskType_UnknownTitle,
            Strings.DiskType_UnknownDetail, null,
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
            return CollectorResult.Fail(Id, Strings.DiskHealth_Unavailable);
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
            return [F.Make("HW-DISK-HEALTH", Categories.Hardware, Severity.Critical, Strings.DiskHealth_FailTitle,
                Strings.DiskHealth_FailDetail, "ADV-DISK-HEALTH", ev)];
        if (s.ReadErrorsUncorrected > 0 || s.ReadErrorsTotal > 0 || s.HealthStatus.Equals("Warning", StringComparison.OrdinalIgnoreCase))
            return [F.Make("HW-DISK-HEALTH", Categories.Hardware, Severity.High, Strings.DiskHealth_ReadErrTitle,
                Strings.DiskHealth_ReadErrDetail, "ADV-DISK-HEALTH", ev)];
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
        if (row is null) return Task.FromResult(CollectorResult.Fail(Id, Strings.DiskFree_NoDrive));
        var v = new VolumeInfo(Convert.ToDouble(row["Size"]) / 1e9, Convert.ToDouble(row["FreeSpace"]) / 1e9);
        return Task.FromResult(CollectorResult.Ok(Id, Evaluate(v, ctx.Config.Rules)));
    }

    public static IReadOnlyList<Finding> Evaluate(VolumeInfo v, RulesConfig rules)
    {
        var sev = F.Below(v.FreePercent, rules.Thresholds.DiskFreePercent);
        return sev is null ? [] :
        [
            F.Make("HW-DISK-FREE", Categories.Hardware, sev.Value, string.Format(Strings.DiskFree_Title, v.FreePercent),
                string.Format(Strings.DiskFree_Detail, v.SizeGb, v.FreeGb), "ADV-DISK-FREE",
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
        if (gb is null) return Task.FromResult(CollectorResult.Fail(Id, Strings.Ram_Unreadable));
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
            F.Make("HW-RAM", Categories.Hardware, sev.Value, string.Format(Strings.Ram_Title, gb),
                sev == Severity.High ? Strings.Ram_HighDetail : Strings.Ram_MediumDetail,
                "ADV-RAM", ("totalGb", gb)),
        ];
    }
}
