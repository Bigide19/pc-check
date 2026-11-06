using PcCheck.Collectors.Infra;
using PcCheck.Core;

namespace PcCheck.Collectors.Hardware;

public sealed class MachineInfoCollector(IWmi wmi) : ICollector
{
    public string Id => "SYS-INFO";

    public Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        var info = MachineInfoReader.Read();
        var cpu = wmi.Query(@"root\cimv2", "SELECT Name FROM Win32_Processor").FirstOrDefault()?["Name"] as string;
        info = info with
        {
            Cpu = string.IsNullOrWhiteSpace(cpu) ? info.Cpu : cpu.Trim(),
            RamGb = RamCollector.InstalledRamGb(wmi) ?? info.RamGb,
        };
        return Task.FromResult(CollectorResult.Ok(Id, [], info));
    }
}
