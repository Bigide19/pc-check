using PcCheck.Collectors.Browser;
using PcCheck.Collectors.Hardware;
using PcCheck.Collectors.Infra;
using PcCheck.Collectors.Programs;
using PcCheck.Collectors.Resource;
using PcCheck.Collectors.Security;
using PcCheck.Collectors.Startup;
using PcCheck.Collectors.SystemItems;
using PcCheck.Core;

namespace PcCheck.Collectors;

public static class CollectorCatalog
{
    // Fresh instances per scan: the shared sources cache their reads for that scan only.
    public static IReadOnlyList<ICollector> CreateAll()
    {
        var ps = new PowerShellRunner();
        var wmi = new WmiClient();
        var sig = new SignatureVerifier(ps);
        var storage = new StorageSource(ps, wmi);
        var sampler = new ResourceSampler();
        var startup = new StartupSource();
        var uninstall = new UninstallSource();

        return
        [
            new MachineInfoCollector(wmi),
            new DiskTypeCollector(storage),
            new DiskHealthCollector(storage),
            new DiskFreeCollector(wmi),
            new RamCollector(wmi),
            new DisplayCollector(ps),
            new CpuCollector(sampler),
            new MemoryCollector(sampler),
            new DiskIoCollector(sampler),
            new StartupCountCollector(startup),
            new StartupSuspectCollector(startup, sig),
            new ServiceSuspectCollector(wmi, sig),
            new TaskSuspectCollector(ps),
            new KnownBadProgramCollector(uninstall),
            new RecentProgramCollector(uninstall),
            new PhotosCollector(ps),
            new CrashCollector(ps, uninstall),
            new KrModulesCollector(uninstall, startup),
            new BrowserPolicyCollector(),
            new BrowserExtensionCollector(),
            new HostsCollector(),
            new ProxyCollector(),
            new AntivirusCollector(ps),
            new ThreatCollector(ps),
            new UpdateCollector(ps),
            new EventLogCollector(ps),
            new MiscCollector(),
        ];
    }
}
