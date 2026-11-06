using System.Security.Principal;
using Microsoft.Win32;
using PcCheck.Core;

namespace PcCheck.Collectors;

public static class MachineInfoReader
{
    public static MachineInfo Read()
    {
        using var cv = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
        using var cpu = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0");

        return new MachineInfo
        {
            Name = Environment.MachineName,
            Os = DescribeOs(cv),
            Cpu = (cpu?.GetValue("ProcessorNameString") as string)?.Trim() ?? "",
            RamGb = Math.Round(GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / 1024d / 1024 / 1024, 1),
            User = $"{Environment.UserDomainName}\\{Environment.UserName}",
            IsAdmin = IsAdministrator(),
        };
    }

    public static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static int OsBuild => Environment.OSVersion.Version.Build;

    private static string DescribeOs(RegistryKey? cv)
    {
        var build = OsBuild;
        // ProductName still says "Windows 10" on Windows 11, so the build number decides.
        var name = build >= 22000 ? "Windows 11" : "Windows 10";
        var display = cv?.GetValue("DisplayVersion") as string;
        var ubr = cv?.GetValue("UBR");
        return $"{name} {display} (build {build}{(ubr is int u ? $".{u}" : "")})".Replace("  ", " ");
    }
}
