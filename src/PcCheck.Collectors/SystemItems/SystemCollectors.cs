using System.Diagnostics;
using System.Text.RegularExpressions;
using PcCheck.Collectors.Infra;
using PcCheck.Core;
using PcCheck.Core.Config;

namespace PcCheck.Collectors.SystemItems;

public sealed record UpdateStatus(bool RebootRequired, bool RebootPending, bool PendingFileRename, string? LastHotFix, DateTimeOffset? LastInstalledOn);

public sealed class UpdateCollector(IPowerShell ps, TimeProvider? clock = null) : ICollector
{
    public string Id => "SYS-UPDATE";

    private const string Script = """
        $rr = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        $cbs = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        $pfro = $null -ne (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)
        $last = Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
        [pscustomobject]@{
          RebootRequired = $rr; RebootPending = $cbs; PendingFileRename = $pfro
          LastHotFix = [string]$last.HotFixID
          LastInstalledOn = $(if ($last) { $last.InstalledOn.ToString('o') })
        }
        """;

    public async Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        var r = (await ps.RunJsonAsync(Script, ct)).EnumerateArray().First();
        var s = new UpdateStatus(r.Bool("RebootRequired") == true, r.Bool("RebootPending") == true, r.Bool("PendingFileRename") == true,
            r.Str("LastHotFix"), r.Date("LastInstalledOn"));
        return CollectorResult.Ok(Id, Evaluate(s, ctx.Config.Rules, (clock ?? TimeProvider.System).GetLocalNow()));
    }

    public static IReadOnlyList<Finding> Evaluate(UpdateStatus s, RulesConfig rules, DateTimeOffset now)
    {
        var findings = new List<Finding>();
        if (s.RebootRequired || s.RebootPending || s.PendingFileRename)
            findings.Add(F.Make("SYS-UPDATE", Categories.System, Severity.Medium, Strings.Update_RebootTitle,
                Strings.Update_RebootDetail, "ADV-REBOOT",
                ("rebootRequired", s.RebootRequired), ("cbsRebootPending", s.RebootPending), ("pendingFileRename", s.PendingFileRename)));

        var days = s.LastInstalledOn is { } d ? (now - d).TotalDays : (double?)null;
        if (days is null || F.Above(days.Value, rules.Thresholds.LastUpdateAgeDays) is not null)
            findings.Add(F.Make("SYS-UPDATE", Categories.System, Severity.Medium,
                days is null ? Strings.Update_NoneTitle : string.Format(Strings.Update_AgeTitle, days),
                Strings.Update_AgeDetail, "ADV-UPDATE",
                ("lastHotFix", s.LastHotFix), ("lastInstalledOn", s.LastInstalledOn?.ToString("yyyy-MM-dd"))));
        return findings;
    }
}

public sealed record SystemEvent(int Id, string Provider, DateTimeOffset? Time);

public sealed partial class EventLogCollector(IPowerShell ps) : ICollector
{
    public string Id => "SYS-EVENTS";

    private const string Script = """
        Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7, 51, 153, 41; StartTime = (Get-Date).AddDays(-7) } -ErrorAction SilentlyContinue |
          ForEach-Object { [pscustomobject]@{ Id = $_.Id; Provider = $_.ProviderName; Time = $_.TimeCreated.ToString('o') } }
        """;

    public async Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        var rows = await ps.RunJsonAsync(Script, ct);
        var events = rows.EnumerateArray().Select(r => new SystemEvent((int)(r.Num("Id") ?? 0), r.Str("Provider") ?? "", r.Date("Time"))).ToList();
        return CollectorResult.Ok(Id, Evaluate(events, ctx.Config.Rules));
    }

    // IDs 7/51/153 are shared with unrelated providers; only storage drivers count as disk errors.
    [GeneratedRegex("disk|stor|nvme|ahci|iastor|atapi|scsi|ntfs", RegexOptions.IgnoreCase)]
    private static partial Regex StorageProvider();

    public static IReadOnlyList<Finding> Evaluate(IReadOnlyList<SystemEvent> events, RulesConfig rules)
    {
        var findings = new List<Finding>();
        var disk = events.Where(e => e.Id is 7 or 51 or 153 && StorageProvider().IsMatch(e.Provider)).ToList();
        if (disk.Count >= 1)
            findings.Add(F.Make("SYS-EVENTS", Categories.System, Severity.High, string.Format(Strings.Events_DiskTitle, disk.Count),
                Strings.Events_DiskDetail, "ADV-DISK-CHECK",
                ("count", disk.Count), ("byId", string.Join(", ", disk.GroupBy(e => e.Id).Select(g => $"{g.Key}:{g.Count()}"))),
                ("last", disk.Max(e => e.Time)?.ToString("yyyy-MM-dd HH:mm"))));

        var shutdowns = events.Where(e => e.Id == 41 && e.Provider.Contains("Kernel-Power", StringComparison.OrdinalIgnoreCase)).ToList();
        if (rules.Thresholds.UnexpectedShutdowns7d.Medium is { } limit && shutdowns.Count >= limit)
            findings.Add(F.Make("SYS-EVENTS", Categories.System, Severity.Medium, string.Format(Strings.Events_ShutdownTitle, shutdowns.Count),
                Strings.Events_ShutdownDetail, "ADV-POWER",
                ("count", shutdowns.Count), ("last", shutdowns.Max(e => e.Time)?.ToString("yyyy-MM-dd HH:mm"))));
        return findings;
    }
}

public sealed record MiscInfo(Guid? PowerScheme, string? PowerSchemeName, long TempBytes, TimeSpan Uptime);

public sealed partial class MiscCollector : ICollector
{
    public string Id => "SYS-MISC";

    public static readonly Guid PowerSaver = new("a1841308-3541-4fab-bc81-f71556f20b4a");

    public async Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        var (guid, name) = await ActiveSchemeAsync(ct);
        var temp = TempDirs().Sum(DirSize);
        var info = new MiscInfo(guid, name, temp, TimeSpan.FromMilliseconds(Environment.TickCount64));
        return CollectorResult.Ok(Id, Evaluate(info, ctx.Config.Rules));
    }

    public static IEnumerable<string> TempDirs() =>
        new[] { Path.GetTempPath(), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp") }
            .Select(p => Path.GetFullPath(p).TrimEnd('\\')).Distinct(StringComparer.OrdinalIgnoreCase);

    private static long DirSize(string dir)
    {
        if (!Directory.Exists(dir)) return 0;
        var opts = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
        long total = 0;
        foreach (var f in new DirectoryInfo(dir).EnumerateFiles("*", opts))
        {
            try { total += f.Length; } catch (IOException) { }
        }
        return total;
    }

    private static async Task<(Guid?, string?)> ActiveSchemeAsync(CancellationToken ct)
    {
        var psi = new ProcessStartInfo("powercfg.exe", "/getactivescheme")
        { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
        using var p = Process.Start(psi);
        if (p is null) return (null, null);
        var output = await p.StandardOutput.ReadToEndAsync(ct);
        await p.WaitForExitAsync(ct);
        var m = SchemeLine().Match(output);
        return m.Success ? (Guid.Parse(m.Groups[1].Value), m.Groups[2].Value.Trim()) : (null, null);
    }

    [GeneratedRegex(@"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\s*\(([^)]*)\)")]
    private static partial Regex SchemeLine();

    public static IReadOnlyList<Finding> Evaluate(MiscInfo m, RulesConfig rules)
    {
        var t = rules.Thresholds;
        var findings = new List<Finding>();
        if (m.PowerScheme == PowerSaver)
            findings.Add(F.Make("SYS-MISC", Categories.System, Severity.Low, Strings.Misc_PowerSaverTitle,
                Strings.Misc_PowerSaverDetail, "RM-POWER-PLAN", ("scheme", m.PowerSchemeName), ("guid", m.PowerScheme)));

        var tempGb = m.TempBytes / 1024d / 1024 / 1024;
        if (F.Above(tempGb, t.TempSizeGb) is { } ts)
            findings.Add(F.Make("SYS-MISC", Categories.System, ts, string.Format(Strings.Misc_TempTitle, tempGb),
                Strings.Misc_TempDetail, "RM-TEMP-CLEAN", ("tempGb", Math.Round(tempGb, 2))));

        if (F.Above(m.Uptime.TotalDays, t.UptimeDays) is { } us)
            findings.Add(F.Make("SYS-MISC", Categories.System, us, string.Format(Strings.Misc_UptimeTitle, m.Uptime.TotalDays),
                Strings.Misc_UptimeDetail, "ADV-REBOOT",
                ("uptimeDays", Math.Round(m.Uptime.TotalDays, 1))));
        return findings;
    }
}
