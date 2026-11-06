using System.Globalization;
using Microsoft.Win32;
using PcCheck.Collectors.Infra;
using PcCheck.Core;
using PcCheck.Core.Config;

namespace PcCheck.Collectors.Programs;

public sealed record InstalledProgram(string DisplayName, string? Publisher, DateOnly? InstallDate, string? UninstallString, string RegistryKey);

public sealed class UninstallSource
{
    private const string Path = @"Software\Microsoft\Windows\CurrentVersion\Uninstall";

    public Shared<IReadOnlyList<InstalledProgram>> Programs { get; } = new(_ => Task.FromResult(Read()));

    private static IReadOnlyList<InstalledProgram> Read()
    {
        var list = new List<InstalledProgram>();
        Read(list, RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64), "HKLM");
        Read(list, RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32), "HKLM(WOW6432Node)");
        Read(list, Registry.CurrentUser, "HKCU");
        return list;
    }

    private static void Read(List<InstalledProgram> list, RegistryKey root, string rootName)
    {
        using var key = root.OpenSubKey(Path);
        if (key is null) return;
        foreach (var sub in key.GetSubKeyNames())
        {
            using var k = key.OpenSubKey(sub);
            if (k?.GetValue("DisplayName") is not string name || name.Length == 0) continue;
            // Hidden components and updates that Programs and Features does not list either.
            if (k.GetValue("SystemComponent") is int sc && sc == 1) continue;
            if (k.GetValue("ParentKeyName") is string) continue;
            list.Add(new InstalledProgram(name, k.GetValue("Publisher") as string, ParseDate(k.GetValue("InstallDate") as string),
                k.GetValue("UninstallString") as string, $@"{rootName}\{Path}\{sub}"));
        }
    }

    public static DateOnly? ParseDate(string? s) =>
        DateOnly.TryParseExact(s, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d) ? d : null;
}

public sealed class KnownBadProgramCollector(UninstallSource source) : ICollector
{
    public string Id => "APP-KNOWN-BAD";

    public async Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct) =>
        CollectorResult.Ok(Id, Evaluate(await source.Programs.GetAsync(ct), ctx.Config.KnownBad, ctx.Config.Protect));

    public static IReadOnlyList<Finding> Evaluate(IReadOnlyList<InstalledProgram> programs, KnownBadConfig knownBad, ProtectConfig protect)
    {
        var findings = new List<Finding>();
        foreach (var p in programs.Where(p => !protect.IsProtectedProgram(p.DisplayName)))
        {
            var hit = knownBad.Programs.FirstOrDefault(k => k.Regex is not null && k.Regex.IsMatch(
                k.Field.Equals("Publisher", StringComparison.OrdinalIgnoreCase) ? p.Publisher ?? "" : p.DisplayName));
            if (hit is null) continue;
            findings.Add(F.Make("APP-KNOWN-BAD", Categories.Program, Severity.High, $"알려진 불필요 프로그램: {p.DisplayName}",
                hit.Reason, "RM-UNINSTALL",
                ("displayName", p.DisplayName), ("publisher", p.Publisher), ("installDate", p.InstallDate?.ToString("yyyy-MM-dd")),
                ("pattern", hit.Match), ("uninstallString", p.UninstallString), ("registryKey", p.RegistryKey)));
        }
        return findings;
    }
}

public sealed class RecentProgramCollector(UninstallSource source, TimeProvider? clock = null) : ICollector
{
    public string Id => "APP-RECENT";

    public async Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        var today = DateOnly.FromDateTime((clock ?? TimeProvider.System).GetLocalNow().Date);
        return CollectorResult.Ok(Id, Evaluate(await source.Programs.GetAsync(ct), ctx.Config.Rules, today));
    }

    public static IReadOnlyList<Finding> Evaluate(IReadOnlyList<InstalledProgram> programs, RulesConfig rules, DateOnly today)
    {
        var days = rules.Thresholds.RecentInstallDays;
        var recent = programs
            .Where(p => p.InstallDate is { } d && d >= today.AddDays(-days) && d <= today)
            .DistinctBy(p => p.DisplayName)
            .OrderByDescending(p => p.InstallDate)
            .ToList();
        if (recent.Count == 0) return [];
        var ev = recent.Select((p, i) => ($"{i + 1:00}", (object?)$"{p.DisplayName} ({p.InstallDate:yyyy-MM-dd}){(p.Publisher is null ? "" : $" - {p.Publisher}")}")).ToArray();
        return [F.Make("APP-RECENT", Categories.Program, Severity.Info, $"최근 {days}일 설치 프로그램 {recent.Count}개",
            "느려지기 시작한 시점과 겹치는 프로그램이 있는지 확인하세요.", null, ev)];
    }
}
