using PcCheck.Collectors.Infra;
using PcCheck.Collectors.Startup;
using PcCheck.Core;
using PcCheck.Core.Config;

namespace PcCheck.Collectors.Programs;

public sealed class KrModulesCollector(UninstallSource uninstall, StartupSource startup) : ICollector
{
    public string Id => "SEC-KR-MODULES";

    public async Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct) =>
        CollectorResult.Ok(Id, Evaluate(await uninstall.Programs.GetAsync(ct), await startup.Entries.GetAsync(ct), ctx.Config));

    // Not malware: these are reported as clean-up candidates, one finding per module so each can be removed on its own.
    public static IReadOnlyList<Finding> Evaluate(IReadOnlyList<InstalledProgram> programs, IReadOnlyList<StartupEntry> startup, PcCheckConfig config)
    {
        var findings = new List<Finding>();
        foreach (var m in config.KrModules.Modules)
        {
            var installed = programs.Where(p => m.MatchesName(p.DisplayName) || m.MatchesPublisher(p.Publisher)
                                                || (p.InstallLocation is { Length: > 3 } loc && m.MatchesPath(loc)))
                .Where(p => !config.Protect.IsProtectedProgram(p.DisplayName))
                .DistinctBy(p => p.DisplayName).ToList();
            var autoStart = startup.Where(e => e.Enabled && (m.MatchesPath(e.TargetPath ?? e.Command) || m.MatchesName(e.Name))).ToList();
            if (installed.Count == 0 && autoStart.Count == 0) continue;
            if (installed.Count == 0 && autoStart.Any(e => config.Protect.IsProtectedPath(e.TargetPath))) continue;

            var sev = m.KnownIssues.Count > 0 ? Severity.Medium : Severity.Low;
            var issues = m.KnownIssues.Concat(m.Compatibility).Take(4).ToList();
            var detail = (m.Purpose.Length > 0 ? m.Purpose + " " : "")
                + "은행, 공공기관 사이트용 보안 프로그램입니다. 지워도 되고, 사이트가 필요할 때 다시 설치를 안내합니다."
                + (autoStart.Count > 0 ? $" 부팅할 때마다 {autoStart.Count}개가 함께 실행됩니다." : "");

            if (installed.Count == 0)
            {
                findings.Add(Make(m, sev, detail, null, autoStart, issues));
                continue;
            }
            // One finding per uninstall entry: each becomes its own RM-UNINSTALL target.
            foreach (var p in installed)
                findings.Add(Make(m, sev, detail, p, autoStart, issues));
        }
        return findings;
    }

    private static Finding Make(KrModule m, Severity sev, string detail, InstalledProgram? p, IReadOnlyList<StartupEntry> autoStart, IReadOnlyList<KrIssue> issues)
    {
        var ev = new List<(string, object?)>
        {
            ("module", m.Name), ("vendor", m.Vendor),
            ("displayName", p?.DisplayName), ("publisher", p?.Publisher), ("installDate", p?.InstallDate?.ToString("yyyy-MM-dd")),
            ("uninstallString", p?.UninstallString), ("registryKey", p?.RegistryKey),
            ("processNames", m.ProcessNames.Count > 0 ? string.Join(",", m.ProcessNames) : null),
            ("autoStart", autoStart.Count > 0 ? string.Join(", ", autoStart.Select(e => e.Name)) : null),
            ("uninstallNotes", m.UninstallNotes.Length > 0 ? m.UninstallNotes : null),
        };
        ev.AddRange(issues.Select((x, i) => ($"issue{i + 1}", (object?)$"{(x.Year is { } y ? $"{y}년 " : "")}{x.Summary}{(x.Source.Length > 0 ? $" ({x.Source})" : "")}")));
        return F.Make("SEC-KR-MODULES", Categories.Program, sev, $"보안 모듈: {p?.DisplayName ?? m.Name}", detail,
            p?.UninstallString is null ? "ADV-KR-MODULES" : "RM-UNINSTALL", ev.ToArray());
    }
}
