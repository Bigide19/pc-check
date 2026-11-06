using PcCheck.Collectors.Infra;
using PcCheck.Core;
using PcCheck.Core.Config;

namespace PcCheck.Collectors.Startup;

public sealed class StartupCountCollector(StartupSource source) : ICollector
{
    public string Id => "ST-COUNT";

    public async Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct) =>
        CollectorResult.Ok(Id, Evaluate(await source.Entries.GetAsync(ct), ctx.Config.Rules));

    public static IReadOnlyList<Finding> Evaluate(IReadOnlyList<StartupEntry> entries, RulesConfig rules)
    {
        var enabled = entries.Where(e => e.Enabled).ToList();
        var sev = F.Above(enabled.Count, rules.Thresholds.StartupCount);
        if (sev is null) return [];
        var ev = new List<(string, object?)> { ("enabled", enabled.Count), ("total", entries.Count) };
        ev.AddRange(enabled.Select((e, i) => ($"{i + 1:00}", (object?)$"{e.Name} = {e.Command}")));
        return [F.Make("ST-COUNT", Categories.Startup, sev.Value, $"시작 항목 {enabled.Count}개",
            $"부팅할 때 함께 켜지는 프로그램이 {enabled.Count}개입니다 (기준 {rules.Thresholds.StartupCount.Medium}개).",
            "RM-STARTUP-DISABLE", ev.ToArray())];
    }
}

public sealed class StartupSuspectCollector(StartupSource source, ISignatureVerifier signatures) : ICollector
{
    public string Id => "ST-SUSPECT";

    public async Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        var entries = await source.Entries.GetAsync(ct);
        var sigs = await signatures.VerifyAsync(entries.Select(e => e.TargetPath!).Where(p => p is not null), ct);
        return CollectorResult.Ok(Id, Evaluate(entries, sigs, ctx.Config.Protect));
    }

    public static IReadOnlyList<Finding> Evaluate(IReadOnlyList<StartupEntry> entries,
        IReadOnlyDictionary<string, SignatureInfo> sigs, ProtectConfig protect)
    {
        var candidates = entries
            .Where(e => e.Enabled && PathRules.IsUserWritable(e.TargetPath))
            .Where(e => !protect.IsProtectedPath(e.TargetPath) && !protect.IsProtectedProgram(e.Name))
            .Select(e => (e, sig: e.TargetPath is not null && sigs.TryGetValue(e.TargetPath, out var s) ? s : new SignatureInfo("Unknown", null)))
            .ToList();

        var findings = candidates.Where(x => x.sig.IsUnsigned)
            .Select(x => F.Make("ST-SUSPECT", Categories.Startup, Severity.High, $"의심 시작 항목: {x.e.Name}",
                "서명이 없는 파일이 사용자가 쓸 수 있는 경로에서 부팅 때마다 실행됩니다.", "RM-STARTUP-DISABLE",
                ("target", x.e.DisplayTarget), ("name", x.e.Name), ("command", x.e.Command), ("path", x.e.TargetPath),
                ("signature", x.sig.Status), ("approvedKey", x.e.ApprovedKey), ("approvedValue", x.e.ApprovedValue)))
            .ToList();

        // Counting these as unsigned would inflate the suspect count that drives a "Format" verdict.
        var unknown = candidates.Where(x => x.sig.IsUnknown).ToList();
        if (unknown.Count > 0)
            findings.Add(F.Make("ST-SUSPECT", Categories.Startup, Severity.Info, $"서명을 확인하지 못한 시작 항목 {unknown.Count}개",
                "사용자 폴더에서 실행되는 시작 항목이지만 파일을 읽지 못해 서명 여부를 판단하지 못했습니다. 아는 프로그램인지 직접 확인하세요.", null,
                unknown.Take(20).Select((x, i) => ($"{i + 1:00}", (object?)$"{x.e.Name} = {x.e.TargetPath}{(x.sig.Error is null ? "" : $" ({x.sig.Error})")}")).ToArray()));
        return findings;
    }
}

public sealed record ServiceEntry(string Name, string DisplayName, string PathName, string? TargetPath, string State);

public sealed class ServiceSuspectCollector(IWmi wmi, ISignatureVerifier signatures) : ICollector
{
    public string Id => "SVC-SUSPECT";

    public async Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        var services = wmi.Query(@"root\cimv2", "SELECT Name, DisplayName, PathName, State FROM Win32_Service WHERE StartMode='Auto'")
            .Select(r => new ServiceEntry(r["Name"] as string ?? "", r["DisplayName"] as string ?? "", r["PathName"] as string ?? "",
                PathRules.ExtractTarget(r["PathName"] as string), r["State"] as string ?? ""))
            .ToList();
        var sigs = await signatures.VerifyAsync(services.Select(s => s.TargetPath!).Where(p => p is not null), ct);
        return CollectorResult.Ok(Id, Evaluate(services, sigs, ctx.Config.Protect));
    }

    public static IReadOnlyList<Finding> Evaluate(IReadOnlyList<ServiceEntry> services,
        IReadOnlyDictionary<string, SignatureInfo> sigs, ProtectConfig protect) =>
        services
            .Where(s => s.TargetPath is not null && !protect.IsProtectedService(s.Name) && !protect.IsProtectedPath(s.TargetPath)
                        && !protect.IsProtectedProgram(s.DisplayName))
            .Select(s => (s, sig: sigs.TryGetValue(s.TargetPath!, out var v) ? v : null))
            // A missing binary is a broken service, not a running threat; an unreadable one is not known to be unsigned.
            .Where(x => x.sig is { IsUnsigned: true })
            .Select(x => F.Make("SVC-SUSPECT", Categories.Startup, Severity.High, $"서명 없는 자동 시작 서비스: {x.s.DisplayName}",
                "디지털 서명이 없는 서비스가 부팅 때 자동으로 시작됩니다.", "RM-SERVICE-DISABLE",
                ("service", x.s.Name), ("displayName", x.s.DisplayName), ("path", x.s.PathName),
                ("state", x.s.State), ("signature", x.sig!.Status)))
            .ToList();
}

public sealed record TaskEntry(string TaskPath, string TaskName, string Execute, string Arguments, string State)
{
    public string FullName => TaskPath + TaskName;
}

public sealed class TaskSuspectCollector(IPowerShell ps) : ICollector
{
    public string Id => "TASK-SUSPECT";

    private const string Script = """
        Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
          $t = $_
          foreach ($a in @($t.Actions)) {
            if ($a.Execute) { [pscustomobject]@{ TaskPath = $t.TaskPath; TaskName = $t.TaskName; Execute = $a.Execute; Arguments = [string]$a.Arguments; State = [string]$t.State } }
          }
        }
        """;

    public async Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        var rows = await ps.RunJsonAsync(Script, ct);
        var tasks = rows.EnumerateArray()
            .Select(r => new TaskEntry(r.Str("TaskPath") ?? "", r.Str("TaskName") ?? "", r.Str("Execute") ?? "", r.Str("Arguments") ?? "", r.Str("State") ?? ""))
            .ToList();
        return CollectorResult.Ok(Id, Evaluate(tasks, ctx.Config.Protect));
    }

    // PowerShell accepts any prefix of -EncodedCommand (and -ec); -ExecutionPolicy shares only "-e" and is excluded by the "x".
    private static readonly System.Text.RegularExpressions.Regex EncodedFlag = new(
        @"(?:^|\s)[-/](?:ec|e|en|enc|enco|encod|encode|encoded|encodedc[a-z]*)(?:\s|:|$)",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    private static readonly string[] Hosts = ["mshta.exe", "wscript.exe", "cscript.exe", "mshta", "wscript", "cscript"];

    public static IReadOnlyList<Finding> Evaluate(IReadOnlyList<TaskEntry> tasks, ProtectConfig protect)
    {
        var findings = new List<Finding>();
        foreach (var t in tasks)
        {
            if (protect.IsProtectedTask(t.FullName)) continue;
            var exe = Environment.ExpandEnvironmentVariables(t.Execute.Trim('"'));
            if (protect.IsProtectedPath(exe)) continue;
            var builtIn = t.TaskPath.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase);

            var reasons = new List<string>();
            if (PathRules.IsUserWritable(exe) || PathRules.IsUserWritable(PathRules.ExtractTarget($"\"{exe}\" {t.Arguments}")))
                reasons.Add("사용자 쓰기 가능 경로 실행");
            var isPowerShell = Path.GetFileName(exe).ToLowerInvariant() is "powershell.exe" or "pwsh.exe" or "powershell" or "pwsh";
            if (isPowerShell && EncodedFlag.IsMatch(t.Arguments))
                reasons.Add("인코딩된 PowerShell 명령");
            // Built-in Microsoft tasks are trusted for script hosts; the writable-path rule still applies to them.
            if (!builtIn && Hosts.Contains(Path.GetFileName(exe), StringComparer.OrdinalIgnoreCase))
                reasons.Add($"{Path.GetFileName(exe)} 호출");
            if (reasons.Count == 0) continue;

            findings.Add(F.Make("TASK-SUSPECT", Categories.Startup, Severity.High, $"의심 예약 작업: {t.TaskName}",
                string.Join(", ", reasons) + ".", "RM-TASK-DISABLE",
                ("task", t.FullName), ("taskPath", t.TaskPath), ("taskName", t.TaskName),
                ("execute", t.Execute), ("arguments", t.Arguments), ("state", t.State)));
        }
        return findings;
    }
}
