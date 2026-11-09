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
        return [F.Make("ST-COUNT", Categories.Startup, sev.Value, string.Format(Strings.StCount_Title, enabled.Count),
            string.Format(Strings.StCount_Detail, enabled.Count, rules.Thresholds.StartupCount.Medium),
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
            .Select(x => F.Make("ST-SUSPECT", Categories.Startup, Severity.High, string.Format(Strings.StSuspect_Title, x.e.Name),
                Strings.StSuspect_Detail, "RM-STARTUP-DISABLE",
                ("target", x.e.DisplayTarget), ("name", x.e.Name), ("command", x.e.Command), ("path", x.e.TargetPath),
                ("signature", x.sig.Status), ("approvedKey", x.e.ApprovedKey), ("approvedValue", x.e.ApprovedValue)))
            .ToList();

        // Counting these as unsigned would inflate the suspect count that drives a "Format" verdict.
        var unknown = candidates.Where(x => x.sig.IsUnknown).ToList();
        if (unknown.Count > 0)
            findings.Add(F.Make("ST-SUSPECT", Categories.Startup, Severity.Info, string.Format(Strings.StSuspect_UnknownTitle, unknown.Count),
                Strings.StSuspect_UnknownDetail, null,
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
        return CollectorResult.Ok(Id, Evaluate(services, sigs, ctx.Config.Protect, ctx.Config.KrModules));
    }

    // Korean security modules are reported by SEC-KR-MODULES as clean-up candidates, not as suspects.
    public static IReadOnlyList<Finding> Evaluate(IReadOnlyList<ServiceEntry> services,
        IReadOnlyDictionary<string, SignatureInfo> sigs, ProtectConfig protect, KrModulesConfig? kr = null) =>
        services
            .Where(s => s.TargetPath is not null && !protect.IsProtectedService(s.Name) && !protect.IsProtectedPath(s.TargetPath)
                        && !protect.IsProtectedProgram(s.DisplayName) && kr?.MatchPath(s.TargetPath) is null)
            .Select(s => (s, sig: sigs.TryGetValue(s.TargetPath!, out var v) ? v : null))
            // A missing binary is a broken service, not a running threat; an unreadable one is not known to be unsigned.
            .Where(x => x.sig is { IsUnsigned: true })
            .Select(x => F.Make("SVC-SUSPECT", Categories.Startup, Severity.High, string.Format(Strings.Svc_Title, x.s.DisplayName),
                Strings.Svc_Detail, "RM-SERVICE-DISABLE",
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
        return CollectorResult.Ok(Id, Evaluate(tasks, ctx.Config.Protect, ctx.Config.KrModules));
    }

    // PowerShell accepts any prefix of -EncodedCommand (and -ec); -ExecutionPolicy shares only "-e" and is excluded by the "x".
    private static readonly System.Text.RegularExpressions.Regex EncodedFlag = new(
        @"(?:^|\s)[-/](?:ec|e|en|enc|enco|encod|encode|encoded|encodedc[a-z]*)(?:\s|:|$)",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    private static readonly string[] Hosts = ["mshta.exe", "wscript.exe", "cscript.exe", "mshta", "wscript", "cscript"];

    public static IReadOnlyList<Finding> Evaluate(IReadOnlyList<TaskEntry> tasks, ProtectConfig protect, KrModulesConfig? kr = null)
    {
        var findings = new List<Finding>();
        foreach (var t in tasks)
        {
            if (protect.IsProtectedTask(t.FullName)) continue;
            var exe = Environment.ExpandEnvironmentVariables(t.Execute.Trim('"'));
            if (protect.IsProtectedPath(exe) || kr?.MatchPath(exe) is not null) continue;
            var builtIn = t.TaskPath.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase);

            var reasons = new List<string>();
            if (PathRules.IsUserWritable(exe) || PathRules.IsUserWritable(PathRules.ExtractTarget($"\"{exe}\" {t.Arguments}")))
                reasons.Add(Strings.Task_UserWritable);
            var isPowerShell = Path.GetFileName(exe).ToLowerInvariant() is "powershell.exe" or "pwsh.exe" or "powershell" or "pwsh";
            if (isPowerShell && EncodedFlag.IsMatch(t.Arguments))
                reasons.Add(Strings.Task_EncodedPs);
            // Built-in Microsoft tasks are trusted for script hosts; the writable-path rule still applies to them.
            if (!builtIn && Hosts.Contains(Path.GetFileName(exe), StringComparer.OrdinalIgnoreCase))
                reasons.Add(string.Format(Strings.Task_Calls, Path.GetFileName(exe)));
            if (reasons.Count == 0) continue;

            findings.Add(F.Make("TASK-SUSPECT", Categories.Startup, Severity.High, string.Format(Strings.Task_Title, t.TaskName),
                Sentence(string.Join(", ", reasons)), "RM-TASK-DISABLE",
                ("task", t.FullName), ("taskPath", t.TaskPath), ("taskName", t.TaskName),
                ("execute", t.Execute), ("arguments", t.Arguments), ("state", t.State)));
        }
        return findings;
    }

    // English reasons start lower-case so they can be joined; the sentence still needs a capital.
    private static string Sentence(string s) => s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s[1..] + ".";
}
