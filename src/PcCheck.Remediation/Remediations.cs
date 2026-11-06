using Microsoft.Win32;
using PcCheck.Collectors.Browser;
using PcCheck.Collectors.Infra;
using PcCheck.Collectors.Startup;
using PcCheck.Collectors.SystemItems;
using PcCheck.Core;
using PcCheck.Core.Config;

namespace PcCheck.Remediation;

public abstract class RemediationBase(ISystemOps sys) : IRemediation
{
    protected ISystemOps Sys { get; } = sys;
    public abstract string Id { get; }
    public abstract RiskLevel Risk { get; }
    public abstract bool Reversible { get; }

    public virtual IReadOnlyList<RemediationTarget> Plan(Finding f) =>
        [new(Id, f.Id, f.Evidence.GetValueOrDefault("target") ?? f.Id, f.Title, f.Evidence)];

    public abstract Task<ActionRecord> ApplyAsync(RemediationTarget t, CancellationToken ct);

    public virtual Task UndoAsync(ActionRecord record, CancellationToken ct) =>
        throw new InvalidOperationException("되돌릴 수 없는 조치입니다. 복원 지점을 사용하세요.");

    protected ActionRecord Record(RemediationTarget t, Dictionary<string, string> before, Dictionary<string, string> after) => new()
    {
        RemediationId = Id, FindingId = t.FindingId, Target = t.Target, Title = t.Title,
        Before = before, After = after, Reversible = Reversible, Status = ActionStatus.Applied, AppliedAt = DateTimeOffset.Now,
    };

    protected static async Task Check(Task<CommandResult> run, string what)
    {
        var r = await run;
        if (!r.Ok) throw new InvalidOperationException($"{what} 실패 (exit {r.ExitCode}): {(r.Error + r.Output).Trim()}");
    }
}

public sealed class TempCleanRemediation(ISystemOps sys) : RemediationBase(sys)
{
    public override string Id => "RM-TEMP-CLEAN";
    public override RiskLevel Risk => RiskLevel.Auto;
    public override bool Reversible => false;

    public override IReadOnlyList<RemediationTarget> Plan(Finding f) =>
        f.Title.StartsWith("임시 파일", StringComparison.Ordinal) ? [new(Id, f.Id, "TEMP", "임시 파일 정리 (1일 지난 파일)", f.Evidence)] : [];

    public override Task<ActionRecord> ApplyAsync(RemediationTarget t, CancellationToken ct)
    {
        var cutoff = DateTime.UtcNow.AddDays(-1);
        var deleted = new List<string>();
        var skipped = 0;
        foreach (var dir in MiscCollector.TempDirs())
            foreach (var file in Sys.FilesOlderThan(dir, cutoff).ToList())
            {
                ct.ThrowIfCancellationRequested();
                if (Sys.TryDeleteFile(file)) deleted.Add(file); else skipped++;
            }
        var after = new Dictionary<string, string> { ["deleted"] = deleted.Count.ToString(), ["skippedLocked"] = skipped.ToString() };
        // Only a sample of paths: a full list can run to tens of thousands of lines.
        for (var i = 0; i < Math.Min(50, deleted.Count); i++) after[$"file{i + 1:00}"] = deleted[i];
        return Task.FromResult(Record(t, new() { ["dirs"] = string.Join("; ", MiscCollector.TempDirs()) }, after));
    }
}

public sealed class PowerPlanRemediation(ISystemOps sys) : RemediationBase(sys)
{
    public static readonly Guid Balanced = new("381b4222-f694-41f0-9685-ff5bb260df2e");

    public override string Id => "RM-POWER-PLAN";
    public override RiskLevel Risk => RiskLevel.Auto;
    public override bool Reversible => true;

    public override IReadOnlyList<RemediationTarget> Plan(Finding f) =>
        f.Evidence.TryGetValue("guid", out var g) ? [new(Id, f.Id, "PowerScheme", "전원 계획을 균형 조정으로 변경", f.Evidence)] : [];

    public override async Task<ActionRecord> ApplyAsync(RemediationTarget t, CancellationToken ct)
    {
        var before = t.Data["guid"];
        await Check(Sys.RunAsync("powercfg.exe", $"/setactive {Balanced}", ct), "powercfg /setactive");
        return Record(t, new() { ["scheme"] = before }, new() { ["scheme"] = Balanced.ToString() });
    }

    public override Task UndoAsync(ActionRecord r, CancellationToken ct) =>
        Check(Sys.RunAsync("powercfg.exe", $"/setactive {r.Before["scheme"]}", ct), "powercfg /setactive");
}

public sealed class StartupDisableRemediation(ISystemOps sys, StartupSource startup, ProtectConfig protect) : RemediationBase(sys)
{
    public override string Id => "RM-STARTUP-DISABLE";
    public override RiskLevel Risk => RiskLevel.Confirm;
    public override bool Reversible => true;

    private const string None = "(none)";

    public override IReadOnlyList<RemediationTarget> Plan(Finding f)
    {
        if (f.Id == "ST-SUSPECT")
            return f.Evidence.TryGetValue("approvedKey", out var key) && f.Evidence.TryGetValue("name", out var name)
                ? [Target(f.Id, key, name, f.Evidence.GetValueOrDefault("command") ?? "")]
                : [];

        // ST-COUNT: each enabled entry is offered on its own; RunOnce entries have no switch to flip.
        var entries = startup.Entries.GetAsync(CancellationToken.None).GetAwaiter().GetResult();
        return entries
            .Where(e => e.Enabled && e.ApprovedKey is not null)
            .Where(e => !protect.IsProtectedPath(e.TargetPath) && !protect.IsProtectedProgram(e.Name))
            .Select(e => Target(f.Id, e.ApprovedKey!, e.Name, e.Command))
            .ToList();
    }

    private RemediationTarget Target(string findingId, string approvedKey, string name, string command) =>
        new(Id, findingId, $@"{approvedKey}\{name}", $"시작 항목 끄기: {name}",
            new Dictionary<string, string> { ["approvedKey"] = approvedKey, ["name"] = name, ["command"] = command });

    public override Task<ActionRecord> ApplyAsync(RemediationTarget t, CancellationToken ct)
    {
        var key = t.Data["approvedKey"];
        var name = t.Data["name"];
        var current = Sys.GetValue(key, name) as byte[];
        // Keep the rest of the bytes (Task Manager stores a timestamp there); bit 0 of byte 0 is the off switch.
        var next = current is { Length: > 0 } ? (byte[])current.Clone() : new byte[12];
        next[0] = (byte)(next[0] | 0x01);
        if (next[0] == 0x01) next[0] = 0x03;
        Sys.SetValue(key, name, next, RegistryValueKind.Binary);
        return Task.FromResult(Record(t,
            new() { ["startupApproved"] = current is null ? None : Convert.ToHexString(current) },
            new() { ["startupApproved"] = Convert.ToHexString(next) }));
    }

    public override Task UndoAsync(ActionRecord r, CancellationToken ct)
    {
        var (key, name) = SplitTarget(r.Target);
        var before = r.Before["startupApproved"];
        if (before == None) Sys.DeleteValue(key, name);
        else Sys.SetValue(key, name, Convert.FromHexString(before), RegistryValueKind.Binary);
        return Task.CompletedTask;
    }

    private static (string Key, string Name) SplitTarget(string target)
    {
        var i = target.LastIndexOf('\\');
        return (target[..i], target[(i + 1)..]);
    }
}

public sealed class ServiceDisableRemediation(ISystemOps sys) : RemediationBase(sys)
{
    public override string Id => "RM-SERVICE-DISABLE";
    public override RiskLevel Risk => RiskLevel.Confirm;
    public override bool Reversible => true;

    private static string Key(string service) => $@"HKLM\SYSTEM\CurrentControlSet\Services\{service}";

    public override IReadOnlyList<RemediationTarget> Plan(Finding f) =>
        f.Evidence.TryGetValue("service", out var s) ? [new(Id, f.Id, s, $"서비스 끄기: {f.Evidence.GetValueOrDefault("displayName") ?? s}", f.Evidence)] : [];

    public static string ScStartArg(int start, int delayed) => start switch
    {
        0 => "boot", 1 => "system", 2 => delayed == 1 ? "delayed-auto" : "auto", 3 => "demand", _ => "disabled",
    };

    public override async Task<ActionRecord> ApplyAsync(RemediationTarget t, CancellationToken ct)
    {
        var svc = t.Target;
        var start = Convert.ToInt32(Sys.GetValue(Key(svc), "Start") ?? 2);
        var delayed = Convert.ToInt32(Sys.GetValue(Key(svc), "DelayedAutostart") ?? 0);
        var state = t.Data.GetValueOrDefault("state") ?? "";
        // A stop failure (already stopped, or refuses to stop) must not block disabling the start type.
        await Sys.RunAsync("sc.exe", $"stop \"{svc}\"", ct);
        await Check(Sys.RunAsync("sc.exe", $"config \"{svc}\" start= disabled", ct), "sc config");
        return Record(t, new() { ["start"] = start.ToString(), ["delayedAutostart"] = delayed.ToString(), ["state"] = state },
            new() { ["start"] = "4" });
    }

    public override async Task UndoAsync(ActionRecord r, CancellationToken ct)
    {
        var start = int.Parse(r.Before["start"]);
        var delayed = int.Parse(r.Before.GetValueOrDefault("delayedAutostart") ?? "0");
        await Check(Sys.RunAsync("sc.exe", $"config \"{r.Target}\" start= {ScStartArg(start, delayed)}", ct), "sc config");
        if (r.Before.GetValueOrDefault("state") == "Running") await Sys.RunAsync("sc.exe", $"start \"{r.Target}\"", ct);
    }
}

public sealed class TaskDisableRemediation(ISystemOps sys) : RemediationBase(sys)
{
    public override string Id => "RM-TASK-DISABLE";
    public override RiskLevel Risk => RiskLevel.Confirm;
    public override bool Reversible => true;

    public override IReadOnlyList<RemediationTarget> Plan(Finding f) =>
        f.Evidence.TryGetValue("taskName", out var n)
            ? [new(Id, f.Id, f.Evidence.GetValueOrDefault("task") ?? n, $"예약 작업 끄기: {n}", f.Evidence)]
            : [];

    private static string Script(string verb, IReadOnlyDictionary<string, string> d) =>
        $"{verb} -TaskPath {Json.PsLiteral(d["taskPath"])} -TaskName {Json.PsLiteral(d["taskName"])} | Out-Null";

    public override async Task<ActionRecord> ApplyAsync(RemediationTarget t, CancellationToken ct)
    {
        await Sys.PowerShellAsync(Script("Disable-ScheduledTask", t.Data), ct);
        return Record(t, new() { ["taskPath"] = t.Data["taskPath"], ["taskName"] = t.Data["taskName"], ["state"] = t.Data.GetValueOrDefault("state") ?? "" },
            new() { ["state"] = "Disabled" });
    }

    public override Task UndoAsync(ActionRecord r, CancellationToken ct) =>
        Sys.PowerShellAsync(Script("Enable-ScheduledTask", r.Before), ct);
}

public sealed class UninstallRemediation(ISystemOps sys, Func<string, CancellationToken, Task<int>> runInteractive) : RemediationBase(sys)
{
    public override string Id => "RM-UNINSTALL";
    public override RiskLevel Risk => RiskLevel.Confirm;
    public override bool Reversible => false;

    public override IReadOnlyList<RemediationTarget> Plan(Finding f) =>
        f.Evidence.TryGetValue("uninstallString", out var u) && u.Length > 0
            ? [new(Id, f.Id, f.Evidence.GetValueOrDefault("displayName") ?? u, $"프로그램 제거: {f.Evidence.GetValueOrDefault("displayName")}", f.Evidence)]
            : [];

    // The vendor uninstaller runs with its own UI; no silent flags are added.
    public override async Task<ActionRecord> ApplyAsync(RemediationTarget t, CancellationToken ct)
    {
        var exit = await runInteractive(t.Data["uninstallString"], ct);
        return Record(t, new() { ["uninstallString"] = t.Data["uninstallString"], ["registryKey"] = t.Data.GetValueOrDefault("registryKey") ?? "" },
            new() { ["exitCode"] = exit.ToString() });
    }
}

public sealed class BrowserPolicyRemediation(ISystemOps sys, string backupDir) : RemediationBase(sys)
{
    public override string Id => "RM-BROWSER-POLICY";
    public override RiskLevel Risk => RiskLevel.Confirm;
    public override bool Reversible => true;

    public override IReadOnlyList<RemediationTarget> Plan(Finding f) =>
        f.Evidence.TryGetValue("key", out var k) ? [new(Id, f.Id, k, $"{f.Evidence.GetValueOrDefault("browser")} 강제 정책 삭제", f.Evidence)] : [];

    public override async Task<ActionRecord> ApplyAsync(RemediationTarget t, CancellationToken ct)
    {
        var file = Path.Combine(backupDir, $"policy_{t.Target.Replace('\\', '_')}_{DateTime.Now:HHmmss}.reg");
        Directory.CreateDirectory(backupDir);
        await Check(Sys.RunAsync("reg.exe", $"export \"{t.Target}\" \"{file}\" /y /reg:64", ct), "reg export");
        await Check(Sys.RunAsync("reg.exe", $"delete \"{t.Target}\" /f /reg:64", ct), "reg delete");
        return Record(t, new() { ["backup"] = file }, new() { ["deleted"] = t.Target });
    }

    public override Task UndoAsync(ActionRecord r, CancellationToken ct) =>
        Check(Sys.RunAsync("reg.exe", $"import \"{r.Before["backup"]}\" /reg:64", ct), "reg import");
}

public sealed class HostsResetRemediation(ISystemOps sys, string backupDir) : RemediationBase(sys)
{
    public override string Id => "RM-HOSTS-RESET";
    public override RiskLevel Risk => RiskLevel.Confirm;
    public override bool Reversible => true;

    public const string DefaultHosts = """
        # Copyright (c) 1993-2009 Microsoft Corp.
        #
        # This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
        #
        # localhost name resolution is handled within DNS itself.
        #	127.0.0.1       localhost
        #	::1             localhost

        """;

    public override IReadOnlyList<RemediationTarget> Plan(Finding f) => [new(Id, f.Id, HostsCollector.HostsPath, "hosts 파일 초기화", f.Evidence)];

    public override Task<ActionRecord> ApplyAsync(RemediationTarget t, CancellationToken ct)
    {
        var backup = Path.Combine(backupDir, $"hosts_{DateTime.Now:HHmmss}.bak");
        Sys.CopyFile(t.Target, backup);
        Sys.WriteText(t.Target, DefaultHosts.Replace("\n", "\r\n"));
        return Task.FromResult(Record(t, new() { ["backup"] = backup }, new() { ["content"] = "default" }));
    }

    public override Task UndoAsync(ActionRecord r, CancellationToken ct)
    {
        Sys.CopyFile(r.Before["backup"], r.Target);
        return Task.CompletedTask;
    }
}

public sealed class ProxyResetRemediation(ISystemOps sys) : RemediationBase(sys)
{
    private const string Key = @"HKCU\" + ProxyCollector.KeyPath;
    private const string Missing = "(none)";

    public override string Id => "RM-PROXY-RESET";
    public override RiskLevel Risk => RiskLevel.Confirm;
    public override bool Reversible => true;

    public override IReadOnlyList<RemediationTarget> Plan(Finding f) => [new(Id, f.Id, Key, "프록시 설정 해제", f.Evidence)];

    public override Task<ActionRecord> ApplyAsync(RemediationTarget t, CancellationToken ct)
    {
        var before = new Dictionary<string, string>
        {
            ["ProxyEnable"] = Sys.GetValue(Key, "ProxyEnable")?.ToString() ?? Missing,
            ["ProxyServer"] = Sys.GetValue(Key, "ProxyServer") as string ?? Missing,
            ["AutoConfigURL"] = Sys.GetValue(Key, "AutoConfigURL") as string ?? Missing,
        };
        Sys.SetValue(Key, "ProxyEnable", 0, RegistryValueKind.DWord);
        Sys.DeleteValue(Key, "AutoConfigURL");
        return Task.FromResult(Record(t, before, new() { ["ProxyEnable"] = "0", ["AutoConfigURL"] = Missing }));
    }

    public override Task UndoAsync(ActionRecord r, CancellationToken ct)
    {
        var enable = r.Before["ProxyEnable"];
        if (enable == Missing) Sys.DeleteValue(Key, "ProxyEnable");
        else Sys.SetValue(Key, "ProxyEnable", int.Parse(enable), RegistryValueKind.DWord);
        var pac = r.Before["AutoConfigURL"];
        if (pac == Missing) Sys.DeleteValue(Key, "AutoConfigURL");
        else Sys.SetValue(Key, "AutoConfigURL", pac, RegistryValueKind.String);
        return Task.CompletedTask;
    }
}

public sealed class DefenderRemediation(ISystemOps sys) : RemediationBase(sys)
{
    public override string Id => "RM-DEFENDER";
    public override RiskLevel Risk => RiskLevel.Confirm;
    public override bool Reversible => false;

    // One action per scan even when SEC-AV and SEC-THREAT both point here.
    public override IReadOnlyList<RemediationTarget> Plan(Finding f) =>
        [new(Id, f.Id, "WindowsDefender", "Defender 실시간 보호 켜기, 정의 업데이트, 위협 제거", f.Evidence)];

    private const string Script = """
        $steps = @()
        try { Set-MpPreference -DisableRealtimeMonitoring $false; $steps += 'realtime:on' } catch { $steps += "realtime:fail $($_.Exception.Message)" }
        try { Update-MpSignature; $steps += 'signature:updated' } catch { $steps += "signature:fail $($_.Exception.Message)" }
        try { Remove-MpThreat; $steps += 'threats:removed' } catch { $steps += "threats:fail $($_.Exception.Message)" }
        $s = Get-MpComputerStatus
        [pscustomobject]@{ Steps = ($steps -join '; '); RealTime = $s.RealTimeProtectionEnabled; SignatureAge = $s.AntivirusSignatureAge }
        """;

    public override async Task<ActionRecord> ApplyAsync(RemediationTarget t, CancellationToken ct)
    {
        var r = (await Sys.PowerShellAsync(Script, ct)).EnumerateArray().First();
        return Record(t, new() { ["note"] = "격리된 항목은 Windows 보안 > 보호 기록에서 복원할 수 있습니다." },
            new() { ["steps"] = r.Str("Steps") ?? "", ["realTime"] = r.Str("RealTime") ?? "", ["signatureAge"] = r.Str("SignatureAge") ?? "" });
    }
}
