using System.Text.Json;
using Microsoft.Win32;
using PcCheck.Core;
using PcCheck.Core.Config;
using PcCheck.Remediation;

namespace PcCheck.Remediation.Tests;

public sealed class FakeSystemOps : ISystemOps
{
    public Dictionary<(string Key, string Name), object> Registry { get; } = new();
    public Dictionary<string, string> Files { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> Commands { get; } = [];
    public Func<string, CommandResult> OnCommand { get; set; } = _ => new(0, "", "");

    private static (string, string) K(string key, string name) => (key.ToUpperInvariant(), name);

    public object? GetValue(string key, string name) => Registry.GetValueOrDefault(K(key, name));
    public void SetValue(string key, string name, object value, RegistryValueKind kind) => Registry[K(key, name)] = value;
    public void DeleteValue(string key, string name) => Registry.Remove(K(key, name));
    public bool KeyExists(string key) => Registry.Keys.Any(k => k.Key == key.ToUpperInvariant());

    public Task<CommandResult> RunAsync(string exe, string args, CancellationToken ct)
    {
        var line = $"{exe} {args}";
        Commands.Add(line);
        return Task.FromResult(OnCommand(line));
    }

    public Task<JsonElement> PowerShellAsync(string script, CancellationToken ct)
    {
        Commands.Add("ps: " + script);
        return Task.FromResult(JsonDocument.Parse("[{}]").RootElement);
    }

    public bool FileExists(string path) => Files.ContainsKey(path);
    public string ReadText(string path) => Files[path];
    public void WriteText(string path, string text) => Files[path] = text;
    public void CopyFile(string from, string to) => Files[to] = Files[from];
    public IEnumerable<string> FilesOlderThan(string dir, DateTime cutoffUtc) => Files.Keys.Where(k => k.StartsWith(dir, StringComparison.OrdinalIgnoreCase)).ToList();
    public bool TryDeleteFile(string path) => !path.Contains("locked") && Files.Remove(path);
}

public class RemediationTests
{
    private static Finding F(string id, string? remediation, params (string k, string v)[] ev) =>
        new(id, Categories.Startup, Severity.High, id, "", 15, remediation, ev.ToDictionary(x => x.k, x => x.v));

    private static async Task<ActionRecord> ApplyOnly(IRemediation r, Finding f) => await r.ApplyAsync(Assert.Single(r.Plan(f)), default);

    private const string ApprovedRun = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";

    [Fact]
    public async Task Startup_disable_keeps_timestamp_and_undo_restores_bytes()
    {
        var sys = new FakeSystemOps();
        byte[] original = [0x02, 0, 0, 0, 0xAA, 0xBB, 0, 0, 0, 0, 0, 0];
        sys.SetValue(ApprovedRun, "Updater", original, RegistryValueKind.Binary);
        var rem = new StartupDisableRemediation(sys, new(), new ProtectConfig());

        var rec = await ApplyOnly(rem, F("ST-SUSPECT", "RM-STARTUP-DISABLE", ("approvedKey", ApprovedRun), ("name", "Updater")));
        var now = (byte[])sys.GetValue(ApprovedRun, "Updater")!;
        Assert.Equal(0x03, now[0]);
        Assert.Equal(0xAA, now[4]);
        Assert.True(rec.Reversible);

        await rem.UndoAsync(rec, default);
        Assert.Equal(original, (byte[])sys.GetValue(ApprovedRun, "Updater")!);
    }

    [Fact]
    public async Task Startup_disable_without_prior_value_undo_removes_it()
    {
        var sys = new FakeSystemOps();
        var rem = new StartupDisableRemediation(sys, new(), new ProtectConfig());
        var rec = await ApplyOnly(rem, F("ST-SUSPECT", "RM-STARTUP-DISABLE", ("approvedKey", ApprovedRun), ("name", "New")));
        Assert.Equal(0x03, ((byte[])sys.GetValue(ApprovedRun, "New")!)[0]);
        await rem.UndoAsync(rec, default);
        Assert.Null(sys.GetValue(ApprovedRun, "New"));
    }

    [Fact]
    public async Task Proxy_reset_and_undo()
    {
        var sys = new FakeSystemOps();
        const string key = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        sys.SetValue(key, "ProxyEnable", 1, RegistryValueKind.DWord);
        sys.SetValue(key, "ProxyServer", "1.2.3.4:8080", RegistryValueKind.String);
        sys.SetValue(key, "AutoConfigURL", "http://x/p.pac", RegistryValueKind.String);
        var rem = new ProxyResetRemediation(sys);

        var rec = await ApplyOnly(rem, F("NET-PROXY", "RM-PROXY-RESET"));
        Assert.Equal(0, sys.GetValue(key, "ProxyEnable"));
        Assert.Null(sys.GetValue(key, "AutoConfigURL"));

        await rem.UndoAsync(rec, default);
        Assert.Equal(1, sys.GetValue(key, "ProxyEnable"));
        Assert.Equal("http://x/p.pac", sys.GetValue(key, "AutoConfigURL"));
    }

    [Fact]
    public async Task Hosts_reset_backs_up_and_restores()
    {
        var sys = new FakeSystemOps();
        var hosts = PcCheck.Collectors.Browser.HostsCollector.HostsPath;
        sys.Files[hosts] = "1.2.3.4 www.kbstar.com";
        var rem = new HostsResetRemediation(sys, "/backup");

        var rec = await ApplyOnly(rem, F("NET-HOSTS", "RM-HOSTS-RESET"));
        Assert.DoesNotContain("kbstar", sys.Files[hosts]);
        Assert.Equal("1.2.3.4 www.kbstar.com", sys.Files[rec.Before["backup"]]);

        await rem.UndoAsync(rec, default);
        Assert.Equal("1.2.3.4 www.kbstar.com", sys.Files[hosts]);
    }

    [Fact]
    public async Task Service_disable_records_start_type_and_undo_restores_delayed_auto()
    {
        var sys = new FakeSystemOps();
        sys.SetValue(@"HKLM\SYSTEM\CurrentControlSet\Services\evil", "Start", 2, RegistryValueKind.DWord);
        sys.SetValue(@"HKLM\SYSTEM\CurrentControlSet\Services\evil", "DelayedAutostart", 1, RegistryValueKind.DWord);
        var rem = new ServiceDisableRemediation(sys);

        var rec = await ApplyOnly(rem, F("SVC-SUSPECT", "RM-SERVICE-DISABLE", ("service", "evil"), ("state", "Running")));
        Assert.Contains("sc.exe config \"evil\" start= disabled", sys.Commands);

        await rem.UndoAsync(rec, default);
        Assert.Contains("sc.exe config \"evil\" start= delayed-auto", sys.Commands);
        Assert.Contains("sc.exe start \"evil\"", sys.Commands);
    }

    [Fact]
    public async Task Failed_command_surfaces_as_exception()
    {
        var sys = new FakeSystemOps { OnCommand = c => c.Contains("config") ? new(5, "", "Access denied") : new(0, "", "") };
        var rem = new ServiceDisableRemediation(sys);
        await Assert.ThrowsAsync<InvalidOperationException>(() => ApplyOnly(rem, F("SVC-SUSPECT", "RM-SERVICE-DISABLE", ("service", "x"))));
    }

    [Fact]
    public async Task Power_plan_switches_and_restores()
    {
        var sys = new FakeSystemOps();
        var rem = new PowerPlanRemediation(sys);
        var rec = await ApplyOnly(rem, F("SYS-MISC", "RM-POWER-PLAN", ("guid", "a1841308-3541-4fab-bc81-f71556f20b4a")));
        await rem.UndoAsync(rec, default);
        Assert.Equal(["powercfg.exe /setactive 381b4222-f694-41f0-9685-ff5bb260df2e", "powercfg.exe /setactive a1841308-3541-4fab-bc81-f71556f20b4a"], sys.Commands);
    }

    [Fact]
    public async Task Browser_policy_exports_before_delete()
    {
        var sys = new FakeSystemOps();
        var rem = new BrowserPolicyRemediation(sys, Path.GetTempPath());
        var rec = await ApplyOnly(rem, F("BR-POLICY", "RM-BROWSER-POLICY", ("key", @"HKLM\SOFTWARE\Policies\Google\Chrome"), ("browser", "Chrome")));
        Assert.StartsWith("reg.exe export", sys.Commands[0]);
        Assert.StartsWith("reg.exe delete", sys.Commands[1]);
        await rem.UndoAsync(rec, default);
        Assert.StartsWith("reg.exe import", sys.Commands[2]);
        Assert.Contains(rec.Before["backup"], sys.Commands[2]);
    }

    [Fact]
    public async Task Temp_clean_is_irreversible_and_skips_locked()
    {
        var sys = new FakeSystemOps();
        var temp = PcCheck.Collectors.SystemItems.MiscCollector.TempDirs().First();
        sys.Files[Path.Combine(temp, "a.tmp")] = "";
        sys.Files[Path.Combine(temp, "locked.tmp")] = "";
        var rem = new TempCleanRemediation(sys);
        var rec = await ApplyOnly(rem, F("SYS-MISC", "RM-TEMP-CLEAN") with { Title = "임시 파일 3.0GB" });
        Assert.False(rec.Reversible);
        Assert.Equal("1", rec.After["deleted"]);
        Assert.Equal("1", rec.After["skippedLocked"]);
        await Assert.ThrowsAsync<InvalidOperationException>(() => rem.UndoAsync(rec, default));
    }

    [Fact]
    public void Plan_dedupes_targets_and_separates_advice()
    {
        var sys = new FakeSystemOps();
        var reg = RemediationRegistry.CreateDefault("/b", new ProtectConfig(), (_, _) => Task.FromResult(0), sys);
        var plan = reg.BuildPlan(
        [
            F("SEC-AV", "RM-DEFENDER"), F("SEC-THREAT", "RM-DEFENDER"),
            F("HW-DISK-TYPE", "ADV-DISK-SSD"),
            F("NET-PROXY", "RM-PROXY-RESET"),
        ]);
        Assert.Equal(2, plan.Actions.Count);
        Assert.Single(plan.Advice);
        Assert.All(plan.Actions, a => Assert.Equal(RiskLevel.Confirm, a.Risk));
    }

    [Fact]
    public async Task Fix_session_persists_each_action_and_undo_runs_in_reverse_and_continues()
    {
        var dir = Directory.CreateTempSubdirectory("pccheck").FullName;
        var sys = new FakeSystemOps();
        const string proxyKey = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        sys.SetValue(proxyKey, "ProxyEnable", 1, RegistryValueKind.DWord);
        var reg = RemediationRegistry.CreateDefault(dir, new ProtectConfig(), (_, _) => Task.FromResult(0), sys);
        var plan = reg.BuildPlan(
        [
            F("SYS-MISC", "RM-POWER-PLAN", ("guid", "a1841308-3541-4fab-bc81-f71556f20b4a")),
            F("NET-PROXY", "RM-PROXY-RESET"),
            F("ST-SUSPECT", "RM-STARTUP-DISABLE", ("approvedKey", ApprovedRun), ("name", "U")),
        ]);
        var session = FixSession.Start(dir, new RestorePointInfo(true, "t"));
        foreach (var a in plan.Actions) await session.ApplyAsync(a, default);
        Assert.Equal(3, ActionLogStore.Load(dir)!.Actions.Count);

        // Make the power plan undo (applied first, undone last) fail; the others must still be undone.
        sys.OnCommand = c => c.Contains("a1841308") ? new(1, "", "boom") : new(0, "", "");
        var log = ActionLogStore.Load(dir)!;
        var results = await UndoRunner.RunAsync(dir, log, reg, null, default);

        Assert.Equal(["RM-STARTUP-DISABLE", "RM-PROXY-RESET", "RM-POWER-PLAN"], results.Select(r => r.Record.RemediationId));
        Assert.Equal([true, true, false], results.Select(r => r.Ok));
        Assert.Equal(1, sys.GetValue(proxyKey, "ProxyEnable"));
        var saved = ActionLogStore.Load(dir)!;
        Assert.Equal(ActionStatus.UndoFailed, saved.Actions.Single(a => a.RemediationId == "RM-POWER-PLAN").Status);
        Assert.Equal(2, saved.Actions.Count(a => a.Status == ActionStatus.Undone));
    }

    [Fact]
    public async Task Restore_point_lifts_frequency_limit_then_restores_it()
    {
        var sys = new FakeSystemOps();
        const string key = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore";
        var info = await new RestorePointService(sys).CreateAsync("PcCheck before fix", default);
        Assert.True(info.Created);
        Assert.Contains(sys.Commands, c => c.Contains("Checkpoint-Computer"));
        Assert.Null(sys.GetValue(key, "SystemRestorePointCreationFrequency"));
    }
}
