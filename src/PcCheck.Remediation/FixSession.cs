using System.Text.Json;
using PcCheck.Collectors.Infra;
using PcCheck.Collectors.Startup;
using PcCheck.Core;
using PcCheck.Core.Config;

namespace PcCheck.Remediation;

public sealed record PlannedAction(RemediationTarget Target, IRemediation Remediation)
{
    public RiskLevel Risk => Remediation.Risk;
    public bool Reversible => Remediation.Reversible;
}

public sealed record AdviceItem(string FindingId, string FindingTitle, RemediationInfo Info);

public sealed record FixPlan(IReadOnlyList<PlannedAction> Actions, IReadOnlyList<AdviceItem> Advice)
{
    public IEnumerable<PlannedAction> Auto => Actions.Where(a => a.Risk == RiskLevel.Auto);
    public IEnumerable<PlannedAction> Confirm => Actions.Where(a => a.Risk == RiskLevel.Confirm);
}

public static class ActionLogStore
{
    public const string FileName = "actions.json";

    public static string PathIn(string scanDir) => Path.Combine(scanDir, FileName);

    public static async Task SaveAsync(ActionLog log, string scanDir)
    {
        var tmp = PathIn(scanDir) + ".tmp";
        await File.WriteAllTextAsync(tmp, JsonSerializer.Serialize(log, PcCheckJson.OutputOptions));
        File.Move(tmp, PathIn(scanDir), overwrite: true);
    }

    public static ActionLog? Load(string scanDir)
    {
        var p = PathIn(scanDir);
        return File.Exists(p) ? JsonSerializer.Deserialize<ActionLog>(File.ReadAllText(p), PcCheckJson.ConfigOptions) : null;
    }

    // Newest scan folder whose log still has something to undo.
    public static string? LatestUndoable(string baseDir) =>
        Directory.Exists(baseDir)
            ? Directory.GetDirectories(baseDir, "PcCheck_*").OrderByDescending(d => d, StringComparer.Ordinal)
                .FirstOrDefault(d => Load(d)?.Actions.Any(a => a.Status == ActionStatus.Applied && a.Reversible) == true)
            : null;
}

public sealed class RemediationRegistry
{
    private readonly Dictionary<string, IRemediation> _byId;

    public RemediationRegistry(IEnumerable<IRemediation> all) => _byId = all.ToDictionary(r => r.Id);

    public IRemediation? Find(string id) => _byId.GetValueOrDefault(id);

    public static RemediationRegistry CreateDefault(string backupDir, ProtectConfig protect,
        Func<string, CancellationToken, Task<int>> runInteractive, ISystemOps? sys = null, StartupSource? startup = null)
    {
        var ops = sys ?? new WindowsSystemOps(new PowerShellRunner());
        return new RemediationRegistry(
        [
            new TempCleanRemediation(ops), new PowerPlanRemediation(ops),
            new StartupDisableRemediation(ops, startup ?? new StartupSource(), protect), new ServiceDisableRemediation(ops),
            new TaskDisableRemediation(ops), new UninstallRemediation(ops, runInteractive),
            new BrowserPolicyRemediation(ops, backupDir), new HostsResetRemediation(ops, backupDir),
            new ProxyResetRemediation(ops), new DefenderRemediation(ops),
        ]);
    }

    public FixPlan BuildPlan(IEnumerable<Finding> findings)
    {
        var actions = new List<PlannedAction>();
        var advice = new List<AdviceItem>();
        foreach (var f in findings)
        {
            var info = RemediationCatalog.Find(f.RemediationId);
            if (info is null) continue;
            if (info.Risk == RiskLevel.AdviceOnly) { advice.Add(new AdviceItem(f.Id, f.Title, info)); continue; }
            if (Find(info.Id) is not { } rem) continue;
            actions.AddRange(rem.Plan(f).Select(t => new PlannedAction(t, rem)));
        }
        // ST-SUSPECT and ST-COUNT can point at the same entry; SEC-AV and SEC-THREAT at the same Defender fix.
        var unique = actions.DistinctBy(a => (a.Target.RemediationId, a.Target.Target.ToUpperInvariant())).ToList();
        return new FixPlan(unique, advice.DistinctBy(a => (a.FindingId, a.Info.Id)).ToList());
    }
}

// Applies approved actions one at a time and persists actions.json after each, so a crash mid-fix still leaves a usable undo log.
public sealed class FixSession(string scanDir, ActionLog log)
{
    public ActionLog Log { get; } = log;

    public static FixSession Start(string scanDir, RestorePointInfo? restorePoint) =>
        new(scanDir, new ActionLog { CreatedAt = DateTimeOffset.Now, ScanDir = scanDir, RestorePoint = restorePoint });

    public async Task<ActionRecord> ApplyAsync(PlannedAction a, CancellationToken ct)
    {
        ActionRecord record;
        try
        {
            // Off the UI thread: some remediations (temp cleanup) do long synchronous file work.
            record = await Task.Run(() => a.Remediation.ApplyAsync(a.Target, ct), ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            record = new ActionRecord
            {
                RemediationId = a.Target.RemediationId, FindingId = a.Target.FindingId, Target = a.Target.Target, Title = a.Target.Title,
                Reversible = false, Status = ActionStatus.Failed, Error = ex.Message, AppliedAt = DateTimeOffset.Now,
            };
        }
        record = record with { Seq = Log.Actions.Count + 1 };
        Log.Actions.Add(record);
        await ActionLogStore.SaveAsync(Log, scanDir);
        return record;
    }

    public async Task SkipAsync(PlannedAction a)
    {
        Log.Actions.Add(new ActionRecord
        {
            Seq = Log.Actions.Count + 1, RemediationId = a.Target.RemediationId, FindingId = a.Target.FindingId,
            Target = a.Target.Target, Title = a.Target.Title, Reversible = false, Status = ActionStatus.Skipped,
        });
        await ActionLogStore.SaveAsync(Log, scanDir);
    }
}

public sealed record UndoResult(ActionRecord Record, bool Ok, string? Error);

public static class UndoRunner
{
    // Reverse order; one failure does not stop the rest.
    public static async Task<IReadOnlyList<UndoResult>> RunAsync(string scanDir, ActionLog log, RemediationRegistry registry,
        IProgress<UndoResult>? progress, CancellationToken ct)
    {
        var results = new List<UndoResult>();
        var targets = log.Actions.Where(a => a.Status == ActionStatus.Applied && a.Reversible).OrderByDescending(a => a.Seq).ToList();
        foreach (var rec in targets)
        {
            UndoResult result;
            try
            {
                var rem = registry.Find(rec.RemediationId) ?? throw new InvalidOperationException(string.Format(Strings.Err_UnknownRemediation, rec.RemediationId));
                await Task.Run(() => rem.UndoAsync(rec, ct), ct);
                result = new UndoResult(rec, true, null);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                result = new UndoResult(rec, false, ex.Message);
            }

            var i = log.Actions.FindIndex(a => a.Seq == rec.Seq);
            log.Actions[i] = rec with
            {
                Status = result.Ok ? ActionStatus.Undone : ActionStatus.UndoFailed,
                Error = result.Error, UndoneAt = DateTimeOffset.Now,
            };
            await ActionLogStore.SaveAsync(log, scanDir);
            results.Add(result);
            progress?.Report(result);
        }
        return results;
    }
}
