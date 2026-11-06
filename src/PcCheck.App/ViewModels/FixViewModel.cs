using System.Collections.ObjectModel;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PcCheck.App.Services;
using PcCheck.Core;
using PcCheck.Remediation;
using PcCheck.Report;

namespace PcCheck.App.ViewModels;

public enum FixState { Overview, Working, AskRestore, Confirm, Done }

public sealed partial class ActionRowViewModel(string title, string target) : ObservableObject
{
    public string Title { get; } = title;
    public string Target { get; } = target;
    [ObservableProperty] private string _status = "";
    [ObservableProperty] private string? _error;
    [ObservableProperty] private bool _isFailed;
}

public sealed record PlanRow(string Title, string Target, string Kind, string ReversibleText);

public sealed partial class FixViewModel : ObservableObject
{
    private readonly MainViewModel _main;
    private readonly ScanOutcome _outcome;
    private readonly RemediationRegistry _registry;
    private readonly ISystemOps _ops;
    private readonly FixPlan _plan;
    private readonly Queue<PlannedAction> _pending = new();
    private FixSession? _session;
    private RestorePointInfo? _restore;

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(IsOverview), nameof(IsWorking), nameof(IsAskRestore), nameof(IsConfirm), nameof(IsDone))]
    private FixState _state = FixState.Overview;

    [ObservableProperty] private string _workingText = "";
    [ObservableProperty] private PlannedAction? _current;
    [ObservableProperty] private string _confirmCounter = "";
    [ObservableProperty] private string _restoreError = "";

    public bool IsOverview => State == FixState.Overview;
    public bool IsWorking => State == FixState.Working;
    public bool IsAskRestore => State == FixState.AskRestore;
    public bool IsConfirm => State == FixState.Confirm;
    public bool IsDone => State == FixState.Done;

    public IReadOnlyList<PlanRow> AutoRows { get; }
    public IReadOnlyList<PlanRow> ConfirmRows { get; }
    public IReadOnlyList<AdviceItem> Advice { get; }
    public ObservableCollection<ActionRowViewModel> Results { get; } = [];
    public bool HasActions => _plan.Actions.Count > 0;
    public bool IsPreview => _outcome.IsPreview;
    public string ActionsPath => ActionLogStore.PathIn(_outcome.OutputDir);

    public string CurrentTitle => Current?.Target.Title ?? "";
    public string CurrentTarget => Current?.Target.Target ?? "";
    public string CurrentKind => Current is null ? "" : RemediationCatalog.Find(Current.Target.RemediationId)?.Name ?? Current.Target.RemediationId;
    public string CurrentReversible => Current is null ? "" : Current.Reversible ? "나중에 되돌릴 수 있습니다." : "되돌릴 수 없는 조치입니다. 복원 지점으로만 되돌릴 수 있습니다.";
    public bool CurrentIrreversible => Current is { Reversible: false };
    public string CurrentCommand => Current?.Target.Data.GetValueOrDefault("command") ?? Current?.Target.Data.GetValueOrDefault("execute") ?? "";

    partial void OnCurrentChanged(PlannedAction? value)
    {
        foreach (var p in new[] { nameof(CurrentTitle), nameof(CurrentTarget), nameof(CurrentKind), nameof(CurrentReversible), nameof(CurrentIrreversible), nameof(CurrentCommand) })
            OnPropertyChanged(p);
    }

    public FixViewModel(MainViewModel main, ScanOutcome outcome)
    {
        _main = main;
        _outcome = outcome;
        var (config, _) = ScanPipeline.LoadConfig();
        _ops = outcome.IsPreview ? new PreviewSystemOps() : new WindowsSystemOps(new Collectors.Infra.PowerShellRunner());
        _registry = outcome.IsPreview
            ? RemediationRegistry.CreateDefault(Path.Combine(outcome.OutputDir, "backup"), config.Protect, (_, _) => Task.FromResult(0), _ops, new([]))
            : RemediationRegistry.CreateDefault(Path.Combine(outcome.OutputDir, "backup"), config.Protect, RunInteractiveAsync, _ops);
        _plan = _registry.BuildPlan(outcome.Report.Findings);

        static PlanRow Row(PlannedAction a) => new(a.Target.Title, a.Target.Target,
            RemediationCatalog.Find(a.Target.RemediationId)?.Name ?? a.Target.RemediationId, a.Reversible ? "되돌릴 수 있음" : "되돌릴 수 없음");
        AutoRows = _plan.Auto.Select(Row).ToList();
        ConfirmRows = _plan.Confirm.Select(Row).ToList();
        Advice = _plan.Advice;
    }

    private static async Task<int> RunInteractiveAsync(string command, CancellationToken ct)
    {
        using var p = Process.Start(new ProcessStartInfo("cmd.exe", "/c " + command) { UseShellExecute = false, CreateNoWindow = true })
            ?? throw new InvalidOperationException("제거 프로그램을 시작하지 못했습니다.");
        await p.WaitForExitAsync(ct);
        return p.ExitCode;
    }

    [RelayCommand]
    private async Task StartAsync()
    {
        State = FixState.Working;
        WorkingText = "복원 지점을 만드는 중입니다. 1~2분 걸릴 수 있습니다.";
        _restore = await new RestorePointService(_ops).CreateAsync("PcCheck before fix", CancellationToken.None);
        if (!_restore.Created)
        {
            RestoreError = _restore.Error ?? "알 수 없는 오류";
            State = FixState.AskRestore;
            return;
        }
        await RunAutoAsync();
    }

    [RelayCommand]
    private async Task ContinueWithoutRestoreAsync() => await RunAutoAsync();

    [RelayCommand]
    private void Stop() => _main.ShowResult(_outcome);

    private async Task RunAutoAsync()
    {
        _session = FixSession.Start(_outcome.OutputDir, _restore);
        State = FixState.Working;
        foreach (var a in _plan.Auto)
        {
            WorkingText = $"{a.Target.Title} 진행 중";
            await ApplyAsync(a);
        }
        foreach (var a in _plan.Confirm) _pending.Enqueue(a);
        NextConfirm();
    }

    private async Task ApplyAsync(PlannedAction a)
    {
        var row = new ActionRowViewModel(a.Target.Title, a.Target.Target) { Status = "진행 중" };
        Results.Add(row);
        var rec = await _session!.ApplyAsync(a, CancellationToken.None);
        row.Status = rec.Status == ActionStatus.Applied ? "완료" : "실패";
        row.IsFailed = rec.Status != ActionStatus.Applied;
        row.Error = rec.Error;
    }

    private void NextConfirm()
    {
        if (_pending.Count == 0)
        {
            Current = null;
            State = FixState.Done;
            return;
        }
        var total = _plan.Confirm.Count();
        ConfirmCounter = $"{total - _pending.Count + 1} / {total}";
        Current = _pending.Dequeue();
        State = FixState.Confirm;
    }

    [RelayCommand]
    private async Task ApproveAsync()
    {
        var a = Current!;
        State = FixState.Working;
        WorkingText = $"{a.Target.Title} 진행 중";
        await ApplyAsync(a);
        NextConfirm();
    }

    [RelayCommand]
    private async Task SkipAsync()
    {
        await SkipOne(Current!);
        NextConfirm();
    }

    [RelayCommand]
    private async Task SkipAllAsync()
    {
        await SkipOne(Current!);
        while (_pending.Count > 0) await SkipOne(_pending.Dequeue());
        NextConfirm();
    }

    private async Task SkipOne(PlannedAction a)
    {
        await _session!.SkipAsync(a);
        Results.Add(new ActionRowViewModel(a.Target.Title, a.Target.Target) { Status = "건너뜀" });
    }

    [RelayCommand]
    private void GoUndo() => _main.ShowUndo(_outcome.OutputDir, _outcome.IsPreview);

    [RelayCommand]
    private void Back() => _main.ShowResult(_outcome);

    [RelayCommand]
    private void Home() => _main.ShowStart();
}
