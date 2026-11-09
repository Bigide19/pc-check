using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PcCheck.App.Services;
using PcCheck.Core;
using PcCheck.Remediation;

namespace PcCheck.App.ViewModels;

public sealed partial class UndoViewModel : ObservableObject
{
    private readonly MainViewModel _main;
    private readonly string? _scanDir;
    private readonly ActionLog? _log;
    private readonly bool _preview;

    public ObservableCollection<ActionRowViewModel> Rows { get; } = [];
    public string Summary { get; }
    public bool HasLog => _log is not null;
    public bool HasNothing => _log is null;

    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(RunCommand))] private bool _isRunning;
    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(RunCommand))] private bool _isFinished;
    [ObservableProperty] private string? _failureNote;

    public bool IsPreview => _preview;

    public UndoViewModel(MainViewModel main, string? scanDir, bool preview = false)
    {
        _main = main;
        _preview = preview;
        _scanDir = scanDir ?? ActionLogStore.LatestUndoable(ScanPipeline.BaseDir);
        _log = _scanDir is null ? null : ActionLogStore.Load(_scanDir);
        if (_log is null)
        {
            Summary = Strings.Undo_NoLog;
            return;
        }

        foreach (var a in _log.Actions.Where(a => a.Status is ActionStatus.Applied or ActionStatus.UndoFailed or ActionStatus.Undone))
            Rows.Add(new ActionRowViewModel(a.Title ?? a.RemediationId, a.Target)
            {
                Status = a.Status switch
                {
                    ActionStatus.Undone => Strings.Undo_Undone,
                    ActionStatus.UndoFailed => Strings.Undo_Failed,
                    _ => a.Reversible ? Strings.Undo_Pending : Strings.Undo_Irreversible,
                },
                IsFailed = a.Status == ActionStatus.UndoFailed,
                Error = a.Error,
            });
        var rp = _log.RestorePoint is { Created: true } ? Strings.Undo_RestoreMade : Strings.Undo_RestoreMissing;
        Summary = string.Format(Strings.Undo_Summary, _log.CreatedAt, rp);
    }

    private bool CanRun() => HasLog && !IsRunning && !IsFinished;

    [RelayCommand(CanExecute = nameof(CanRun))]
    private async Task RunAsync()
    {
        IsRunning = true;
        var (config, _) = ScanPipeline.LoadConfig();
        var registry = _preview
            ? RemediationRegistry.CreateDefault(Path.Combine(_scanDir!, "backup"), config.Protect, (_, _) => Task.FromResult(0), new PreviewSystemOps(), new([]))
            : RemediationRegistry.CreateDefault(Path.Combine(_scanDir!, "backup"), config.Protect, (_, _) => Task.FromResult(0));
        var results = await UndoRunner.RunAsync(_scanDir!, _log!, registry, null, CancellationToken.None);

        foreach (var r in results)
        {
            var row = Rows.FirstOrDefault(x => x.Target == r.Record.Target && x.Status == Strings.Undo_Pending);
            if (row is null) continue;
            row.Status = r.Ok ? Strings.Undo_Undone : Strings.Undo_Failed;
            row.IsFailed = !r.Ok;
            row.Error = r.Error;
        }
        if (results.Any(r => !r.Ok) || _log!.Actions.Any(a => a.Status == ActionStatus.Applied && !a.Reversible))
            FailureNote = Strings.Undo_FailureNote;
        IsRunning = false;
        IsFinished = true;
    }

    [RelayCommand]
    private void Home() => _main.ShowStart();
}
