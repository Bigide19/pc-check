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
            Summary = "되돌릴 조치 기록이 없습니다.";
            return;
        }

        foreach (var a in _log.Actions.Where(a => a.Status is ActionStatus.Applied or ActionStatus.UndoFailed or ActionStatus.Undone))
            Rows.Add(new ActionRowViewModel(a.Title ?? a.RemediationId, a.Target)
            {
                Status = a.Status switch
                {
                    ActionStatus.Undone => "되돌림",
                    ActionStatus.UndoFailed => "되돌리기 실패",
                    _ => a.Reversible ? "되돌릴 예정" : "되돌릴 수 없음",
                },
                IsFailed = a.Status == ActionStatus.UndoFailed,
                Error = a.Error,
            });
        var rp = _log.RestorePoint is { Created: true } ? "조치 전에 복원 지점을 만들었습니다." : "조치 전에 복원 지점을 만들지 못했습니다.";
        Summary = $"{_log.CreatedAt:yyyy-MM-dd HH:mm}에 실행한 조치입니다. {rp}";
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
            var row = Rows.FirstOrDefault(x => x.Target == r.Record.Target && x.Status == "되돌릴 예정");
            if (row is null) continue;
            row.Status = r.Ok ? "되돌림" : "되돌리기 실패";
            row.IsFailed = !r.Ok;
            row.Error = r.Error;
        }
        if (results.Any(r => !r.Ok) || _log!.Actions.Any(a => a.Status == ActionStatus.Applied && !a.Reversible))
            FailureNote = "되돌리지 못한 항목이 있습니다. 시스템 복원(제어판 > 복구 > 시스템 복원 열기)에서 'PcCheck before fix' 복원 지점을 선택하세요.";
        IsRunning = false;
        IsFinished = true;
    }

    [RelayCommand]
    private void Home() => _main.ShowStart();
}
