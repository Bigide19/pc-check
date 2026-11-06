using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PcCheck.App.Services;
using PcCheck.Core;
using PcCheck.Report;

namespace PcCheck.App.ViewModels;

public sealed partial class CollectorRowViewModel(string id) : ObservableObject
{
    public string Id { get; } = id;
    public string Name { get; } = Labels.Collector(id);
    [ObservableProperty] private string _status = "실행 중";
    [ObservableProperty] private string _message = "";
    [ObservableProperty] private double _fraction;
    [ObservableProperty] private bool _isIndeterminate = true;
    [ObservableProperty] private bool _isDone;
    [ObservableProperty] private bool _isFailed;
}

public sealed partial class StepViewModel(string title) : ObservableObject
{
    public string Title { get; } = title;
    [ObservableProperty] private bool _isActive;
    [ObservableProperty] private bool _isDone;
}

public sealed partial class ProgressViewModel : ObservableObject
{
    private static readonly TimeSpan MinimumVisible = TimeSpan.FromSeconds(1.5);

    private readonly MainViewModel _main;
    private readonly CancellationTokenSource _cts = new();
    private readonly Stopwatch _sw = Stopwatch.StartNew();
    private readonly DispatcherTimer _timer;

    public ObservableCollection<CollectorRowViewModel> Rows { get; } = [];
    public IReadOnlyList<StepViewModel> Steps { get; } =
        [new("설정 확인"), new("정보 수집"), new("분석"), new("저장")];

    [ObservableProperty] private int _completed;
    [ObservableProperty] private int _total;
    [ObservableProperty] private string _elapsed = "0:00";
    [ObservableProperty] private double _samplingFraction;
    [ObservableProperty] private string _samplingText = "측정 준비 중";
    [ObservableProperty] private string? _error;
    [ObservableProperty] private bool _isCanceling;

    public string DefenderNote { get; }
    public bool HasDefenderNote => DefenderNote.Length > 0;

    public ProgressViewModel(MainViewModel main, ScanOptions options)
    {
        _main = main;
        DefenderNote = options.DefenderScan switch
        {
            DefenderScanType.Quick => "Defender 빠른 검사가 끝날 때까지 몇 분 더 걸릴 수 있습니다.",
            DefenderScanType.Full => "Defender 전체 검사가 끝날 때까지 수십 분 이상 걸릴 수 있습니다.",
            _ => "",
        };
        _timer = new DispatcherTimer(TimeSpan.FromSeconds(1), DispatcherPriority.Normal,
            (_, _) => Elapsed = _sw.Elapsed.ToString(@"m\:ss"), Dispatcher.CurrentDispatcher);
        _ = RunAsync(options);
    }

    public string CompletedText => $"{Completed} / {Total}";

    partial void OnCompletedChanged(int value) => OnPropertyChanged(nameof(CompletedText));
    partial void OnTotalChanged(int value) => OnPropertyChanged(nameof(CompletedText));

    private void SetStage(ScanStage stage)
    {
        var i = (int)stage;
        for (var k = 0; k < Steps.Count; k++)
        {
            Steps[k].IsDone = k < i;
            Steps[k].IsActive = k == i;
        }
    }

    private async Task RunAsync(ScanOptions options)
    {
        var pipeline = new ScanPipeline();
        foreach (var c in pipeline.Collectors) Rows.Add(new CollectorRowViewModel(c.Id));
        Total = Rows.Count;

        // Progress<T> captures the UI context, so every update below lands on the dispatcher thread.
        var progress = new Progress<CollectorProgress>(p =>
        {
            var row = Rows.FirstOrDefault(r => r.Id == p.CollectorId);
            if (row is null || row.IsDone) return;
            row.Message = p.Message;
            if (p.Fraction is { } f)
            {
                row.IsIndeterminate = false;
                row.Fraction = f;
                if (p.CollectorId == "RES-CPU") { SamplingFraction = f; SamplingText = p.Message; }
            }
        });
        IProgress<CollectorResult> completed = new Progress<CollectorResult>(r =>
        {
            var row = Rows.FirstOrDefault(x => x.Id == r.CollectorId);
            if (row is null) return;
            row.IsDone = true;
            row.IsIndeterminate = false;
            row.Fraction = 1;
            row.IsFailed = r.Status != CollectorStatus.Ok;
            row.Status = Labels.Of(r.Status);
            row.Message = r.Error ?? (r.Findings.Count == 0 ? "문제 없음" : $"{r.Findings.Count}건 발견");
            Completed++;
            if (r.CollectorId == "RES-CPU") { SamplingFraction = 1; SamplingText = row.IsFailed ? "측정 실패" : "측정 완료"; }
        });
        IProgress<ScanStage> stage = new Progress<ScanStage>(SetStage);

        try
        {
            var outcome = await pipeline.RunAsync(options, progress, completed.Report, _cts.Token, stage.Report);
            var left = MinimumVisible - _sw.Elapsed;
            if (left > TimeSpan.Zero) await Task.Delay(left);
            _timer.Stop();
            _main.ShowResult(outcome);
        }
        catch (OperationCanceledException)
        {
            _timer.Stop();
            _main.ShowStart();
        }
        catch (Exception ex)
        {
            _timer.Stop();
            Error = $"점검을 마치지 못했습니다: {ex.Message}";
        }
    }

    [RelayCommand]
    private void Cancel()
    {
        IsCanceling = true;
        _cts.Cancel();
    }

    [RelayCommand]
    private void Back() => _main.ShowStart();
}
