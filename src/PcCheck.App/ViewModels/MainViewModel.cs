using CommunityToolkit.Mvvm.ComponentModel;
using PcCheck.App.Services;
using PcCheck.Core;

namespace PcCheck.App.ViewModels;

public sealed partial class MainViewModel : ObservableObject
{
    [ObservableProperty] private object? _page;

    public string Title { get; } = $"PC Check {typeof(MainViewModel).Assembly.GetName().Version?.ToString(3)}";

    public MainViewModel(ScanReport? mock = null)
    {
        if (mock is not null)
        {
            var dir = Path.Combine(Path.GetTempPath(), "pccheck-preview", DateTime.Now.ToString("yyyyMMdd_HHmmss"));
            Directory.CreateDirectory(dir);
            ShowResult(new ScanOutcome(mock, dir, IsPreview: true));
        }
        else ShowStart();
    }

    public void ShowStart() => Page = new StartViewModel(this);

    public void StartScan(ScanOptions options) => Page = new ProgressViewModel(this, options);

    public void ShowResult(ScanOutcome outcome) => Page = new ResultViewModel(this, outcome);

    public void ShowFix(ScanOutcome outcome) => Page = new FixViewModel(this, outcome);

    public void ShowUndo(string? scanDir = null, bool preview = false) => Page = new UndoViewModel(this, scanDir, preview);
}
