using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PcCheck.App.Services;
using PcCheck.Collectors;
using PcCheck.Core;

namespace PcCheck.App.ViewModels;

public sealed partial class StartViewModel : ObservableObject
{
    private readonly MainViewModel _main;

    public MachineInfo Machine { get; }
    public IReadOnlyList<string> Warnings { get; }
    public int DurationSec { get; }
    public int QuickDurationSec { get; }

    [ObservableProperty] private bool _quick;
    [ObservableProperty] private bool _defenderQuick;
    [ObservableProperty] private bool _defenderFull;

    public StartViewModel(MainViewModel main)
    {
        _main = main;
        Machine = MachineInfoReader.Read();
        var (config, configWarnings) = ScanPipeline.LoadConfig();
        DurationSec = config.Rules.Sampling.DurationSec;
        QuickDurationSec = config.Rules.Sampling.QuickDurationSec;

        var warnings = new List<string>();
        if (!Machine.IsAdmin) warnings.Add("관리자 권한이 아닙니다. 대부분의 항목을 수집할 수 없습니다.");
        if (MachineInfoReader.OsBuild < 19045) warnings.Add($"지원 대상(Windows 10 22H2, Windows 11)보다 오래된 빌드({MachineInfoReader.OsBuild})입니다.");
        warnings.AddRange(configWarnings);
        Warnings = warnings;
    }

    public string DurationLabel => $"기본 측정 ({DurationSec}초)";
    public string QuickLabel => $"빠른 측정 ({QuickDurationSec}초)";

    public bool CanUndo { get; } = Remediation.ActionLogStore.LatestUndoable(ScanPipeline.BaseDir) is not null;

    [RelayCommand]
    private void Undo() => _main.ShowUndo();

    [RelayCommand]
    private void Start() => _main.StartScan(new ScanOptions(Quick,
        DefenderFull ? DefenderScanType.Full : DefenderQuick ? DefenderScanType.Quick : DefenderScanType.None));
}
