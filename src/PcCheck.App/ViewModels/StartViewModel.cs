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
        if (!Machine.IsAdmin) warnings.Add(Strings.Start_NotAdmin);
        if (MachineInfoReader.OsBuild < 19045) warnings.Add(string.Format(Strings.Start_OldBuild, MachineInfoReader.OsBuild));
        warnings.AddRange(configWarnings);
        Warnings = warnings;
    }

    public string DurationLabel => string.Format(Strings.Start_Duration, DurationSec);
    public string QuickLabel => string.Format(Strings.Start_Quick, QuickDurationSec);

    public bool CanUndo { get; } = Remediation.ActionLogStore.LatestUndoable(ScanPipeline.BaseDir) is not null;

    [RelayCommand]
    private void Undo() => _main.ShowUndo();

    [RelayCommand]
    private void Start() => _main.StartScan(new ScanOptions(Quick,
        DefenderFull ? DefenderScanType.Full : DefenderQuick ? DefenderScanType.Quick : DefenderScanType.None));
}
