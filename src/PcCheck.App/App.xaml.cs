using System.Windows;
using PcCheck.App.Services;
using PcCheck.App.ViewModels;
using PcCheck.Core;

namespace PcCheck.App;

public partial class App : Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var args = e.Args.Select(a => a.ToLowerInvariant()).ToArray();

        if (args.FirstOrDefault() == "scan")
        {
            // Headless: no window, outputs only. Exit code 0 = findings.json written.
            Shutdown(await RunHeadlessAsync(args));
            return;
        }

        var vm = new MainViewModel(args.Contains("--mock") ? MockData.Report() : null);
        MainWindow = new MainWindow { DataContext = vm };
        MainWindow.Show();
    }

    private static async Task<int> RunHeadlessAsync(string[] args)
    {
        var defender = args.Contains("--defender-full-scan") ? DefenderScanType.Full
            : args.Contains("--defender-scan") ? DefenderScanType.Quick : DefenderScanType.None;
        var options = new ScanOptions(args.Contains("--quick"), defender, args.Contains("--vt"));
        try
        {
            await new ScanPipeline().RunAsync(options, null, null, CancellationToken.None);
            return 0;
        }
        catch (Exception ex)
        {
            // The run log lives inside the output folder, which may not exist when this fires.
            await File.WriteAllTextAsync(Path.Combine(ScanPipeline.BaseDir, "last-scan-error.txt"), ex.ToString());
            return 1;
        }
    }
}
