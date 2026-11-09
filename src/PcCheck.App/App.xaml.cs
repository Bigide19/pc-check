using System.Net.Http;
using System.Windows;
using PcCheck.App.Services;
using PcCheck.App.ViewModels;
using PcCheck.Core;
using PcCheck.Report;

namespace PcCheck.App;

public partial class App : Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var args = e.Args.Select(a => a.ToLowerInvariant()).ToArray();
        // Before anything reads a resource or starts a scan task.
        if (Lang.FromArgs(args) is { } lang) Lang.Set(lang);
        ApplyLanguageFont();

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

    // Segoe UI draws Latin text better; Hangul it lacks falls back to Malgun Gothic. Read by windows created afterwards.
    public static void ApplyLanguageFont() =>
        Current.Resources["UiFont"] = new System.Windows.Media.FontFamily(Lang.IsKorean ? "Malgun Gothic, Segoe UI" : "Segoe UI, Malgun Gothic");

    private static async Task<int> RunHeadlessAsync(string[] args)
    {
        var defender = args.Contains("--defender-full-scan") ? DefenderScanType.Full
            : args.Contains("--defender-scan") ? DefenderScanType.Quick : DefenderScanType.None;
        var options = new ScanOptions(args.Contains("--quick"), defender, args.Contains("--vt"));
        try
        {
            var outcome = await new ScanPipeline().RunAsync(options, null, null, CancellationToken.None);
            if (!args.Contains("--slack")) return 0;

            // The webhook URL is a secret: environment only, never an argument (visible in process lists) or a file.
            var url = Environment.GetEnvironmentVariable(SlackWebhookSender.EnvVar);
            try
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
                await new SlackWebhookSender(http).SendAsync(url ?? "", SlackReportFormatter.Format(outcome.Report), null, CancellationToken.None);
                return 0;
            }
            catch (Exception ex) when (ex is ArgumentException or HttpRequestException or TaskCanceledException)
            {
                await File.WriteAllTextAsync(Path.Combine(outcome.OutputDir, "slack-error.txt"), ex.Message);
                return 3;
            }
        }
        catch (Exception ex)
        {
            // The run log lives inside the output folder, which may not exist when this fires.
            await File.WriteAllTextAsync(Path.Combine(ScanPipeline.BaseDir, "last-scan-error.txt"), ex.ToString());
            return 1;
        }
    }
}
