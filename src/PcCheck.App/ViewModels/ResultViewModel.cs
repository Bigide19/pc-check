using System.Net.Http;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PcCheck.App.Services;
using PcCheck.App.Views;
using PcCheck.Core;
using PcCheck.Report;

namespace PcCheck.App.ViewModels;

public sealed record FindingItem(Finding Finding)
{
    public string SeverityText => Labels.Of(Finding.Severity);
    public string CategoryText => Labels.Category(Finding.Category);
    public string EvidenceText => string.Join("\n", Finding.Evidence.Select(kv => $"{kv.Key}: {kv.Value}"));
    public bool HasEvidence => Finding.Evidence.Count > 0;
    public string? RemediationText => RemediationCatalog.Find(Finding.RemediationId) is { } r
        ? r.Advice is null ? $"{r.Name} ({r.Id})" : $"{r.Name}: {r.Advice}"
        : null;
}

public sealed record CategoryScore(string Name, int Score);

public sealed record RemediationGroup(string Title, IReadOnlyList<RemediationCandidate> Items);

public sealed record RemediationCandidate(string Id, string Name, string FindingId, string FindingTitle, RiskLevel Risk, bool Reversible)
{
    public string ReversibleText => Risk == RiskLevel.AdviceOnly ? "" : Reversible ? Strings.Result_Reversible : Strings.Result_Irreversible;
}

public sealed record ErrorItem(CollectorError Error)
{
    public string StatusText => Labels.Of(Error.Status);
}

public sealed record ProcessRow(string Name, int Pid, string ValueText);

public sealed record ProcessColumn(string Title, string Unit, IReadOnlyList<ProcessRow> Items)
{
    public static ProcessColumn Of(string title, string unit, string format, IReadOnlyList<ProcessSample> samples) =>
        new(title, unit, samples.Select(p => new ProcessRow(p.Name, p.Pid, p.Value.ToString(format))).ToList());
}

public sealed partial class ResultViewModel : ObservableObject
{
    private readonly MainViewModel _main;
    private readonly ScanOutcome _outcome;

    public ScanReport Report { get; }
    public string OutputDir { get; }

    public string VerdictText => Labels.Of(Report.Verdict.Primary);
    public string VerdictDescription => Labels.DescribeVerdict(Report.Verdict.Primary);
    public string? SecondaryText => Report.Verdict.Secondary is { } s ? string.Format(Strings.Result_Secondary, Labels.Of(s)) : null;
    public string BasisText =>
        (Report.Verdict.Basis.Count > 0 ? string.Format(Strings.Result_Basis, string.Join(", ", Report.Verdict.Basis)) : Strings.Result_NoBasis)
        + (Report.Verdict.SecondaryBasis is { Count: > 0 } sb ? string.Format(Strings.Result_SecondaryBasis, string.Join(", ", sb)) : "");
    public string ScannedAtText => $"{Report.ScannedAt:yyyy-MM-dd HH:mm}\n" + (Report.SamplingSec > 0 ? string.Format(Strings.Result_Sampled, Report.SamplingSec) : Strings.Result_NotSampled);

    public IReadOnlyList<FindingItem> Findings { get; }
    public IReadOnlyList<CategoryScore> CategoryScores { get; }
    public IReadOnlyList<RemediationGroup> RemediationGroups { get; }
    public IReadOnlyList<ProcessColumn> ProcessColumns { get; }
    public IReadOnlyList<ErrorItem> Errors { get; }

    public string FindingsHeader => string.Format(Strings.Result_Findings, Findings.Count);
    // Follows the verdict so the drop never says "leaking" next to a "healthy" verdict.
    public int LeakCount => Report.Verdict.Primary == Verdict.Healthy ? 0 : Report.Findings.Count(f => f.Severity != Severity.Info);
    public LeakDropMode LeakMode => LeakCount == 0 ? LeakDropMode.Clean : LeakDropMode.Leaking;
    public string LeakText => LeakCount switch { 0 => Strings.Result_NoLeak, 1 => Strings.Result_LeakOne, var n => string.Format(Strings.Result_Leaks, n) };
    public string ErrorsHeader => string.Format(Strings.Result_Errors, Report.CollectorErrors.Count);
    public bool HasErrors => Report.CollectorErrors.Count > 0;
    public string ReportPath => Path.Combine(OutputDir, "report.html");
    public bool CanOpenReport => File.Exists(ReportPath);

    public ResultViewModel(MainViewModel main, ScanOutcome outcome)
    {
        _main = main;
        _outcome = outcome;
        Report = outcome.Report;
        OutputDir = outcome.OutputDir;
        Findings = Report.Findings.Select(f => new FindingItem(f)).ToList();
        Errors = Report.CollectorErrors.Select(e => new ErrorItem(e)).ToList();

        CategoryScores = Labels.CategoryOrder
            .Select(c => new CategoryScore(Labels.CategoryShort(c), Report.Scores.ByCategory.GetValueOrDefault(c)))
            .ToList();

        RemediationGroups = Report.Findings
            .Select(f => (f, info: RemediationCatalog.Find(f.RemediationId)))
            .Where(x => x.info is not null)
            .GroupBy(x => x.info!.Risk)
            .OrderBy(g => g.Key)
            .Select(g => new RemediationGroup(Labels.Of(g.Key),
                g.Select(x => new RemediationCandidate(x.info!.Id, x.info.Name, x.f.Id, x.f.Title, x.info.Risk, x.info.Reversible)).ToList()))
            .ToList();

        var tp = Report.TopProcesses;
        ProcessColumns = tp is null ? [] :
        [
            ProcessColumn.Of("CPU", "%", "0.0", tp.Cpu),
            ProcessColumn.Of(Strings.Result_Memory, "MB", "0", tp.Memory),
            ProcessColumn.Of(Strings.Result_Disk, "MB/s", "0.0", tp.Disk),
        ];
    }

    [RelayCommand]
    private void OpenReport() => Shell(ReportPath);

    [RelayCommand]
    private void OpenFolder() => Shell(OutputDir);

    // Rebuilt at click time so actions.json from a later fix is included; explorer then highlights the file.
    [RelayCommand]
    private void OpenBundle()
    {
        var zip = ResultBundle.Create(OutputDir);
        if (zip is null) { Shell(OutputDir); return; }
        Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{zip}\"") { UseShellExecute = true });
    }

    [RelayCommand]
    private void NewScan() => _main.ShowStart();

    public bool CanFix => RemediationGroups.Any(g => g.Items.Any(i => i.Risk != RiskLevel.AdviceOnly)) && Directory.Exists(OutputDir);
    public bool IsPreview => _outcome.IsPreview;

    [RelayCommand]
    private void Fix() => _main.ShowFix(_outcome);

    // Kept in memory only; prefilled from the environment so a technician's machine can skip pasting.
    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(SendSlackCommand))] private string _slackUrl =
        Environment.GetEnvironmentVariable(SlackWebhookSender.EnvVar) ?? "";
    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(SendSlackCommand))] private bool _isSendingSlack;
    [ObservableProperty] private string? _slackStatus;
    [ObservableProperty] private bool _slackFailed;

    private bool CanSendSlack() => !IsSendingSlack && SlackWebhookSender.IsValidUrl(SlackUrl);

    [RelayCommand(CanExecute = nameof(CanSendSlack))]
    private async Task SendSlackAsync()
    {
        IsSendingSlack = true;
        SlackFailed = false;
        var messages = SlackReportFormatter.Format(Report);
        SlackStatus = string.Format(Strings.Result_Sending, 0, messages.Count);
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            var progress = new Progress<int>(n => SlackStatus = string.Format(Strings.Result_Sending, n, messages.Count));
            await new SlackWebhookSender(http).SendAsync(SlackUrl, messages, progress, CancellationToken.None);
            SlackStatus = string.Format(Strings.Result_Sent, messages.Count);
        }
        catch (Exception ex) when (ex is ArgumentException or HttpRequestException or TaskCanceledException)
        {
            SlackFailed = true;
            SlackStatus = ex is TaskCanceledException ? Strings.Result_SlackTimeout : ex.Message;
        }
        finally
        {
            IsSendingSlack = false;
        }
    }

    private static void Shell(string path) => Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
}
