using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PcCheck.App.Services;
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
    public string ReversibleText => Risk == RiskLevel.AdviceOnly ? "" : Reversible ? "되돌릴 수 있음" : "되돌릴 수 없음";
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
    public string? SecondaryText => Report.Verdict.Secondary is { } s ? $"보조 판정: {Labels.Of(s)}" : null;
    public string BasisText =>
        (Report.Verdict.Basis.Count > 0 ? $"근거: {string.Join(", ", Report.Verdict.Basis)}" : "근거 항목 없음")
        + (Report.Verdict.SecondaryBasis is { Count: > 0 } sb ? $"   보조 근거: {string.Join(", ", sb)}" : "");
    public string ScannedAtText => $"{Report.ScannedAt:yyyy-MM-dd HH:mm}\n" + (Report.SamplingSec > 0 ? $"리소스 측정 {Report.SamplingSec}초" : "리소스 측정 안 함");

    public IReadOnlyList<FindingItem> Findings { get; }
    public IReadOnlyList<CategoryScore> CategoryScores { get; }
    public IReadOnlyList<RemediationGroup> RemediationGroups { get; }
    public IReadOnlyList<ProcessColumn> ProcessColumns { get; }
    public IReadOnlyList<ErrorItem> Errors { get; }

    public string FindingsHeader => $"발견 항목 ({Findings.Count})";
    public string ErrorsHeader => $"수집 오류 ({Report.CollectorErrors.Count})";
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
            ProcessColumn.Of("메모리", "MB", "0", tp.Memory),
            ProcessColumn.Of("디스크", "MB/s", "0.0", tp.Disk),
        ];
    }

    [RelayCommand]
    private void OpenReport() => Shell(ReportPath);

    [RelayCommand]
    private void OpenFolder() => Shell(OutputDir);

    [RelayCommand]
    private void NewScan() => _main.ShowStart();

    public bool CanFix => RemediationGroups.Any(g => g.Items.Any(i => i.Risk != RiskLevel.AdviceOnly)) && Directory.Exists(OutputDir);
    public bool IsPreview => _outcome.IsPreview;

    [RelayCommand]
    private void Fix() => _main.ShowFix(_outcome);

    private static void Shell(string path) => Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
}
