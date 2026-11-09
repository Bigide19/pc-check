using PcCheck.Core;
using PcCheck.Report;

namespace PcCheck.Analysis.Tests;

public class LocalizationTests
{
    private static T InEnglish<T>(Func<T> f)
    {
        Lang.Set("en");
        try { return f(); }
        finally { Lang.Set("ko"); }
    }

    private static ScanReport Report() => new()
    {
        ScannedAt = new DateTimeOffset(2026, 11, 6, 15, 30, 0, TimeSpan.FromHours(9)),
        Machine = new MachineInfo { Name = "SAMPLE-PC", User = "operator" },
        Verdict = new VerdictResult(Verdict.Format, null, ["SEC-THREAT"]),
        Scores = new ScoreSummary(),
        Findings = [new Finding("RES-MEM", Categories.Resource, Severity.High, "t", "d", 15, "ADV-MEM", new Dictionary<string, string>())],
    };

    [Fact]
    public void Report_and_slack_follow_the_current_language()
    {
        var html = InEnglish(() => HtmlReportRenderer.Render(Report()));
        Assert.Contains("<html lang=\"en\">", html);
        Assert.Contains("Reformat recommended", html);
        Assert.Contains("Recommended action: Reduce memory use", html);
        Assert.Contains("Browser, network", html);

        var slack = InEnglish(() => string.Join("\n", SlackReportFormatter.Format(Report())));
        Assert.Contains("*PC Check  scan result*", slack);
        Assert.Contains(":large_orange_circle: High", slack);

        Assert.Contains("<html lang=\"ko\">", HtmlReportRenderer.Render(Report()));
    }
}
