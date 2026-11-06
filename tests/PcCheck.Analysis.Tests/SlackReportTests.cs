using PcCheck.Core;
using PcCheck.Report;

namespace PcCheck.Analysis.Tests;

public class SlackReportTests
{
    private static ScanReport Report(int findings) => new()
    {
        ScannedAt = new DateTimeOffset(2026, 11, 6, 15, 30, 0, TimeSpan.FromHours(9)),
        SamplingSec = 120,
        Machine = new MachineInfo { Name = "SAMPLE-PC", Os = "Windows 11", Cpu = "CPU", RamGb = 8, SystemDisk = "SSD", User = @"SAMPLE-PC\operator" },
        Verdict = new VerdictResult(Verdict.Format, null, ["SEC-THREAT"]),
        Scores = new ScoreSummary { Hardware = 0, Software = 90 },
        Findings = Enumerable.Range(1, findings).Select(i => new Finding($"ID-{i:00}", Categories.Security, Severity.High,
            $"항목 {i} <b>&", "설명", 15, "ADV-PHOTOS",
            new Dictionary<string, string> { ["path"] = new string('x', 400), ["n"] = i.ToString() })).ToList(),
        CollectorErrors = [new CollectorError("ST-SUSPECT", CollectorStatus.Failed, "PowerShellException: boom")],
    };

    [Fact]
    public void Splits_into_numbered_messages_under_the_limit_and_keeps_every_finding()
    {
        var msgs = SlackReportFormatter.Format(Report(40), "카운터 PC");
        Assert.True(msgs.Count > 3);
        Assert.All(msgs, m => Assert.True(m.Length <= SlackReportFormatter.MaxChars + 20, $"length {m.Length}"));
        Assert.Contains("포맷 권장", msgs[0]);
        Assert.Contains("카운터 PC", msgs[0]);
        Assert.EndsWith($"(1/{msgs.Count})_", msgs[0]);
        var all = string.Join("\n", msgs);
        for (var i = 1; i <= 40; i++) Assert.Contains($"`ID-{i:00}`", all);
        Assert.Contains("ST-SUSPECT", msgs[^1]);
    }

    [Fact]
    public void Escapes_slack_control_characters_and_clips_long_values()
    {
        var all = string.Join("\n", SlackReportFormatter.Format(Report(1)));
        Assert.Contains("&lt;b&gt;&amp;", all);
        Assert.DoesNotContain(new string('x', 300), all);
    }

    [Fact]
    public void Small_report_is_a_single_unnumbered_pair_or_less()
    {
        var msgs = SlackReportFormatter.Format(Report(0) with { CollectorErrors = [] });
        Assert.Single(msgs);
        Assert.DoesNotContain("(1/", msgs[0]);
    }

    [Theory]
    [InlineData("https://hooks.slack.com/services/T000/B000/XXXX", true)]
    [InlineData("  https://hooks.slack.com/services/T000/B000/XXXX  ", true)]
    [InlineData("http://hooks.slack.com/services/T000/B000/XXXX", false)]
    [InlineData("https://hooks.slack.com.evil.example/services/T/B/X", false)]
    [InlineData("https://example.com/services/T/B/X", false)]
    [InlineData("", false)]
    public void Accepts_only_slack_webhook_urls(string url, bool ok) => Assert.Equal(ok, SlackWebhookSender.IsValidUrl(url));
}
