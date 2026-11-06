using PcCheck.Analysis;
using PcCheck.Core;
using PcCheck.Core.Config;

namespace PcCheck.Analysis.Tests;

public class VerdictTests
{
    private static readonly RulesConfig Rules = new();

    private static Finding F(string id, Severity s, string? category = null) =>
        new(id, category ?? (id.StartsWith("HW-") ? Categories.Hardware : Categories.System), s, id, "", 0, null, new Dictionary<string, string>());

    private static VerdictResult Decide(params Finding[] f) => ScanAnalyzer.Analyze(f, Rules).Verdict;

    [Fact]
    public void Healthy_when_nothing_scores()
    {
        var v = Decide(F("APP-RECENT", Severity.Info), F("SYS-MISC", Severity.Low));
        Assert.Equal(Verdict.Healthy, v.Primary);
        Assert.Null(v.Secondary);
    }

    [Fact]
    public void Cleanup_at_ten_software_points()
    {
        var v = Decide(F("ST-COUNT", Severity.Medium), F("SYS-UPDATE", Severity.Medium));
        Assert.Equal(Verdict.Cleanup, v.Primary);
        Assert.Equal(["ST-COUNT", "SYS-UPDATE"], v.Basis.Order());
    }

    [Fact]
    public void Nine_points_is_still_healthy() =>
        Assert.Equal(Verdict.Healthy, Decide(F("ST-COUNT", Severity.Medium), F("SYS-MISC", Severity.Low), F("SYS-MISC", Severity.Low),
            F("SYS-MISC", Severity.Low), F("SYS-MISC", Severity.Low)).Primary);

    [Fact]
    public void Format_on_unresolved_threat()
    {
        var v = Decide(F("SEC-THREAT", Severity.Critical));
        Assert.Equal(Verdict.Format, v.Primary);
        Assert.Contains("SEC-THREAT", v.Basis);
    }

    [Fact]
    public void Format_on_five_high_suspects()
    {
        var v = Decide(F("ST-SUSPECT", Severity.High), F("ST-SUSPECT", Severity.High), F("TASK-SUSPECT", Severity.High),
            F("BR-POLICY", Severity.High), F("NET-PROXY", Severity.High));
        Assert.Equal(Verdict.Format, v.Primary);
        Assert.Equal(["BR-POLICY", "NET-PROXY", "ST-SUSPECT", "TASK-SUSPECT"], v.Basis.Order());
    }

    [Fact]
    public void Four_suspects_is_cleanup_not_format()
    {
        var v = Decide(F("ST-SUSPECT", Severity.High), F("TASK-SUSPECT", Severity.High), F("BR-POLICY", Severity.High), F("NET-PROXY", Severity.High));
        Assert.Equal(Verdict.Cleanup, v.Primary);
    }

    [Fact]
    public void Format_on_eighty_software_points()
    {
        var v = Decide(Enumerable.Range(0, 6).Select(_ => F("APP-KNOWN-BAD", Severity.High)).ToArray());
        Assert.Equal(Verdict.Format, v.Primary);
    }

    [Theory]
    [InlineData("HW-DISK-HEALTH", Severity.Critical, null, null)]
    [InlineData("HW-DISK-TYPE", Severity.High, "RES-DISK", Severity.High)]
    [InlineData("HW-RAM", Severity.High, "RES-MEM", Severity.High)]
    public void HardwareReplace(string id, Severity s, string? with, Severity? withSev)
    {
        var f = new List<Finding> { F(id, s) };
        if (with is not null) f.Add(F(with, withSev!.Value, Categories.Resource));
        var v = Decide(f.ToArray());
        Assert.Equal(Verdict.HardwareReplace, v.Primary);
        Assert.Contains(id, v.Basis);
    }

    [Fact]
    public void Hdd_alone_is_not_hardware_replace()
    {
        Assert.NotEqual(Verdict.HardwareReplace, Decide(F("HW-DISK-TYPE", Severity.High)).Primary);
        Assert.NotEqual(Verdict.HardwareReplace, Decide(F("HW-DISK-HEALTH", Severity.High)).Primary);
    }

    [Fact]
    public void Hardware_and_format_together()
    {
        var v = Decide(F("HW-DISK-HEALTH", Severity.Critical), F("SEC-THREAT", Severity.Critical));
        Assert.Equal(Verdict.HardwareReplace, v.Primary);
        Assert.Equal(Verdict.Format, v.Secondary);
        Assert.Equal(["HW-DISK-HEALTH"], v.Basis);
        Assert.Equal(["SEC-THREAT"], v.SecondaryBasis!);
    }

    [Fact]
    public void Spec_example_hdd_bottleneck_with_cleanup_secondary()
    {
        var v = Decide(F("HW-DISK-TYPE", Severity.High), F("RES-DISK", Severity.High, Categories.Resource), F("ST-COUNT", Severity.Medium));
        Assert.Equal(Verdict.HardwareReplace, v.Primary);
        Assert.Equal(Verdict.Cleanup, v.Secondary);
    }

    [Fact]
    public void Scores_split_hardware_and_software()
    {
        var r = ScanAnalyzer.Analyze([F("HW-RAM", Severity.High), F("RES-CPU", Severity.Medium, Categories.Resource), F("SYS-MISC", Severity.Low)], Rules);
        Assert.Equal(15, r.Scores.Hardware);
        Assert.Equal(6, r.Scores.Software);
        Assert.Equal(Severity.High, r.Findings[0].Severity);
    }
}
