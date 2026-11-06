using PcCheck.Core;
using PcCheck.Core.Config;

namespace PcCheck.Analysis;

public sealed record AnalysisResult(IReadOnlyList<Finding> Findings, ScoreSummary Scores, VerdictResult Verdict);

public static class ScanAnalyzer
{
    public static AnalysisResult Analyze(IEnumerable<Finding> findings, RulesConfig rules)
    {
        // Score always comes from rules.json, whatever a collector put in the field.
        var scored = findings
            .Select(f => f with { Score = rules.ScoreOf(f.Severity) })
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Id, StringComparer.Ordinal)
            .ToList();

        var scores = Scorer.Score(scored);
        var verdict = VerdictEngine.Decide(scored, scores, rules);
        return new AnalysisResult(scored, scores, verdict);
    }
}

public static class Scorer
{
    public static ScoreSummary Score(IReadOnlyList<Finding> findings)
    {
        var byCategory = findings
            .GroupBy(f => f.Category)
            .ToDictionary(g => g.Key, g => g.Sum(f => f.Score));
        var hardware = byCategory.GetValueOrDefault(Categories.Hardware);
        return new ScoreSummary
        {
            Hardware = hardware,
            Software = byCategory.Values.Sum() - hardware,
            ByCategory = byCategory,
        };
    }
}

public static class VerdictEngine
{
    public static readonly string[] SuspectIds =
        ["ST-SUSPECT", "SVC-SUSPECT", "TASK-SUSPECT", "BR-POLICY", "BR-EXT", "NET-HOSTS", "NET-PROXY"];

    // Rules are evaluated top-down; hardware comes first because a format cannot fix it.
    public static VerdictResult Decide(IReadOnlyList<Finding> findings, ScoreSummary scores, RulesConfig rules)
    {
        var hardware = HardwareBasis(findings);
        var software = SoftwareVerdict(findings, scores, rules);

        if (hardware.Count > 0)
            return new VerdictResult(Verdict.HardwareReplace, software?.Verdict, hardware, software?.Basis);
        if (software is { } s)
            return new VerdictResult(s.Verdict, null, s.Basis);
        return new VerdictResult(Verdict.Healthy, null, []);
    }

    private static bool Has(IReadOnlyList<Finding> f, string id, Severity atLeast) =>
        f.Any(x => x.Id == id && x.Severity >= atLeast);

    private static List<string> HardwareBasis(IReadOnlyList<Finding> f)
    {
        var basis = new List<string>();
        if (f.Any(x => x.Id == "HW-DISK-HEALTH" && x.Severity == Severity.Critical)) basis.Add("HW-DISK-HEALTH");
        // HW-DISK-TYPE is High only for an HDD; HW-RAM is High only at or below the low-memory threshold.
        if (Has(f, "HW-DISK-TYPE", Severity.High) && Has(f, "RES-DISK", Severity.High)) basis.AddRange(["HW-DISK-TYPE", "RES-DISK"]);
        if (Has(f, "HW-RAM", Severity.High) && Has(f, "RES-MEM", Severity.High)) basis.AddRange(["HW-RAM", "RES-MEM"]);
        return basis.Distinct().ToList();
    }

    private static (Verdict Verdict, IReadOnlyList<string> Basis)? SoftwareVerdict(IReadOnlyList<Finding> f, ScoreSummary scores, RulesConfig rules)
    {
        var v = rules.Verdict;
        var basis = new List<string>();
        if (f.Any(x => x.Id == "SEC-THREAT" && x.Severity == Severity.Critical)) basis.Add("SEC-THREAT");

        var suspects = f.Where(x => SuspectIds.Contains(x.Id) && x.Severity >= Severity.High).ToList();
        if (suspects.Count >= v.FormatSuspectHighCount) basis.AddRange(suspects.Select(x => x.Id));

        if (scores.Software >= v.FormatSoftwareScore) basis.AddRange(TopSoftware(f));
        if (basis.Count > 0) return (Verdict.Format, basis.Distinct().ToList());

        if (scores.Software >= v.CleanupSoftwareScore) return (Verdict.Cleanup, TopSoftware(f));
        return null;
    }

    private static List<string> TopSoftware(IReadOnlyList<Finding> f) =>
        f.Where(x => x.Category != Categories.Hardware && x.Score > 0)
            .GroupBy(x => x.Id)
            .OrderByDescending(g => g.Sum(x => x.Score))
            .Take(5)
            .Select(g => g.Key)
            .ToList();
}
