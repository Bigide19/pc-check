namespace PcCheck.Core;

// The three kinds of leak a PC can have. Performance is what the verdict is about; space and
// information leaks are found by their own collectors and only ever reported, never scored into the verdict.
public enum LeakKind { Performance, Space, Information }

public sealed record LeakSummary(LeakKind Kind, bool Checked, int Count, IReadOnlyList<Finding> Findings);

public static class Leaks
{
    public static readonly LeakKind[] Order = [LeakKind.Performance, LeakKind.Space, LeakKind.Information];

    // Leaks this build has collectors for. A leak with findings in the report counts as checked too (--mock).
    public static readonly IReadOnlySet<LeakKind> Implemented = new HashSet<LeakKind> { LeakKind.Performance };

    public static LeakKind Of(string category) => category switch
    {
        Categories.Space => LeakKind.Space,
        Categories.Privacy => LeakKind.Information,
        _ => LeakKind.Performance,
    };

    public static LeakKind Of(Finding f) => Of(f.Category);

    // Count follows the verdict banner's rule: Info findings are context, not leaks.
    public static IReadOnlyList<LeakSummary> Summarize(IReadOnlyList<Finding> findings) =>
        Order.Select(kind =>
        {
            var mine = findings.Where(f => Of(f) == kind).ToList();
            return new LeakSummary(kind, Implemented.Contains(kind) || mine.Count > 0, mine.Count(f => f.Severity != Severity.Info), mine);
        }).ToList();
}
