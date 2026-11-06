using PcCheck.Core;

namespace PcCheck.Collectors.Infra;

public static class F
{
    // Score is filled in by the analyzer from rules.json.
    public static Finding Make(string id, string category, Severity sev, string title, string detail,
        string? remediationId = null, params (string Key, object? Value)[] evidence) =>
        new(id, category, sev, title, detail, 0, remediationId,
            evidence.Where(e => e.Value is not null).ToDictionary(e => e.Key, e => Convert.ToString(e.Value, System.Globalization.CultureInfo.InvariantCulture)!));

    public static Severity? Above(double value, Core.Config.Level level) =>
        level.High is { } h && value > h ? Severity.High
        : level.Medium is { } m && value > m ? Severity.Medium
        : level.Low is { } l && value > l ? Severity.Low
        : null;

    public static Severity? Below(double value, Core.Config.Level level) =>
        level.High is { } h && value < h ? Severity.High
        : level.Medium is { } m && value < m ? Severity.Medium
        : level.Low is { } l && value < l ? Severity.Low
        : null;
}
