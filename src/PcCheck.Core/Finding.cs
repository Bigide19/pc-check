namespace PcCheck.Core;

public record Finding(
    string Id, string Category, Severity Severity,
    string Title, string Detail, int Score,
    string? RemediationId, IReadOnlyDictionary<string, string> Evidence);
