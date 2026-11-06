using System.Text.Json;
using PcCheck.Core;

namespace PcCheck.Report;

public static class FindingsJsonWriter
{
    public const string FileName = "findings.json";

    public static async Task<string> WriteAsync(ScanReport report, string outputDir, CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputDir);
        var path = Path.Combine(outputDir, FileName);
        await using var stream = File.Create(path);
        await JsonSerializer.SerializeAsync(stream, report, PcCheckJson.OutputOptions, ct);
        return path;
    }
}
