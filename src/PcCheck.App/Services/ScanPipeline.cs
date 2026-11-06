using PcCheck.Analysis;
using PcCheck.Collectors;
using PcCheck.Core;
using PcCheck.Core.Config;
using PcCheck.Core.Scanning;
using PcCheck.Report;
using Serilog;

namespace PcCheck.App.Services;

// IsPreview: sample data shown with --mock; fix and undo then run against PreviewSystemOps only.
public sealed record ScanOutcome(ScanReport Report, string OutputDir, bool IsPreview = false);

public enum ScanStage { Config, Collect, Analyze, Save }

public sealed class ScanPipeline
{
    public static string BaseDir => AppContext.BaseDirectory;
    public static string ConfigDir => Path.Combine(BaseDir, "config");

    public IReadOnlyList<ICollector> Collectors { get; } = CollectorCatalog.CreateAll();

    public static ConfigLoadResult LoadConfig() => ConfigLoader.Load(ConfigDir);

    public async Task<ScanOutcome> RunAsync(
        ScanOptions options,
        IProgress<CollectorProgress>? progress,
        Action<CollectorResult>? onCollectorCompleted,
        CancellationToken ct,
        Action<ScanStage>? onStage = null)
    {
        onStage?.Invoke(ScanStage.Config);
        var startedAt = DateTimeOffset.Now;
        var outputDir = CreateOutputDir(startedAt);
        using var log = new LoggerConfiguration()
            .MinimumLevel.Debug()
            .WriteTo.File(Path.Combine(outputDir, "pccheck.log"))
            .CreateLogger();

        log.Information("PcCheck {Version} scan start, options {@Options}", typeof(ScanPipeline).Assembly.GetName().Version, options);

        var (config, warnings) = LoadConfig();
        foreach (var w in warnings) log.Warning("Config: {Warning}", w);

        var ctx = new CollectContext
        {
            Config = config,
            Options = options,
            DefaultTimeout = TimeSpan.FromSeconds(config.Rules.Collectors.DefaultTimeoutSec),
            Progress = progress,
        };

        onStage?.Invoke(ScanStage.Collect);
        var runner = new ScanRunner(Collectors, (msg, ex) => log.Warning(ex, "{Message}", msg));
        var results = await runner.RunAsync(ctx, ct, onCollectorCompleted);
        foreach (var r in results)
            log.Information("Collector {Id} {Status} in {Elapsed} ({Count} findings) {Error}",
                r.CollectorId, r.Status, r.Elapsed, r.Findings.Count, r.Error);

        onStage?.Invoke(ScanStage.Analyze);
        var analysis = ScanAnalyzer.Analyze(results.SelectMany(r => r.Findings), config.Rules);

        var errors = warnings.Select(w => new CollectorError("CONFIG", CollectorStatus.Failed, w))
            .Concat(results.Where(r => r.Status != CollectorStatus.Ok)
                .Select(r => new CollectorError(r.CollectorId, r.Status, r.Error ?? "")))
            .ToList();

        var report = new ScanReport
        {
            ScannedAt = TruncateToSeconds(startedAt),
            // Only what was actually sampled; 0 when the resource collectors did not finish.
            SamplingSec = results.Any(r => r.CollectorId == "RES-CPU" && r.Status == CollectorStatus.Ok) ? (int)ctx.SamplingDuration.TotalSeconds : 0,
            Machine = MergeMachine(results),
            Verdict = analysis.Verdict,
            Scores = analysis.Scores,
            Findings = analysis.Findings,
            TopProcesses = results.Select(r => r.Payload).OfType<TopProcesses>().FirstOrDefault(),
            CollectorErrors = errors,
        };

        onStage?.Invoke(ScanStage.Save);
        var path = await FindingsJsonWriter.WriteAsync(report, outputDir, ct);
        var html = await HtmlReportRenderer.WriteAsync(report, outputDir, ct);
        log.Information("Wrote {Path}, {Html}", path, html);
        return new ScanOutcome(report, outputDir);
    }

    private static MachineInfo MergeMachine(IReadOnlyList<CollectorResult> results)
    {
        var machine = results.Select(r => r.Payload).OfType<MachineInfo>().FirstOrDefault() ?? MachineInfoReader.Read();
        var disk = results.Select(r => r.Payload).OfType<Collectors.Hardware.SystemDiskPayload>().FirstOrDefault();
        return disk is null ? machine : machine with { SystemDisk = disk.Kind };
    }

    private static string CreateOutputDir(DateTimeOffset at)
    {
        var baseName = Path.Combine(BaseDir, $"PcCheck_{at:yyyyMMdd_HHmm}");
        var dir = baseName;
        for (var i = 2; Directory.Exists(dir); i++) dir = $"{baseName}_{i}";
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static DateTimeOffset TruncateToSeconds(DateTimeOffset t) =>
        new(t.Ticks - t.Ticks % TimeSpan.TicksPerSecond, t.Offset);
}
