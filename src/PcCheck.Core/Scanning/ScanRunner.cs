using System.Diagnostics;

namespace PcCheck.Core.Scanning;

public sealed class ScanRunner(IReadOnlyList<ICollector> collectors, Action<string, Exception?>? log = null)
{
    public IReadOnlyList<ICollector> Collectors => collectors;

    // Never throws for a collector fault: every collector yields exactly one result, in input order.
    public async Task<IReadOnlyList<CollectorResult>> RunAsync(
        CollectContext ctx, CancellationToken ct, Action<CollectorResult>? onCompleted = null)
    {
        var tasks = collectors.Select(async c =>
        {
            var r = await RunOneAsync(c, ctx, ct).ConfigureAwait(false);
            onCompleted?.Invoke(r);
            return r;
        }).ToArray();
        return await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    private async Task<CollectorResult> RunOneAsync(ICollector collector, CollectContext ctx, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var timeout = collector.GetTimeout(ctx);
        try
        {
            // Task.Run so a collector that blocks synchronously cannot stall the others;
            // WaitAsync so one that ignores its token is still abandoned at the timeout.
            var work = Task.Run(() => collector.CollectAsync(ctx, cts.Token), cts.Token);
            var result = await work.WaitAsync(timeout, ct).ConfigureAwait(false);
            return result with { CollectorId = collector.Id, Elapsed = sw.Elapsed };
        }
        catch (TimeoutException)
        {
            cts.Cancel();
            log?.Invoke($"Collector {collector.Id} timed out after {timeout.TotalSeconds:0}s", null);
            return new CollectorResult
            {
                CollectorId = collector.Id,
                Status = CollectorStatus.TimedOut,
                Error = $"{timeout.TotalSeconds:0}초 안에 끝나지 않아 중단했습니다.",
                Elapsed = sw.Elapsed,
            };
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return new CollectorResult
            {
                CollectorId = collector.Id,
                Status = CollectorStatus.Canceled,
                Error = "사용자가 점검을 취소했습니다.",
                Elapsed = sw.Elapsed,
            };
        }
        catch (Exception ex)
        {
            log?.Invoke($"Collector {collector.Id} failed", ex);
            return new CollectorResult
            {
                CollectorId = collector.Id,
                Status = CollectorStatus.Failed,
                Error = $"{ex.GetType().Name}: {ex.Message}",
                Elapsed = sw.Elapsed,
            };
        }
    }
}
