using PcCheck.Core;
using PcCheck.Core.Config;
using PcCheck.Core.Scanning;

namespace PcCheck.Core.Tests;

public class ScanRunnerTests
{
    private sealed class FakeCollector(string id, Func<CancellationToken, Task<CollectorResult>> run, TimeSpan? timeout = null) : ICollector
    {
        public string Id => id;
        public TimeSpan GetTimeout(CollectContext ctx) => timeout ?? ctx.DefaultTimeout;
        public Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct) => run(ct);
    }

    [Fact]
    public async Task Faulting_and_hanging_collectors_do_not_stop_the_others()
    {
        var finding = new Finding("X-1", Categories.System, Severity.Low, "t", "d", 0, null, new Dictionary<string, string>());
        var collectors = new ICollector[]
        {
            new FakeCollector("ok", _ => Task.FromResult(CollectorResult.Ok("ok", [finding]))),
            new FakeCollector("throws", _ => throw new InvalidOperationException("boom")),
            // Ignores its token on purpose: the runner must abandon it at the timeout anyway.
            new FakeCollector("hangs", _ => new TaskCompletionSource<CollectorResult>().Task, TimeSpan.FromMilliseconds(200)),
            new FakeCollector("reports", _ => Task.FromResult(CollectorResult.Fail("reports", "unsupported"))),
        };
        var ctx = new CollectContext { Config = PcCheckConfig.Default(), Options = new ScanOptions() };

        var results = await new ScanRunner(collectors).RunAsync(ctx, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(["ok", "throws", "hangs", "reports"], results.Select(r => r.CollectorId));
        Assert.Equal(CollectorStatus.Ok, results[0].Status);
        Assert.Single(results[0].Findings);
        Assert.Equal(CollectorStatus.Failed, results[1].Status);
        Assert.Contains("boom", results[1].Error);
        Assert.Equal(CollectorStatus.TimedOut, results[2].Status);
        Assert.Equal(CollectorStatus.Failed, results[3].Status);
    }
}
