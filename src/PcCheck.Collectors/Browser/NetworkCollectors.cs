using Microsoft.Win32;
using PcCheck.Collectors.Infra;
using PcCheck.Core;
using PcCheck.Core.Config;

namespace PcCheck.Collectors.Browser;

public sealed record HostsEntry(string Address, string Host, int Line);

public sealed class HostsCollector : ICollector
{
    public string Id => "NET-HOSTS";

    public static string HostsPath => Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts");

    public async Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        if (!File.Exists(HostsPath)) return CollectorResult.Ok(Id, []);
        var text = await File.ReadAllTextAsync(HostsPath, ct);
        return CollectorResult.Ok(Id, Evaluate(Parse(text), ctx.Config.KnownBad));
    }

    public static IReadOnlyList<HostsEntry> Parse(string text)
    {
        var list = new List<HostsEntry>();
        var lines = text.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash];
            var parts = line.Split((char[])[' ', '\t', '\r'], StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;
            foreach (var host in parts.Skip(1)) list.Add(new HostsEntry(parts[0], host.ToLowerInvariant(), i + 1));
        }
        return list;
    }

    public static IReadOnlyList<Finding> Evaluate(IReadOnlyList<HostsEntry> entries, KnownBadConfig knownBad)
    {
        var custom = entries.Where(e => e.Host != "localhost").ToList();
        if (custom.Count == 0) return [];
        var critical = custom.Where(e => knownBad.HostsCriticalDomains.Any(d => e.Host == d || e.Host.EndsWith("." + d))).ToList();
        var sev = critical.Count > 0 ? Severity.Critical : Severity.Medium;
        var detail = critical.Count > 0
            ? $"포털, 은행, 보안 사이트 주소가 다른 곳으로 재지정되어 있습니다: {string.Join(", ", critical.Select(e => e.Host).Distinct().Take(5))}"
            : $"hosts 파일에 기본값이 아닌 항목이 {custom.Count}개 있습니다.";
        return [F.Make("NET-HOSTS", Categories.BrowserNetwork, sev, critical.Count > 0 ? "hosts 파일 변조 (중요 사이트 재지정)" : "hosts 파일에 추가 항목",
            detail, "RM-HOSTS-RESET",
            custom.Take(30).Select(e => ($"line{e.Line:000}", (object?)$"{e.Address} {e.Host}")).ToArray())];
    }
}

public sealed record ProxySettings(bool Enabled, string? Server, string? AutoConfigUrl);

public sealed class ProxyCollector : ICollector
{
    public string Id => "NET-PROXY";

    public const string KeyPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    public Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        using var key = Registry.CurrentUser.OpenSubKey(KeyPath);
        var s = new ProxySettings(key?.GetValue("ProxyEnable") is int e && e != 0, key?.GetValue("ProxyServer") as string,
            key?.GetValue("AutoConfigURL") as string);
        return Task.FromResult(CollectorResult.Ok(Id, Evaluate(s)));
    }

    public static IReadOnlyList<Finding> Evaluate(ProxySettings s)
    {
        var proxy = s.Enabled && !string.IsNullOrWhiteSpace(s.Server);
        var pac = !string.IsNullOrWhiteSpace(s.AutoConfigUrl);
        if (!proxy && !pac) return [];
        return [F.Make("NET-PROXY", Categories.BrowserNetwork, Severity.High, "프록시 설정됨",
            "인터넷 연결이 다른 서버를 거치도록 설정되어 있습니다. 직접 설정한 적이 없다면 변조입니다.", "RM-PROXY-RESET",
            ("proxyEnable", s.Enabled), ("proxyServer", s.Server), ("autoConfigUrl", s.AutoConfigUrl))];
    }
}
