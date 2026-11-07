using System.Net;
using System.Net.Http.Json;
using System.Text;
using PcCheck.Core;

namespace PcCheck.Report;

// Turns a scan report into Slack incoming-webhook messages small enough for one post each.
public static class SlackReportFormatter
{
    // Slack accepts longer text, but past ~4,000 characters it truncates the preview and folds the message.
    public const int MaxChars = 3500;
    private const int MaxValueChars = 200;

    private static string Sev(Severity s) => s switch
    {
        Severity.Critical => ":red_circle: 심각",
        Severity.High => ":large_orange_circle: 높음",
        Severity.Medium => ":large_yellow_circle: 보통",
        Severity.Low => ":white_circle: 낮음",
        _ => ":information_source: 정보",
    };

    // Slack mrkdwn treats & < > as control characters.
    private static string E(string? s) => (s ?? "").Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");

    private static string Clip(string s) => s.Length <= MaxValueChars ? s : s[..MaxValueChars] + "…";

    public static IReadOnlyList<string> Format(ScanReport r, string? label = null)
    {
        var m = r.Machine;
        var head = new StringBuilder();
        head.AppendLine($"*pitstop {E(r.ToolVersion)} 점검 결과*{(string.IsNullOrWhiteSpace(label) ? "" : $" ({E(label)})")}");
        head.AppendLine($"*{E(Labels.Of(r.Verdict.Primary))}*{(r.Verdict.Secondary is { } s ? $"  (보조 판정: {E(Labels.Of(s))})" : "")}");
        head.AppendLine(E(Labels.DescribeVerdict(r.Verdict.Primary)));
        head.AppendLine($"근거: `{(r.Verdict.Basis.Count > 0 ? string.Join(", ", r.Verdict.Basis) : "없음")}`"
            + (r.Verdict.SecondaryBasis is { Count: > 0 } sb ? $"  보조 근거: `{string.Join(", ", sb)}`" : ""));
        head.AppendLine($"점수: 하드웨어 {r.Scores.Hardware}, 소프트웨어 {r.Scores.Software}");
        head.AppendLine($"PC: {E(m.Name)} · {E(m.Os)} · {E(m.Cpu)} · {m.RamGb} GB · {E(m.SystemDisk)}");
        head.AppendLine($"실행 계정: {E(m.User)} · 점검 {r.ScannedAt:yyyy-MM-dd HH:mm} · " + (r.SamplingSec > 0 ? $"측정 {r.SamplingSec}초" : "측정 안 함"));
        head.Append($"발견 항목 {r.Findings.Count}개, 수집 오류 {r.CollectorErrors.Count}개");

        var messages = new List<string> { head.ToString() };

        var blocks = r.Findings.Select(f =>
        {
            var b = new StringBuilder();
            b.AppendLine($"{Sev(f.Severity)} *{E(f.Title)}*  `{f.Id}` · {E(Labels.Category(f.Category))} · {f.Score}점");
            b.AppendLine(E(f.Detail));
            foreach (var (k, v) in f.Evidence) b.AppendLine($"> {E(k)}: {E(Clip(v))}");
            if (RemediationCatalog.Find(f.RemediationId) is { } rem)
                b.AppendLine($"권장 조치: {E(rem.Name)}{(rem.Advice is null ? "" : $" - {E(rem.Advice)}")}");
            return b.ToString().TrimEnd();
        });
        Pack(messages, "*발견 항목*", blocks);

        var tail = new List<string>();
        if (r.TopProcesses is { } tp)
        {
            static string Line(string title, string unit, IEnumerable<ProcessSample> xs, string fmt) =>
                $"*{title}* ({unit}): " + string.Join(", ", xs.Select(p => $"{E(p.Name)} {p.Value.ToString(fmt)}"));
            tail.Add("*상위 프로세스*\n" + string.Join("\n",
                Line("CPU", "%", tp.Cpu, "0.0"), Line("메모리", "MB", tp.Memory, "0"), Line("디스크 I/O", "MB/s", tp.Disk, "0.0")));
        }
        if (r.CollectorErrors.Count > 0)
            tail.Add("*수집 오류*\n" + string.Join("\n", r.CollectorErrors.Select(e => $"`{e.CollectorId}` {E(Labels.Of(e.Status))}: {E(Clip(e.Message))}")));
        Pack(messages, null, tail);

        if (messages.Count > 1)
            for (var i = 0; i < messages.Count; i++) messages[i] = $"{messages[i]}\n_({i + 1}/{messages.Count})_";
        return messages;
    }

    // Greedy packing at block boundaries; a single oversized block is cut rather than dropped.
    private static void Pack(List<string> messages, string? title, IEnumerable<string> blocks)
    {
        var cur = new StringBuilder(title ?? "");
        foreach (var raw in blocks)
        {
            var block = raw.Length > MaxChars ? raw[..(MaxChars - 20)] + "\n… (잘림)" : raw;
            if (cur.Length > 0 && cur.Length + block.Length + 2 > MaxChars)
            {
                messages.Add(cur.ToString());
                cur.Clear();
            }
            if (cur.Length > 0) cur.Append("\n\n");
            cur.Append(block);
        }
        if (cur.Length > (title?.Length ?? 0)) messages.Add(cur.ToString());
    }
}

public sealed class SlackWebhookSender(HttpClient http)
{
    public const string EnvVar = "PCCHECK_SLACK_WEBHOOK";

    // Only Slack's own webhook host: a typo must not ship the report (which holds user paths) somewhere else.
    public static bool IsValidUrl(string? url) =>
        Uri.TryCreate(url?.Trim(), UriKind.Absolute, out var u)
        && u.Scheme == Uri.UriSchemeHttps
        && u.Host.Equals("hooks.slack.com", StringComparison.OrdinalIgnoreCase)
        && u.AbsolutePath.StartsWith("/services/", StringComparison.Ordinal);

    public async Task SendAsync(string url, IReadOnlyList<string> messages, IProgress<int>? progress, CancellationToken ct)
    {
        if (!IsValidUrl(url)) throw new ArgumentException("Slack 웹훅 주소(https://hooks.slack.com/services/...)가 아닙니다.");
        for (var i = 0; i < messages.Count; i++)
        {
            await PostAsync(url.Trim(), messages[i], ct);
            progress?.Report(i + 1);
            // Incoming webhooks allow about one message per second.
            if (i < messages.Count - 1) await Task.Delay(1100, ct);
        }
    }

    private async Task PostAsync(string url, string text, CancellationToken ct)
    {
        for (var attempt = 0; ; attempt++)
        {
            using var res = await http.PostAsJsonAsync(url, new { text, mrkdwn = true }, ct);
            if (res.IsSuccessStatusCode) return;
            if (res.StatusCode == HttpStatusCode.TooManyRequests && attempt < 3)
            {
                var wait = res.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(2);
                await Task.Delay(wait, ct);
                continue;
            }
            var body = await res.Content.ReadAsStringAsync(ct);
            // The URL itself is the secret, so it never goes into the message.
            throw new HttpRequestException($"Slack 전송 실패 ({(int)res.StatusCode}): {body.Trim()}");
        }
    }
}
