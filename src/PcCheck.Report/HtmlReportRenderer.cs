using System.Net;
using System.Text;
using PcCheck.Core;

namespace PcCheck.Report;

public static class HtmlReportRenderer
{
    public const string FileName = "report.html";

    public static async Task<string> WriteAsync(ScanReport report, string outputDir, CancellationToken ct = default)
    {
        var path = Path.Combine(outputDir, FileName);
        await File.WriteAllTextAsync(path, Render(report), new UTF8Encoding(false), ct);
        return path;
    }

    private static string H(object? s) => WebUtility.HtmlEncode(Convert.ToString(s, System.Globalization.CultureInfo.InvariantCulture) ?? "");

    private static string SevClass(Severity s) => s.ToString().ToLowerInvariant();

    private static string VerdictClass(Verdict v) => v switch
    {
        Verdict.HardwareReplace => "critical",
        Verdict.Format => "high",
        Verdict.Cleanup => "cleanup",
        _ => "ok",
    };

    public static string Render(ScanReport r)
    {
        var sb = new StringBuilder();
        var m = r.Machine;
        sb.Append($$"""
            <!doctype html>
            <html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
            <title>PC 점검 결과 - {{H(m.Name)}}</title>
            <style>
            :root{--bg:#f4f5f7;--surface:#fff;--border:#e1e4e8;--text:#1f2328;--muted:#656d76;--accent:#b9430d;--cleanup:#1f6feb;--brand:#ff742f;--brand-surface:#24282b;--ok:#1a7f37;--critical:#c4231c;--high:#d4600a;--medium:#b88700;--low:#57606a;--info:#8c959f;--code:#f6f8fa}
            *{box-sizing:border-box}
            body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 "Malgun Gothic","Apple SD Gothic Neo","Segoe UI",sans-serif;word-break:keep-all;overflow-wrap:break-word}
            main{max-width:1040px;margin:0 auto;padding:24px 16px 48px}
            h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}
            .muted{color:var(--muted)}.mono{font-family:Consolas,"D2Coding",monospace;font-size:13px}
            .card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px 20px}
            .meta{display:grid;grid-template-columns:110px 1fr;gap:4px 12px;margin-top:12px}
            .verdict{border-left:8px solid var(--c);margin-top:16px}.verdict .big{font-size:26px;font-weight:700;color:var(--c)}
            .chip{display:inline-block;background:var(--bg);border-radius:4px;padding:2px 8px;font-size:13px;margin-left:8px;vertical-align:middle}
            .scores{display:grid;grid-template-columns:repeat(auto-fit,minmax(92px,1fr));gap:10px}
            .score .n{font-size:24px;font-weight:700}.score .l{font-size:12px;color:var(--muted);white-space:nowrap}
            .finding{display:grid;grid-template-columns:64px 1fr;gap:12px;padding:14px 0;border-bottom:1px solid var(--border)}
            .finding:last-child{border-bottom:0}
            .badge{display:inline-block;color:#fff;border-radius:4px;padding:1px 8px;font-size:12px;font-weight:600;background:var(--c);text-align:center}
            .title{font-weight:600}.title .mono{color:var(--muted);margin-left:8px;font-weight:400}
            dl.ev{display:grid;grid-template-columns:max-content 1fr;gap:2px 12px;background:var(--code);border-radius:4px;padding:8px 12px;margin:8px 0 0}
            dl.ev dt{color:var(--muted)}dl.ev dd{margin:0;word-break:break-all}
            .action{color:var(--accent);margin-top:6px}
            table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--border);vertical-align:top}
            th{font-weight:600;color:var(--muted);font-size:13px}td.num{text-align:right;font-family:Consolas,monospace}
            .procs{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}
            .sev-critical{--c:var(--critical)}.sev-high{--c:var(--high)}.sev-medium{--c:var(--medium)}.sev-low{--c:var(--low)}.sev-info{--c:var(--info)}
            .v-critical{--c:var(--critical)}.v-high{--c:var(--high)}.v-cleanup{--c:var(--cleanup)}.v-ok{--c:var(--ok)}
            footer{margin-top:32px;font-size:13px;color:var(--muted)}
            .brand{background:var(--brand-surface);border-bottom:3px solid var(--brand);color:#fff}
            .brand div{max-width:1040px;margin:0 auto;padding:12px 16px;display:flex;align-items:center;gap:10px}
            .brand b{font:700 22px "Segoe UI",sans-serif}.brand span{margin-left:auto;font-size:12px;color:#cdd0d1}
            @media print{body{background:#fff}.card{break-inside:avoid} }
            </style></head><body>
            <header class="brand"><div><svg width="24" height="22" viewBox="0 0 28 26" aria-hidden="true"><path fill="#ff742f" d="M9 0h8L8 26H0z"/><path fill="#fff" d="M20 0h8l-9 26h-8z"/></svg><b>pitstop</b><span>PC 진단 및 정비</span></div></header>
            <main>
            """);

        // 1. Header
        sb.Append($"""
            <h1>PC 점검 결과</h1>
            <div class="card"><div class="meta">
            <span class="muted">PC 이름</span><span>{H(m.Name)}</span>
            <span class="muted">운영체제</span><span>{H(m.Os)}</span>
            <span class="muted">CPU</span><span>{H(m.Cpu)}</span>
            <span class="muted">메모리</span><span>{H(m.RamGb)} GB</span>
            <span class="muted">디스크</span><span>{H(m.SystemDisk)}</span>
            <span class="muted">실행 계정</span><span>{H(m.User)}{(m.IsAdmin ? "" : " (관리자 아님)")}</span>
            <span class="muted">실행 일시</span><span>{r.ScannedAt:yyyy-MM-dd HH:mm}</span>
            <span class="muted">샘플링</span><span>{(r.SamplingSec > 0 ? $"{r.SamplingSec}초" : "측정 안 함")}</span>
            <span class="muted">툴 버전</span><span>pitstop {H(r.ToolVersion)}</span>
            </div></div>
            """);

        // 2. Verdict
        var v = r.Verdict;
        sb.Append($"""
            <div class="card verdict v-{VerdictClass(v.Primary)}">
            <div><span class="big">{H(Labels.Of(v.Primary))}</span>{(v.Secondary is { } s ? $"<span class=\"chip\">보조 판정: {H(Labels.Of(s))}</span>" : "")}</div>
            <div>{H(Labels.DescribeVerdict(v.Primary))}</div>
            <div class="muted mono">근거: {(v.Basis.Count > 0 ? H(string.Join(", ", v.Basis)) : "없음")}{(v.SecondaryBasis is { Count: > 0 } sb2 ? $" / 보조 근거: {H(string.Join(", ", sb2))}" : "")}</div>
            </div>
            """);

        // 3. Scores
        sb.Append("<h2>점수 요약</h2><div class=\"card scores\">");
        sb.Append($"<div class=\"score\"><div class=\"l\">하드웨어 소계</div><div class=\"n\">{r.Scores.Hardware}</div></div>");
        sb.Append($"<div class=\"score\"><div class=\"l\">소프트웨어 소계</div><div class=\"n\">{r.Scores.Software}</div></div>");
        foreach (var c in Labels.CategoryOrder)
            sb.Append($"<div class=\"score\"><div class=\"l\">{H(Labels.CategoryShort(c))}</div><div class=\"n\">{r.Scores.ByCategory.GetValueOrDefault(c)}</div></div>");
        sb.Append("</div>");

        // 4. Findings
        sb.Append($"<h2>발견 항목 ({r.Findings.Count})</h2><div class=\"card\">");
        if (r.Findings.Count == 0) sb.Append("<p class=\"muted\">발견된 항목이 없습니다.</p>");
        foreach (var f in r.Findings)
        {
            var rem = RemediationCatalog.Find(f.RemediationId);
            sb.Append($"""
                <div class="finding sev-{SevClass(f.Severity)}"><div><span class="badge">{H(Labels.Of(f.Severity))}</span></div><div>
                <div class="title">{H(f.Title)}<span class="mono">{H(f.Id)}</span> <span class="muted">{H(Labels.Category(f.Category))} · {f.Score}점</span></div>
                <div>{H(f.Detail)}</div>
                """);
            if (f.Evidence.Count > 0)
            {
                sb.Append("<dl class=\"ev mono\">");
                foreach (var (k, val) in f.Evidence) sb.Append($"<dt>{H(k)}</dt><dd>{H(val)}</dd>");
                sb.Append("</dl>");
            }
            if (rem is not null)
                sb.Append($"<div class=\"action\">권장 조치: {H(rem.Name)}{(rem.Advice is null ? "" : $" - {H(rem.Advice)}")}</div>");
            sb.Append("</div></div>");
        }
        sb.Append("</div>");

        // 5. Top processes
        sb.Append("<h2>상위 프로세스</h2>");
        if (r.TopProcesses is { } tp)
        {
            sb.Append("<div class=\"card procs\">");
            foreach (var (title, unit, fmt, items) in new[] { ("CPU", "%", "0.0", tp.Cpu), ("메모리", "MB", "0", tp.Memory), ("디스크 I/O", "MB/s", "0.0", tp.Disk) })
            {
                sb.Append($"<div><table><tr><th>{H(title)}</th><th>PID</th><th style=\"text-align:right\">{H(unit)}</th></tr>");
                foreach (var p in items) sb.Append($"<tr><td>{H(p.Name)}</td><td class=\"mono\">{p.Pid}</td><td class=\"num\">{p.Value.ToString(fmt)}</td></tr>");
                sb.Append("</table></div>");
            }
            sb.Append("</div>");
        }
        else sb.Append("<div class=\"card muted\">리소스 샘플링 결과가 없습니다.</div>");

        // 6. Remediation candidates
        sb.Append("<h2>조치 후보</h2><div class=\"card\">");
        var groups = r.Findings.Select(f => (f, info: RemediationCatalog.Find(f.RemediationId))).Where(x => x.info is not null)
            .GroupBy(x => x.info!.Risk).OrderBy(g => g.Key).ToList();
        if (groups.Count == 0) sb.Append("<p class=\"muted\">조치 후보가 없습니다.</p>");
        foreach (var g in groups)
        {
            sb.Append($"<h3 style=\"font-size:15px;margin:12px 0 6px\">{H(Labels.Of(g.Key))}</h3><table><tr><th>조치</th><th>대상</th><th>되돌리기</th></tr>");
            foreach (var (f, info) in g)
                sb.Append($"<tr><td><span class=\"mono\">{H(info!.Id)}</span> {H(info.Name)}</td><td>{H(f.Title)} <span class=\"mono muted\">{H(f.Id)}</span></td>" +
                          $"<td>{(info.Risk == RiskLevel.AdviceOnly ? "" : info.Reversible ? "가능" : "불가")}</td></tr>");
            sb.Append("</table>");
        }
        sb.Append("</div>");

        // 7. Collector errors
        sb.Append($"<h2>수집 오류 ({r.CollectorErrors.Count})</h2><div class=\"card\">");
        if (r.CollectorErrors.Count == 0) sb.Append("<p class=\"muted\">수집 오류가 없습니다.</p>");
        else
        {
            sb.Append("<table><tr><th>항목</th><th>상태</th><th>내용</th></tr>");
            foreach (var e in r.CollectorErrors)
                sb.Append($"<tr><td class=\"mono\">{H(e.CollectorId)}</td><td>{H(Labels.Of(e.Status))}</td><td>{H(e.Message)}</td></tr>");
            sb.Append("</table>");
        }
        sb.Append("</div>");

        sb.Append("""
            <footer>툴의 판정은 참고용입니다. "포맷 권장"이 나와도 백업과 업무 프로그램 재설치 가능 여부를 확인한 뒤 진행하세요.
            이 리포트에는 사용자 이름이 들어간 경로가 그대로 있으니 외부에 공유할 때 주의하세요.</footer>
            </main></body></html>
            """);
        return sb.ToString();
    }
}
