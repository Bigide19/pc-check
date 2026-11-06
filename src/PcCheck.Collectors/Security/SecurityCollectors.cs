using System.Text.Json;
using PcCheck.Collectors.Infra;
using PcCheck.Core;
using PcCheck.Core.Config;

namespace PcCheck.Collectors.Security;

public sealed record AvProduct(string Name, int State)
{
    // productState bytes: 0x00RRSS - RR 0x10/0x11 = on, SS 0x00 = definitions up to date.
    public bool Enabled => ((State >> 12) & 0xF) == 1;
    public bool UpToDate => (State & 0xF0) == 0;
    public bool IsDefender => Name.Contains("Defender", StringComparison.OrdinalIgnoreCase);
}

public sealed record AvStatus
{
    public bool DefenderAvailable { get; init; }
    public bool? RealTimeProtection { get; init; }
    public bool? AntivirusEnabled { get; init; }
    public string? RunningMode { get; init; }
    public double? SignatureAgeDays { get; init; }
    public DateTimeOffset? SignatureUpdated { get; init; }
    public IReadOnlyList<AvProduct> Products { get; init; } = [];

    public bool DefenderIsPrimary => DefenderAvailable && (RunningMode is null || RunningMode.Equals("Normal", StringComparison.OrdinalIgnoreCase));
}

public sealed class AntivirusCollector(IPowerShell ps) : ICollector
{
    public string Id => "SEC-AV";

    private const string Script = """
        $mp = $null
        try { $mp = Get-MpComputerStatus } catch { }
        $products = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
          ForEach-Object { [pscustomobject]@{ Name = [string]$_.displayName; State = [int]$_.productState } })
        [pscustomobject]@{
          DefenderAvailable = [bool]$mp
          RealTimeProtection = $mp.RealTimeProtectionEnabled
          AntivirusEnabled = $mp.AntivirusEnabled
          RunningMode = [string]$mp.AMRunningMode
          SignatureAgeDays = $mp.AntivirusSignatureAge
          SignatureUpdated = $(if ($mp -and $mp.AntivirusSignatureLastUpdated) { $mp.AntivirusSignatureLastUpdated.ToString('o') })
          Products = $products
        }
        """;

    public async Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        var r = (await ps.RunJsonAsync(Script, ct)).EnumerateArray().First();
        var products = r.TryGetProperty("Products", out var p) && p.ValueKind == JsonValueKind.Array
            ? p.EnumerateArray().Select(x => new AvProduct(x.Str("Name") ?? "", (int)(x.Num("State") ?? 0))).ToList()
            : [];
        var status = new AvStatus
        {
            DefenderAvailable = r.Bool("DefenderAvailable") == true,
            RealTimeProtection = r.Bool("RealTimeProtection"),
            AntivirusEnabled = r.Bool("AntivirusEnabled"),
            RunningMode = string.IsNullOrEmpty(r.Str("RunningMode")) ? null : r.Str("RunningMode"),
            SignatureAgeDays = r.Num("SignatureAgeDays"),
            SignatureUpdated = r.Date("SignatureUpdated"),
            Products = products,
        };
        return CollectorResult.Ok(Id, Evaluate(status, ctx.Config.Rules));
    }

    public static IReadOnlyList<Finding> Evaluate(AvStatus s, RulesConfig rules)
    {
        var findings = new List<Finding>();
        var active = s.Products.Where(p => p.Enabled).ToList();
        (string, object?)[] ev =
        [
            ("defenderMode", s.RunningMode), ("realTimeProtection", s.RealTimeProtection),
            ("signatureAgeDays", s.SignatureAgeDays), ("signatureUpdated", s.SignatureUpdated?.ToString("yyyy-MM-dd")),
            ("products", string.Join(", ", s.Products.Select(p => $"{p.Name}({(p.Enabled ? "on" : "off")}, 0x{p.State:X6})"))),
        ];

        var defenderOff = s.DefenderIsPrimary && s.RealTimeProtection == false;
        var nothingOn = active.Count == 0 && !(s.DefenderIsPrimary && s.RealTimeProtection == true);
        if (defenderOff || nothingOn)
            findings.Add(F.Make("SEC-AV", Categories.Security, Severity.High, "실시간 보호 꺼짐",
                "백신의 실시간 보호가 동작하지 않습니다.", "RM-DEFENDER", ev));

        if (s.DefenderIsPrimary && s.RealTimeProtection == true && s.SignatureAgeDays is { } age
            && F.Above(age, rules.Thresholds.DefenderSignatureAgeDays) is { } sev)
            findings.Add(F.Make("SEC-AV", Categories.Security, sev, $"백신 정의 {age:0}일 지남",
                "Defender 정의 업데이트가 오래되었습니다.", "RM-DEFENDER", ev));

        foreach (var p in active.Where(p => !p.IsDefender && !p.UpToDate))
            findings.Add(F.Make("SEC-AV", Categories.Security, Severity.Medium, $"{p.Name} 정의 업데이트 필요",
                "백신이 최신 상태가 아니라고 보고합니다.", "ADV-AV-UPDATE", ev));

        if (active.Count >= 2)
            findings.Add(F.Make("SEC-AV", Categories.Security, Severity.Medium, $"백신 {active.Count}개 동시 활성",
                $"{string.Join(", ", active.Select(a => a.Name))}가 함께 켜져 있어 서로 검사하며 느려질 수 있습니다.", "ADV-AV-DUP", ev));
        return findings;
    }
}

public sealed record ThreatDetection(string ThreatId, string Name, int StatusId, bool? ActionSuccess, bool? IsActive,
    DateTimeOffset? Detected, string Resources)
{
    // Detected, quarantine/remove/allow failed, abandoned, block failed.
    private static readonly int[] UnresolvedStatus = [1, 102, 103, 104, 105, 107];
    public bool Unresolved => UnresolvedStatus.Contains(StatusId) || ActionSuccess == false || IsActive == true;
}

public sealed record ThreatReport(IReadOnlyList<ThreatDetection> Detections, DefenderScanType ScanType, string? ScanError);

public sealed class ThreatCollector(IPowerShell ps, TimeProvider? clock = null) : ICollector
{
    public string Id => "SEC-THREAT";

    public TimeSpan GetTimeout(CollectContext ctx) => ctx.Options.DefenderScan switch
    {
        DefenderScanType.Quick => TimeSpan.FromSeconds(ctx.Config.Rules.Collectors.DefenderQuickScanTimeoutSec),
        DefenderScanType.Full => TimeSpan.FromSeconds(ctx.Config.Rules.Collectors.DefenderFullScanTimeoutSec),
        _ => ctx.DefaultTimeout,
    };

    private static string Script(DefenderScanType scan) => $$"""
        if (-not (Get-MpComputerStatus -ErrorAction SilentlyContinue)) { throw 'Windows Defender를 사용할 수 없습니다 (다른 백신이 주 백신일 수 있음).' }
        $scanError = $null
        $scanType = '{{scan}}'
        if ($scanType -ne 'None') { try { Start-MpScan -ScanType "$($scanType)Scan" } catch { $scanError = $_.Exception.Message } }
        $threats = @{}
        Get-MpThreat -ErrorAction SilentlyContinue | ForEach-Object { $threats[[string]$_.ThreatID] = $_ }
        $det = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | ForEach-Object {
          $t = $threats[[string]$_.ThreatID]
          [pscustomobject]@{
            ThreatID = [string]$_.ThreatID; Name = [string]$t.ThreatName; IsActive = $t.IsActive
            StatusID = [int]$_.ThreatStatusID; ActionSuccess = $_.ActionSuccess
            Detected = $(if ($_.InitialDetectionTime) { $_.InitialDetectionTime.ToString('o') })
            Resources = [string](@($_.Resources) -join '; ')
          }
        })
        [pscustomobject]@{ ScanError = $scanError; Detections = $det }
        """;

    public async Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        var scan = ctx.Options.DefenderScan;
        if (scan != DefenderScanType.None)
            ctx.Progress?.Report(new CollectorProgress(Id, scan == DefenderScanType.Full ? "Defender 전체 검사 중 (오래 걸림)" : "Defender 빠른 검사 중"));
        var r = (await ps.RunJsonAsync(Script(scan), ct)).EnumerateArray().First();
        var dets = r.TryGetProperty("Detections", out var d) && d.ValueKind == JsonValueKind.Array
            ? d.EnumerateArray().Select(x => new ThreatDetection(x.Str("ThreatID") ?? "", x.Str("Name") ?? "", (int)(x.Num("StatusID") ?? 0),
                x.Bool("ActionSuccess"), x.Bool("IsActive"), x.Date("Detected"), x.Str("Resources") ?? "")).ToList()
            : [];
        var now = (clock ?? TimeProvider.System).GetLocalNow();
        return CollectorResult.Ok(Id, Evaluate(new ThreatReport(dets, scan, r.Str("ScanError")), now));
    }

    public static IReadOnlyList<Finding> Evaluate(ThreatReport report, DateTimeOffset now)
    {
        var findings = new List<Finding>();
        var scanText = report.ScanType switch
        {
            DefenderScanType.Quick => "빠른 검사 후",
            DefenderScanType.Full => "전체 검사 후",
            _ => "검사 없이 이력만 확인",
        };

        foreach (var t in report.Detections.Where(t => t.Unresolved).DistinctBy(t => t.ThreatId))
            findings.Add(F.Make("SEC-THREAT", Categories.Security, Severity.Critical, $"미해결 위협: {Name(t)}",
                $"Defender가 찾았지만 제거하지 못한 위협이 남아 있습니다 ({scanText}).", "RM-DEFENDER",
                ("threatId", t.ThreatId), ("name", t.Name), ("statusId", t.StatusId), ("detected", t.Detected?.ToString("yyyy-MM-dd HH:mm")),
                ("resources", t.Resources), ("scan", report.ScanType), ("scanError", report.ScanError)));

        var recent = report.Detections.Where(t => !t.Unresolved && t.Detected is { } dt && dt >= now.AddDays(-30)).DistinctBy(t => t.ThreatId).ToList();
        if (recent.Count > 0)
            findings.Add(F.Make("SEC-THREAT", Categories.Security, Severity.Medium, $"최근 30일 위협 {recent.Count}건 처리됨",
                "Defender가 최근 위협을 찾아 처리했습니다. 같은 경로로 다시 들어오지 않는지 확인하세요.", null,
                recent.Select((t, i) => ($"{i + 1:00}", (object?)$"{Name(t)} ({t.Detected:yyyy-MM-dd}) {t.Resources}")).ToArray()));

        if (report.ScanError is not null && findings.Count == 0)
            findings.Add(F.Make("SEC-THREAT", Categories.Security, Severity.Info, "Defender 검사를 실행하지 못함",
                report.ScanError, null, ("scan", report.ScanType)));
        return findings;
    }

    private static string Name(ThreatDetection t) => string.IsNullOrEmpty(t.Name) ? $"ID {t.ThreatId}" : t.Name;
}
