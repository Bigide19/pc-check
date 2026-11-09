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
            findings.Add(F.Make("SEC-AV", Categories.Security, Severity.High, Strings.Av_RealtimeOffTitle,
                Strings.Av_RealtimeOffDetail, "RM-DEFENDER", ev));

        if (s.DefenderIsPrimary && s.RealTimeProtection == true && s.SignatureAgeDays is { } age
            && F.Above(age, rules.Thresholds.DefenderSignatureAgeDays) is { } sev)
            findings.Add(F.Make("SEC-AV", Categories.Security, sev, string.Format(Strings.Av_DefsAgeTitle, age),
                Strings.Av_DefsAgeDetail, "RM-DEFENDER", ev));

        foreach (var p in active.Where(p => !p.IsDefender && !p.UpToDate))
            findings.Add(F.Make("SEC-AV", Categories.Security, Severity.Medium, string.Format(Strings.Av_OutdatedTitle, p.Name),
                Strings.Av_OutdatedDetail, "ADV-AV-UPDATE", ev));

        if (active.Count >= 2)
            findings.Add(F.Make("SEC-AV", Categories.Security, Severity.Medium, string.Format(Strings.Av_DupTitle, active.Count),
                string.Format(Strings.Av_DupDetail, string.Join(", ", active.Select(a => a.Name))), "ADV-AV-DUP", ev));
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

public sealed record ThreatReport(IReadOnlyList<ThreatDetection> Detections, DefenderScanType ScanType, string? ScanError)
{
    public string? RunningMode { get; init; }
    public IReadOnlyList<string> OtherAntivirus { get; init; } = [];
}

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
        if (-not (Get-MpComputerStatus -ErrorAction SilentlyContinue)) { throw '{{Strings.Threat_NoDefender.Replace("'", "''")}}' }
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
        # Why a scan can be refused: another antivirus is primary and Defender sits in passive mode.
        $mode = [string](Get-MpComputerStatus).AMRunningMode
        $others = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
          Where-Object { $_.displayName -notmatch 'Defender' -and ((([int]$_.productState) -shr 12) -band 0xF) -eq 1 } | ForEach-Object { [string]$_.displayName })
        [pscustomobject]@{ ScanError = $scanError; Detections = $det; RunningMode = $mode; OtherAv = $others }
        """;

    public async Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        var scan = ctx.Options.DefenderScan;
        if (scan != DefenderScanType.None)
            ctx.Progress?.Report(new CollectorProgress(Id, scan == DefenderScanType.Full ? Strings.Threat_FullScanning : Strings.Threat_QuickScanning));
        var r = (await ps.RunJsonAsync(Script(scan), ct)).EnumerateArray().First();
        var dets = r.TryGetProperty("Detections", out var d) && d.ValueKind == JsonValueKind.Array
            ? d.EnumerateArray().Select(x => new ThreatDetection(x.Str("ThreatID") ?? "", x.Str("Name") ?? "", (int)(x.Num("StatusID") ?? 0),
                x.Bool("ActionSuccess"), x.Bool("IsActive"), x.Date("Detected"), x.Str("Resources") ?? "")).ToList()
            : [];
        var now = (clock ?? TimeProvider.System).GetLocalNow();
        var others = r.TryGetProperty("OtherAv", out var o) && o.ValueKind == JsonValueKind.Array
            ? o.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList()
            : r.Str("OtherAv") is { Length: > 0 } one ? [one] : [];
        var report = new ThreatReport(dets, scan, r.Str("ScanError")) { RunningMode = r.Str("RunningMode"), OtherAntivirus = others };
        return CollectorResult.Ok(Id, Evaluate(report, now));
    }

    public static IReadOnlyList<Finding> Evaluate(ThreatReport report, DateTimeOffset now)
    {
        var findings = new List<Finding>();
        var scanText = report.ScanType switch
        {
            DefenderScanType.Quick => Strings.Threat_AfterQuick,
            DefenderScanType.Full => Strings.Threat_AfterFull,
            _ => Strings.Threat_HistoryOnly,
        };

        foreach (var t in report.Detections.Where(t => t.Unresolved).DistinctBy(t => t.ThreatId))
            findings.Add(F.Make("SEC-THREAT", Categories.Security, Severity.Critical, string.Format(Strings.Threat_UnresolvedTitle, Name(t)),
                string.Format(Strings.Threat_UnresolvedDetail, scanText), "RM-DEFENDER",
                ("threatId", t.ThreatId), ("name", t.Name), ("statusId", t.StatusId), ("detected", t.Detected?.ToString("yyyy-MM-dd HH:mm")),
                ("resources", t.Resources), ("scan", report.ScanType), ("scanError", report.ScanError)));

        var recent = report.Detections.Where(t => !t.Unresolved && t.Detected is { } dt && dt >= now.AddDays(-30)).DistinctBy(t => t.ThreatId).ToList();
        if (recent.Count > 0)
            findings.Add(F.Make("SEC-THREAT", Categories.Security, Severity.Medium, string.Format(Strings.Threat_RecentTitle, recent.Count),
                Strings.Threat_RecentDetail, null,
                recent.Select((t, i) => ($"{i + 1:00}", (object?)$"{Name(t)} ({t.Detected:yyyy-MM-dd}) {t.Resources}")).ToArray()));

        if (report.ScanError is not null)
        {
            var passive = report.RunningMode?.Contains("Passive", StringComparison.OrdinalIgnoreCase) == true;
            var other = string.Join(", ", report.OtherAntivirus);
            var detail = report.OtherAntivirus.Count > 0
                ? string.Format(Strings.Threat_OtherAv, other)
                : passive
                    ? Strings.Threat_Passive
                    : string.Format(Strings.Threat_ScanFailed, report.ScanError);
            findings.Add(F.Make("SEC-THREAT", Categories.Security, Severity.Info, Strings.Threat_ScanFailedTitle, detail, null,
                ("scan", report.ScanType), ("defenderMode", report.RunningMode), ("otherAntivirus", other.Length > 0 ? other : null),
                ("error", report.ScanError)));
        }
        return findings;
    }

    private static string Name(ThreatDetection t) => string.IsNullOrEmpty(t.Name) ? $"ID {t.ThreatId}" : t.Name;
}
