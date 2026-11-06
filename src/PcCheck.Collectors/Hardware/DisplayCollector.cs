using System.Text.Json;
using PcCheck.Collectors.Infra;
using PcCheck.Core;
using PcCheck.Core.Config;

namespace PcCheck.Collectors.Hardware;

public sealed record VideoAdapter(string Name, string DriverVersion, string DriverDate, int ErrorCode);

public sealed record DisplayStatus(IReadOnlyList<VideoAdapter> Adapters, int DriverResets7d);

public sealed class DisplayCollector(IPowerShell ps) : ICollector
{
    public string Id => "SYS-DISPLAY";

    // Event 4101 from provider "Display": the driver stopped responding and Windows restarted it (a visible flicker or black flash).
    private const string Script = """
        $adapters = @(Get-CimInstance Win32_VideoController | ForEach-Object {
          [pscustomobject]@{ Name = [string]$_.Name; DriverVersion = [string]$_.DriverVersion
            DriverDate = $(if ($_.DriverDate) { $_.DriverDate.ToString('yyyy-MM-dd') } else { '' }); ErrorCode = [int]$_.ConfigManagerErrorCode } })
        $resets = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 4101; StartTime = (Get-Date).AddDays(-7) } -ErrorAction SilentlyContinue |
          Where-Object ProviderName -eq 'Display').Count
        [pscustomobject]@{ Adapters = $adapters; Resets = $resets }
        """;

    public async Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        var r = (await ps.RunJsonAsync(Script, ct)).EnumerateArray().First();
        var adapters = r.TryGetProperty("Adapters", out var a) && a.ValueKind == JsonValueKind.Array
            ? a.EnumerateArray().Select(x => new VideoAdapter(x.Str("Name") ?? "", x.Str("DriverVersion") ?? "", x.Str("DriverDate") ?? "", (int)(x.Num("ErrorCode") ?? 0))).ToList()
            : [];
        return CollectorResult.Ok(Id, Evaluate(new DisplayStatus(adapters, (int)(r.Num("Resets") ?? 0)), ctx.Config.Rules));
    }

    // Windows names the fallback driver per display language.
    public static bool IsBasicAdapter(string name) =>
        name.Contains("Basic Display", StringComparison.OrdinalIgnoreCase) || name.Contains("기본 디스플레이", StringComparison.Ordinal);

    public static IReadOnlyList<Finding> Evaluate(DisplayStatus s, RulesConfig rules)
    {
        var findings = new List<Finding>();
        var ev = s.Adapters.Select((x, i) => ($"adapter{i + 1}", (object?)$"{x.Name} (드라이버 {x.DriverVersion}, {x.DriverDate}{(x.ErrorCode != 0 ? $", 오류 코드 {x.ErrorCode}" : "")})")).ToList();
        ev.Add(("driverResets7d", s.DriverResets7d));

        if (s.Adapters.Any(x => IsBasicAdapter(x.Name)))
            findings.Add(F.Make("SYS-DISPLAY", Categories.Hardware, Severity.High, "그래픽 드라이버가 설치되어 있지 않음",
                "Windows 기본 디스플레이 어댑터로 동작하고 있습니다. 화면 깜빡임이나 앱 오류의 원인이 될 수 있습니다.", "ADV-GPU-DRIVER", ev.ToArray()));
        else if (s.Adapters.FirstOrDefault(x => x.ErrorCode != 0) is { } bad)
            findings.Add(F.Make("SYS-DISPLAY", Categories.Hardware, Severity.High, $"그래픽 장치 오류 (코드 {bad.ErrorCode})",
                $"{bad.Name}이 장치 관리자에서 오류 상태입니다.", "ADV-GPU-DRIVER", ev.ToArray()));

        if (rules.Thresholds.DisplayDriverResets7d.Medium is { } limit && s.DriverResets7d >= limit)
            findings.Add(F.Make("SYS-DISPLAY", Categories.Hardware, Severity.Medium, $"최근 7일 그래픽 드라이버 재시작 {s.DriverResets7d}회",
                "그래픽 드라이버가 응답을 멈췄다가 다시 시작된 기록입니다. 화면이 순간 깜빡이거나 까맣게 됩니다.", "ADV-GPU-DRIVER", ev.ToArray()));
        return findings;
    }
}
