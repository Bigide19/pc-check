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
        var ev = s.Adapters.Select((x, i) => ($"adapter{i + 1}", (object?)string.Format(Strings.Display_Adapter, x.Name, x.DriverVersion, x.DriverDate, x.ErrorCode != 0 ? string.Format(Strings.Display_ErrorCode, x.ErrorCode) : ""))).ToList();
        ev.Add(("driverResets7d", s.DriverResets7d));

        if (s.Adapters.Any(x => IsBasicAdapter(x.Name)))
            findings.Add(F.Make("SYS-DISPLAY", Categories.Hardware, Severity.High, Strings.Display_NoDriverTitle,
                Strings.Display_NoDriverDetail, "ADV-GPU-DRIVER", ev.ToArray()));
        else if (s.Adapters.FirstOrDefault(x => x.ErrorCode != 0) is { } bad)
            findings.Add(F.Make("SYS-DISPLAY", Categories.Hardware, Severity.High, string.Format(Strings.Display_ErrorTitle, bad.ErrorCode),
                string.Format(Strings.Display_ErrorDetail, bad.Name), "ADV-GPU-DRIVER", ev.ToArray()));

        if (rules.Thresholds.DisplayDriverResets7d.Medium is { } limit && s.DriverResets7d >= limit)
            findings.Add(F.Make("SYS-DISPLAY", Categories.Hardware, Severity.Medium, string.Format(Strings.Display_ResetsTitle, s.DriverResets7d),
                Strings.Display_ResetsDetail, "ADV-GPU-DRIVER", ev.ToArray()));
        return findings;
    }
}
