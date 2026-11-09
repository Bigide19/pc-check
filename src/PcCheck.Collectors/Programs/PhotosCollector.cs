using System.Text.Json;
using System.Text.RegularExpressions;
using PcCheck.Collectors.Infra;
using PcCheck.Core;

namespace PcCheck.Collectors.Programs;

public sealed record AppCrash(DateTimeOffset? Time, string App, string Module, string ExceptionCode);

public sealed record PhotosStatus
{
    public bool Installed { get; init; }
    public bool InstalledForAnyUser { get; init; }
    public bool RunningAsSystem { get; init; }
    public string Version { get; init; } = "";
    public string Status { get; init; } = "";
    public IReadOnlyList<AppCrash> Crashes { get; init; } = [];
    public int ActivationFailures { get; init; }
}

public sealed partial class PhotosCollector(IPowerShell ps) : ICollector
{
    public string Id => "APP-PHOTOS";

    // Event 1000 properties are positional (0 app, 3 faulting module, 6 exception code), so this works on any display language.
    private const string Script = """
        $me = [Security.Principal.WindowsIdentity]::GetCurrent()
        $pkg = Get-AppxPackage -Name Microsoft.Windows.Photos -ErrorAction SilentlyContinue | Select-Object -First 1
        $any = $null
        try { $any = Get-AppxPackage -AllUsers -Name Microsoft.Windows.Photos -ErrorAction Stop | Select-Object -First 1 } catch { }
        $since = (Get-Date).AddDays(-7)
        $crashes = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1000; StartTime = $since } -ErrorAction SilentlyContinue |
          Where-Object { $_.Properties.Count -gt 6 -and [string]$_.Properties[0].Value -match 'Photos' } |
          ForEach-Object { [pscustomobject]@{ Time = $_.TimeCreated.ToString('o'); App = [string]$_.Properties[0].Value; Module = [string]$_.Properties[3].Value; Code = [string]$_.Properties[6].Value } })
        $activation = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TWinUI/Operational'; Id = 5961; StartTime = $since } -ErrorAction SilentlyContinue |
          Where-Object { $_.Message -match 'Photos' }).Count
        [pscustomobject]@{
          Installed = [bool]$pkg; InstalledForAnyUser = [bool]$any; RunningAsSystem = $me.IsSystem
          Version = [string]$(if ($pkg) { $pkg.Version } else { $any.Version }); Status = [string]$(if ($pkg) { $pkg.Status } else { $any.Status })
          Crashes = $crashes; ActivationFailures = $activation
        }
        """;

    public async Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        var r = (await ps.RunJsonAsync(Script, ct)).EnumerateArray().First();
        var crashes = r.TryGetProperty("Crashes", out var c) && c.ValueKind == JsonValueKind.Array
            ? c.EnumerateArray().Select(x => new AppCrash(x.Date("Time"), x.Str("App") ?? "", x.Str("Module") ?? "", x.Str("Code") ?? "")).ToList()
            : [];
        var status = new PhotosStatus
        {
            Installed = r.Bool("Installed") == true,
            InstalledForAnyUser = r.Bool("InstalledForAnyUser") == true,
            RunningAsSystem = r.Bool("RunningAsSystem") == true,
            Version = r.Str("Version") ?? "",
            Status = r.Str("Status") ?? "",
            Crashes = crashes,
            ActivationFailures = (int)(r.Num("ActivationFailures") ?? 0),
        };
        return CollectorResult.Ok(Id, Evaluate(status));
    }

    [GeneratedRegex(@"^(d3d\d+|d3d\d+core|dxgi|d2d1|dcomp|dxcore|igd\w+|ig\w*umd\w*|nvwgf\w+|nvd3dum\w*|nvoglv\w*|atiu\w+|amdx\w+|aticfx\w+|amdihk\w+)\.dll$", RegexOptions.IgnoreCase)]
    private static partial Regex GraphicsModule();

    [GeneratedRegex(@"ahnlab|^v3|alyac|ayagent|avast|aswhook|avg|avira|kaspersky|^kl|norton|symantec|mcafee|bitdefender|^eset|ebehmoni|malwarebytes|mbae|360|hauri|vrbase", RegexOptions.IgnoreCase)]
    private static partial Regex AntivirusModule();

    public static string? CauseOf(string module) =>
        GraphicsModule().IsMatch(module) ? Strings.Photos_CauseGraphics
        : AntivirusModule().IsMatch(module) ? Strings.Photos_CauseAntivirus
        : null;

    public static IReadOnlyList<Finding> Evaluate(PhotosStatus s)
    {
        var findings = new List<Finding>();
        (string, object?)[] baseEv = [("version", s.Version), ("status", s.Status)];

        // Headless scans run as SYSTEM, which has no Store apps of its own; only "nobody has it" counts there.
        var missing = s.RunningAsSystem ? !s.InstalledForAnyUser : !s.Installed;
        if (missing)
            findings.Add(F.Make("APP-PHOTOS", Categories.Program, Severity.Medium, Strings.Photos_MissingTitle,
                Strings.Photos_MissingDetail, "ADV-PHOTOS", baseEv));
        else if (s.Status.Length > 0 && !s.Status.Equals("Ok", StringComparison.OrdinalIgnoreCase))
            findings.Add(F.Make("APP-PHOTOS", Categories.Program, Severity.High, string.Format(Strings.Photos_BadTitle, s.Status),
                Strings.Photos_BadDetail, "ADV-PHOTOS", baseEv));

        // Crashes are reported by APP-CRASHES, which can name the program that caused them.
        if (s.Crashes.Count == 0 && s.ActivationFailures > 0)
            findings.Add(F.Make("APP-PHOTOS", Categories.Program, Severity.Medium, string.Format(Strings.Photos_FailTitle, s.ActivationFailures),
                Strings.Photos_FailDetail,
                "ADV-PHOTOS", [.. baseEv, ("activationFailures7d", s.ActivationFailures)]));
        return findings;
    }
}
