using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using PcCheck.Collectors.Infra;
using PcCheck.Core;
using PcCheck.Core.Config;

namespace PcCheck.Collectors.Programs;

public sealed record CrashEvent(DateTimeOffset? Time, string App, string AppPath, string Module, string ModulePath, string ExceptionCode);

// What we know about the file that crashed the app; filled from version info on the PC, or by tests.
public sealed record ModuleOwner(string? Company, string? Product);

public enum CrashCause { Graphics, Antivirus, KoreanSecurity, ThirdParty }

/// <summary>
/// Finds third-party modules that crash other programs: injected DLLs (keyboard security, overlays, antivirus hooks).
/// The 2026-11-06 field case: TouchEn nxKey's TENXWGuard64 DLL crashed the Photos app 21 times.
/// </summary>
public sealed partial class CrashCollector(IPowerShell ps, UninstallSource uninstall) : ICollector
{
    public string Id => "APP-CRASHES";

    // Event 1000 properties are positional, so this reads the same on any display language:
    // 0 app, 3 module, 6 exception code, 10 app path, 11 module path.
    private const string Script = """
        Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1000; StartTime = (Get-Date).AddDays(-7) } -ErrorAction SilentlyContinue |
          Where-Object { $_.Properties.Count -gt 11 } |
          ForEach-Object { [pscustomobject]@{ Time = $_.TimeCreated.ToString('o'); App = [string]$_.Properties[0].Value; AppPath = [string]$_.Properties[10].Value
            Module = [string]$_.Properties[3].Value; ModulePath = [string]$_.Properties[11].Value; Code = [string]$_.Properties[6].Value } }
        """;

    public async Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        var rows = await ps.RunJsonAsync(Script, ct);
        var events = rows.EnumerateArray().Select(r => new CrashEvent(r.Date("Time"), r.Str("App") ?? "", r.Str("AppPath") ?? "",
            r.Str("Module") ?? "", r.Str("ModulePath") ?? "", r.Str("Code") ?? "")).ToList();
        var programs = await uninstall.Programs.GetAsync(ct);
        return CollectorResult.Ok(Id, Evaluate(events, ReadOwner, programs, ctx.Config));
    }

    private static ModuleOwner ReadOwner(string path)
    {
        try
        {
            if (!File.Exists(path)) return new ModuleOwner(null, null);
            var v = FileVersionInfo.GetVersionInfo(path);
            return new ModuleOwner(v.CompanyName?.Trim(), v.ProductName?.Trim());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return new ModuleOwner(null, null); }
    }

    [GeneratedRegex(@"^(d3d\d+|d3d\d+core|dxgi|d2d1|dcomp|dxcore|igd\w+|ig\w*umd\w*|nvwgf\w+|nvd3dum\w*|nvoglv\w*|nvldumd\w*|atiu\w+|amdx\w+|aticfx\w+|amdihk\w+)\.dll$", RegexOptions.IgnoreCase)]
    private static partial Regex GraphicsModule();

    [GeneratedRegex(@"intel|nvidia|advanced micro devices|\bamd\b|qualcomm", RegexOptions.IgnoreCase)]
    private static partial Regex GraphicsVendor();

    [GeneratedRegex(@"ahnlab|estsoft|avast|avg technologies|avira|kaspersky|norton|symantec|gen digital|mcafee|bitdefender|eset|malwarebytes|hauri|360", RegexOptions.IgnoreCase)]
    private static partial Regex AntivirusVendor();

    private static bool IsMicrosoft(ModuleOwner o, string path) =>
        o.Company?.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) == true
        || (o.Company is null && path.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase));

    // Built-in Windows apps: a third-party module crashing these is never the app's own fault.
    private static bool IsWindowsApp(CrashEvent e) =>
        e.AppPath.Contains(@"\WindowsApps\Microsoft.", StringComparison.OrdinalIgnoreCase)
        || e.AppPath.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase);

    public static CrashCause Classify(string module, ModuleOwner owner, KrModule? kr) =>
        kr is not null ? CrashCause.KoreanSecurity
        : GraphicsModule().IsMatch(module) || GraphicsVendor().IsMatch(owner.Company ?? "") ? CrashCause.Graphics
        : AntivirusVendor().IsMatch(owner.Company ?? "") ? CrashCause.Antivirus
        : CrashCause.ThirdParty;

    public static IReadOnlyList<Finding> Evaluate(IReadOnlyList<CrashEvent> events, Func<string, ModuleOwner> ownerOf,
        IReadOnlyList<InstalledProgram> programs, PcCheckConfig config)
    {
        var level = config.Rules.Thresholds.AppCrashes7d;
        var findings = new List<Finding>();
        var groups = events
            .Where(e => e.Module.Length > 0)
            .GroupBy(e => e.ModulePath.Length > 0 ? e.ModulePath : e.Module, StringComparer.OrdinalIgnoreCase);

        foreach (var g in groups)
        {
            var path = g.First().ModulePath;
            var module = g.First().Module;
            // A program crashing in its own files is its own bug, not something injected into it.
            var injected = g.Where(e => path.Length == 0 || e.AppPath.Length == 0
                || !path.StartsWith(DirOf(e.AppPath), StringComparison.OrdinalIgnoreCase)).ToList();
            if (injected.Count == 0) continue;

            var owner = path.Length > 0 ? ownerOf(path) : new ModuleOwner(null, null);
            var kr = config.KrModules.MatchDll(module) ?? config.KrModules.MatchPath(path);
            if (kr is null && IsMicrosoft(owner, path)) continue;
            if (config.Protect.IsProtectedPath(path)) continue;

            var count = injected.Count;
            var windowsVictim = injected.Any(IsWindowsApp);
            Severity? sev = level.High is { } h && count >= h || windowsVictim && level.Medium is { } m0 && count >= m0 ? Severity.High
                : level.Medium is { } m && count >= m ? Severity.Medium : null;
            if (sev is null) continue;

            var program = FindProgram(programs, path, owner, kr, config.KrModules);
            var cause = Classify(module, owner, kr);
            var ownerName = kr?.Name ?? program?.DisplayName ?? owner.Product ?? owner.Company ?? module;
            var apps = injected.Select(e => e.App).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var appText = string.Join(", ", apps.Take(3)) + (apps.Count > 3 ? string.Format(Strings.Crash_More, apps.Count - 3) : "");

            var (detail, remediation) = cause switch
            {
                CrashCause.Graphics => (string.Format(Strings.Crash_Graphics, module, appText), "ADV-GPU-DRIVER"),
                CrashCause.KoreanSecurity => (string.Format(Strings.Crash_KoreanSecurity, ownerName, appText), program?.UninstallString is null ? "ADV-CRASH-MODULE" : "RM-UNINSTALL"),
                CrashCause.Antivirus => (string.Format(Strings.Crash_Antivirus, ownerName, appText), program?.UninstallString is null ? "ADV-CRASH-MODULE" : "RM-UNINSTALL"),
                _ => (string.Format(Strings.Crash_Other, ownerName, module, appText), program?.UninstallString is null ? "ADV-CRASH-MODULE" : "RM-UNINSTALL"),
            };

            findings.Add(F.Make("APP-CRASHES", Categories.Program, sev.Value, string.Format(Strings.Crash_Title, ownerName, count), detail, remediation,
                ("module", module), ("modulePath", path), ("company", owner.Company), ("cause", cause.ToString()),
                ("apps", string.Join(", ", apps)), ("crashes7d", count),
                ("lastException", injected.OrderByDescending(e => e.Time).First().ExceptionCode),
                ("last", injected.Max(e => e.Time)?.ToString("yyyy-MM-dd HH:mm")),
                // RM-UNINSTALL plans from these three keys.
                ("displayName", program?.DisplayName), ("uninstallString", program?.UninstallString), ("registryKey", program?.RegistryKey),
                ("processNames", kr is { ProcessNames.Count: > 0 } ? string.Join(",", kr.ProcessNames) : null)));
        }
        return findings;
    }

    // Windows paths on any host: Path.GetDirectoryName ignores '\' outside Windows, which broke this in tests.
    private static string DirOf(string path)
    {
        var i = path.LastIndexOf('\\');
        return i > 0 ? path[..(i + 1)] : "\0";
    }

    // Owner program: installed under the module's folder, else a known security module, else same publisher.
    public static InstalledProgram? FindProgram(IReadOnlyList<InstalledProgram> programs, string path, ModuleOwner owner, KrModule? kr, KrModulesConfig krConfig)
    {
        if (path.Length > 0)
        {
            var byLocation = programs
                .Where(p => p.InstallLocation is { Length: > 3 } loc && path.StartsWith(loc.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(p => p.InstallLocation!.Length).FirstOrDefault();
            if (byLocation is not null) return byLocation;
        }
        if (kr is not null)
        {
            var byModule = programs.FirstOrDefault(p => kr.MatchesName(p.DisplayName) || kr.MatchesPublisher(p.Publisher));
            if (byModule is not null) return byModule;
        }
        if (owner.Company is { Length: > 2 } company)
            return programs.FirstOrDefault(p => p.Publisher is not null && p.Publisher.Contains(company, StringComparison.OrdinalIgnoreCase)
                && (owner.Product is null || p.DisplayName.Contains(owner.Product, StringComparison.OrdinalIgnoreCase)));
        return null;
    }
}
