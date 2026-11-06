using System.Text.Json;
using Microsoft.Win32;
using PcCheck.Collectors.Infra;
using PcCheck.Core;
using PcCheck.Core.Config;

namespace PcCheck.Collectors.Browser;

public sealed record BrowserPolicy(string Browser, string KeyPath, IReadOnlyDictionary<string, string> Values);

public sealed class BrowserPolicyCollector : ICollector
{
    public string Id => "BR-POLICY";

    private static readonly (string Browser, string Path)[] PolicyKeys =
    [
        ("Chrome", @"SOFTWARE\Policies\Google\Chrome"),
        ("Edge", @"SOFTWARE\Policies\Microsoft\Edge"),
    ];

    private static readonly string[] Watched =
        ["HomepageLocation", "HomepageIsNewTabPage", "NewTabPageLocation", "RestoreOnStartup", "RestoreOnStartupURLs",
         "DefaultSearchProviderEnabled", "DefaultSearchProviderName", "DefaultSearchProviderSearchURL", "ExtensionInstallForcelist",
         "ProxyMode", "ProxyServer", "ProxyPacUrl"];

    public Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        var policies = new List<BrowserPolicy>();
        foreach (var (hive, hiveName) in new[] { (Registry.LocalMachine, "HKLM"), (Registry.CurrentUser, "HKCU") })
            foreach (var (browser, path) in PolicyKeys)
            {
                using var key = hive.OpenSubKey(path);
                if (key is null) continue;
                var values = new Dictionary<string, string>();
                foreach (var name in key.GetValueNames().Where(n => Watched.Contains(n, StringComparer.OrdinalIgnoreCase)))
                    values[name] = Convert.ToString(key.GetValue(name)) ?? "";
                // List policies are subkeys with numbered values.
                foreach (var sub in key.GetSubKeyNames().Where(n => Watched.Contains(n, StringComparer.OrdinalIgnoreCase)))
                {
                    using var sk = key.OpenSubKey(sub);
                    if (sk is null) continue;
                    values[sub] = string.Join(" | ", sk.GetValueNames().Select(n => Convert.ToString(sk.GetValue(n))));
                }
                if (values.Count > 0) policies.Add(new BrowserPolicy(browser, $@"{hiveName}\{path}", values));
            }
        return Task.FromResult(CollectorResult.Ok(Id, Evaluate(policies)));
    }

    // A standalone PC is not domain-managed, so any forced browser policy was not set by its user.
    public static IReadOnlyList<Finding> Evaluate(IReadOnlyList<BrowserPolicy> policies) =>
        policies.Select(p => F.Make("BR-POLICY", Categories.BrowserNetwork, Severity.High, $"{p.Browser} 강제 정책 설정됨",
                $"{p.Browser}의 시작 페이지, 검색엔진, 확장 프로그램 등이 정책으로 고정되어 있습니다. 사용자가 바꿀 수 없습니다.",
                "RM-BROWSER-POLICY",
                new[] { ("browser", (object?)p.Browser), ("key", p.KeyPath) }.Concat(p.Values.Select(kv => (kv.Key, (object?)kv.Value))).ToArray()))
            .ToList();
}

public sealed record BrowserExtension(string Browser, string Profile, string Id, string Name, bool FromStore, int Location, bool Enabled);

public sealed class BrowserExtensionCollector : ICollector
{
    public string Id => "BR-EXT";

    private static readonly (string Browser, string UserData)[] Browsers =
    [
        ("Chrome", @"Google\Chrome\User Data"),
        ("Edge", @"Microsoft\Edge\User Data"),
    ];

    private static readonly string[] StoreUpdateHosts = ["clients2.google.com", "edge.microsoft.com"];

    public Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct)
    {
        var exts = new List<BrowserExtension>();
        // Every local profile, not just the elevated account's, since the PC's real user may differ.
        var usersRoot = Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)) ?? @"C:\Users";
        foreach (var userDir in SafeDirs(usersRoot))
            foreach (var (browser, rel) in Browsers)
            {
                var userData = Path.Combine(userDir, "AppData", "Local", rel);
                foreach (var profile in SafeDirs(userData).Where(d => File.Exists(Path.Combine(d, "Preferences"))))
                    exts.AddRange(Read(browser, $"{Path.GetFileName(userDir)}/{Path.GetFileName(profile)}", profile));
            }
        return Task.FromResult(CollectorResult.Ok(Id, Evaluate(exts, ctx.Config.KnownBad)));
    }

    private static IEnumerable<string> SafeDirs(string path)
    {
        try { return Directory.Exists(path) ? Directory.GetDirectories(path) : []; }
        catch (UnauthorizedAccessException) { return []; }
    }

    private static IEnumerable<BrowserExtension> Read(string browser, string profileLabel, string profileDir)
    {
        var seen = new Dictionary<string, BrowserExtension>();
        // Recent Chrome keeps extension settings in Secure Preferences; older builds in Preferences.
        foreach (var file in new[] { "Secure Preferences", "Preferences" })
        {
            var path = Path.Combine(profileDir, file);
            if (!File.Exists(path)) continue;
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(path));
                if (!doc.RootElement.TryGetProperty("extensions", out var e) || !e.TryGetProperty("settings", out var settings)) continue;
                foreach (var ext in settings.EnumerateObject())
                {
                    var v = ext.Value;
                    var location = v.TryGetProperty("location", out var loc) && loc.TryGetInt32(out var l) ? l : 0;
                    // 5 = component, 10 = external component: built into the browser.
                    // No location or manifest: leftover settings for something not installed (Edge keeps many).
                    if (location is 0 or 5 or 10) continue;
                    if (!v.TryGetProperty("manifest", out var manifest) || manifest.ValueKind != JsonValueKind.Object) continue;
                    var name = manifest.Str("name") ?? ext.Name;
                    var updateUrl = manifest.Str("update_url") ?? "";
                    var fromStore = v.Bool("from_webstore") == true || StoreUpdateHosts.Any(h => updateUrl.Contains(h, StringComparison.OrdinalIgnoreCase));
                    var enabled = !(v.TryGetProperty("disable_reasons", out var dr) && dr.ValueKind == JsonValueKind.Number && dr.GetInt32() != 0)
                                  && v.Num("state") != 0;
                    seen.TryAdd(ext.Name, new BrowserExtension(browser, profileLabel, ext.Name, name, fromStore, location, enabled));
                }
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException) { }
        }
        return seen.Values;
    }

    public static IReadOnlyList<Finding> Evaluate(IReadOnlyList<BrowserExtension> exts, KnownBadConfig knownBad)
    {
        var findings = new List<Finding>();
        var others = new List<BrowserExtension>();
        foreach (var x in exts)
        {
            var bad = knownBad.Extensions.FirstOrDefault(k => k.Id.Equals(x.Id, StringComparison.OrdinalIgnoreCase));
            if (bad is not null || !x.FromStore)
                findings.Add(F.Make("BR-EXT", Categories.BrowserNetwork, Severity.High, $"의심 확장 프로그램: {x.Name}",
                    bad is not null ? bad.Reason : "웹스토어가 아닌 경로로 설치된 확장 프로그램입니다.", "ADV-EXT",
                    ("browser", x.Browser), ("profile", x.Profile), ("id", x.Id), ("name", x.Name),
                    ("fromStore", x.FromStore), ("location", x.Location), ("enabled", x.Enabled)));
            else others.Add(x);
        }
        if (others.Count > 0)
            findings.Add(F.Make("BR-EXT", Categories.BrowserNetwork, Severity.Info, $"설치된 확장 프로그램 {others.Count}개",
                "웹스토어에서 설치한 확장 프로그램 목록입니다. 쓰지 않는 것은 브라우저에서 직접 제거하세요.", null,
                others.Select((x, i) => ($"{i + 1:00}", (object?)$"[{x.Browser} {x.Profile}] {x.Name} ({x.Id}){(x.Enabled ? "" : " 꺼짐")}")).ToArray()));
        return findings;
    }
}
