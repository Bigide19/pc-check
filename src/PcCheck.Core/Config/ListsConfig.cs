using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace PcCheck.Core.Config;

// Lists replace the defaults rather than append to them, since populate mode would otherwise merge.
public sealed class KnownBadConfig
{
    public int Version { get; set; } = 1;
    [JsonObjectCreationHandling(JsonObjectCreationHandling.Replace)] public List<KnownBadProgram> Programs { get; set; } =
    [
        new() { Field = "DisplayName", Match = @"(pc|system)\s*(optimizer|booster|speed ?up)", Reason = "가짜 최적화 프로그램 유형", ReasonEn = "Fake optimizer type" },
        new() { Field = "DisplayName", Match = @"driver\s*(updater|booster)", Reason = "드라이버 업데이트 유도형 프로그램", ReasonEn = "Program that pushes driver updates" },
        new() { Field = "DisplayName", Match = @"registry\s*(cleaner|fixer)", Reason = "레지스트리 정리 유도형 프로그램", ReasonEn = "Program that pushes registry cleaning" },
    ];
    [JsonObjectCreationHandling(JsonObjectCreationHandling.Replace)] public List<KnownBadExtension> Extensions { get; set; } = [];

    // hosts entries redirecting these (or their subdomains) are Critical: portals, banks, update and AV sites.
    [JsonObjectCreationHandling(JsonObjectCreationHandling.Replace)] public List<string> HostsCriticalDomains { get; set; } =
    [
        "naver.com", "daum.net", "kakao.com", "nate.com", "google.com", "google.co.kr", "youtube.com",
        "kbstar.com", "shinhan.com", "wooribank.com", "ibk.co.kr", "nonghyup.com", "hanabank.com", "kebhana.com",
        "epostbank.go.kr", "kfcc.co.kr", "cu.co.kr", "busanbank.co.kr", "dgb.co.kr", "kjbank.com", "jbbank.co.kr",
        "knbank.co.kr", "suhyup-bank.com", "kdb.co.kr", "citibank.co.kr", "standardchartered.co.kr",
        "kakaobank.com", "tossbank.com", "kbanknow.com", "toss.im", "nicepay.co.kr",
        "microsoft.com", "windowsupdate.com", "windows.com", "ahnlab.com", "estsecurity.com", "virustotal.com",
    ];
}

public sealed class KnownBadProgram
{
    public string Field { get; set; } = "DisplayName";
    public string Match { get; set; } = "";
    public string Reason { get; set; } = "";
    public string ReasonEn { get; set; } = "";
    [JsonIgnore] public string DisplayReason => Lang.Pick(Reason, ReasonEn);

    [JsonIgnore] public Regex? Regex { get; set; }
}

public sealed class KnownBadExtension
{
    public string Id { get; set; } = "";
    public string Reason { get; set; } = "";
    public string ReasonEn { get; set; } = "";
    [JsonIgnore] public string DisplayReason => Lang.Pick(Reason, ReasonEn);
}

public sealed class ProtectConfig
{
    public int Version { get; set; } = 1;
    [JsonObjectCreationHandling(JsonObjectCreationHandling.Replace)] public List<ProtectProgram> Programs { get; set; } = [];
    [JsonObjectCreationHandling(JsonObjectCreationHandling.Replace)] public List<string> Paths { get; set; } = [];
    [JsonObjectCreationHandling(JsonObjectCreationHandling.Replace)] public List<string> Services { get; set; } = [];
    [JsonObjectCreationHandling(JsonObjectCreationHandling.Replace)] public List<string> Tasks { get; set; } = [];

    public bool IsProtectedProgram(string? displayName) =>
        displayName is not null && Programs.Any(p => p.Regex?.IsMatch(displayName) == true);

    public bool IsProtectedPath(string? path) =>
        path is not null && Paths.Any(p => p.Length > 0 && path.StartsWith(p, StringComparison.OrdinalIgnoreCase));

    public bool IsProtectedService(string? name) =>
        name is not null && Services.Contains(name, StringComparer.OrdinalIgnoreCase);

    public bool IsProtectedTask(string? taskPath) =>
        taskPath is not null && Tasks.Contains(taskPath, StringComparer.OrdinalIgnoreCase);
}

public sealed class ProtectProgram
{
    public string DisplayNameMatch { get; set; } = "";
    public string Note { get; set; } = "";

    [JsonIgnore] public Regex? Regex { get; set; }
}

public sealed record PcCheckConfig(RulesConfig Rules, KnownBadConfig KnownBad, ProtectConfig Protect)
{
    public KrModulesConfig KrModules { get; init; } = new();

    public static PcCheckConfig Default() => new(new RulesConfig(), new KnownBadConfig(), new ProtectConfig());
}
