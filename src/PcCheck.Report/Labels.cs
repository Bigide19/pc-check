using PcCheck.Core;

namespace PcCheck.Report;

public static class Labels
{
    private static string R(string key) => Strings.ResourceManager.GetString(key, Strings.Culture) ?? key;

    public static string Of(Verdict v) => R($"Verdict_{v}");

    public static string DescribeVerdict(Verdict v) => R($"VerdictDesc_{v}");

    public static string Of(Severity s) => R($"Severity_{s}");

    public static string Of(RiskLevel r) => R($"Risk_{r}");

    public static string Of(CollectorStatus s) => R($"Status_{s}");

    public static string Category(string c) => Strings.ResourceManager.GetString($"Cat_{c}", Strings.Culture) ?? c;

    public static string CategoryShort(string c) => c == Categories.BrowserNetwork ? Strings.Cat_BrowserNetworkShort : Category(c);

    public static string Collector(string id) => Strings.ResourceManager.GetString("Col_" + id.Replace('-', '_'), Strings.Culture) ?? id;

    public static readonly string[] CategoryOrder =
    [
        Categories.Hardware, Categories.Resource, Categories.Startup, Categories.Program,
        Categories.BrowserNetwork, Categories.Security, Categories.System,
    ];
}
