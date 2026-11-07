using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace PcCheck.Core.Config;

// Korean banking/government security modules: what to look for and what to tell the user.
// The built-in list covers identification only; config/kr-modules.json adds researched notes and sources.
public sealed class KrModulesConfig
{
    public int Version { get; set; } = 1;

    [JsonObjectCreationHandling(JsonObjectCreationHandling.Replace)]
    public List<KrModule> Modules { get; set; } =
    [
        new() { Id = "touchen-nxkey", Name = "TouchEn nxKey", Vendor = "RaonSecure", DisplayNamePatterns = [@"TouchEn\s*nxKey"], PathPatterns = [@"\RaonSecure\", @"\TouchEn"], DllPatterns = ["^TENX", "^TKFW"] },
        new() { Id = "ahnlab-safe-transaction", Name = "AhnLab Safe Transaction", Vendor = "AhnLab", DisplayNamePatterns = [@"Safe\s*Transaction"], PathPatterns = [@"\AhnLab\Safe Transaction\"] },
        new() { Id = "veraport", Name = "Veraport", Vendor = "Wizvera", DisplayNamePatterns = ["Veraport"], PathPatterns = [@"\Wizvera\Veraport"] },
        new() { Id = "delfino", Name = "Delfino", Vendor = "Wizvera", DisplayNamePatterns = ["Delfino"], PathPatterns = [@"\Wizvera\Delfino"] },
        new() { Id = "ipinside", Name = "IPinside LWS", Vendor = "Interezen", DisplayNamePatterns = ["IPinside"], PathPatterns = [@"\IPinside"] },
        new() { Id = "magicline4nx", Name = "MagicLine4NX", Vendor = "DreamSecurity", DisplayNamePatterns = ["MagicLine"], PathPatterns = [@"\DreamSecurity\"] },
        new() { Id = "crosscert-unicrs", Name = "CrossCert UniSign CRS", Vendor = "CrossCert", DisplayNamePatterns = ["UniSign|UniCRS|CrossCert"], PathPatterns = [@"\Crosscert\"] },
        new() { Id = "anysign", Name = "AnySign4PC (XecureWeb)", Vendor = "SoftForum", DisplayNamePatterns = ["AnySign|XecureWeb"], PathPatterns = [@"\SoftForum\"] },
        new() { Id = "crossex", Name = "CrossEX", Vendor = "iniLINE", DisplayNamePatterns = ["CrossEX|CrossWeb"], PathPatterns = [@"\iniLINE\", @"\Initech\"] },
        new() { Id = "markany-eps", Name = "MarkAny EPS", Vendor = "MarkAny", DisplayNamePatterns = ["MarkAny|MaEPS"], PathPatterns = [@"\MarkAny\"] },
        new() { Id = "nprotect", Name = "nProtect Online Security", Vendor = "INCA Internet", DisplayNamePatterns = ["nProtect"], PathPatterns = [@"\nProtect", @"\INCA Internet\"] },
    ];

    public KrModule? MatchProgram(string? displayName, string? publisher) =>
        Modules.FirstOrDefault(m => m.MatchesName(displayName) || m.MatchesPublisher(publisher));

    public KrModule? MatchPath(string? path) => path is null ? null : Modules.FirstOrDefault(m => m.MatchesPath(path));

    public KrModule? MatchDll(string? fileName) => fileName is null ? null : Modules.FirstOrDefault(m => m.MatchesDll(fileName));
}

public sealed class KrModule
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Vendor { get; set; } = "";
    public string Purpose { get; set; } = "";
    public List<string> DisplayNamePatterns { get; set; } = [];
    public List<string> PublisherPatterns { get; set; } = [];
    public List<string> PathPatterns { get; set; } = [];
    public List<string> ProcessNames { get; set; } = [];
    public List<string> ServiceNames { get; set; } = [];
    public List<string> DllPatterns { get; set; } = [];
    public List<KrIssue> KnownIssues { get; set; } = [];
    public List<KrIssue> Compatibility { get; set; } = [];
    public string UninstallNotes { get; set; } = "";

    private static bool Any(List<string> patterns, string? input) =>
        !string.IsNullOrEmpty(input) && patterns.Any(p => Safe(p)?.IsMatch(input) == true);

    private static Regex? Safe(string pattern)
    {
        try { return new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200)); }
        catch (ArgumentException) { return null; }
    }

    public bool MatchesName(string? displayName) => Any(DisplayNamePatterns, displayName);
    public bool MatchesPublisher(string? publisher) => Any(PublisherPatterns, publisher);
    // Path patterns are literal folder fragments, not regexes, so backslashes need no escaping in JSON beyond JSON's own.
    public bool MatchesPath(string path) => PathPatterns.Any(p => p.Length > 0 && path.Contains(p, StringComparison.OrdinalIgnoreCase));
    public bool MatchesDll(string fileName) => Any(DllPatterns, fileName);
}

public sealed class KrIssue
{
    public int? Year { get; set; }
    public string Summary { get; set; } = "";
    public string Source { get; set; } = "";
}
