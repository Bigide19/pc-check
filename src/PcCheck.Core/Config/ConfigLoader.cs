using System.Text.Json;
using System.Text.RegularExpressions;

namespace PcCheck.Core.Config;

public sealed record ConfigLoadResult(PcCheckConfig Config, IReadOnlyList<string> Warnings);

public static class ConfigLoader
{
    public const string RulesFile = "rules.json";
    public const string KnownBadFile = "known-bad.json";
    public const string ProtectFile = "protect.json";
    public const string KrModulesFile = "kr-modules.json";

    public static ConfigLoadResult Load(string configDir)
    {
        var warnings = new List<string>();
        var rules = Read<RulesConfig>(configDir, RulesFile, warnings);
        var knownBad = Read<KnownBadConfig>(configDir, KnownBadFile, warnings);
        var protect = Read<ProtectConfig>(configDir, ProtectFile, warnings);
        var krModules = Read<KrModulesConfig>(configDir, KrModulesFile, warnings);

        foreach (var p in knownBad.Programs)
            p.Regex = Compile(p.Match, $"{KnownBadFile} programs '{p.Match}'", warnings);
        knownBad.Programs.RemoveAll(p => p.Regex is null);

        foreach (var p in protect.Programs)
            p.Regex = Compile(p.DisplayNameMatch, $"{ProtectFile} programs '{p.DisplayNameMatch}'", warnings);
        // Dropping an unparsable protect entry would silently expose the program it was meant to shield,
        // so it stays and matches by plain substring instead.
        foreach (var p in protect.Programs.Where(p => p.Regex is null && p.DisplayNameMatch.Length > 0))
            p.Regex = new Regex(Regex.Escape(p.DisplayNameMatch), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        return new ConfigLoadResult(new PcCheckConfig(rules, knownBad, protect) { KrModules = krModules }, warnings);
    }

    // Missing file: built-in defaults. Broken file: defaults plus a warning surfaced in the report.
    private static T Read<T>(string dir, string file, List<string> warnings) where T : new()
    {
        var target = new T();
        var path = Path.Combine(dir, file);
        if (!File.Exists(path)) return target;

        try
        {
            var json = File.ReadAllText(path);
            var parsed = JsonSerializer.Deserialize<T>(json, PcCheckJson.ConfigOptions);
            if (parsed is null) warnings.Add(string.Format(Strings.Config_Empty, file));
            return parsed ?? target;
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            warnings.Add(string.Format(Strings.Config_Unreadable, file, ex.Message));
            return target;
        }
    }

    private static Regex? Compile(string pattern, string label, List<string> warnings)
    {
        try
        {
            return new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        }
        catch (ArgumentException ex)
        {
            warnings.Add(string.Format(Strings.Config_BadRegex, label, ex.Message));
            return null;
        }
    }
}
