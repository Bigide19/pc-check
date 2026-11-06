using System.Text.RegularExpressions;

namespace PcCheck.Collectors.Infra;

public static partial class PathRules
{
    private static readonly string[] ScriptHosts =
        ["rundll32.exe", "regsvr32.exe", "wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe", "pwsh.exe", "cmd.exe"];

    private static readonly string[] PayloadExtensions = [".exe", ".dll", ".js", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".hta", ".wsf"];

    // Spec: AppData, Temp, or a random-looking folder directly under ProgramData.
    public static bool IsUserWritable(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var p = path.Replace('/', '\\');
        if (p.Contains(@"\AppData\", StringComparison.OrdinalIgnoreCase)) return true;
        if (p.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) || p.Contains(@"\Tmp\", StringComparison.OrdinalIgnoreCase)) return true;

        var m = ProgramDataChild().Match(p);
        return m.Success && LooksRandom(m.Groups[1].Value);
    }

    public static bool LooksRandom(string name)
    {
        if (Guid.TryParse(name.Trim('{', '}'), out _)) return true;
        if (name.Length >= 8 && HexOnly().IsMatch(name)) return true;
        var digits = name.Count(char.IsDigit);
        var letters = name.Count(char.IsLetter);
        return name.Length >= 6 && digits >= 2 && letters >= 2 && !name.Contains(' ') && AlnumOnly().IsMatch(name);
    }

    public static bool IsScriptHost(string? exe) =>
        exe is not null && ScriptHosts.Contains(Path.GetFileName(exe), StringComparer.OrdinalIgnoreCase);

    // Returns the file a command line ultimately runs: the executable, or for script hosts the script/dll it is handed.
    public static string? ExtractTarget(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        var cmd = Environment.ExpandEnvironmentVariables(commandLine.Trim());
        string exe, rest;
        if (cmd.StartsWith('"'))
        {
            var end = cmd.IndexOf('"', 1);
            exe = end > 0 ? cmd[1..end] : cmd.Trim('"');
            rest = end > 0 ? cmd[(end + 1)..] : "";
        }
        else
        {
            var idx = cmd.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            if (idx > 0) { exe = cmd[..(idx + 4)]; rest = cmd[(idx + 4)..]; }
            else { var sp = cmd.IndexOf(' '); exe = sp > 0 ? cmd[..sp] : cmd; rest = sp > 0 ? cmd[sp..] : ""; }
        }

        if (IsScriptHost(exe))
        {
            foreach (Match m in ArgPath().Matches(rest))
            {
                var candidate = m.Groups["q"].Success ? m.Groups["q"].Value : m.Groups["u"].Value;
                if (PayloadExtensions.Any(e => candidate.EndsWith(e, StringComparison.OrdinalIgnoreCase)) && candidate.Contains('\\'))
                    return candidate.TrimEnd(',');
            }
        }

        if (!exe.Contains('\\'))
        {
            var sys = Path.Combine(Environment.SystemDirectory, exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? exe : exe + ".exe");
            return sys;
        }
        return exe;
    }

    [GeneratedRegex(@"^[A-Za-z]:\\ProgramData\\([^\\]+)\\", RegexOptions.IgnoreCase)]
    private static partial Regex ProgramDataChild();

    [GeneratedRegex("^[0-9a-fA-F]+$")]
    private static partial Regex HexOnly();

    [GeneratedRegex("^[A-Za-z0-9]+$")]
    private static partial Regex AlnumOnly();

    [GeneratedRegex("\"(?<q>[^\"]+)\"|(?<u>[A-Za-z]:\\\\[^\\s,]+)")]
    private static partial Regex ArgPath();
}
