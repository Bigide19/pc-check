using Microsoft.Win32;
using PcCheck.Collectors.Infra;

namespace PcCheck.Collectors.Startup;

public sealed record StartupEntry
{
    public required string Location { get; init; }      // registry key path or startup folder
    public required string Name { get; init; }           // value name or file name
    public required string Command { get; init; }
    public string? TargetPath { get; init; }
    public bool Enabled { get; init; } = true;
    public string? ApprovedKey { get; init; }            // StartupApproved key that controls this entry, null for RunOnce
    public string? ApprovedValue { get; init; }          // hex of the StartupApproved bytes, if present

    public string DisplayTarget => $@"{Location}\{Name}";
}

public sealed class StartupSource
{
    private const string Cv = @"Software\Microsoft\Windows\CurrentVersion";
    private const string Approved = Cv + @"\Explorer\StartupApproved";

    public Shared<IReadOnlyList<StartupEntry>> Entries { get; }

    public StartupSource() => Entries = new(_ => Task.FromResult(Read()));

    public StartupSource(IReadOnlyList<StartupEntry> fixedEntries) => Entries = new(_ => Task.FromResult(fixedEntries));

    private static IReadOnlyList<StartupEntry> Read()
    {
        var list = new List<StartupEntry>();
        var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        var hklm32 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
        var hkcu = Registry.CurrentUser;

        ReadRun(list, hklm, "HKLM", Cv + @"\Run", Approved + @"\Run");
        ReadRun(list, hklm, "HKLM", Cv + @"\RunOnce", null);
        // WOW6432Node: 32-bit apps register here; Task Manager tracks them under Run32.
        ReadRun(list, hklm32, "HKLM(WOW6432Node)", Cv + @"\Run", Approved + @"\Run32", approvedRoot: hklm, approvedRootName: "HKLM");
        ReadRun(list, hklm32, "HKLM(WOW6432Node)", Cv + @"\RunOnce", null);
        ReadRun(list, hkcu, "HKCU", Cv + @"\Run", Approved + @"\Run");
        ReadRun(list, hkcu, "HKCU", Cv + @"\RunOnce", null);

        ReadFolder(list, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), hklm, "HKLM");
        ReadFolder(list, Environment.GetFolderPath(Environment.SpecialFolder.Startup), hkcu, "HKCU");
        return list;
    }

    private static void ReadRun(List<StartupEntry> list, RegistryKey root, string rootName, string path, string? approvedPath,
        RegistryKey? approvedRoot = null, string? approvedRootName = null)
    {
        using var key = root.OpenSubKey(path);
        if (key is null) return;
        using var approved = approvedPath is null ? null : (approvedRoot ?? root).OpenSubKey(approvedPath);
        foreach (var name in key.GetValueNames())
        {
            if (key.GetValue(name) is not string cmd || cmd.Length == 0) continue;
            var bytes = approved?.GetValue(name) as byte[];
            list.Add(new StartupEntry
            {
                Location = $@"{rootName}\{path}",
                Name = name,
                Command = cmd,
                TargetPath = PathRules.ExtractTarget(cmd),
                Enabled = IsEnabled(bytes),
                ApprovedKey = approvedPath is null ? null : $@"{approvedRootName ?? rootName}\{approvedPath}",
                ApprovedValue = bytes is null ? null : Convert.ToHexString(bytes),
            });
        }
    }

    private static void ReadFolder(List<StartupEntry> list, string folder, RegistryKey approvedRoot, string rootName)
    {
        if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) return;
        using var approved = approvedRoot.OpenSubKey(Approved + @"\StartupFolder");
        foreach (var file in Directory.EnumerateFiles(folder))
        {
            var name = Path.GetFileName(file);
            if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
            var target = name.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ? ResolveShortcut(file) ?? file : file;
            var bytes = approved?.GetValue(name) as byte[];
            list.Add(new StartupEntry
            {
                Location = folder,
                Name = name,
                Command = target,
                TargetPath = target,
                Enabled = IsEnabled(bytes),
                ApprovedKey = $@"{rootName}\{Approved}\StartupFolder",
                ApprovedValue = bytes is null ? null : Convert.ToHexString(bytes),
            });
        }
    }

    // StartupApproved: first byte even (02, 06) = enabled, odd (03, 07) = disabled; no value = enabled.
    public static bool IsEnabled(byte[]? approved) => approved is not { Length: > 0 } || (approved[0] & 1) == 0;

    private static string? ResolveShortcut(string lnk)
    {
        try
        {
            var shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType is null) return null;
            dynamic shell = Activator.CreateInstance(shellType)!;
            var sc = shell.CreateShortcut(lnk);
            string target = sc.TargetPath;
            return string.IsNullOrWhiteSpace(target) ? null : target;
        }
        catch (Exception) { return null; }
    }
}
