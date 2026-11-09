using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using PcCheck.Collectors.Infra;

namespace PcCheck.Remediation;

public sealed record CommandResult(int ExitCode, string Output, string Error)
{
    public bool Ok => ExitCode == 0;
}

// Every system write in remediation goes through here, so tests can run against an in-memory fake.
public interface ISystemOps
{
    object? GetValue(string key, string name);
    void SetValue(string key, string name, object value, RegistryValueKind kind);
    void DeleteValue(string key, string name);
    bool KeyExists(string key);

    Task<CommandResult> RunAsync(string exe, string args, CancellationToken ct);
    Task<JsonElement> PowerShellAsync(string script, CancellationToken ct);

    bool FileExists(string path);
    string ReadText(string path);
    void WriteText(string path, string text);
    void CopyFile(string from, string to);
    IEnumerable<string> FilesOlderThan(string dir, DateTime cutoffUtc);
    bool TryDeleteFile(string path);
}

public sealed class WindowsSystemOps(IPowerShell ps) : ISystemOps
{
    private static (RegistryKey Root, string Sub) Split(string key)
    {
        var i = key.IndexOf('\\');
        var hive = i < 0 ? key : key[..i];
        var sub = i < 0 ? "" : key[(i + 1)..];
        var root = hive.ToUpperInvariant() switch
        {
            "HKLM" or "HKEY_LOCAL_MACHINE" => RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64),
            "HKCU" or "HKEY_CURRENT_USER" => Registry.CurrentUser,
            _ => throw new ArgumentException(string.Format(Strings.Err_BadHive, hive)),
        };
        return (root, sub);
    }

    public object? GetValue(string key, string name)
    {
        var (root, sub) = Split(key);
        using var k = root.OpenSubKey(sub);
        return k?.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
    }

    public void SetValue(string key, string name, object value, RegistryValueKind kind)
    {
        var (root, sub) = Split(key);
        using var k = root.CreateSubKey(sub, writable: true);
        k.SetValue(name, value, kind);
    }

    public void DeleteValue(string key, string name)
    {
        var (root, sub) = Split(key);
        using var k = root.OpenSubKey(sub, writable: true);
        k?.DeleteValue(name, throwOnMissingValue: false);
    }

    public bool KeyExists(string key)
    {
        var (root, sub) = Split(key);
        using var k = root.OpenSubKey(sub);
        return k is not null;
    }

    public async Task<CommandResult> RunAsync(string exe, string args, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException(string.Format(Strings.Err_StartFailed, exe));
        var o = p.StandardOutput.ReadToEndAsync(ct);
        var e = p.StandardError.ReadToEndAsync(ct);
        await p.WaitForExitAsync(ct);
        return new CommandResult(p.ExitCode, await o, await e);
    }

    public Task<JsonElement> PowerShellAsync(string script, CancellationToken ct) => ps.RunJsonAsync(script, ct);

    public bool FileExists(string path) => File.Exists(path);
    public string ReadText(string path) => File.ReadAllText(path);

    public void WriteText(string path, string text)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, text, new UTF8Encoding(false));
    }

    public void CopyFile(string from, string to)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(to)!);
        File.Copy(from, to, overwrite: true);
    }

    public IEnumerable<string> FilesOlderThan(string dir, DateTime cutoffUtc)
    {
        if (!Directory.Exists(dir)) yield break;
        var opts = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
        foreach (var f in new DirectoryInfo(dir).EnumerateFiles("*", opts))
        {
            DateTime written;
            try { written = f.LastWriteTimeUtc; } catch (IOException) { continue; }
            if (written < cutoffUtc) yield return f.FullName;
        }
    }

    public bool TryDeleteFile(string path)
    {
        try { File.Delete(path); return true; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }
}
