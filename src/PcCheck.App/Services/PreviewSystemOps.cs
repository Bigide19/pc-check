using System.Text.Json;
using Microsoft.Win32;
using PcCheck.Remediation;

namespace PcCheck.App.Services;

// Backs the --mock walkthrough of the fix and undo screens: every write stays in memory,
// so the preview can never change the PC it runs on.
public sealed class PreviewSystemOps : ISystemOps
{
    private readonly Dictionary<(string, string), object> _registry = new();

    public object? GetValue(string key, string name) => _registry.GetValueOrDefault((key.ToUpperInvariant(), name));
    public void SetValue(string key, string name, object value, RegistryValueKind kind) => _registry[(key.ToUpperInvariant(), name)] = value;
    public void DeleteValue(string key, string name) => _registry.Remove((key.ToUpperInvariant(), name));
    public bool KeyExists(string key) => false;

    public async Task<CommandResult> RunAsync(string exe, string args, CancellationToken ct)
    {
        await Task.Delay(400, ct);
        return new CommandResult(0, "", "");
    }

    public async Task<JsonElement> PowerShellAsync(string script, CancellationToken ct)
    {
        await Task.Delay(400, ct);
        return JsonDocument.Parse("[{}]").RootElement;
    }

    public bool FileExists(string path) => false;
    public string ReadText(string path) => "";
    public void WriteText(string path, string text) { }
    public void CopyFile(string from, string to) { }
    public IEnumerable<string> FilesOlderThan(string dir, DateTime cutoffUtc) => [];
    public bool TryDeleteFile(string path) => false;
}
