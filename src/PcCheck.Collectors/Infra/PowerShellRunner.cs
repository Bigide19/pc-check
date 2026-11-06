using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace PcCheck.Collectors.Infra;

public interface IPowerShell
{
    // Always yields a JSON array: the script's output objects, possibly empty.
    Task<JsonElement> RunJsonAsync(string script, CancellationToken ct);
}

public sealed class PowerShellException(string message) : Exception(message);

public sealed class PowerShellRunner : IPowerShell
{
    public async Task<JsonElement> RunJsonAsync(string script, CancellationToken ct)
    {
        // -EncodedCommand sidesteps quoting entirely; UTF-8 output keeps Hangul intact.
        var wrapped =
            "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';" +
            "[Console]::OutputEncoding = [Text.Encoding]::UTF8;" +
            "$__r = @(& {\n" + script + "\n});" +
            "ConvertTo-Json -InputObject $__r -Depth 6 -Compress";
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(wrapped));

        var psi = new ProcessStartInfo("powershell.exe",
            $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };

        using var p = Process.Start(psi) ?? throw new PowerShellException("powershell.exe를 시작하지 못했습니다.");
        var stdout = p.StandardOutput.ReadToEndAsync(ct);
        var stderr = p.StandardError.ReadToEndAsync(ct);
        try
        {
            await p.WaitForExitAsync(ct);
        }
        catch (OperationCanceledException)
        {
            try { p.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            throw;
        }

        var output = (await stdout).Trim();
        if (p.ExitCode != 0)
            throw new PowerShellException(FirstLine(await stderr) ?? $"exit code {p.ExitCode}");
        if (output.Length == 0) return JsonDocument.Parse("[]").RootElement;

        var root = JsonDocument.Parse(output).RootElement;
        // PowerShell 5.1 unrolls a one-element array into a bare object.
        return root.ValueKind == JsonValueKind.Array ? root : JsonDocument.Parse($"[{output}]").RootElement;
    }

    private static string? FirstLine(string s) =>
        s.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();
}

public static class Json
{
    public static string? Str(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind != JsonValueKind.Null
            ? (v.ValueKind == JsonValueKind.String ? v.GetString() : v.ToString())
            : null;

    public static double? Num(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number
            ? v.GetDouble()
            : double.TryParse(e.Str(name), out var d) ? d : null;

    public static bool? Bool(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v)
            ? v.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => null }
            : null;

    public static DateTimeOffset? Date(this JsonElement e, string name) =>
        DateTimeOffset.TryParse(e.Str(name), out var d) ? d : null;

    // Embeds a value as a single-quoted PowerShell literal.
    public static string PsLiteral(string s) => "'" + s.Replace("'", "''") + "'";
}
