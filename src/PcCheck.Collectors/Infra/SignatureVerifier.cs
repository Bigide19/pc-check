using System.Collections.Concurrent;
using System.Text.Json;

namespace PcCheck.Collectors.Infra;

public sealed record SignatureInfo(string Status, string? Signer)
{
    public bool IsValid => Status == "Valid";
    public bool IsMissing => Status == "Missing";
    public bool IsMicrosoft => IsValid && Signer?.Contains("O=Microsoft Corporation", StringComparison.OrdinalIgnoreCase) == true;
}

public interface ISignatureVerifier
{
    Task<IReadOnlyDictionary<string, SignatureInfo>> VerifyAsync(IEnumerable<string> paths, CancellationToken ct);
}

// Get-AuthenticodeSignature instead of a bare WinVerifyTrust call: most Windows binaries are
// catalog-signed, and a file-only check would report them as unsigned.
public sealed class SignatureVerifier(IPowerShell ps) : ISignatureVerifier
{
    private readonly ConcurrentDictionary<string, SignatureInfo> _cache = new(StringComparer.OrdinalIgnoreCase);

    public async Task<IReadOnlyDictionary<string, SignatureInfo>> VerifyAsync(IEnumerable<string> paths, CancellationToken ct)
    {
        var all = paths.Where(p => !string.IsNullOrWhiteSpace(p)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var todo = all.Where(p => !_cache.ContainsKey(p)).ToList();
        if (todo.Count > 0)
        {
            var script =
                $"$paths = {Json.PsLiteral(JsonSerializer.Serialize(todo))} | ConvertFrom-Json\n" +
                "foreach ($p in $paths) {\n" +
                "  if (Test-Path -LiteralPath $p -PathType Leaf) {\n" +
                "    $s = Get-AuthenticodeSignature -LiteralPath $p\n" +
                "    [pscustomobject]@{ Path = $p; Status = [string]$s.Status; Signer = $s.SignerCertificate.Subject }\n" +
                "  } else { [pscustomobject]@{ Path = $p; Status = 'Missing'; Signer = $null } }\n" +
                "}";
            var rows = await ps.RunJsonAsync(script, ct);
            foreach (var r in rows.EnumerateArray())
                if (r.Str("Path") is { } path)
                    _cache[path] = new SignatureInfo(r.Str("Status") ?? "Unknown", r.Str("Signer"));
        }
        return all.ToDictionary(p => p, p => _cache.TryGetValue(p, out var s) ? s : new SignatureInfo("Unknown", null),
            StringComparer.OrdinalIgnoreCase);
    }
}
