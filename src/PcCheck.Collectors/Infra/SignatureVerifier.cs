using System.Collections.Concurrent;
using System.Text.Json;

namespace PcCheck.Collectors.Infra;

public sealed record SignatureInfo(string Status, string? Signer, string? Error = null)
{
    public bool IsValid => Status == "Valid";
    public bool IsMissing => Status == "Missing";
    // The check itself failed (access denied, malformed path): neither signed nor unsigned is known.
    public bool IsUnknown => Status is "Error" or "Unknown";
    public bool IsUnsigned => !IsValid && !IsMissing && !IsUnknown;
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
    // Keeps each -EncodedCommand well under the 32K command-line limit.
    public const int ChunkSize = 40;

    private readonly ConcurrentDictionary<string, SignatureInfo> _cache = new(StringComparer.OrdinalIgnoreCase);

    // Per-file try/catch: on a real PC one unreadable path (WindowsApps, a malformed command line)
    // used to abort the whole batch and fail the collector.
    public static string Script(IReadOnlyList<string> paths) =>
        // PowerShell 5.1's ConvertFrom-Json emits a JSON array as ONE object: wrapping that pipeline in @() nests it,
        // so assign first and enumerate the variable (v0.1.2 shipped the nested form and matched no path at all).
        $"$paths = {Json.PsLiteral(JsonSerializer.Serialize(paths))} | ConvertFrom-Json\n" +
        """
        foreach ($p in @($paths)) {
          try {
            if (Test-Path -LiteralPath $p -PathType Leaf -ErrorAction Stop) {
              $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
              [pscustomobject]@{ Path = $p; Status = [string]$s.Status; Signer = $s.SignerCertificate.Subject; Error = $null }
            } else { [pscustomobject]@{ Path = $p; Status = 'Missing'; Signer = $null; Error = $null } }
          } catch {
            [pscustomobject]@{ Path = $p; Status = 'Error'; Signer = $null; Error = $_.Exception.Message }
          }
        }
        """;

    public async Task<IReadOnlyDictionary<string, SignatureInfo>> VerifyAsync(IEnumerable<string> paths, CancellationToken ct)
    {
        var all = paths.Where(p => !string.IsNullOrWhiteSpace(p)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        foreach (var chunk in all.Where(p => !_cache.ContainsKey(p)).Chunk(ChunkSize))
        {
            var rows = await ps.RunJsonAsync(Script(chunk), ct);
            var matched = 0;
            foreach (var r in rows.EnumerateArray())
                if (r.Str("Path") is { } path && chunk.Contains(path, StringComparer.OrdinalIgnoreCase))
                {
                    _cache[path] = new SignatureInfo(r.Str("Status") ?? "Unknown", r.Str("Signer"), r.Str("Error"));
                    matched++;
                }
            // Every path unanswered means the script itself misbehaved; failing loudly beats reporting all files as "unknown".
            if (matched == 0)
                throw new PowerShellException(string.Format(Strings.Sig_NoPaths, chunk.Length));
        }
        return all.ToDictionary(p => p, p => _cache.TryGetValue(p, out var s) ? s : new SignatureInfo("Unknown", null),
            StringComparer.OrdinalIgnoreCase);
    }
}
