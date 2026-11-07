using System.IO.Compression;

namespace PcCheck.Report;

// One file to carry off the PC (messenger, USB, Wormhole) instead of four.
public static class ResultBundle
{
    public static readonly string[] Files = ["report.html", "findings.json", "pccheck.log", "actions.json"];

    public static string PathFor(string outputDir) => Path.Combine(outputDir, Path.GetFileName(outputDir.TrimEnd('\\', '/')) + ".zip");

    // Rebuilt on demand so a later fix run's actions.json gets included.
    public static string? Create(string outputDir)
    {
        var present = Files.Select(f => Path.Combine(outputDir, f)).Where(File.Exists).ToList();
        if (present.Count == 0) return null;
        var zip = PathFor(outputDir);
        var tmp = zip + ".tmp";
        using (var archive = ZipFile.Open(tmp, ZipArchiveMode.Create))
            foreach (var f in present)
            {
                // ReadWrite share: the log may still be open in another handle.
                using var src = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var dst = archive.CreateEntry(Path.GetFileName(f), CompressionLevel.Optimal).Open();
                src.CopyTo(dst);
            }
        File.Move(tmp, zip, overwrite: true);
        return zip;
    }
}
