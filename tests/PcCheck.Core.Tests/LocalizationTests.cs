using System.Text.RegularExpressions;
using System.Xml.Linq;
using PcCheck.Core;

namespace PcCheck.Core.Tests;

public class LocalizationTests
{
    internal static T InEnglish<T>(Func<T> f)
    {
        Lang.Set("en");
        try { return f(); }
        finally { Lang.Set("ko"); }
    }

    private static Dictionary<string, string> Load(string path) =>
        XDocument.Load(path).Root!.Elements("data").ToDictionary(e => (string)e.Attribute("name")!, e => (string?)e.Element("value") ?? "");

    private static string Placeholders(string s) =>
        string.Join(",", Regex.Matches(s, @"\{(\d+)[^}]*\}").Select(m => m.Groups[1].Value).Distinct().Order());

    [Fact]
    public void Every_resx_pair_has_the_same_keys_and_placeholders()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "PcCheck.slnx"))) root = root.Parent;
        Assert.NotNull(root);

        var pairs = Directory.GetFiles(Path.Combine(root.FullName, "src"), "Strings.resx", SearchOption.AllDirectories)
            .Where(p => !p.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")).ToList();
        Assert.True(pairs.Count >= 5, $"found {pairs.Count} Strings.resx files");

        var problems = new List<string>();
        foreach (var en in pairs)
        {
            var ko = Path.ChangeExtension(en, ".ko.resx");
            var (e, k) = (Load(en), Load(ko));
            var project = Path.GetFileName(Path.GetDirectoryName(en));
            problems.AddRange(e.Keys.Except(k.Keys).Select(x => $"{project}: {x} missing in ko"));
            problems.AddRange(k.Keys.Except(e.Keys).Select(x => $"{project}: {x} missing in en"));
            problems.AddRange(e.Keys.Intersect(k.Keys).Where(x => Placeholders(e[x]) != Placeholders(k[x]))
                .Select(x => $"{project}: {x} placeholders differ"));
            problems.AddRange(e.Where(x => Regex.IsMatch(x.Value, @"[가-힣]")).Select(x => $"{project}: {x.Key} has Korean in en"));
        }
        Assert.Empty(problems);
    }

    [Fact]
    public void Remediation_names_follow_the_current_language()
    {
        var info = RemediationCatalog.Find("ADV-RAM")!;
        Assert.Equal("메모리 증설", info.Name);
        Assert.Equal("Add memory", InEnglish(() => info.Name));
        Assert.StartsWith("8 GB", InEnglish(() => info.Advice));
        Assert.Equal("Recommendation", InEnglish(() => RemediationCatalog.Find("ADV-UNLISTED")!.Name));
    }
}
