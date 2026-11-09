using PcCheck.Core;

namespace PcCheck.Core.Tests;

public class LeaksTests
{
    private static Finding F(string category, Severity sev = Severity.Medium) =>
        new("X", category, sev, "t", "d", 5, null, new Dictionary<string, string>());

    [Fact]
    public void Existing_categories_are_performance_leaks()
    {
        foreach (var c in new[] { Categories.Hardware, Categories.Resource, Categories.Startup, Categories.Program,
                                  Categories.BrowserNetwork, Categories.Security, Categories.System })
            Assert.Equal(LeakKind.Performance, Leaks.Of(c));
        Assert.Equal(LeakKind.Space, Leaks.Of(Categories.Space));
        Assert.Equal(LeakKind.Information, Leaks.Of(Categories.Privacy));
    }

    [Fact]
    public void Unimplemented_leaks_are_unchecked_until_they_have_findings()
    {
        var real = Leaks.Summarize([F(Categories.Startup), F(Categories.System, Severity.Info)]);
        Assert.Equal([LeakKind.Performance, LeakKind.Space, LeakKind.Information], real.Select(x => x.Kind));
        Assert.True(real[0].Checked);
        Assert.Equal(1, real[0].Count);
        Assert.Equal(2, real[0].Findings.Count);
        Assert.False(real[1].Checked);
        Assert.False(real[2].Checked);

        var mock = Leaks.Summarize([F(Categories.Space), F(Categories.Privacy), F(Categories.Privacy, Severity.Low)]);
        Assert.True(mock[1].Checked);
        Assert.Equal(1, mock[1].Count);
        Assert.Equal(2, mock[2].Count);
        Assert.Equal(0, mock[0].Count);
    }
}
