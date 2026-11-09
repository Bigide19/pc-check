using System.Runtime.CompilerServices;

// Language is process-wide (Lang.Culture), so tests that switch it must not overlap with wording assertions.
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace PcCheck.Analysis.Tests;

// Wording assertions are written against the Korean resources.
internal static class TestCulture
{
    [ModuleInitializer]
    internal static void Init() => PcCheck.Core.Lang.Set("ko");
}
