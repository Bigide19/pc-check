using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace PcCheck.Core;

internal static class StringsCulture
{
    // Pins this assembly's resource lookups to Lang.Culture on every thread, including assemblies loaded after --lang.
    [ModuleInitializer]
    [SuppressMessage("Usage", "CA2255", Justification = "Binds this assembly's own resources; no caller ordering involved.")]
    internal static void Bind()
    {
        Strings.Culture = Lang.Culture;
        Lang.Changed += c => Strings.Culture = c;
    }
}
