using System.Globalization;

namespace PcCheck.Core;

// App language: Korean when Windows is Korean, English otherwise, unless overridden (--lang, header toggle).
// Kept in a static rather than CurrentUICulture: that one is async-local, so a change made inside an async
// method or a dispatcher operation reverts afterwards and later screens come back in the Windows language.
// Number and date formats keep following Windows.
public static class Lang
{
    public static CultureInfo Culture { get; private set; } = Normalize(CultureInfo.CurrentUICulture.TwoLetterISOLanguageName);

    // Each assembly binds its generated Strings.Culture to this (see StringsCulture in each project).
    public static event Action<CultureInfo>? Changed;

    public static bool IsKorean => Culture.TwoLetterISOLanguageName == "ko";

    public static string Code => IsKorean ? "ko" : "en";

    // For text that lives in data rather than resources: English when set, Korean otherwise.
    public static string Pick(string ko, string? en) => IsKorean || string.IsNullOrEmpty(en) ? ko : en;

    public static void Set(string code)
    {
        Culture = Normalize(code);
        Changed?.Invoke(Culture);
    }

    public static string? FromArgs(IReadOnlyList<string> args)
    {
        var i = args.ToList().IndexOf("--lang");
        return i >= 0 && i + 1 < args.Count && args[i + 1] is "ko" or "en" ? args[i + 1] : null;
    }

    private static CultureInfo Normalize(string code) => CultureInfo.GetCultureInfo(code == "ko" ? "ko-KR" : "en-US");
}
