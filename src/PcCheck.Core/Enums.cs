namespace PcCheck.Core;

public enum Severity { Info, Low, Medium, High, Critical }

public enum Verdict { Healthy, Cleanup, Format, HardwareReplace }

public enum RiskLevel { Auto, Confirm, AdviceOnly }

public enum CollectorStatus { Ok, Failed, TimedOut, Canceled }

public enum ActionStatus { Applied, Failed, Skipped, Undone, UndoFailed }

public static class Categories
{
    public const string Hardware = "Hardware";
    public const string Resource = "Resource";
    public const string Startup = "Startup";
    public const string Program = "Program";
    public const string BrowserNetwork = "BrowserNetwork";
    public const string Security = "Security";
    public const string System = "System";
    // Space and information leaks (stages 3 and 4); they never feed the cleanup/format/hardware verdict.
    public const string Space = "Space";
    public const string Privacy = "Privacy";
}
