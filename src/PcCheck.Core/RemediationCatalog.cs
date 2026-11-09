namespace PcCheck.Core;

// Name and advice resolve on every access so a language switch after startup still applies.
public sealed record RemediationInfo(string Id, RiskLevel Risk, bool Reversible)
{
    private string Key => Id.Replace('-', '_');
    public string Name => Strings.ResourceManager.GetString("Rm_" + Key, Strings.Culture) ?? Strings.Rm_Fallback;
    public string? Advice => Strings.ResourceManager.GetString("Adv_" + Key, Strings.Culture);
}

public static class RemediationCatalog
{
    public static readonly IReadOnlyList<RemediationInfo> All =
    [
        new("RM-TEMP-CLEAN", RiskLevel.Auto, false),
        new("RM-POWER-PLAN", RiskLevel.Auto, true),
        new("RM-STARTUP-DISABLE", RiskLevel.Confirm, true),
        new("RM-SERVICE-DISABLE", RiskLevel.Confirm, true),
        new("RM-TASK-DISABLE", RiskLevel.Confirm, true),
        new("RM-UNINSTALL", RiskLevel.Confirm, false),
        new("RM-BROWSER-POLICY", RiskLevel.Confirm, true),
        new("RM-HOSTS-RESET", RiskLevel.Confirm, true),
        new("RM-PROXY-RESET", RiskLevel.Confirm, true),
        new("RM-DEFENDER", RiskLevel.Confirm, false),

        new("ADV-DISK-SSD", RiskLevel.AdviceOnly, false),
        new("ADV-DISK-HEALTH", RiskLevel.AdviceOnly, false),
        new("ADV-DISK-FREE", RiskLevel.AdviceOnly, false),
        new("ADV-RAM", RiskLevel.AdviceOnly, false),
        new("ADV-CPU", RiskLevel.AdviceOnly, false),
        new("ADV-MEM", RiskLevel.AdviceOnly, false),
        new("ADV-DISK-IO", RiskLevel.AdviceOnly, false),
        new("ADV-EXT", RiskLevel.AdviceOnly, false),
        new("ADV-UPDATE", RiskLevel.AdviceOnly, false),
        new("ADV-REBOOT", RiskLevel.AdviceOnly, false),
        new("ADV-DISK-CHECK", RiskLevel.AdviceOnly, false),
        new("ADV-POWER", RiskLevel.AdviceOnly, false),
        new("ADV-AV-UPDATE", RiskLevel.AdviceOnly, false),
        new("ADV-PHOTOS", RiskLevel.AdviceOnly, false),
        new("ADV-GPU-DRIVER", RiskLevel.AdviceOnly, false),
        new("ADV-PERFCOUNTER", RiskLevel.AdviceOnly, false),
        new("ADV-CRASH-MODULE", RiskLevel.AdviceOnly, false),
        new("ADV-KR-MODULES", RiskLevel.AdviceOnly, false),
        new("ADV-AV-DUP", RiskLevel.AdviceOnly, false),
    ];

    public static RemediationInfo? Find(string? id) =>
        id is null ? null
        : All.FirstOrDefault(r => r.Id == id)
          ?? (id.StartsWith("ADV-", StringComparison.Ordinal) ? new RemediationInfo(id, RiskLevel.AdviceOnly, false) : null);
}
