using Microsoft.Win32;
using PcCheck.Collectors.Infra;
using PcCheck.Core;

namespace PcCheck.Remediation;

public interface IRestorePointService
{
    Task<RestorePointInfo> CreateAsync(string description, CancellationToken ct);
}

public sealed class RestorePointService(ISystemOps sys) : IRestorePointService
{
    private const string Key = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore";
    private const string Frequency = "SystemRestorePointCreationFrequency";

    public async Task<RestorePointInfo> CreateAsync(string description, CancellationToken ct)
    {
        // Windows silently skips a restore point if one was made in the last 24h; lift the limit for this one call.
        var previous = sys.GetValue(Key, Frequency);
        try
        {
            sys.SetValue(Key, Frequency, 0, RegistryValueKind.DWord);
            await sys.PowerShellAsync(
                "Enable-ComputerRestore -Drive \"$env:SystemDrive\\\"\n" +
                $"Checkpoint-Computer -Description {Json.PsLiteral(description)} -RestorePointType MODIFY_SETTINGS", ct);
            return new RestorePointInfo(true, description);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new RestorePointInfo(false, description, ex.Message);
        }
        finally
        {
            if (previous is null) sys.DeleteValue(Key, Frequency);
            else sys.SetValue(Key, Frequency, previous, RegistryValueKind.DWord);
        }
    }
}
