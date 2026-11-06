using System.Management;
using PcCheck.Collectors.Infra;

namespace PcCheck.Collectors.Hardware;

public sealed record StorageInfo
{
    public string MediaType { get; init; } = "";
    public string BusType { get; init; } = "";
    public string Model { get; init; } = "";
    public string HealthStatus { get; init; } = "";
    public string OperationalStatus { get; init; } = "";
    public double? SpindleSpeed { get; init; }
    public double? ReadErrorsTotal { get; init; }
    public double? ReadErrorsUncorrected { get; init; }
    public double? Wear { get; init; }
    public bool? PredictFailure { get; init; }
    public string? PredictFailureInstance { get; init; }

    public string Kind =>
        MediaType.Equals("HDD", StringComparison.OrdinalIgnoreCase) ? "HDD"
        : MediaType.Equals("SSD", StringComparison.OrdinalIgnoreCase) || MediaType.Equals("SCM", StringComparison.OrdinalIgnoreCase) ? "SSD"
        : BusType.Equals("NVMe", StringComparison.OrdinalIgnoreCase) ? "SSD"
        : SpindleSpeed == 0 ? "SSD"
        : SpindleSpeed is > 0 and < uint.MaxValue ? "HDD"
        : "Unknown";
}

public sealed class StorageSource
{
    private readonly IPowerShell _ps;
    private readonly IWmi _wmi;

    private const string Script = """
        $part = Get-Partition -DriveLetter C
        $disk = Get-Disk -Number $part.DiskNumber
        $pd = Get-PhysicalDisk | Where-Object { $_.DeviceId -eq [string]$disk.Number } | Select-Object -First 1
        $rel = $null
        if ($pd) { $rel = $pd | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue }
        [pscustomobject]@{
          MediaType = [string]$pd.MediaType; BusType = [string]$pd.BusType; Model = [string]$pd.FriendlyName
          HealthStatus = [string]$pd.HealthStatus; OperationalStatus = [string]($pd.OperationalStatus -join ',')
          SpindleSpeed = $pd.SpindleSpeed
          ReadErrorsTotal = $rel.ReadErrorsTotal; ReadErrorsUncorrected = $rel.ReadErrorsUncorrected; Wear = $rel.Wear
        }
        """;

    public Shared<StorageInfo> Info { get; }

    public StorageSource(IPowerShell ps, IWmi wmi)
    {
        _ps = ps;
        _wmi = wmi;
        Info = new Shared<StorageInfo>(FetchAsync);
    }

    private async Task<StorageInfo> FetchAsync(CancellationToken ct)
    {
        var row = (await _ps.RunJsonAsync(Script, ct)).EnumerateArray().FirstOrDefault();
        bool? predict = null;
        string? instance = null;
        try
        {
            // Not every controller exposes SMART through WMI (VMs, RAID, many NVMe drivers).
            foreach (var r in _wmi.Query(@"root\wmi", "SELECT InstanceName, PredictFailure FROM MSStorageDriver_FailurePredictStatus"))
            {
                var p = r["PredictFailure"] as bool? ?? false;
                predict = (predict ?? false) || p;
                if (p) instance = r["InstanceName"] as string;
            }
        }
        catch (ManagementException) { }

        return new StorageInfo
        {
            MediaType = row.Str("MediaType") ?? "",
            BusType = row.Str("BusType") ?? "",
            Model = row.Str("Model") ?? "",
            HealthStatus = row.Str("HealthStatus") ?? "",
            OperationalStatus = row.Str("OperationalStatus") ?? "",
            SpindleSpeed = row.Num("SpindleSpeed"),
            ReadErrorsTotal = row.Num("ReadErrorsTotal"),
            ReadErrorsUncorrected = row.Num("ReadErrorsUncorrected"),
            Wear = row.Num("Wear"),
            PredictFailure = predict,
            PredictFailureInstance = instance,
        };
    }
}
