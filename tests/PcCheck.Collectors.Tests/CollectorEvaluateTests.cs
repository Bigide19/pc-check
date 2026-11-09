using PcCheck.Collectors.Browser;
using PcCheck.Collectors.Hardware;
using PcCheck.Collectors.Infra;
using PcCheck.Collectors.Programs;
using PcCheck.Collectors.Resource;
using PcCheck.Collectors.Security;
using PcCheck.Collectors.Startup;
using PcCheck.Collectors.SystemItems;
using PcCheck.Core;
using PcCheck.Core.Config;

namespace PcCheck.Collectors.Tests;

public class CollectorEvaluateTests
{
    private static readonly PcCheckConfig Config = LoadConfig();
    private static RulesConfig Rules => Config.Rules;

    private static PcCheckConfig LoadConfig()
    {
        var c = PcCheckConfig.Default();
        foreach (var p in c.KnownBad.Programs)
            p.Regex = new System.Text.RegularExpressions.Regex(p.Match, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        c.Protect.Programs.Add(new ProtectProgram { DisplayNameMatch = "업무 프로그램", Regex = new("업무 프로그램") });
        c.Protect.Paths.Add(@"C:\Users\kim\AppData\Local\MemberApp\");
        return c;
    }

    private static Severity? Sev(IReadOnlyList<Finding> f) => f.Count == 0 ? null : f.Max(x => x.Severity);

    // Hardware

    [Theory]
    [InlineData("HDD", "SATA", null, Severity.High)]
    [InlineData("SSD", "NVMe", null, null)]
    [InlineData("Unspecified", "SATA", 7200.0, Severity.High)]
    [InlineData("Unspecified", "SATA", 0.0, null)]
    [InlineData("Unspecified", "Virtual", null, Severity.Info)]
    public void DiskType(string media, string bus, double? spindle, Severity? expected) =>
        Assert.Equal(expected, Sev(DiskTypeCollector.Evaluate(new StorageInfo { MediaType = media, BusType = bus, SpindleSpeed = spindle })));

    [Fact]
    public void Finding_text_follows_the_current_language()
    {
        var hdd = new StorageInfo { MediaType = "HDD", BusType = "SATA" };
        Assert.Equal("시스템 드라이브가 HDD", DiskTypeCollector.Evaluate(hdd).Single().Title);
        Lang.Set("en");
        try
        {
            var f = DiskTypeCollector.Evaluate(hdd).Single();
            Assert.Equal("System drive is an HDD", f.Title);
            Assert.StartsWith("Drive C: is an HDD (SATA).", f.Detail);
        }
        finally { Lang.Set("ko"); }
    }

    [Theory]
    [InlineData("Healthy", true, 0.0, Severity.Critical)]
    [InlineData("Unhealthy", null, 0.0, Severity.Critical)]
    [InlineData("Healthy", false, 12.0, Severity.High)]
    [InlineData("Warning", false, 0.0, Severity.High)]
    [InlineData("Healthy", false, 0.0, null)]
    public void DiskHealth(string health, bool? predict, double readErrors, Severity? expected) =>
        Assert.Equal(expected, Sev(DiskHealthCollector.Evaluate(new StorageInfo { HealthStatus = health, PredictFailure = predict, ReadErrorsTotal = readErrors })));

    [Theory]
    [InlineData(100, 4, Severity.High)]
    [InlineData(100, 10, Severity.Medium)]
    [InlineData(100, 30, null)]
    public void DiskFree(double size, double free, Severity? expected) =>
        Assert.Equal(expected, Sev(DiskFreeCollector.Evaluate(new VolumeInfo(size, free), Rules)));

    [Theory]
    [InlineData(4, Severity.High)]
    [InlineData(3.9, Severity.High)]
    [InlineData(6, Severity.Medium)]
    [InlineData(8, null)]
    public void Ram(double gb, Severity? expected) => Assert.Equal(expected, Sev(RamCollector.Evaluate(gb, Rules)));

    // Resource

    private static ResourceSnapshot Snap(double cpu = 10, double avail = 4000, double commit = 50, double idle = 90, double queue = 0.2) =>
        new(120, new Series(cpu, cpu, 60), new Series(avail, avail, 60), new Series(commit, commit, 60),
            new Series(idle, idle, 60), new Series(queue, queue, 60), new TopProcesses([], [], []));

    [Theory]
    [InlineData(90, Severity.High)]
    [InlineData(70, Severity.Medium)]
    [InlineData(40, null)]
    public void Cpu(double avg, Severity? expected) => Assert.Equal(expected, Sev(CpuCollector.Check(Snap(cpu: avg), Rules)));

    [Fact]
    public void Memory()
    {
        Assert.Equal(Severity.High, Sev(MemoryCollector.Check(Snap(avail: 800), Rules)));
        Assert.Equal(Severity.High, Sev(MemoryCollector.Check(Snap(commit: 95), Rules)));
        Assert.Null(Sev(MemoryCollector.Check(Snap(), Rules)));
    }

    [Fact]
    public void DiskIo()
    {
        Assert.Equal(Severity.High, Sev(DiskIoCollector.Check(Snap(idle: 8), Rules)));
        Assert.Equal(Severity.High, Sev(DiskIoCollector.Check(Snap(queue: 3.4), Rules)));
        Assert.Null(Sev(DiskIoCollector.Check(Snap(), Rules)));
    }

    [Fact]
    public void Series_percentile()
    {
        var s = Series.Of(Enumerable.Range(1, 100).Select(i => (double)i).ToList())!;
        Assert.Equal(50.5, s.Avg);
        Assert.Equal(95, s.P95);
    }

    // Startup, services, tasks

    private static StartupEntry Entry(string name, string path, bool enabled = true) =>
        new() { Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", Name = name, Command = $"\"{path}\" /bg", TargetPath = path, Enabled = enabled };

    [Fact]
    public void StartupCount()
    {
        var many = Enumerable.Range(0, 16).Select(i => Entry($"app{i}", $@"C:\Program Files\App{i}\a.exe")).ToList();
        Assert.Equal(Severity.Medium, Sev(StartupCountCollector.Evaluate(many, Rules)));
        // Disabled entries do not count.
        Assert.Null(Sev(StartupCountCollector.Evaluate(many.Select((e, i) => i < 2 ? e with { Enabled = false } : e).ToList(), Rules)));
    }

    [Fact]
    public void StartupSuspect()
    {
        var bad = Entry("Updater", @"C:\Users\kim\AppData\Roaming\x7f3a91\updater.exe");
        var signed = Entry("Teams", @"C:\Users\kim\AppData\Local\Microsoft\Teams\Update.exe");
        var programFiles = Entry("Vendor", @"C:\Program Files\Vendor\tray.exe");
        var protectedApp = Entry("Member", @"C:\Users\kim\AppData\Local\MemberApp\member.exe");
        var sigs = new Dictionary<string, SignatureInfo>(StringComparer.OrdinalIgnoreCase)
        {
            [bad.TargetPath!] = new("NotSigned", null),
            [signed.TargetPath!] = new("Valid", "CN=Microsoft Corporation, O=Microsoft Corporation"),
            [programFiles.TargetPath!] = new("NotSigned", null),
            [protectedApp.TargetPath!] = new("NotSigned", null),
        };
        var f = StartupSuspectCollector.Evaluate([bad, signed, programFiles, protectedApp], sigs, Config.Protect);
        Assert.Equal("의심 시작 항목: Updater", Assert.Single(f).Title);
    }

    [Fact]
    public void ServiceSuspect()
    {
        var services = new List<ServiceEntry>
        {
            new("evil", "Evil Svc", @"C:\ProgramData\abc123x\svc.exe", @"C:\ProgramData\abc123x\svc.exe", "Running"),
            new("ok", "Good Svc", @"C:\Program Files\Good\svc.exe", @"C:\Program Files\Good\svc.exe", "Running"),
            new("gone", "Gone Svc", @"C:\Gone\svc.exe", @"C:\Gone\svc.exe", "Stopped"),
        };
        var sigs = new Dictionary<string, SignatureInfo>(StringComparer.OrdinalIgnoreCase)
        {
            [@"C:\ProgramData\abc123x\svc.exe"] = new("NotSigned", null),
            [@"C:\Program Files\Good\svc.exe"] = new("Valid", "CN=Good, O=Good Inc"),
            [@"C:\Gone\svc.exe"] = new("Missing", null),
        };
        Assert.Equal("evil", Assert.Single(ServiceSuspectCollector.Evaluate(services, sigs, Config.Protect)).Evidence["service"]);
    }

    [Theory]
    [InlineData(@"\", "Upd", @"C:\Users\kim\AppData\Local\Temp\a.exe", "", true)]
    [InlineData(@"\", "Ps", "powershell.exe", "-NoP -enc SQBFAFgA", true)]
    [InlineData(@"\", "Ps2", "powershell.exe", "-ExecutionPolicy Bypass -File C:\\Tools\\x.ps1", false)]
    [InlineData(@"\", "Hta", "mshta.exe", "http://x/y.hta", true)]
    [InlineData(@"\Microsoft\Windows\Subscription\", "EnableLicenseAcquisition", @"%SystemRoot%\system32\ClipRenew.exe", "-e", false)]
    [InlineData(@"\Microsoft\Windows\X\", "Wsh", "wscript.exe", @"C:\Windows\System32\x.vbs", false)]
    public void TaskSuspect(string path, string name, string exe, string args, bool flagged) =>
        Assert.Equal(flagged, TaskSuspectCollector.Evaluate([new TaskEntry(path, name, exe, args, "Ready")], Config.Protect).Count == 1);

    [Fact]
    public void Path_rules()
    {
        Assert.True(PathRules.IsUserWritable(@"C:\Users\a\AppData\Roaming\x\y.exe"));
        Assert.True(PathRules.IsUserWritable(@"C:\ProgramData\a8f3k29d\y.exe"));
        Assert.False(PathRules.IsUserWritable(@"C:\ProgramData\Microsoft\y.exe"));
        Assert.False(PathRules.IsUserWritable(@"C:\Program Files\x\y.exe"));
        Assert.Equal(@"C:\Users\a\AppData\x.dll", PathRules.ExtractTarget(@"rundll32.exe C:\Users\a\AppData\x.dll,Start"));
        Assert.Equal(@"C:\Program Files\App\app.exe", PathRules.ExtractTarget("\"C:\\Program Files\\App\\app.exe\" --tray"));
    }

    [Fact]
    public void Startup_approved_bytes()
    {
        Assert.True(StartupSource.IsEnabled(null));
        Assert.True(StartupSource.IsEnabled([0x02, 0, 0]));
        Assert.True(StartupSource.IsEnabled([0x06, 0, 0]));
        Assert.False(StartupSource.IsEnabled([0x03, 0, 0]));
    }

    // Programs

    [Fact]
    public void KnownBad()
    {
        var programs = new List<InstalledProgram>
        {
            new("Super PC Optimizer 2026", "X", null, "uninst.exe", "k1"),
            new("Driver Booster", "Y", null, "u.exe", "k2"),
            new("Chrome", "Google", null, "u.exe", "k3"),
            new("업무 프로그램 PC Booster", "Z", null, "u.exe", "k4"),
        };
        var f = KnownBadProgramCollector.Evaluate(programs, Config.KnownBad, Config.Protect);
        Assert.Equal(["Super PC Optimizer 2026", "Driver Booster"], f.Select(x => x.Evidence["displayName"]));
    }

    [Fact]
    public void Recent()
    {
        var today = new DateOnly(2026, 11, 5);
        var programs = new List<InstalledProgram>
        {
            new("A", null, new DateOnly(2026, 11, 1), null, "k"),
            new("B", null, new DateOnly(2026, 9, 1), null, "k"),
        };
        var f = Assert.Single(RecentProgramCollector.Evaluate(programs, Rules, today));
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Single(f.Evidence);
    }

    // Browser and network

    [Fact]
    public void BrowserPolicy()
    {
        var p = new BrowserPolicy("Chrome", @"HKLM\SOFTWARE\Policies\Google\Chrome", new Dictionary<string, string> { ["HomepageLocation"] = "http://bad" });
        Assert.Equal(Severity.High, Sev(BrowserPolicyCollector.Evaluate([p])));
        Assert.Empty(BrowserPolicyCollector.Evaluate([]));
    }

    [Fact]
    public void BrowserExtension()
    {
        var exts = new List<BrowserExtension>
        {
            new("Chrome", "kim/Default", "abc", "Side Loaded", false, 4, true),
            new("Chrome", "kim/Default", "def", "AdBlock", true, 1, true),
        };
        var f = BrowserExtensionCollector.Evaluate(exts, Config.KnownBad);
        Assert.Equal(Severity.High, f.Single(x => x.Evidence.ContainsKey("id")).Severity);
        Assert.Equal(Severity.Info, f.Single(x => !x.Evidence.ContainsKey("id")).Severity);
    }

    [Fact]
    public void Hosts()
    {
        const string clean = "# comment\n127.0.0.1 localhost\n::1 localhost\n";
        Assert.Empty(HostsCollector.Evaluate(HostsCollector.Parse(clean), Config.KnownBad));
        Assert.Equal(Severity.Medium, Sev(HostsCollector.Evaluate(HostsCollector.Parse(clean + "0.0.0.0 ads.example.com"), Config.KnownBad)));
        Assert.Equal(Severity.Critical, Sev(HostsCollector.Evaluate(HostsCollector.Parse(clean + "1.2.3.4 www.kbstar.com"), Config.KnownBad)));
    }

    [Fact]
    public void Proxy()
    {
        Assert.Empty(ProxyCollector.Evaluate(new ProxySettings(false, "1.2.3.4:8080", null)));
        Assert.Equal(Severity.High, Sev(ProxyCollector.Evaluate(new ProxySettings(true, "1.2.3.4:8080", null))));
        Assert.Equal(Severity.High, Sev(ProxyCollector.Evaluate(new ProxySettings(false, null, "http://x/proxy.pac"))));
    }

    // Security

    private const int On = 0x061000, Off = 0x060000, OnStale = 0x061010;

    [Fact]
    public void Antivirus()
    {
        var healthy = new AvStatus { DefenderAvailable = true, RealTimeProtection = true, RunningMode = "Normal", SignatureAgeDays = 1, Products = [new("Windows Defender", On)] };
        Assert.Empty(AntivirusCollector.Evaluate(healthy, Rules));
        Assert.Equal(Severity.High, Sev(AntivirusCollector.Evaluate(healthy with { RealTimeProtection = false, Products = [new("Windows Defender", Off)] }, Rules)));
        Assert.Equal(Severity.Medium, Sev(AntivirusCollector.Evaluate(healthy with { SignatureAgeDays = 10 }, Rules)));
        Assert.Equal(Severity.Medium, Sev(AntivirusCollector.Evaluate(healthy with { Products = [new("Windows Defender", On), new("V3 Lite", On)] }, Rules)));
        // Defender passive behind a third-party AV is fine.
        var thirdParty = new AvStatus { DefenderAvailable = true, RealTimeProtection = false, RunningMode = "Passive Mode", Products = [new("V3 Lite", On)] };
        Assert.Empty(AntivirusCollector.Evaluate(thirdParty, Rules));
        Assert.Equal(Severity.Medium, Sev(AntivirusCollector.Evaluate(thirdParty with { Products = [new("V3 Lite", OnStale)] }, Rules)));
    }

    [Fact]
    public void Threats()
    {
        var now = new DateTimeOffset(2026, 11, 5, 12, 0, 0, TimeSpan.FromHours(9));
        ThreatDetection D(int status, int daysAgo) => new("1" + status + daysAgo, "Trojan:Win32/X", status, status is 2 or 3 or 4, null, now.AddDays(-daysAgo), "file:_C:\\x.exe");
        Assert.Equal(Severity.Critical, Sev(ThreatCollector.Evaluate(new([D(1, 2)], DefenderScanType.Quick, null), now)));
        Assert.Equal(Severity.Medium, Sev(ThreatCollector.Evaluate(new([D(3, 5)], DefenderScanType.None, null), now)));
        Assert.Empty(ThreatCollector.Evaluate(new([D(3, 60)], DefenderScanType.None, null), now));
    }

    // System

    [Fact]
    public void Update()
    {
        var now = new DateTimeOffset(2026, 11, 5, 0, 0, 0, TimeSpan.Zero);
        Assert.Empty(UpdateCollector.Evaluate(new(false, false, false, "KB1", now.AddDays(-10)), Rules, now));
        Assert.Single(UpdateCollector.Evaluate(new(true, false, false, "KB1", now.AddDays(-10)), Rules, now));
        Assert.Equal(2, UpdateCollector.Evaluate(new(false, true, false, "KB1", now.AddDays(-90)), Rules, now).Count);
    }

    [Fact]
    public void Events()
    {
        var t = DateTimeOffset.Now;
        Assert.Equal(Severity.High, Sev(EventLogCollector.Evaluate([new(7, "disk", t)], Rules)));
        Assert.Empty(EventLogCollector.Evaluate([new(7, "Microsoft-Windows-Something", t)], Rules));
        Assert.Equal(Severity.Medium, Sev(EventLogCollector.Evaluate(Enumerable.Repeat(new SystemEvent(41, "Microsoft-Windows-Kernel-Power", t), 3).ToList(), Rules)));
        Assert.Empty(EventLogCollector.Evaluate(Enumerable.Repeat(new SystemEvent(41, "Microsoft-Windows-Kernel-Power", t), 2).ToList(), Rules));
    }

    [Fact]
    public void Misc()
    {
        var f = MiscCollector.Evaluate(new MiscInfo(MiscCollector.PowerSaver, "절전", 3L * 1024 * 1024 * 1024, TimeSpan.FromDays(20)), Rules);
        Assert.Equal(3, f.Count);
        Assert.All(f, x => Assert.Equal(Severity.Low, x.Severity));
        Assert.Empty(MiscCollector.Evaluate(new MiscInfo(Guid.NewGuid(), "균형 조정", 1024, TimeSpan.FromDays(1)), Rules));
    }
}

public class PhotosAndDisplayTests
{
    private static readonly RulesConfig Rules = new();
    private static AppCrash Crash(string module) => new(DateTimeOffset.Now, "Microsoft.Photos.exe", module, "c0000005");

    [Fact]
    public void Photos_leaves_crashes_to_APP_CRASHES() =>
        Assert.Empty(PhotosCollector.Evaluate(new PhotosStatus { Installed = true, Status = "Ok", Crashes = [Crash("igd10iumd64.dll")] }));

    [Theory]
    [InlineData("d3d11.dll", "그래픽 드라이버")]
    [InlineData("aswhook.dll", "백신")]
    [InlineData("KERNELBASE.dll", null)]
    public void Crash_module_cause(string module, string? cause) => Assert.Equal(cause, PhotosCollector.CauseOf(module));

    [Fact]
    public void Photos_package_states()
    {
        Assert.Empty(PhotosCollector.Evaluate(new PhotosStatus { Installed = true, Status = "Ok" }));
        Assert.Equal(Severity.High, PhotosCollector.Evaluate(new PhotosStatus { Installed = true, Status = "Modified" }).Single().Severity);
        Assert.Equal(Severity.Medium, PhotosCollector.Evaluate(new PhotosStatus { Installed = false }).Single().Severity);
        Assert.Equal(Severity.Medium, PhotosCollector.Evaluate(new PhotosStatus { Installed = true, Status = "Ok", ActivationFailures = 2 }).Single().Severity);
    }

    [Fact]
    public void Headless_system_run_is_not_reported_as_missing_when_a_user_has_it() =>
        Assert.Empty(PhotosCollector.Evaluate(new PhotosStatus { RunningAsSystem = true, Installed = false, InstalledForAnyUser = true, Status = "Ok" }));

    [Fact]
    public void Display_checks()
    {
        var ok = new VideoAdapter("Intel(R) UHD Graphics 630", "31.0.101.2125", "2023-04-01", 0);
        Assert.Empty(DisplayCollector.Evaluate(new DisplayStatus([ok], 0), Rules));
        Assert.Equal(Severity.Medium, DisplayCollector.Evaluate(new DisplayStatus([ok], 2), Rules).Single().Severity);
        Assert.Equal(Severity.High, DisplayCollector.Evaluate(new DisplayStatus([new("Microsoft 기본 디스플레이 어댑터", "10.0", "2006-06-21", 0)], 0), Rules).Single().Severity);
        Assert.Equal(Severity.High, DisplayCollector.Evaluate(new DisplayStatus([ok with { ErrorCode = 43 }], 0), Rules).Single().Severity);
    }
}

public class SignatureRobustnessTests
{
    private sealed class FakePs(Func<string, string> respond) : IPowerShell
    {
        public List<string> Scripts { get; } = [];
        public Task<System.Text.Json.JsonElement> RunJsonAsync(string script, CancellationToken ct)
        {
            Scripts.Add(script);
            return Task.FromResult(System.Text.Json.JsonDocument.Parse(respond(script)).RootElement);
        }
    }

    [Fact]
    public async Task Verifier_chunks_paths_and_keeps_per_file_errors()
    {
        var paths = Enumerable.Range(0, 95).Select(i => $@"C:\Users\a\AppData\Local\app{i}\a.exe").ToList();
        var ps = new FakePs(script =>
        {
            var json = System.Text.RegularExpressions.Regex.Match(script, @"\$paths = '(.*)' \| ConvertFrom-Json").Groups[1].Value.Replace("''", "'");
            var batch = System.Text.Json.JsonSerializer.Deserialize<string[]>(json)!;
            return System.Text.Json.JsonSerializer.Serialize(batch.Select((p, i) =>
                new { Path = p, Status = i == 0 ? "Error" : "Valid", Signer = (string?)null, Error = i == 0 ? "Access denied" : null }));
        });
        var result = await new SignatureVerifier(ps).VerifyAsync(paths, default);
        Assert.Equal(3, ps.Scripts.Count);
        Assert.Equal(95, result.Count);
        Assert.True(result[paths[0]].IsUnknown);
        Assert.Equal("Access denied", result[paths[0]].Error);
        Assert.True(result[paths[1]].IsValid);
    }

    [Fact]
    public void Unreadable_startup_file_is_info_not_a_suspect()
    {
        var entry = new StartupEntry { Location = "HKCU", Name = "StoreApp", Command = "x", TargetPath = @"C:\Users\a\AppData\Local\x\a.exe" };
        var f = Assert.Single(StartupSuspectCollector.Evaluate([entry],
            new Dictionary<string, SignatureInfo> { [entry.TargetPath!] = new("Error", null, "Access denied") }, new ProtectConfig()));
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("Access denied", f.Evidence["01"]);
    }

    [Fact]
    public void Clixml_error_text_is_decoded()
    {
        const string clixml = "#< CLIXML\r\n<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\"><S S=\"Error\">Get-AuthenticodeSignature : 액세스가 거부되었습니다._x000D__x000A_</S><S S=\"Error\">위치 줄:5 문자:12_x000D__x000A_</S></Objs>";
        Assert.Equal("Get-AuthenticodeSignature : 액세스가 거부되었습니다.", PowerShellRunner.ErrorText(clixml));
        Assert.Equal("plain failure", PowerShellRunner.ErrorText("plain failure\n+ CategoryInfo"));
    }
}

public class DefenderReasonTests
{
    [Fact]
    public void Refused_scan_names_the_primary_antivirus()
    {
        var r = new ThreatReport([], DefenderScanType.Full, "Errors were encountered when attempted to scan your device.")
        { RunningMode = "Passive Mode", OtherAntivirus = ["ALYac", "Avast Antivirus"] };
        var f = Assert.Single(ThreatCollector.Evaluate(r, DateTimeOffset.Now));
        Assert.Equal(Severity.Info, f.Severity);
        Assert.Contains("ALYac, Avast Antivirus", f.Detail);
        Assert.Equal(0, f.Score);
    }

    [Fact]
    public void Refused_scan_without_other_antivirus_keeps_the_raw_error() =>
        Assert.Contains("boom", ThreatCollector.Evaluate(new ThreatReport([], DefenderScanType.Quick, "boom") { RunningMode = "Normal" }, DateTimeOffset.Now).Single().Detail);
}

public class CrashAndKrModuleTests
{
    private static PcCheckConfig Config() => PcCheckConfig.Default();

    private static CrashEvent Crash(string app, string appPath, string module, string modulePath) =>
        new(DateTimeOffset.Now, app, appPath, module, modulePath, "c0000005");

    private const string PhotosPath = @"C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2025.11010.4004.0_x64__8wekyb3d8bbwe\Photos.exe";

    // The 2026-11-06 field case, names removed: TouchEn nxKey's injected DLL killed the Photos app 21 times.
    [Fact]
    public void Field_case_names_TouchEn_nxKey_and_offers_its_uninstaller()
    {
        const string dll = @"C:\Program Files (x86)\RaonSecure\TouchEn nxKey\TENXWGuard64_127.dll";
        var events = Enumerable.Repeat(Crash("Photos.exe", PhotosPath, "TENXWGuard64_127.dll", dll), 21).ToList();
        var programs = new List<InstalledProgram>
        {
            new("TouchEn nxKey with E2E for 64bit", "RaonSecure Co., Ltd.", null, @"""C:\Program Files (x86)\RaonSecure\TouchEn nxKey\unins000.exe""", "HKLM\\x")
            { InstallLocation = @"C:\Program Files (x86)\RaonSecure\TouchEn nxKey\" },
        };
        var f = Assert.Single(CrashCollector.Evaluate(events, _ => new ModuleOwner("RaonSecure Co., Ltd.", "TouchEn nxKey"), programs, Config()));
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal("RM-UNINSTALL", f.RemediationId);
        Assert.Equal("KoreanSecurity", f.Evidence["cause"]);
        Assert.Equal("21", f.Evidence["crashes7d"]);
        Assert.Contains("TouchEn nxKey", f.Title);
        Assert.Contains("unins000.exe", f.Evidence["uninstallString"]);
    }

    [Fact]
    public void App_crashing_in_its_own_files_is_not_blamed_on_anyone() =>
        Assert.Empty(CrashCollector.Evaluate(
            Enumerable.Repeat(Crash("chrome.exe", @"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.dll", @"C:\Program Files\Google\Chrome\Application\140.0\chrome.dll"), 6).ToList(),
            _ => new ModuleOwner("Google LLC", "Google Chrome"), [], Config()));

    [Fact]
    public void Microsoft_modules_are_skipped() =>
        Assert.Empty(CrashCollector.Evaluate(
            Enumerable.Repeat(Crash("Photos.exe", PhotosPath, "KERNELBASE.dll", @"C:\Windows\System32\KERNELBASE.dll"), 9).ToList(),
            _ => new ModuleOwner("Microsoft Corporation", "Microsoft® Windows® Operating System"), [], Config()));

    [Fact]
    public void Graphics_driver_gets_driver_advice_not_uninstall()
    {
        var f = Assert.Single(CrashCollector.Evaluate(
            Enumerable.Repeat(Crash("Photos.exe", PhotosPath, "amdxx64.dll", @"C:\Windows\System32\DriverStore\FileRepository\u0399.inf_amd64\B399\amdxx64.dll"), 3).ToList(),
            _ => new ModuleOwner("Advanced Micro Devices, Inc.", "AMD driver"), [], Config()));
        Assert.Equal("ADV-GPU-DRIVER", f.RemediationId);
    }

    [Fact]
    public void One_crash_is_below_the_threshold() =>
        Assert.Empty(CrashCollector.Evaluate([Crash("app.exe", @"C:\Apps\app.exe", "hook.dll", @"C:\Vendor\hook.dll")],
            _ => new ModuleOwner("Vendor", "Hook"), [], Config()));

    // The field case's startup entries (names and paths only).
    private static readonly (string Name, string Path)[] FieldStartup =
    [
        ("wizvera-veraport-x64", @"C:\Program Files\Wizvera\Veraport20\veraport-x64.exe"),
        ("AhnLab Safe Transaction Application", @"C:\Program Files\AhnLab\Safe Transaction\stsess.exe"),
        ("ipinside-lws", @"C:\Program Files (x86)\IPinside_LWS\I3GProc.exe"),
        ("MagicLine4NX", @"C:\Program Files (x86)\DreamSecurity\MagicLine4NX\MagicLine4NX.exe"),
        ("wizvera-delfino-pc", @"C:\Program Files (x86)\Wizvera\Delfino-G3\delfino.exe"),
        ("CROSSCERT UniCRSV3", @"C:\Program Files (x86)\Crosscert\UniSignCRSV3\UniCRSLocalServer.exe"),
        ("MaEPSBroker", @"C:\Program Files (x86)\MarkAny\EPSBroker\MaEPSBroker.exe"),
        ("AnySign4PC", @"C:\Program Files (x86)\SoftForum\XecureWeb\AnySign\dll\AnySign4PC.exe"),
        ("CrossEXService", @"C:\Program Files (x86)\iniLINE\CrossEX\crossex\CrossEXService.exe"),
        ("KakaoTalk", @"C:\Program Files (x86)\Kakao\KakaoTalk\KakaoTalk.exe"),
    ];

    [Fact]
    public void Field_startup_list_yields_the_nine_security_modules_and_not_KakaoTalk()
    {
        var entries = FieldStartup.Select(e => new StartupEntry { Location = "HKLM", Name = e.Name, Command = e.Path, TargetPath = e.Path }).ToList();
        var f = KrModulesCollector.Evaluate([], entries, Config());
        Assert.Equal(9, f.Count);
        Assert.DoesNotContain(f, x => x.Title.Contains("KakaoTalk"));
        Assert.All(f, x => Assert.Equal("ADV-KR-MODULES", x.RemediationId));
    }

    [Fact]
    public void Installed_module_becomes_an_uninstall_target_unless_protected()
    {
        var p = new InstalledProgram("TouchEn nxKey with E2E for 64bit", "RaonSecure", null, "unins000.exe", "k");
        Assert.Equal("RM-UNINSTALL", KrModulesCollector.Evaluate([p], [], Config()).Single().RemediationId);
        var cfg = Config();
        cfg.Protect.Programs.Add(new ProtectProgram { DisplayNameMatch = "TouchEn", Regex = new("TouchEn") });
        Assert.Empty(KrModulesCollector.Evaluate([p], [], cfg));
    }

    [Fact]
    public void Security_module_service_is_not_a_suspect()
    {
        var svc = new ServiceEntry("CrossEXService", "CrossEX Service", @"C:\Program Files (x86)\iniLINE\CrossEX\crossex\CrossEXService.exe",
            @"C:\Program Files (x86)\iniLINE\CrossEX\crossex\CrossEXService.exe", "Running");
        var sigs = new Dictionary<string, SignatureInfo>(StringComparer.OrdinalIgnoreCase) { [svc.TargetPath!] = new("NotSigned", null) };
        Assert.Single(ServiceSuspectCollector.Evaluate([svc], sigs, new ProtectConfig()));
        Assert.Empty(ServiceSuspectCollector.Evaluate([svc], sigs, new ProtectConfig(), Config().KrModules));
    }
}

public class KrModulePathTests
{
    [Theory]
    [InlineData(@"C:\Program Files\AhnLab\Safe Transaction\stsess.exe", "ahnlab-safe-transaction")]
    [InlineData(@"C:\Program Files\Wizvera\Veraport20\veraport-x64.exe", "veraport")]
    [InlineData(@"C:\Program Files (x86)\RaonSecure\TouchEn nxKey\TENXWGuard64_127.dll", "touchen-nxkey")]
    [InlineData(@"C:\Program Files\AhnLab\V3Lite40\V3Lite.exe", null)]
    public void Built_in_path_patterns_match_real_install_folders(string path, string? id) =>
        Assert.Equal(id, new KrModulesConfig().MatchPath(path)?.Id);
}

public class SignatureScriptShapeTests
{
    [Fact]
    public void Script_assigns_the_parsed_array_before_enumerating_it()
    {
        var script = SignatureVerifier.Script([@"C:\a.exe", @"C:\b.exe"]);
        Assert.Contains("$paths = '", script);
        Assert.DoesNotContain("@('", script);
        Assert.Contains("foreach ($p in @($paths))", script);
    }

    [Fact]
    public async Task Unmatched_output_fails_instead_of_marking_everything_unknown()
    {
        var ps = new FakeAll("[{\"Path\":[\"C:\\\\a.exe\",\"C:\\\\b.exe\"],\"Status\":\"Valid\"}]");
        await Assert.ThrowsAsync<PowerShellException>(() => new SignatureVerifier(ps).VerifyAsync([@"C:\a.exe", @"C:\b.exe"], default));
    }

    private sealed class FakeAll(string json) : IPowerShell
    {
        public Task<System.Text.Json.JsonElement> RunJsonAsync(string script, CancellationToken ct) =>
            Task.FromResult(System.Text.Json.JsonDocument.Parse(json).RootElement);
    }
}
