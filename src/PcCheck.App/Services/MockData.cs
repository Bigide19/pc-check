using PcCheck.Core;

namespace PcCheck.App.Services;

// Sample result for laying out the screens (--mock) before real collectors exist.
public static class MockData
{
    public static ScanReport Report()
    {
        static Dictionary<string, string> Ev(params (string k, string v)[] kv) => kv.ToDictionary(x => x.k, x => x.v);

        return new ScanReport
        {
            ScannedAt = new DateTimeOffset(2026, 11, 5, 14, 20, 0, TimeSpan.FromHours(9)),
            SamplingSec = 120,
            Machine = new MachineInfo
            {
                Name = "SAMPLE-PC", Os = "Windows 10 22H2 (build 19045.6036)",
                Cpu = "Intel(R) Core(TM) i3-4130 CPU @ 3.40GHz", RamGb = 4, SystemDisk = "HDD",
                User = @"SAMPLE-PC\operator", IsAdmin = true,
            },
            Verdict = new VerdictResult(Verdict.HardwareReplace, Verdict.Cleanup, ["HW-DISK-TYPE", "RES-DISK"]),
            Scores = new ScoreSummary
            {
                Hardware = 30, Software = 71,
                ByCategory = new Dictionary<string, int>
                {
                    [Categories.Hardware] = 30, [Categories.Resource] = 15, [Categories.Startup] = 35,
                    [Categories.BrowserNetwork] = 15, [Categories.System] = 6, [Categories.Program] = 0,
                },
            },
            Findings =
            [
                new("HW-DISK-TYPE", Categories.Hardware, Severity.High, "시스템 드라이브가 HDD", "C: 드라이브가 HDD(SATA)입니다.", 15, "ADV-DISK-SSD",
                    Ev(("mediaType", "HDD"), ("busType", "SATA"), ("model", "ST500DM002-1BD142"))),
                new("HW-RAM", Categories.Hardware, Severity.High, "메모리 용량 부족", "설치된 메모리가 4GB입니다.", 15, "ADV-RAM",
                    Ev(("totalGb", "4"))),
                new("RES-DISK", Categories.Resource, Severity.High, "디스크 병목", "샘플링 중 디스크 Idle 평균 8%", 15, null,
                    Ev(("idleAvgPercent", "8"), ("queueAvg", "3.4"), ("queueP95", "7.1"))),
                new("ST-SUSPECT", Categories.Startup, Severity.High, "의심 시작 항목: ExampleUpdater",
                    @"서명 없는 실행 파일이 사용자 쓰기 가능 경로에서 시작됩니다.", 15, "RM-STARTUP-DISABLE",
                    Ev(("target", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ExampleUpdater"), ("name", "ExampleUpdater"),
                       ("command", @"""C:\Users\operator\AppData\Roaming\x7f3a\updater.exe"" /silent"),
                       ("path", @"C:\Users\operator\AppData\Roaming\x7f3a\updater.exe"), ("signature", "없음"),
                       ("approvedKey", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"))),
                new("TASK-SUSPECT", Categories.Startup, Severity.High, "의심 예약 작업: ExampleSync",
                    "인코딩된 PowerShell 명령.", 15, "RM-TASK-DISABLE",
                    Ev(("task", @"\ExampleSync"), ("taskPath", @"\"), ("taskName", "ExampleSync"),
                       ("execute", "powershell.exe"), ("arguments", "-NoProfile -enc SQBFAFgA..."), ("state", "Ready"))),
                new("NET-PROXY", Categories.BrowserNetwork, Severity.High, "프록시 설정됨",
                    "인터넷 연결이 다른 서버를 거치도록 설정되어 있습니다. 직접 설정한 적이 없다면 변조입니다.", 15, "RM-PROXY-RESET",
                    Ev(("proxyEnable", "True"), ("proxyServer", "127.0.0.1:8888"))),
                new("ST-COUNT", Categories.Startup, Severity.Medium, "시작 항목이 많음", "활성 시작 항목 18개 (기준 15개)", 5, "RM-STARTUP-DISABLE",
                    Ev(("enabled", "18"))),
                new("SYS-MISC", Categories.System, Severity.Low, "임시 파일 2.8GB", @"%TEMP%와 C:\Windows\Temp 합계", 1, "RM-TEMP-CLEAN",
                    Ev(("tempGb", "2.8"))),
                new("SYS-UPDATE", Categories.System, Severity.Medium, "재부팅 대기 중", "업데이트 설치 후 재부팅되지 않았습니다.", 5, "ADV-UPDATE",
                    Ev(("rebootRequired", "true"))),
                new("APP-RECENT", Categories.Program, Severity.Info, "최근 30일 설치 프로그램 3개", "판정 보조 정보", 0, null,
                    Ev(("1", "PDF Viewer Plus (2026-10-28)"), ("2", "KakaoTalk (2026-10-20)"), ("3", "Chrome (2026-10-11)"))),
            ],
            TopProcesses = new TopProcesses(
                [new("chrome", 4120, 23.5), new("MsMpEng", 2980, 11.2), new("SearchIndexer", 1544, 6.8), new("BusinessApp", 7712, 4.1), new("explorer", 5120, 2.0)],
                [new("chrome", 4120, 812), new("BusinessApp", 7712, 356), new("MsMpEng", 2980, 210), new("explorer", 5120, 140), new("KakaoTalk", 6620, 128)],
                [new("MsMpEng", 2980, 4.8), new("SearchIndexer", 1544, 3.1), new("System", 4, 2.2), new("chrome", 4120, 1.0), new("svchost", 1180, 0.6)]),
            CollectorErrors =
            [
                new("HW-DISK-HEALTH", CollectorStatus.Failed, "Get-PhysicalDisk가 이 디스크 컨트롤러를 지원하지 않습니다."),
            ],
        };
    }
}
