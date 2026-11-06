using PcCheck.Core;

namespace PcCheck.Report;

public static class Labels
{
    public static string Of(Verdict v) => v switch
    {
        Verdict.HardwareReplace => "하드웨어 교체 권장",
        Verdict.Format => "포맷 권장",
        Verdict.Cleanup => "정리로 충분",
        _ => "이상 없음",
    };

    public static string DescribeVerdict(Verdict v) => v switch
    {
        Verdict.HardwareReplace => "포맷으로는 해결되지 않는 하드웨어 문제가 있습니다. 디스크나 메모리 교체를 먼저 검토하세요.",
        Verdict.Format => "변조나 위협 흔적이 많아 정리만으로는 복구를 장담하기 어렵습니다. 백업 후 포맷을 검토하세요.",
        Verdict.Cleanup => "시작 항목, 불필요한 프로그램 등을 정리하면 개선될 가능성이 높습니다.",
        _ => "판정 기준에 해당하는 문제를 찾지 못했습니다.",
    };

    public static string Of(Severity s) => s switch
    {
        Severity.Critical => "심각",
        Severity.High => "높음",
        Severity.Medium => "보통",
        Severity.Low => "낮음",
        _ => "정보",
    };

    public static string Of(RiskLevel r) => r switch
    {
        RiskLevel.Auto => "자동 (승인 없이 실행)",
        RiskLevel.Confirm => "확인 (항목별 승인)",
        _ => "권고만",
    };

    public static string Of(CollectorStatus s) => s switch
    {
        CollectorStatus.Ok => "완료",
        CollectorStatus.Failed => "실패",
        CollectorStatus.TimedOut => "시간 초과",
        _ => "취소",
    };

    public static string Category(string c) => c switch
    {
        Categories.Hardware => "하드웨어",
        Categories.Resource => "리소스",
        Categories.Startup => "시작 항목",
        Categories.Program => "프로그램",
        Categories.BrowserNetwork => "브라우저와 네트워크",
        Categories.Security => "보안",
        Categories.System => "시스템",
        _ => c,
    };

    public static string CategoryShort(string c) => c == Categories.BrowserNetwork ? "브라우저·네트워크" : Category(c);

    public static string Collector(string id) => id switch
    {
        "SYS-INFO" => "PC 기본 정보",
        "HW-DISK-TYPE" => "디스크 종류",
        "HW-DISK-HEALTH" => "디스크 상태",
        "HW-DISK-FREE" => "여유 공간",
        "HW-RAM" => "메모리 용량",
        "SYS-DISPLAY" => "그래픽 드라이버",
        "RES-CPU" => "CPU 사용률 측정",
        "RES-MEM" => "메모리 압박 측정",
        "RES-DISK" => "디스크 병목 측정",
        "ST-COUNT" => "시작 항목 수",
        "ST-SUSPECT" => "의심 시작 항목",
        "SVC-SUSPECT" => "의심 서비스",
        "TASK-SUSPECT" => "의심 예약 작업",
        "APP-KNOWN-BAD" => "알려진 불필요 프로그램",
        "APP-RECENT" => "최근 설치 프로그램",
        "APP-PHOTOS" => "사진 앱",
        "BR-POLICY" => "브라우저 정책 변조",
        "BR-EXT" => "브라우저 확장 프로그램",
        "NET-HOSTS" => "hosts 변조",
        "NET-PROXY" => "프록시 변조",
        "SEC-AV" => "백신 상태",
        "SEC-THREAT" => "위협 이력, Defender 검사",
        "SYS-UPDATE" => "업데이트, 재부팅 대기",
        "SYS-EVENTS" => "시스템 로그 오류",
        "SYS-MISC" => "전원 계획, 임시 파일, 가동 시간",
        _ => id,
    };

    public static readonly string[] CategoryOrder =
    [
        Categories.Hardware, Categories.Resource, Categories.Startup, Categories.Program,
        Categories.BrowserNetwork, Categories.Security, Categories.System,
    ];
}
