namespace PcCheck.Core;

public sealed record RemediationInfo(string Id, RiskLevel Risk, string Name, bool Reversible, string? Advice = null);

public static class RemediationCatalog
{
    public static readonly IReadOnlyList<RemediationInfo> All =
    [
        new("RM-TEMP-CLEAN", RiskLevel.Auto, "임시 파일 정리 (1일 지난 파일)", false),
        new("RM-POWER-PLAN", RiskLevel.Auto, "전원 계획을 균형 조정으로 변경", true),
        new("RM-STARTUP-DISABLE", RiskLevel.Confirm, "시작 항목 비활성화", true),
        new("RM-SERVICE-DISABLE", RiskLevel.Confirm, "서비스 중지 후 사용 안 함으로 변경", true),
        new("RM-TASK-DISABLE", RiskLevel.Confirm, "예약 작업 비활성화", true),
        new("RM-UNINSTALL", RiskLevel.Confirm, "프로그램 제거 (제거 화면 실행)", false),
        new("RM-BROWSER-POLICY", RiskLevel.Confirm, "브라우저 강제 정책 삭제 (.reg 백업)", true),
        new("RM-HOSTS-RESET", RiskLevel.Confirm, "hosts 파일 초기화 (백업)", true),
        new("RM-PROXY-RESET", RiskLevel.Confirm, "프록시 설정 해제 (백업)", true),
        new("RM-DEFENDER", RiskLevel.Confirm, "Defender 실시간 보호 켜기, 정의 업데이트, 위협 제거", false),

        new("ADV-DISK-SSD", RiskLevel.AdviceOnly, "SSD 교체", false, "SSD로 바꾸면 부팅과 프로그램 실행이 몇 배 빨라집니다. 교체 전에 자료를 백업하세요."),
        new("ADV-DISK-HEALTH", RiskLevel.AdviceOnly, "디스크 즉시 교체", false, "디스크 고장이 임박했을 수 있습니다. 지금 바로 백업하고 디스크를 교체하세요. 포맷으로는 해결되지 않습니다."),
        new("ADV-DISK-FREE", RiskLevel.AdviceOnly, "여유 공간 확보", false, "C: 여유 공간을 15% 이상 확보하세요. 디스크 정리, 다운로드 폴더, 휴지통부터 비우세요."),
        new("ADV-RAM", RiskLevel.AdviceOnly, "메모리 증설", false, "메모리를 8GB 이상으로 늘리는 것을 권장합니다."),
        new("ADV-CPU", RiskLevel.AdviceOnly, "CPU 사용 프로세스 확인", false, "상위 프로세스에서 CPU를 많이 쓰는 프로그램을 확인하세요. 평소에도 계속 높다면 CPU 성능의 한계입니다."),
        new("ADV-MEM", RiskLevel.AdviceOnly, "메모리 사용 줄이기", false, "동시에 띄운 프로그램과 브라우저 탭을 줄이거나 메모리를 늘리세요."),
        new("ADV-DISK-IO", RiskLevel.AdviceOnly, "디스크 병목 해소", false, "디스크가 계속 바쁩니다. HDD라면 SSD 교체가 가장 효과적입니다."),
        new("ADV-EXT", RiskLevel.AdviceOnly, "확장 프로그램 직접 제거", false, "브라우저 확장 관리 화면(chrome://extensions, edge://extensions)에서 모르는 확장을 직접 제거하세요. 툴이 직접 지우면 프로필이 손상될 수 있습니다."),
        new("ADV-UPDATE", RiskLevel.AdviceOnly, "Windows 업데이트 실행", false, "설정의 Windows 업데이트에서 업데이트를 설치하세요."),
        new("ADV-REBOOT", RiskLevel.AdviceOnly, "재부팅", false, "시작 메뉴에서 '다시 시작'을 누르세요. '시스템 종료'는 빠른 시작 때문에 완전히 재시작되지 않습니다."),
        new("ADV-DISK-CHECK", RiskLevel.AdviceOnly, "디스크 검사", false, "디스크 오류가 기록되어 있습니다. 백업 후 디스크 검사(chkdsk)와 교체를 검토하세요."),
        new("ADV-POWER", RiskLevel.AdviceOnly, "전원, 과열 점검", false, "전원 케이블과 멀티탭, 본체 과열(먼지), 드라이버를 점검하세요."),
        new("ADV-AV-UPDATE", RiskLevel.AdviceOnly, "백신 업데이트", false, "백신 프로그램을 열어 업데이트하세요."),
        new("ADV-PHOTOS", RiskLevel.AdviceOnly, "사진 앱 복구", false, "설정 > 앱 > 설치된 앱 > 사진 > 고급 옵션에서 복구, 초기화 순서로 해 보세요. 그래도 안 되면 사진 앱을 지우고 Microsoft Store에서 다시 설치하세요. 원인이 그래픽 드라이버나 백신으로 나오면 그쪽을 먼저 고치세요."),
        new("ADV-GPU-DRIVER", RiskLevel.AdviceOnly, "그래픽 드라이버 재설치", false, "그래픽카드 제조사(Intel, NVIDIA, AMD) 사이트에서 최신 드라이버를 받아 설치하세요. 화면 깜빡임이 함께 있다면 케이블 재연결, 고정 주사율(60Hz), 가변 주사율 끄기도 확인하세요."),
        new("ADV-AV-DUP", RiskLevel.AdviceOnly, "백신 하나만 사용", false, "백신은 하나만 쓰세요. 쓰지 않는 백신을 제거하면 속도가 좋아집니다."),
    ];

    public static RemediationInfo? Find(string? id) =>
        id is null ? null
        : All.FirstOrDefault(r => r.Id == id)
          ?? (id.StartsWith("ADV-", StringComparison.Ordinal) ? new RemediationInfo(id, RiskLevel.AdviceOnly, "권고 사항", false) : null);
}
