# [명세] 윈도우 PC 점검 툴 설계

2026년 11월 5일 · 이대연

## 변경 기록

원 명세에서 바뀐 내용입니다. 본문과 다르면 이 표를 따릅니다.

| 날짜 | 항목 | 원 명세 | 변경 |
|---|---|---|---|
| 2026-11-05 | 런타임 | .NET 8, C# 12 | .NET 10 (LTS). .NET 8 지원 종료일이 2026-11-10 |
| 2026-11-05 | UI | 콘솔 (Spectre.Console), WPF는 2차 이후 | WPF (CommunityToolkit.Mvvm). `scan`은 headless 인자로 유지, fix와 undo는 GUI 전용 |
| 2026-11-05 | 명령 | `pccheck scan/fix/undo` | `PcCheck.exe scan [--quick] [--defender-scan]` (headless), 그 외는 GUI 화면 |
| 2026-11-05 | Collector 타임아웃 | 일괄 60초 | Collector별 타임아웃. 리소스는 샘플링 시간 + 30초, Defender 빠른 검사는 900초 (rules.json `collectors`) |
| 2026-11-05 | SEC-THREAT 빠른 검사 | 항상 실행 | 옵션. 실행 여부를 리포트에 표시 |
| 2026-11-05 | 성능 카운터 | 영어 카운터 이름 | ko-KR에서 조회되지 않으면 `PdhAddEnglishCounter` 사용 (2단계에서 확인) |
| 2026-11-05 | 시작 항목 수집 경로 | HKLM, HKCU Run, RunOnce | HKLM `WOW6432Node` Run, `StartupApproved\Run32` 추가 |
| 2026-11-05 | 보조 판정 | 1, 2번 동시 해당 시 "포맷 권장" | 주 판정이 HardwareReplace이면 2번 규칙부터 평가해 처음 일치한 판정 |
| 2026-11-05 | 리포트 머리말 | | 실행 계정 표시 (HKCU, %TEMP% 기준 계정 확인용) |
| 2026-11-05 | 테스트 | 4단계만 VM | Core, Analysis 단위 테스트는 macOS에서도 실행하고, 실행 검증은 Parallels VM에서 함 |
| 2026-11-05 | 서명 검증 | WinVerifyTrust P/Invoke | `Get-AuthenticodeSignature` 일괄 호출. 카탈로그 서명된 Windows 파일을 서명 없음으로 잘못 판단하지 않기 위해서 |
| 2026-11-05 | Defender 검사 | 빠른 검사 | 검사 안 함, 빠른 검사, 전체 검사 중 선택 (`--defender-scan`, `--defender-full-scan`) |
| 2026-11-05 | IRemediation | `ApplyAsync(Finding)` | `Plan(Finding)`으로 대상을 나눈 뒤 `ApplyAsync(RemediationTarget)`. ST-COUNT는 시작 항목마다 따로 승인 |
| 2026-11-05 | findings.json | `verdict.basis` | 보조 판정 근거 `verdict.secondaryBasis` 추가. 샘플링하지 않으면 `samplingSec`는 0 |
| 2026-11-05 | 미결 | | RES-* 점수가 소프트웨어 소계에 들어가 HDD 병목만으로 보조 판정 "정리로 충분"이 나옴. 명세 예시와 같아 그대로 두었고 결정 대기 |
| 2026-11-05 | 미결 | | RM-TEMP-CLEAN을 Auto로 둘지 결정 대기. VM 테스트에서 확인 없이 14GB를 삭제함 |
| 2026-11-06 | 진단 항목 | 22개 | 24개. `APP-PHOTOS`(사진 앱 패키지 상태, 비정상 종료 원인 모듈, 실행 실패)와 `SYS-DISPLAY`(기본 디스플레이 어댑터, 장치 오류, 드라이버 재시작 이벤트 4101) 추가. `SYS-DISPLAY`는 하드웨어 소계로 셈 |
| 2026-11-06 | 리포트 전송 | 원격 수집 서버는 비범위 | Slack 수신 웹훅으로 요약과 발견 항목을 나눠 전송. 주소는 화면 입력이나 환경 변수 `PCCHECK_SLACK_WEBHOOK`로만 받고 저장하지 않으며, `hooks.slack.com`만 허용 |

## 개요

느려진 Windows PC를 포맷하기 전에 원인을 진단하고, 정리로 복구할 수 있는지 판정하는 단일 실행 파일 툴입니다. 판정 결과는 "정리로 충분", "포맷 권장", "하드웨어 교체 권장" 세 가지입니다.

- 1차 대상: 비개발자가 사용하는 업무용 PC
- 사용자: 점검하는 사람(개발자)이 현장 또는 원격으로 직접 실행
- 대상 OS: Windows 10 22H2, Windows 11 (x64)

### 범위

- 하드웨어, 리소스, 시작 항목, 설치 프로그램, 브라우저 변조, 보안 상태 진단
- 판정과 HTML 리포트 출력
- 승인 기반 조치, 복원 지점과 조치 기록을 통한 롤백

### 비범위

- 자체 악성코드 탐지 엔진, 실시간 감시, 커널 드라이버
- 원격 수집 서버, 다중 PC 관리
- 코드 서명 (본인만 실행하므로 SmartScreen 경고는 수용)

악성코드 탐지는 Windows Defender를 호출해 결과를 받아오고, 툴은 서명, 경로, 알려진 목록 대조로 의심 항목을 표시하는 데까지만 합니다.

## 기술 스택과 실행 환경

self-contained 단일 exe로 배포합니다. 대상 PC에 런타임을 설치하지 않고 USB나 원격 전송으로 바로 실행하기 위해서입니다.

| 항목 | 선택 | 비고 |
|---|---|---|
| 런타임 | .NET 10 (LTS) | PublishSingleFile, SelfContained, win-x64 |
| UI | WPF | CommunityToolkit.Mvvm |
| 시스템 조회 | System.Management (WMI/CIM) | Win32_\*, MSFT_\* 클래스 |
| 성능 측정 | System.Diagnostics.PerformanceCounter | 샘플링 수집 |
| 레지스트리 | Microsoft.Win32.Registry | Run 키, 브라우저 정책 |
| 서명 검증 | WinVerifyTrust P/Invoke | Authenticode 확인 |
| PowerShell 호출 | Process로 powershell.exe 실행 | Defender, Storage cmdlet, 결과는 JSON으로 받음 |
| 리포트 | 정적 HTML 단일 파일 | 외부 리소스 없이 CSS 인라인 |
| 로그 | Serilog 파일 로그 | 실행 폴더 하위 |

- 권한: app.manifest에 requireAdministrator 지정
- 출력 경로: exe와 같은 폴더의 `PcCheck_{yyyyMMdd_HHmm}\` 폴더
- 네트워크: 기본은 오프라인 동작, VirusTotal 조회는 옵션일 때만

## 아키텍처

진단은 읽기 전용 Collector가 수행하고, 판정과 조치는 분리합니다. 진단 모드에서는 시스템을 전혀 바꾸지 않습니다.

### 실행 흐름

1. 관리자 권한, OS 버전 확인
2. 설정 파일(rules.json, known-bad.json, protect.json) 로드
3. Collector 병렬 실행, 리소스 샘플링은 기본 120초
4. Analyzer가 Finding 목록 생성, Scorer가 판정
5. HTML 리포트와 findings.json 저장
6. 조치 화면에서만: 조치 후보를 하나씩 보여주고 승인받아 실행, 실행 전 복원 지점 생성
7. 조치 기록(actions.json) 저장, 되돌리기 화면에서 이 기록으로 되돌림

### 명령과 화면

| 명령, 화면 | 동작 |
|---|---|
| `PcCheck.exe` | GUI 시작 화면 |
| `PcCheck.exe scan` | 창 없이 진단과 리포트만 |
| `PcCheck.exe scan --quick` | 샘플링 30초 |
| `PcCheck.exe scan --defender-scan` | Defender 빠른 검사 포함 |
| `PcCheck.exe --mock` | 샘플 결과로 결과 화면 표시 (개발용) |
| 시작 화면의 VirusTotal 옵션 (키는 환경변수 `PCCHECK_VT_KEY`) | 의심 파일 해시를 VirusTotal로 조회 (5단계) |
| 결과 화면의 조치 탭 | 직전 진단 결과로 조치 진행 (4단계) |
| 되돌리기 화면 | 직전 조치 되돌리기 (4단계) |

### 프로젝트 구조

```
pitstop/
  PcCheck.slnx
  src/
    PcCheck.App/            WPF 진입점, headless scan, 화면 (net10.0-windows)
    PcCheck.Core/           Finding, Severity, Verdict 모델, 인터페이스, 설정 로드, ScanRunner
    PcCheck.Collectors/     ICollector 구현 (항목별 1클래스)
    PcCheck.Analysis/       Analyzer, Scorer, 규칙 엔진
    PcCheck.Remediation/    IRemediation 구현, 복원 지점, 조치 기록
    PcCheck.Report/         findings.json, HTML 템플릿, 렌더러
  config/                   rules.json, known-bad.json, protect.json
  tests/                    Core, Analysis 단위 테스트
  tools/vm/                 Parallels VM 배포, 실행, 화면 캡처 스크립트
```

### 핵심 인터페이스

```csharp
public interface ICollector
{
    string Id { get; }
    TimeSpan GetTimeout(CollectContext ctx) => ctx.DefaultTimeout;
    Task<CollectorResult> CollectAsync(CollectContext ctx, CancellationToken ct);
}

public record Finding(
    string Id, string Category, Severity Severity,
    string Title, string Detail, int Score,
    string? RemediationId, IReadOnlyDictionary<string, string> Evidence);

public interface IRemediation
{
    string Id { get; }
    RiskLevel Risk { get; }          // Auto, Confirm, AdviceOnly
    Task<ActionRecord> ApplyAsync(Finding f, CancellationToken ct);
    Task UndoAsync(ActionRecord record, CancellationToken ct);
}
```

- Collector 하나가 실패해도 전체는 계속 진행하고, 실패 사실을 리포트에 표시합니다.
- 각 Collector는 타임아웃(기본 60초)을 둡니다.

## 진단 항목

항목은 하드웨어, 리소스, 시작 항목, 프로그램, 브라우저와 네트워크, 보안, 시스템 7개 분류, 22개입니다. 임계값은 모두 rules.json에서 조정합니다.

### 하드웨어

| ID | 항목 | 수집 방법 | 판정 기준 |
|---|---|---|---|
| HW-DISK-TYPE | 시스템 드라이브 종류 | Get-PhysicalDisk MediaType, BusType | C: 드라이브가 HDD면 High |
| HW-DISK-HEALTH | 디스크 상태 | Get-PhysicalDisk HealthStatus, Get-StorageReliabilityCounter, WMI MSStorageDriver_FailurePredictStatus | PredictFailure 또는 Unhealthy면 Critical, 읽기 오류 누적이 있으면 High |
| HW-DISK-FREE | 여유 공간 | Win32_LogicalDisk | C: 여유 15% 미만 Medium, 5% 미만 High |
| HW-RAM | 메모리 용량 | Win32_ComputerSystem TotalPhysicalMemory | 4GB 이하 High, 8GB 미만 Medium |

### 리소스 (샘플링)

기본 120초 동안 2초 간격으로 수집하고 평균과 95 백분위수를 함께 기록합니다. 상위 프로세스는 각각 5개씩 리포트에 남깁니다.

| ID | 항목 | 수집 방법 | 판정 기준 |
|---|---|---|---|
| RES-CPU | CPU 사용률 | Processor(_Total)\\% Processor Time, 프로세스별 Process\\% Processor Time | 평균 60% 초과 Medium, 85% 초과 High |
| RES-MEM | 메모리 압박 | Memory\\Available MBytes, Memory\\% Committed Bytes In Use | 가용 1GB 미만 또는 커밋 90% 초과 High |
| RES-DISK | 디스크 병목 | PhysicalDisk(_Total)\\% Idle Time, Avg. Disk Queue Length | Idle 20% 미만 또는 큐 길이 2 초과 High |

### 시작 항목

| ID | 항목 | 수집 방법 | 판정 기준 |
|---|---|---|---|
| ST-COUNT | 시작 항목 수 | HKLM(WOW6432Node 포함), HKCU의 Run, RunOnce, 시작 폴더, StartupApproved(Run, Run32, StartupFolder) | 활성 항목 15개 초과 Medium |
| ST-SUSPECT | 의심 시작 항목 | 대상 파일의 Authenticode 서명, 경로 | 서명 없음 + 사용자 쓰기 가능 경로(AppData, Temp, ProgramData 하위 무작위 폴더)면 High |
| SVC-SUSPECT | 의심 서비스 | Win32_Service 자동 시작, 실행 파일 서명 | Microsoft 외 서명 없는 자동 서비스 High |
| TASK-SUSPECT | 의심 예약 작업 | Get-ScheduledTask, Action 경로와 인자 | 사용자 쓰기 가능 경로 실행, -enc/-EncodedCommand, mshta, wscript 호출이면 High |

### 프로그램

| ID | 항목 | 수집 방법 | 판정 기준 |
|---|---|---|---|
| APP-KNOWN-BAD | 알려진 애드웨어, 가짜 최적화 프로그램 | Uninstall 레지스트리(HKLM, HKLM WOW6432Node, HKCU) DisplayName, Publisher | known-bad.json 패턴 일치 시 High |
| APP-RECENT | 최근 설치 프로그램 | InstallDate | 최근 30일 설치 목록을 Info로 표시 (판정 근거 보조) |

### 브라우저와 네트워크

| ID | 항목 | 수집 방법 | 판정 기준 |
|---|---|---|---|
| BR-POLICY | 정책 변조 | HKLM\\SOFTWARE\\Policies\\Google\\Chrome, ...\\Microsoft\\Edge의 HomepageLocation, DefaultSearchProvider\*, ExtensionInstallForcelist | 사용자가 설정하지 않은 강제 정책 존재 시 High |
| BR-EXT | 확장 프로그램 | Chrome, Edge 프로필의 Preferences JSON | 웹스토어 외 설치 또는 known-bad.json 일치 시 High, 나머지는 목록 표시 |
| NET-HOSTS | hosts 변조 | %SystemRoot%\\System32\\drivers\\etc\\hosts | localhost 외 항목 존재 시 Medium, 포털, 은행 도메인 재지정이면 Critical |
| NET-PROXY | 프록시 변조 | HKCU Internet Settings ProxyEnable, ProxyServer, AutoConfigURL | 설정되어 있으면 High |

### 보안

| ID | 항목 | 수집 방법 | 판정 기준 |
|---|---|---|---|
| SEC-AV | 백신 상태 | Get-MpComputerStatus, WMI root\\SecurityCenter2 AntiVirusProduct | 실시간 보호 꺼짐 High, 정의 업데이트 7일 초과 Medium, 백신 2개 이상 동시 활성 Medium |
| SEC-THREAT | 위협 이력, 빠른 검사 | Get-MpThreatDetection, Start-MpScan -ScanType QuickScan (옵션) | 미해결 위협 존재 시 Critical, 최근 30일 해결된 위협은 Medium |

### 시스템

| ID | 항목 | 수집 방법 | 판정 기준 |
|---|---|---|---|
| SYS-UPDATE | 업데이트, 재부팅 대기 | RebootRequired, PendingFileRenameOperations 레지스트리, Get-HotFix 최근 설치일 | 재부팅 대기 Medium, 마지막 업데이트 60일 초과 Medium |
| SYS-EVENTS | 시스템 로그 오류 | 최근 7일 System 로그, 이벤트 ID 7, 51, 153(디스크), 41(비정상 종료) | 디스크 오류 1건 이상 High, 비정상 종료 3건 이상 Medium |
| SYS-MISC | 기타 | 전원 계획, 임시파일 크기(%TEMP%, C:\\Windows\\Temp), 가동 시간 | 절전 계획 Low, 임시파일 2GB 초과 Low, 가동 14일 초과 Low |

protect.json에 등록된 프로그램(예: 업무 프로그램)은 의심 판정에서 제외하고, 조치 후보에도 올리지 않습니다.

## 판정 로직

판정은 점수 합산이 아니라 규칙 우선순위로 정하고, 점수는 리포트 정렬과 참고용으로만 씁니다. 하드웨어 문제는 포맷으로 해결되지 않으므로 가장 먼저 봅니다.

### 심각도 가중치

| 심각도 | 점수 |
|---|---|
| Critical | 40 |
| High | 15 |
| Medium | 5 |
| Low | 1 |
| Info | 0 |

점수는 분류별 소계와 하드웨어 소계, 소프트웨어 소계(하드웨어 외 전체)로 나눠 표시합니다.

### 판정 규칙 (위에서부터 평가)

1. 하드웨어 교체 권장: 다음 중 하나라도 해당
   - HW-DISK-HEALTH가 Critical
   - HW-DISK-TYPE이 HDD이고 RES-DISK가 High
   - HW-RAM이 4GB 이하이고 RES-MEM이 High
2. 포맷 권장: 다음 중 하나라도 해당
   - SEC-THREAT가 Critical (빠른 검사 후에도 미해결 위협 존재)
   - 의심 항목(ST-SUSPECT, SVC-SUSPECT, TASK-SUSPECT, BR-POLICY, BR-EXT, NET-HOSTS, NET-PROXY) 중 High 이상이 5건 이상
   - 소프트웨어 소계 80점 이상
3. 정리로 충분: 소프트웨어 소계 10점 이상
4. 이상 없음: 그 외

- 주 판정이 "하드웨어 교체 권장"이면 2번 규칙부터 다시 평가해 처음 일치한 판정을 보조 판정으로 표시합니다.
- 판정마다 근거가 된 Finding ID를 리포트에 나열합니다.
- 규칙과 임계값은 rules.json에 두고, 코드에는 기본값만 둡니다.

## 조치와 롤백

모든 조치는 "삭제"보다 "비활성화"를 우선하고, 실행 전 원래 값을 actions.json에 기록합니다. 되돌릴 수 없는 조치는 승인 화면에 그 사실을 표시합니다.

### 조치 목록

| ID | 대상 Finding | 등급 | 방법 | 롤백 |
|---|---|---|---|---|
| RM-TEMP-CLEAN | SYS-MISC | Auto | %TEMP%, C:\\Windows\\Temp에서 1일 지난 파일 삭제, 잠긴 파일은 건너뜀 | 불가 (삭제 목록만 기록) |
| RM-POWER-PLAN | SYS-MISC | Auto | powercfg /setactive 균형 조정 | 이전 계획 GUID로 복구 |
| RM-STARTUP-DISABLE | ST-COUNT, ST-SUSPECT | Confirm | StartupApproved 값을 비활성으로 설정 (Run 값은 유지) | 원래 바이트 값 복구 |
| RM-SERVICE-DISABLE | SVC-SUSPECT | Confirm | 서비스 중지 후 StartType을 Disabled로 변경 | 원래 StartType 복구 |
| RM-TASK-DISABLE | TASK-SUSPECT | Confirm | Disable-ScheduledTask | Enable-ScheduledTask |
| RM-UNINSTALL | APP-KNOWN-BAD | Confirm | UninstallString을 대화형으로 실행 (자동 무음 제거 안 함) | 불가 (복원 지점으로 대응) |
| RM-BROWSER-POLICY | BR-POLICY | Confirm | 정책 키를 .reg로 백업 후 삭제 | .reg 가져오기 |
| RM-HOSTS-RESET | NET-HOSTS | Confirm | hosts 백업 후 기본 내용으로 교체 | 백업 파일 복구 |
| RM-PROXY-RESET | NET-PROXY | Confirm | 값 백업 후 ProxyEnable 0, AutoConfigURL 삭제 | 백업 값 복구 |
| RM-DEFENDER | SEC-AV, SEC-THREAT | Confirm | 실시간 보호 켜기, 정의 업데이트, Remove-MpThreat | 불가 (격리 항목은 Defender 화면에서 복원) |
| ADV-\* | HW-, RES-, BR-EXT, SYS-UPDATE | AdviceOnly | 리포트에 권고 문구만 표시 | 해당 없음 |

- 브라우저 확장은 Preferences 직접 수정 시 프로필이 손상될 수 있어 안내만 합니다.
- 조치 화면은 Confirm 항목을 하나씩 보여주고 승인, 거부, 전체 건너뛰기를 받습니다.

### 복원 지점

1. `Enable-ComputerRestore -Drive C:\`로 시스템 보호 활성화 여부 확인 후 켬
2. 생성 빈도 제한(기본 24시간)을 피하려고 SystemRestorePointCreationFrequency를 일시적으로 0으로 설정
3. `Checkpoint-Computer -RestorePointType MODIFY_SETTINGS`로 생성, 끝나면 2번 값 원복
4. 생성 실패 시 조치를 진행하지 않고 사용자에게 계속할지 묻기

undo는 actions.json의 역순으로 실행합니다. 일부가 실패해도 나머지는 계속 진행하고, 실패 항목은 복원 지점 사용을 안내합니다.

## 설정 파일

설정은 exe 옆 `config\` 폴더의 JSON입니다. 파일이 없으면 코드에 내장된 기본값을 씁니다. 파일에 일부 값만 있으면 나머지는 기본값을 유지합니다. 목록(programs, paths 등)은 기본값에 합치지 않고 파일 내용으로 바꿉니다. 실제 기본값은 `config/` 폴더의 파일을 기준으로 합니다.

- `rules.json`: 임계값, 판정 규칙, 샘플링, Collector 타임아웃
- `known-bad.json`: 알려진 애드웨어, 가짜 최적화 프로그램. match는 대소문자 무시 정규식이고, 실제 목록은 점검하면서 계속 추가합니다.
- `protect.json`: 보호 목록. 점검 전에 보호할 업무 프로그램을 등록합니다. 정규식이 잘못되어도 항목을 버리지 않고 문자열 포함 여부로 비교합니다.
- `actions.json`: 조치 기록, 툴이 생성합니다.

```json
{
  "version": 1,
  "createdAt": "2026-11-05T14:30:00+09:00",
  "restorePoint": { "created": true, "description": "PcCheck before fix" },
  "actions": [
    {
      "seq": 1,
      "remediationId": "RM-STARTUP-DISABLE",
      "findingId": "ST-SUSPECT",
      "target": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ExampleUpdater",
      "before": { "startupApproved": "020000000000000000000000" },
      "after": { "startupApproved": "030000000000000000000000" },
      "reversible": true,
      "status": "Applied"
    }
  ]
}
```

## 리포트 형식

결과는 사람이 보는 report.html과 기계가 읽는 findings.json 두 개로 저장합니다. HTML은 외부 리소스 없는 단일 파일이라 메신저로 받아 바로 열 수 있습니다.

### report.html 구성 (위에서 아래 순서)

1. 머리말: PC 이름, OS 버전, CPU, 메모리, 디스크 종류, 실행 계정, 실행 일시(yyyy-MM-dd HH:mm), 샘플링 시간
2. 판정 배너: 주 판정, 보조 판정, 근거 Finding ID 목록
3. 분류별 점수 요약: 하드웨어 소계, 소프트웨어 소계, 분류별 소계
4. Finding 목록: 심각도 내림차순, 각 항목에 근거(Evidence)와 권장 조치 표시
5. 상위 프로세스: CPU, 메모리, 디스크 각 5개
6. 조치 후보: 등급(Auto, Confirm, AdviceOnly)별 묶음
7. 실패한 Collector와 오류 메시지

### findings.json

```json
{
  "version": 1,
  "scannedAt": "2026-11-05T14:20:00+09:00",
  "samplingSec": 120,
  "machine": { "name": "SAMPLE-PC", "os": "Windows 10 22H2 (build 19045.6036)", "cpu": "...", "ramGb": 4, "systemDisk": "HDD", "user": "SAMPLE-PC\\operator", "isAdmin": true },
  "verdict": { "primary": "HardwareReplace", "secondary": "Cleanup", "basis": ["HW-DISK-TYPE", "RES-DISK"] },
  "scores": { "hardware": 30, "software": 25, "byCategory": { "Hardware": 30, "Resource": 15 } },
  "findings": [
    {
      "id": "RES-DISK",
      "category": "Resource",
      "severity": "High",
      "score": 15,
      "title": "디스크 병목",
      "detail": "샘플링 중 디스크 Idle 평균 8%",
      "remediationId": null,
      "evidence": { "idleAvgPercent": "8", "queueAvg": "3.4" }
    }
  ],
  "topProcesses": null,
  "collectorErrors": []
}
```

- verdict 값: HardwareReplace, Format, Cleanup, Healthy
- 설정 파일 오류는 collectorErrors에 `CONFIG`로 기록합니다.
- 리포트에는 사용자 이름이 들어간 경로가 그대로 남으므로, 외부에 공유할 때는 주의합니다.

## 구현 단계

단계마다 하나씩 진행하고, 완료 기준을 통과한 뒤 다음 단계로 넘어갑니다. 1단계 결과만으로도 업무용 PC를 판정할 수 있습니다.

- [x] 1단계 뼈대: 솔루션 구조, 모델, ICollector, 설정 로드, scan(GUI, headless), Collector 실패 격리
  - 완료 기준: 빈 Collector로 scan 실행 시 findings.json 생성, 단일 exe publish 성공
- [x] 2단계 진단: 22개 진단 항목 Collector 구현
  - 완료 기준: VM에서 전체 실행 성공, 각 Collector 단위 테스트(입력 데이터 모킹) 통과
- [x] 3단계 판정과 리포트: Analyzer, Scorer, report.html
  - 완료 기준: 판정 규칙별 테스트 케이스(4개 판정 + 동시 해당) 통과
- [ ] 4단계 조치: IRemediation 구현, 복원 지점, 조치 화면, 되돌리기 화면 (코드 완료, VM 원상 복구 검증 남음)
  - 완료 기준: VM에서 조치 후 undo로 원상 복구 확인
- [ ] 5단계 선택: VirusTotal 조회, UI 개선

4단계 조치 테스트는 반드시 VM에서 하고, 시작 전에 VM 스냅샷을 만듭니다. 개발 PC에서 조치를 실행하지 않습니다.

## 리스크와 주의사항

가장 큰 리스크는 정상 프로그램을 의심 항목으로 잘못 잡아 비활성화하는 것입니다. 그래서 조치는 승인제, 비활성화 우선, 기록 후 실행으로 설계했습니다.

| 리스크 | 영향 | 대응 |
|---|---|---|
| 오탐 (서명 없는 정상 프로그램) | 업무 프로그램 등 사용 중단 | protect.json 사전 등록, Confirm 승인, undo |
| 실행 전 데이터 미백업 | 조치나 포맷 과정에서 자료 손실 | 툴 실행 전에 자가점검 가이드의 백업 단계 선행 |
| 백신의 PUP 오탐 | exe 격리, 실행 차단 | 실행 폴더를 Defender 예외에 일시 등록, 점검 후 해제 |
| 리소스 샘플링 시점 편향 | 순간 부하를 놓치거나 과대 평가 | 평소 사용 프로그램을 띄운 상태에서 120초 측정, 필요 시 2회 측정 |
| 시스템 보호 꺼짐 | 복원 지점 생성 실패 | 자동 활성화 시도, 실패 시 조치 진행 여부 확인 |
| WMI, Storage cmdlet 미지원 (구형 PC, RAID) | 디스크 상태 항목 누락 | Collector 실패로 리포트에 표시, 판정에서 제외 |
| 관리자 권한 없이 실행 | 대부분 항목 수집 불가 | manifest로 권한 상승 강제, 시작 시 확인 |
| 다른 관리자 계정으로 권한 상승 | HKCU, %TEMP%를 다른 계정 기준으로 읽음 | 머리말에 실행 계정 표시 |

툴의 판정은 참고용입니다. "포맷 권장"이 나와도 백업과 업무 프로그램 재설치 가능 여부를 확인한 뒤 진행합니다.
