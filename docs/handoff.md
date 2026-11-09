# Handoff

Last updated 2026-11-09 by Claude Code. v0.1.3 is released (2026-11-07). The project is being renamed from pitstop to **PC Check** (v0.2.0, branch `feature/rename-pc-check`) and widened to three kinds of "leaks"; see Rename and scope below.

## Rename and scope (2026-11-09, user decision)

- Name: **PC Check**. Code already used `PcCheck` everywhere, so only the pitstop strings, icon file names, README, and docs changed. Namespaces, `PcCheck.exe`, and `PCCHECK_*` env vars stay.
- GitHub repo `Bigide19/pitstop` -> `Bigide19/pc-check`: the README already points at the new name, so rename the repo (`gh repo rename pc-check`) together with merging this branch. Only on the user's order. GitHub redirects old repo URLs.
- Local folder `~/Projects/pitstop` can be renamed after the session ends; `tools/vm/vm.sh` takes the VM share path from the folder name.
- Scope: "PC에서 새는 곳을 찾습니다". Performance leaks (the 26 current checks), space leaks (unused-file cleanup, new), information leaks (personal-data cleanup ported from `Bigide19/windows-pc-privacy-cleaner`, net462 WPF, 46 files). Never claim data *was* leaked; say it remains or could leak.
- Stages: 1 rename (this branch) -> 2 three-leak layout with mock data -> 3 port the privacy cleaner (deletes go through `ISystemOps`) -> 4 unused-file cleanup. Show a plan before each stage.

## Stage status

| Stage | State | Evidence |
|---|---|---|
| 1 Skeleton | Done | |
| 2 Collectors | Done (26 items) | Full VM scan with 0 collector errors (2026-11-07) |
| 3 Verdict + report.html | Done | |
| 4 Remediation, restore point, fix/undo | Done | 2026-11-07 VM end-to-end: 7 planted artifacts detected, all 7 fixes applied, all 7 undone back to the planted state, VM cleaned afterwards (`tools/vm/fixtest/cleanup.ps1`) |
| 5 VirusTotal, UI polish | UI polish done; VirusTotal not started | |

Tests: 108 pass on macOS and in the VM (`dotnet test PcCheck.slnx`, 2026-11-07).

## Release warning

**v0.1.2 (the current latest release) has a regression**: its signature script wrapped `ConvertFrom-Json` output in `@()`, which PowerShell 5.1 nests, so no path matched and every file came back "unknown". ST-SUSPECT and SVC-SUSPECT therefore never flag anything in v0.1.2. Fixed in v0.1.3, released 2026-11-07 (assign, then enumerate; and the verifier now fails loudly when no path matches). Anyone still holding a v0.1.2 exe should replace it.

## Environment state

- The VM snapshot `pccheck-fix-test` was deleted on 2026-11-07 (it held ~22 GB); the VM has no snapshots now. Mac free space after that was about 40 GB.
- The VM is clean: the E2E test's planted artifacts, restore points, and config override were removed and the default config redeployed.
- VM E2E without a snapshot works: raise `tempSizeGb` in the VM's `config/rules.json` first (so the Auto temp cleanup does not delete the VM's temp files), `vm.sh run-ps plant`, GUI scan and fix, undo, `run-ps state`, then `cleanup.ps1 -PowerScheme <original GUID>`. Send approvals at least 6 s apart: a faster burst left the UI behind and the undo commands missed.

## Field case 2026-11-06 (lessons that drive v0.1.3)

A real office PC (Windows 11 25H2, Ryzen 5 5600G, SSD, 16 GB) was checked with v0.1.1. Do not record the PC or user name anywhere.

- Symptom: the Photos app never opened and the "Open with" dialog did not appear. An in-place Windows reinstall did not help.
- `APP-PHOTOS` showed 21 crashes in 7 days, all in `TENXWGuard64_127.dll` (exception `c0000005`), with cause "unknown".
- That DLL belongs to TouchEn nxKey, a Korean banking keyboard-security program that injects into every process. Uninstalling it fixed Photos and the dialog at once.
- The same PC had 39 startup entries, about ten of them banking or government security modules (Veraport, AhnLab Safe Transaction, IPinside LWS, MagicLine4NX, Delfino G3, CrossCert UniCRS, AnySign4PC/XecureWeb, CrossEX, MarkAny EPS), plus ALYac and Avast together.
- The verdict was "Format" from the software-score rule (205 points). The real fix was removing one program.
- RES-CPU/MEM/DISK all failed with `Instance '_Total' does not exist`: performance counters were broken (`lodctr /R` repairs them), and one missing counter took down all three collectors.
- The Defender full scan was refused because a third-party antivirus was primary; the report gave no reason.
- The user ran an older exe without noticing; nothing in the report or the Slack summary shows the tool version.
- Getting results off the PC was the hard part; the Slack webhook (v0.1.1) worked.

## v0.1.3 (implemented 2026-11-07)

User decisions: do not change the verdict rules ("C is overkill"); leave antivirus products alone unless they cause a problem (no keeper or removal logic). All seven items below are done; KSign was left out of `kr-modules.json` because its only identifier (the company name) would also match unrelated KSign products.

1. **APP-CRASHES** (replaces/extends APP-PHOTOS). Read Application event 1000 for all apps over 7 days. Group by faulting module (property 3) and module path (property 11). When a non-Microsoft module crashes Photos or any app repeatedly, resolve its owner: file version info (CompanyName, ProductName) and the uninstall entry whose InstallLocation contains the path. Report "<program> made <app> crash N times" with the path, and offer `RM-UNINSTALL` (Confirm, interactive) for that program. Classify known modules: graphics drivers, antivirus, and Korean security modules (TouchEn nxKey `TENX*`/`TKFW*`, AhnLab Safe Transaction, nProtect, IPinside, Veraport, etc.). Regression test: the 21 x `TENXWGuard64_127.dll` case must name TouchEn nxKey.
2. **SEC-KR-MODULES** (new): find Korean banking/government security modules, explain their known problems, recommend removal, and remove them on approval.
   - **Research first** (user request, 2026-11-07). For each module seen in the field case (TouchEn nxKey, AhnLab Safe Transaction, Wizvera Veraport, IPinside LWS, MagicLine4NX, Wizvera Delfino G3, CrossCert UniCRS, AnySign4PC/XecureWeb, iniLINE CrossEX, MarkAny EPS) plus common ones (nProtect Online Security, KSign, INISAFE CrossWeb EX): vendor, what it does, published vulnerabilities or advisories (with source URLs), known app-compatibility problems (DLL injection crashes like the Photos case), whether sites reinstall it on demand, and how its uninstaller behaves. Record only what a source states; mark anything unverified as such.
   - **Data, not code**: put the result in `config/kr-modules.json` (display-name and publisher patterns, service and startup patterns, injected DLL patterns for APP-CRASHES, a short Korean note per module, source URLs). Users can extend it like known-bad.json.
   - **Finding**: one finding listing the installed modules with each note. Medium when any module has a published vulnerability or appears in APP-CRASHES, otherwise Low. Advice: remove them all; banking and government sites ask to reinstall what they need; reinstall the latest version only when needed and remove it afterwards.
   - **Removal**: each module becomes an `RM-UNINSTALL` target (Confirm, vendor uninstaller run interactively, irreversible, restore point first). Add a "보안 모듈 모두 제거" choice on the fix screen that still walks through each uninstaller; close the module's running processes first, since some uninstallers refuse while they run. Never remove a module listed in protect.json.
   - These programs are not malware: exclude their services and tasks from SVC-SUSPECT and TASK-SUSPECT so they do not inflate the suspect count.
   - Tests: the field case's startup list (names only) must yield the ten modules above; a module in protect.json must not become a removal target.
3. **Resilient resource sampling.** Open each performance counter separately so one missing counter does not fail the others. For CPU, fall back to `GetSystemTimes` (P/Invoke); for memory, `GlobalMemoryStatusEx`. Add a finding when counters are broken or disabled (`HKLM\SYSTEM\CurrentControlSet\Services\PerfOS\Performance\Disable Performance Counters`), advice `lodctr /R` then reboot.
4. **Defender scan failure reason.** When `Start-MpScan` fails and a third-party antivirus is primary (AMRunningMode passive or SecurityCenter2 shows another enabled product), say so in the SEC-THREAT Info finding. No removal advice.
5. **Tool version everywhere.** Put the app version in report.html header, `findings.json` (`toolVersion`), and the first line of the Slack summary.
6. **Result bundle.** After a scan, zip report.html, findings.json, pccheck.log (and actions.json if present) into `PcCheck_<time>.zip` in the output folder; add a "결과 파일 묶음 열기" button.
7. **Field notes.** Add `docs/field-notes.md` with the case above (no names) and the user-facing remedy, so future triage starts there.

Held for the user's confirmation (were bundled with the rejected verdict change): TASK-SUSPECT requiring "unsigned" like ST-SUSPECT (Opera GX false positive), and lowering unresolved `PUA:` threats from Critical to High. Ask before doing either.

## Next tasks, in order

1. **Releases** are built locally: `dotnet publish src/PcCheck.App -c Release -o publish`, zip `PcCheck.exe` + `config/` as `pccheck-win-x64.zip`, `gh release create` with SHA-256 sums. Until a few releases after v0.2.0, also upload the same zip as `pitstop-win-x64.zip` so old `releases/latest/download/pitstop-win-x64.zip` links keep working. Release only on the user's order.
2. **Ask: should `RM-TEMP-CLEAN` stay Auto?** In the VM it deleted 14 GB without a prompt and surprised the user. Proposal: Confirm, with size and file count on the card.
3. **Held items** (see above): TASK-SUSPECT signature check, PUA severity. Ask first.
4. **Not covered end to end**: `RM-DEFENDER` (Tamper Protection blocks turning real-time protection off for a test) and `RM-UNINSTALL` (interactive vendor uninstallers; exercised only in the `--mock` preview). Say so rather than force it.
5. **VirusTotal (stage 5)**: `--vt` and a start-screen checkbox, key from `PCCHECK_VT_KEY`, only files behind ST/SVC/TASK-SUSPECT, 4 requests/min with a configurable cap, result in evidence. No key yet; test with a mocked HTTP handler.
6. **known-bad.json** still holds only the spec's three examples; prepare a reviewed candidate list.
7. **Open question**: RES-* findings count toward the software subtotal, so an HDD bottleneck alone yields a "Cleanup" secondary verdict (matches the spec example).
8. **Repo hygiene**: no LICENSE yet (user picks); a GitHub Actions release workflow is a CI change and needs the user's OK before writing it.

## Implementation notes worth knowing

- Signature checks use `Get-AuthenticodeSignature` (`SignatureVerifier`), per file inside try/catch, 40 paths per call. Most Windows binaries are catalog-signed, so a bare WinVerifyTrust would report them as unsigned. Unreadable files are "unknown" (Info), never "unsigned".
- PowerShell 5.1 traps: `ConvertFrom-Json` emits a JSON array as one object (never wrap it in `@()`), and redirected stderr arrives as CLIXML (`PowerShellRunner.ErrorText` decodes it).
- `Path.GetDirectoryName` ignores `\\` on macOS, so code that splits Windows paths and runs in Mac tests splits them by hand (see `CrashCollector.DirOf`).
- `IRemediation` gained `Plan(Finding)` returning `RemediationTarget`s. ST-COUNT becomes one target per enabled startup entry; duplicates across findings (for example SEC-AV and SEC-THREAT both pointing at RM-DEFENDER) are removed in `RemediationRegistry.BuildPlan`.
- False positives already fixed, keep them fixed: Edge keeps settings entries for extensions that are not installed (no manifest, location 0), and the encoded-command rule must apply only to PowerShell (Windows' own `ClipRenew.exe -e` matched before).
- Balanced power plan GUID is `381b4222-f694-41f0-9685-ff5bb260df2e`.
- Performance counters work with English names on ko-KR Windows, so `PdhAddEnglishCounter` was not needed.
- `PcCheck_*` output folders, `publish/`, `bin/`, `obj/` are gitignored.
