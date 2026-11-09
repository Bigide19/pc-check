# Stage 3 brief: port the privacy cleaner (information leaks)

Status (2026-11-09): **not started, deferred by the user** ("작업이 크니까 다음에"). Claude Code or Codex may pick it up. Read `AGENTS.md`, `docs/handoff.md`, and `docs/spec.md` (section "세 가지 누수") first. As for every stage, show the plan and get the user's answers to the questions below before writing code.

## Goal

Find personal data left on the PC that could leak when someone else uses it, show it as the information leak on the result screen, and let the user remove what they pick. The UI shell already exists (stage 2): `Categories.Privacy`, `LeakKind.Information`, the "개인정보" card, and mock findings `PRIV-*` in `src/PcCheck.App/Services/MockData.cs`.

Wording rule: never say data *leaked*. Say it remains, or could leak.

## Source

- Repo: `Bigide19/windows-pc-privacy-cleaner` (public, MIT, same author). Pin to commit `d12fd21` (release v0.6.0, 2026-10-12) and note it in the commit message.
- .NET Framework 4.6.2 WPF, its own MVVM helpers, no packages. About 20 source files under `src/PcPrivacyCleaner/`.

| Group (`ItemGroup`) | Scanner | What it finds | Default |
|---|---|---|---|
| Cert, CertStore | `Services/Scan/CertScanner.cs` | NPKI certificate folders, certificates in the Windows store | personal certs forced on |
| Browser | `Services/Scan/BrowserScanner.cs`, `SitePreview.cs` | Chrome, Edge, Whale, Brave, Firefox: saved-password sites, cookies, history (counts and site names only) | on |
| Messenger | `Services/Scan/MessengerScanner.cs` | KakaoTalk, Telegram, LINE, Discord login data | on |
| Files | `Services/Scan/PersonalFileScanner.cs` | files in Desktop/Documents/Downloads/Pictures whose names look personal, KakaoTalk received files | off |
| History | `Services/Scan/HistoryScanner.cs` | Run box, Explorer, recent docs, Open/Save MRU (HKCU registry), recent items and jump lists, Recycle Bin, temp, clipboard | on |
| Credential, Wifi | `Services/Scan/AccountScanner.cs`, `Interop/NativeCredentials.cs`, `Interop/WlanApi.cs` | Credential Manager entries, Wi-Fi profiles | off |

Behavior worth keeping:
- Browser files are copied to temp and read through `Interop/WinSqlite.cs` (P/Invoke to `winsqlite3.dll`, shipped with Windows 10+). Password and cookie *values* are never read.
- `FoundItem` carries `Paths` (delete these), `ContentsOf` (empty these folders), `Action` (non-file deletes: credentials, Wi-Fi), `Processes` (must not be running, e.g. the browser), `Default`, `Forced`, `BlockReason`, and a `DeleteScope` text that says exactly what goes.
- `Services/Cleaner.cs` deletes for good (no Recycle Bin) and has a dry-run mode ("연습 모드"). Logs keep group counts; item names only in the detail log.
- `Services/RunContext.cs`: when UAC elevation switches to another account (`OtherAccount`), current-user stores (HKCU, certificates, credentials) belong to that other account. As admin it also scans other profiles' file-based items.
- A consent window runs before the first scan.

## Mapping to PcCheck

| Source | Target in PcCheck |
|---|---|
| `IScanner.Scan` per group | one `ICollector` per group in `PcCheck.Collectors/Privacy/`, collection separate from a static `Evaluate(...)` with plain input (unit-testable on macOS) |
| `FoundItem` | `Finding` with `Category = Categories.Privacy`, ids `PRIV-CERT`, `PRIV-BROWSER`, `PRIV-MESSENGER`, `PRIV-FILES`, `PRIV-USAGE`, `PRIV-CREDENTIALS`, `PRIV-WIFI`; counts and safe metadata in `Evidence` |
| `Cleaner` deletes, `Action` | `IRemediation` classes in `PcCheck.Remediation`, every write through `ISystemOps` (add file/folder delete, credential delete, Wi-Fi profile delete there; fake them in tests) |
| permanent delete | `ActionRecord.Reversible = false`; registry history can follow `RM-BROWSER-POLICY` (`.reg` export first, then reversible) |
| `Processes` / `BlockReason` | plan-time check; a blocked target is shown with its reason and skipped |
| `WinSqlite` interop | keep the P/Invoke (no package; single-file publish stays simple). Windows-only code gets `[SupportedOSPlatform("windows")]` |
| Korean UI text | `Strings.resx` + `Strings.ko.resx` in the owning project (parity test enforces it) |
| `RunContext.OtherAccount` | warn on the start screen and in the report when the elevated account differs from the console user |

Also required in this stage:
- `Leaks.Implemented` gets `LeakKind.Information` (`src/PcCheck.Core/Leaks.cs`).
- `ScanAnalyzer` must stop adding privacy (and space) findings to the scores and the verdict basis. Add a test. The spec already states the rule.
- `protect.json` exclusions apply to privacy targets too (a business program's data must not become a delete target).
- Remove or replace the `PRIV-*` mock findings so `--mock` matches what the collectors really produce.

## Decide with the user before coding

1. **When to scan.** Always, or opt-in on the start screen like the Defender scan? Reading browser files can trip corporate security software, so opt-in is the safer default.
2. **How fixes are approved.** The fix screen approves items one at a time; the source uses a checklist with defaults (some groups off). One "personal data" step with a checklist inside the fix flow, or one Confirm item per group?
3. **What goes into reports.** `report.html`, `findings.json`, and Slack leave the PC. Proposal: counts, group names, and folder paths only; no site names, file names, or credential targets in reports, only on screen.
4. **Overlaps.** Temp files are already `RM-TEMP-CLEAN` (performance, Auto). The Recycle Bin is planned as a space leak (mock `SPACE-RECYCLE`). Which leak owns each?
5. **Dry run.** Keep a 연습 모드 (log what would be deleted), or rely on the `--mock` preview?
6. **Consent.** A one-time notice before the first privacy scan, as in the source?
7. **Old tool.** Archive `windows-pc-privacy-cleaner` after the port, or keep both?

## Phases (proposal)

- [ ] A. Collectors and evaluate tests for all groups, read-only. `Leaks.Implemented` and the `ScanAnalyzer` exclusion with tests.
  - Done when: a VM scan shows the information card with real counts, the verdict is unchanged for the same PC, and no secret values appear in `findings.json`.
- [ ] B. Remediations through `ISystemOps` with fakes in tests; fix-screen integration as decided in question 2.
  - Done when: VM end to end on planted data (a `tools/vm/fixtest` style plant script: fake NPKI folder, browser profile copies, MRU keys, a test credential and Wi-Fi profile), each target removed, irreversible ones marked, registry history restored by undo.
- [ ] C. Report and Slack summary per decision 3, both languages, README (ko and en) updated, then release (v0.3.0) on the user's order.

## Verification notes

- Never run privacy remediations on a real PC. VM only; take a Parallels snapshot first (see `handoff.md` for the no-snapshot fallback).
- The VM is ko-KR and logged in as one user; test the `OtherAccount` path by elevating with a second local admin account.
- Browsers must be closed for deletes; test the blocked path with the browser open.
