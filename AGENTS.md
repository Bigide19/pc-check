# PcCheck

Windows PC check tool: diagnoses a slow PC and decides between cleanup, format, or hardware replacement.
Design source: `docs/spec.md` (Korean; the change log table at its top overrides the body).
Current state and the next tasks: `docs/handoff.md`. Real-PC cases and their lessons: `docs/field-notes.md`. Read both before starting work.

This file is shared by Claude Code (via `CLAUDE.md`) and Codex. Keep rules here, not in `CLAUDE.md`.

## Rules
- .NET 10 (LTS), nullable on. Ship as a self-contained single exe (`win-x64`): `dotnet publish src/PcCheck.App -c Release -o publish` gives `PcCheck.exe` plus `config/`.
- UI is WPF (`PcCheck.App`, MVVM with CommunityToolkit.Mvvm). `PcCheck.exe scan [--quick] [--defender-scan|--defender-full-scan]` runs headless with no window. Fix and undo are GUI only because they need per-item approval. `--mock` shows sample results; fix and undo then run only against `PreviewSystemOps` (in-memory, never touches the PC). Keep that wiring when touching `FixViewModel`/`UndoViewModel`.
- Only `PcCheck.App` targets `net10.0-windows`. Other libraries stay `net10.0` (Windows-only assemblies carry `[assembly: SupportedOSPlatform("windows")]`) so unit tests run on macOS too.
- Scan mode is read-only. Code that writes to the registry, files, or services lives only in `PcCheck.Remediation`, and goes through `ISystemOps` so tests can use a fake.
- Every remediation records the original value in an `ActionRecord` before acting; irreversible ones set `Reversible = false`. `actions.json` is saved after each action.
- Entries in `protect.json` are excluded from findings and remediation candidates. Korean security modules are data in `config/kr-modules.json` (researched notes with sources), not code; they are clean-up candidates, never suspects.
- Collectors never throw outward; `ScanRunner` turns faults and timeouts into `CollectorResult` errors. Timeout is per collector (`ICollector.GetTimeout`).
- Collectors keep collection (Windows APIs) separate from a static `Evaluate(...)` that takes plain input; unit tests target `Evaluate`.
- PowerShell is called through `PowerShellRunner` (`-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand`); results come back as JSON. Emit dates with `.ToString('o')`, since PowerShell 5.1 serializes DateTime as `/Date(...)/`.
- Thresholds come from `rules.json`; the only allowed hardcoded value is the default in `RulesConfig`/`KnownBadConfig`.
- Secrets (VirusTotal key) only via env var `PCCHECK_VT_KEY`; never in logs or reports.
- Tests for code that changes the system never run on a real PC. Remediation end-to-end tests run only in the VM, after a Parallels snapshot.

## Build and test
- macOS: `dotnet build PcCheck.slnx`, `dotnet test PcCheck.slnx` (WPF compiles thanks to `EnableWindowsTargeting`; it cannot run on macOS).
- Windows VM: Parallels "Windows 11 Pro" (ARM64, ko-KR; the x64 build runs under emulation). Drive it with `tools/vm/vm.sh`:
  `deploy | scan [--quick] | gui [--mock] | invoke <AutomationId> | tab N | max | front | shot FILE [MAXWIDTH] | capture FILE | run-ps NAME`.
  - Screenshots: use `shot` (taken inside the guest session). `prlctl capture` (`capture`) can return an empty file.
  - `prlctl exec` runs as SYSTEM in session 0 (no visible windows). GUI runs go through an elevated interactive scheduled task. Do not change the VM UAC policy.
  - Click GUI elements by `AutomationProperties.AutomationId`, not by Korean labels (non-ASCII arguments do not survive `prlctl`).
  - VM disk and sensor values are virtual hardware; verify verdict logic with mocked data, not VM readings.
- Report pages: render `HtmlReportRenderer` output and look at it once (headless Chrome screenshot works on macOS).

## Workflow
- The user is Korean; answer in Korean. Before each stage, show the implementation plan and wait for confirmation unless the user said to run all stages.
- At the end of a stage, report whether the stage's completion criteria (in `docs/spec.md`) are met, with evidence.
- Do not commit, push, or open PRs without the user's explicit instruction. Commit messages: Conventional Commits prefix + Korean description, author `Bigide19 <bigide19@gmail.com>`, no AI attribution lines.
