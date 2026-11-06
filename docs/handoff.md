# Handoff

Last updated 2026-11-06 by Claude Code. Stages 1-3 are done; stage 4 code is done but its VM end-to-end test is unfinished.
Codex then did a brand redesign ("pitstop": dark header, orange accent) and de-identified the sample data; Claude Code finished
the design pass (verdict colors, app icon, branded report.html, `--mock` preview of fix and undo) and published v0.1.0 on GitHub.

## Stage status

| Stage | State | Evidence |
|---|---|---|
| 1 Skeleton | Done | Headless scan writes `findings.json`; single-file publish OK |
| 2 Collectors (22 items + `SYS-INFO`) | Done | Full VM scan, 0 collector errors; `PcCheck.Collectors.Tests` 45 pass (macOS) |
| 3 Verdict + report.html | Done | `PcCheck.Analysis.Tests` 14 pass; report rendered and checked |
| 4 Remediation, restore point, fix/undo screens | Code done, VM end-to-end test unfinished | `PcCheck.Remediation.Tests` 12 pass (macOS) |
| 5 VirusTotal, UI polish | UI polish done (Codex + Claude Code); VirusTotal not started | |

Unit tests have only been run on macOS so far. Also run `dotnet test PcCheck.slnx` inside the VM (SDK 10.0.401 is installed there) at least once.

## Environment state

- The host Mac disk was 99% full on 2026-11-06. Parallels then refused a new snapshot and the VM stopped by itself. Free space before using the VM again; do not start the VM without the user's OK.
- The VM was back at the pre-test state (no planted artifacts) before it stopped. Snapshot `pccheck-fix-test` still exists; ask before switching to or deleting it.
- Inside the VM, C: had only about 1% free.
- The `--mock` preview of the fix and undo screens has not been seen rendered yet (the VM stopped first). Walk it once: `vm.sh gui --mock`, `invoke FixButton`, `invoke FixStartButton`, `invoke ApproveButton` x3, `invoke GoUndoButton`, `invoke UndoRunButton`, capturing each step.

## Next tasks, in order

1. **Ask the user: should `RM-TEMP-CLEAN` stay Auto?** The spec says Auto, but in the VM it silently deleted 14 GB without any prompt, which surprised the user. Proposal: make it Confirm and show the size and file count on the card. Do not change it without an answer.
2. **Finish the stage 4 VM end-to-end test** (completion criterion: undo restores the original state).
   1. With free host disk space and the user's OK, start the VM, `dotnet publish`, `tools/vm/vm.sh deploy`.
   2. `vm.sh run-ps state` (baseline), `vm.sh run-ps plant`, `vm.sh run-ps state` (save as the planted state).
   3. `vm.sh gui`, `invoke QuickRadio`, `invoke StartButton`, wait ~45 s, `invoke FixButton`, `invoke FixStartButton`.
   4. For each Confirm card, capture it, check that the target is one of the planted artifacts, then `invoke ApproveButton`. Expect 6: startup entry, service, task, Chrome policy, hosts, proxy.
   5. `vm.sh run-ps state`: every planted value should be neutralized (startupApproved `03-...`, proxyEnable 0, serviceStart 4, taskState Disabled, hosts without kbstar, no Chrome policy, Balanced power plan).
   6. `invoke GoUndoButton`, `invoke UndoRunButton`, then `run-ps state` must equal the planted state from step 2.2, except `startupApproved` (it goes back to `none`).
   7. Revert the planted artifacts (switch back to a snapshot taken in step 1, or undo them by hand) and ask the user about leftover snapshots.
3. **Verify the UI-thread fix.** `FixSession.ApplyAsync` and `UndoRunner` now wrap the work in `Task.Run`, because temp cleanup froze the window ("응답 없음"). This is built but not yet run in the VM; step 2 covers it.
4. **Check `actions.json` titles.** Reading the file through `prlctl` showed a garbled `title`. It may be only console decoding (`iconv -f cp949` over UTF-8). Open the file as UTF-8 to confirm; fix only if the file itself is wrong.
5. **Not covered end to end:** `RM-DEFENDER` (needs real-time protection turned off, blocked by Tamper Protection) and `RM-UNINSTALL` (interactive uninstaller). Unit-level coverage only. Tell the user rather than force a test.
6. **Stage 5.**
   - VirusTotal: checkbox on the start screen plus `--vt`. Key from `PCCHECK_VT_KEY` only. Look up SHA-256 of files behind ST-SUSPECT, SVC-SUSPECT, and TASK-SUSPECT findings only. The public API allows 4 requests/min, so cap the count and space the calls (make both configurable in `rules.json`). Add the result to the finding's evidence; escalating severity on a malicious count needs a threshold in `rules.json`. No key is available yet, so ask the user for one or test with a mocked HTTP handler.
   - UI polish: whatever the user reports after using the fix and undo screens.
7. **known-bad.json:** the shipped list is still the spec's three format examples. Prepare a candidate list of Korean PUPs and fake optimizers for the user to review; do not ship it unreviewed (false positives lead to uninstall prompts).
8. **Open design question for the user:** RES-* findings count toward the software subtotal, so an HDD bottleneck (RES-DISK High, 15 points) alone gives a "Cleanup" secondary verdict. This matches the spec's own example, so it was left as is.
9. **Release:** public repo `Bigide19/pitstop`, release v0.1.0 with `pitstop-win-x64.zip` and `PcCheck.exe` built locally (no CI). A GitHub Actions release workflow is a CI change: propose it to the user before writing one. There is no LICENSE yet; the user has to pick one.

## Implementation notes worth knowing

- Signature checks use a batched `Get-AuthenticodeSignature` call (`SignatureVerifier`), not a bare WinVerifyTrust. Most Windows binaries are catalog-signed, and a file-only check reports them as unsigned.
- `IRemediation` gained `Plan(Finding)` returning `RemediationTarget`s. ST-COUNT becomes one target per enabled startup entry; duplicates across findings (for example SEC-AV and SEC-THREAT both pointing at RM-DEFENDER) are removed in `RemediationRegistry.BuildPlan`.
- False positives already fixed, keep them fixed: Edge keeps settings entries for extensions that are not installed (no manifest, location 0), and the encoded-command rule must apply only to PowerShell (Windows' own `ClipRenew.exe -e` matched before).
- Balanced power plan GUID is `381b4222-f694-41f0-9685-ff5bb260df2e`.
- Performance counters work with English names on ko-KR Windows, so `PdhAddEnglishCounter` was not needed.
- `PcCheck_*` output folders, `publish/`, `bin/`, `obj/` are gitignored.
