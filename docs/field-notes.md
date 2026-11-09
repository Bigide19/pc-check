# Field notes

Real PCs checked with PC Check, and what they taught. No PC names, user names, or file contents from those PCs go here.

## 2026-11-06: Photos app would not open (office PC, Windows 11 25H2)

| | |
|---|---|
| Symptom | The Photos app never opened; the "Open with" dialog did not appear. Excel input was sometimes sluggish. An in-place Windows reinstall changed nothing. |
| What PC Check showed (v0.1.1) | `APP-PHOTOS`: 21 crashes in 7 days, all in `TENXWGuard64_127.dll`, exception `c0000005`. Cause reported as "unknown". |
| Root cause | TouchEn nxKey (RaonSecure keyboard security for Korean banking sites) injects that DLL into every process. It crashed Photos on start. |
| Fix | Uninstall TouchEn nxKey, reboot. Photos and the "Open with" dialog worked immediately. |
| Also on the PC | 39 startup entries, about ten of them banking/government security modules; ALYac and Avast together (Defender passive, so its scan was refused); broken performance counters (`_Total` instance missing, repaired by `lodctr /R`). |
| Verdict PC Check gave | "Format" from the software-score rule (205 points). The real fix was one uninstall, so treat a score-only "Format" with suspicion and look at APP-CRASHES first. |
| Changes it drove (v0.1.3) | `APP-CRASHES` names the program behind an injected module and offers its uninstaller; `SEC-KR-MODULES` lists security modules with researched notes (`config/kr-modules.json`); resource sampling survives missing counters; the Defender refusal reason is shown; the tool version is printed in every output; results zip into one file. |

Triage order that would have saved a day here: APP-CRASHES (who crashes what) > SEC-KR-MODULES > startup count > everything else.

Reinstalling TouchEn nxKey for online banking brings the problem back. Install the current version from the bank's site only when needed, and remove it afterwards.
