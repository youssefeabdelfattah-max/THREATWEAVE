# Independent Attack Analysis — logs-lokibot.xml

**Analyst posture:** This analysis was performed independently of the correlation engine described in the
task brief. No engine code, scoring logic, or expected output was consulted. Conclusions are drawn only from
the raw Sysmon telemetry, cross-referenced against one public OSINT source for the sample hash (cited below).

## 0. Dataset facts

- **Source:** `logs-lokibot.xml`, a Windows Event Log export, single provider `Microsoft-Windows-Sysmon`,
  single host `DESKTOP-N1A7IAK`.
- **Event count:** **3,720** events (the task brief's estimate of ~2,700 does not match the file as
  uploaded; see `dataset_manifest.json`). The original file is unmodified.
- **Capture window:** 2026-06-29 08:03:50Z → 2026-07-03T11:09:36Z, i.e. **5 separate calendar days**, not one
  continuous session. The XML is **not** chronologically ordered.
- **Sysmon EventIDs present:** 1 (ProcessCreate), 2 (FileCreationTimeChanged), 3 (NetworkConnect), 4
  (ServiceStateChange), 5 (ProcessTerminate), 6 (DriverLoad), 8 (CreateRemoteThread), 11 (FileCreate), 12/13
  (Registry), 16 (ServiceConfigChange), 22 (DnsQuery), 255 (Error).
- **Not present:** EventID 7 (ImageLoad) and 10 (ProcessAccess) — this Sysmon config was not logging module
  loads or direct process-handle access, which limits visibility into any injection technique that relies on
  `OpenProcess`/`WriteProcessMemory` without a corresponding `CreateRemoteThread`. This is a genuine coverage
  gap, noted rather than papered over.
- **Per-day volume:** 06-29: 1,329 · 06-30: 905 · 07-01: 636 · 07-02: 330 · 07-03: 520. 07-03 is where the
  actual detonation occurs; the other four days are baseline lab/analyst activity.

## 1. What actually happened — chronological narrative

### 1.1 Environment/session activity, 2026-06-29 → 2026-07-02 (background)

The four earliest days show a Windows 10 VM (VirtualBox guest, hostname DESKTOP-N1A7IAK, user `Victim`)
being set up and used as a malware-analysis workstation:

- **2026-06-29 18:03Z** — VirtualBox Guest Additions installed/reinstalled (`VBoxWindowsAdditions-amd64.exe`
  → `VBoxCertUtil.exe` adding/removing VirtualBox's own root certificates, `VBoxTray`/`VBoxService` Run-key
  registration). Earlier the same day (08:12–08:53Z) an NSIS uninstaller (`~nsu1.tmp\Un.exe`) removes a prior
  Guest Additions install. Both are ordinary VM provisioning.
- **Recurring across 06-29→07-03:** `spoolsv.exe` self-hostname DNS lookups, `WMIADAP.EXE` performance-counter
  registry housekeeping, `MicrosoftEdgeAutoLaunch` Run-key toggling by `msedge.exe`, Office/Edge telemetry DNS
  (`ecs.office.com` — 86 lookups, by far the most frequent query in the whole dataset — plus
  `edge-consumer-static.azureedge.net`), and a recurring Sysmon driver-config error ("media is write
  protected") on every single day. All are standard OS/application noise.
- **2026-06-30/07-02, early morning:** Windows Disk Cleanup (`cleanmgr.exe`) runs, spawning `DismHost.exe`
  from a GUID-named `%TEMP%` subfolder — legitimate Windows behavior that *looks* like "an executable running
  from Temp" but is fully explained by its signed System32 parent and Windows' own staging convention.
- **2026-06-30 → 2026-07-01, repeatedly:** `powershell.exe`/`sc.exe` connect to `192.168.56.1:9200`
  (Elasticsearch) and `192.168.56.103:53` (DNS), both inside the VirtualBox Host-Only lab subnet
  (`192.168.56.0/24`). This is telemetry-shipping/lab-infrastructure traffic (Winlogbeat/Elastic Agent →
  ELK stack, and DNS to the INetSim sandbox host), not attacker C2 — the destinations are private, not
  internet-routable.
- **2026-07-01, 19:33–20:51Z:** `ping.exe` is run by hand against a family of short, near-identical hostnames
  (`a7a.com`, `a7tta.com`, `aaa7a.com`, `aggg7a.com`, and typo variants). All resolve to `192.168.56.103`
  (the INetSim host). This has the surface shape of DGA/beacon-domain traffic but the cadence (manual,
  irregular, `ping.exe`-driven) and destination (the sandbox's own DNS sinkhole) identify it as the analyst
  hand-testing simulated-internet name resolution ahead of detonation.
- **CreateRemoteThread (Sysmon EventID 8), 140 total in the full dataset:** 134 of these have
  `StartModule=KERNELBASE.dll` / `StartFunction=CtrlRoutine` — the documented Windows signature for console
  control-signal propagation (Ctrl+C/Break, console window close), **not process injection**. 138 of the 140
  fall on 2026-06-29, which is simply the day with the heaviest process churn (650 ProcessCreate events),
  hence the most console-signal traffic. This is flagged explicitly because a naive correlation engine that
  treats every `CreateRemoteThread` as injection would badly over-flag this day.

None of the above ties, by process lineage, network destination, or file path, to any indicator of compromise.
It is included in the evaluation dataset specifically so a correlation engine has real noise to filter.

### 1.2 The attack — 2026-07-03, 10:44:56Z → 10:57:32Z

All genuinely malicious activity in this dataset is confined to a ~13-minute window on the last day, driven
by a single process image.

1. **10:44:56Z / 10:48:34Z — Sample staging (analyst-initiated).** From an Explorer-launched `cmd.exe`, `7z.exe`
   twice tests (`-p infected -t`) and then extracts (`-x`) an archive named after its own payload's SHA256
   (`7e9e014b4127363351ff22d500de90a9872a8d8fcab328277fabd7fc1f4b5c6c.zip`), password `infected` — the
   standard abuse.ch/MalwareBazaar sample-packaging convention. The wrapper command includes a fallback
   `mshta`/vbscript error dialog for a wrong password; it never fires, since extraction succeeds. This is the
   analyst detonating a labelled malware sample in a controlled VM, not an adversary delivery technique, and
   is labelled `SAMPLE_STAGING_DETONATION` in the ground truth rather than a MITRE Initial-Access stage.

2. **10:47:06Z onward — Execution.** The extracted file, renamed **`aaa.exe`**, is launched from
   `C:\Users\Victim\Desktop\New folder\`. Its PE metadata is spoofed: `Description=WinRAR archiver`,
   `Company=WinRAR`, but `OriginalFileName=WPCq.exe` — a metadata mismatch consistent with masquerading
   (MITRE **T1036.005**). Hashes: **SHA256
   7E9E014B4127363351FF22D500DE90A9872A8D8FCAB328277FABD7FC1F4B5C6C**, MD5
   B5F1B1E2ED61F80EDA38FF8263732D41, IMPHASH F34D5F2D4577ED6D9CEEC516C1F5A744.

   Over the following ~10 minutes, `aaa.exe` **relaunches itself repeatedly** — 17 ProcessCreate events for
   the same image, in parent→child chains up to five generations deep (e.g. explorer.exe → aaa.exe → aaa.exe
   → aaa.exe → aaa.exe), 16 of which terminate within the capture window (the 17th, PID 6520 at 10:55:15Z, has
   no captured terminate — its end-state is not resolvable from this telemetry). One instance (PID 2240,
   launched 10:47:11Z) crashes ~15 seconds later, producing a `WerFault.exe` dump — but crashing does not
   fully explain the relaunch pattern, since only 1 of 17 instances crashed.

   No `RegistryValueSet`, `RegistryObjectCreateDelete`, or `FileCreate` event in the entire dataset is
   attributed to `aaa.exe`. **No persistence mechanism, no dropped secondary payload, and no credential-store
   file access are evidenced in this telemetry** — this is stated as an absence of evidence, not evidence of
   absence; Sysmon's config gaps (no EventID 7/10) and the sample's apparent instability both limit what could
   be captured.

3. **10:47:25Z — One malformed DNS query.** `aaa.exe` (PID 7436) issues a single DNS query whose `QueryName`
   decodes to non-printable/garbled characters, one millisecond before the first network beacon. High
   confidence this is malware-issued (exact process and timing); low-to-medium confidence in what the string
   actually represents — it may be an obfuscated/encoded config value or an artifact of the sample's
   instability. Flagged as uncertain rather than asserted.

4. **10:47:25Z → 10:57:32Z — Command and control.** `aaa.exe` makes **7 outbound TCP connections** to
   **94.156.177.41:80**, a public (non-RFC1918) IP with no corresponding forward DNS lookup anywhere in the
   dataset — consistent with a hardcoded C2 endpoint. The connections recur at roughly 60-second intervals,
   a beacon-like cadence. This is the clearest, highest-confidence indicator in the dataset.

5. **End of window.** The last observed beacon is at 10:57:32Z; the log continues (unrelated analyst activity —
   Edge browsing, network-adapter settings) through 11:09:36Z with **no further `aaa.exe` activity of any
   kind**. Whether the sample was manually killed, self-terminated, or continued beaconing outside Sysmon's
   visibility cannot be determined from this file alone — see §2 "active" determination.

### 1.3 External corroboration (used as context, not as ground truth)

A public write-up independently analyzing the same SHA256 describes it as a packed/obfuscated **.NET 32-bit
GUI executable** that imports networking, registry, and input-simulation APIs (`HttpOpenRequestW`,
`InternetConnectW`, `RegConnectRegistryW`, `SendInput`) and that, in that researcher's environment, disguised
C2 traffic inside OCSP-looking HTTPS requests to `ocsp.digicert.com`. That specific OCSP behavior was **not**
observed in this dataset — only a raw TCP connection to `94.156.177.41:80` was captured — which is consistent
with this run crashing/being interrupted before reaching a later stage, or with sandbox/environment
differences. The family label "LokiBot" used elsewhere for this sample is carried over from the prior
investigation on file for this host; **this independent analysis does not itself confirm family attribution**
beyond noting behavior consistent with a packed loader/stealer (self-relaunching, masquerading metadata,
hardcoded-IP beaconing).

## 2. Independent attack scenarios

**Exactly one genuine attack scenario was identified.** Everything else in the 3,720-event dataset is benign
lab, analyst, or OS/application activity — see §1.1 and the false-positive-trap categories called out below.

### CAMP-001 — aaa.exe execution & C2 beaconing

| Field | Value |
|---|---|
| Description | Execution of a masquerading, self-relaunching binary (SHA256 `7e9e...4b5c6c`) followed by repeated hardcoded-IP beaconing |
| Start / End (UTC) | 2026-07-03T10:44:56Z (staging) / 2026-07-03T10:57:32Z (last observed beacon) — core execution 10:47:06Z–10:57:32Z |
| Affected host | DESKTOP-N1A7IAK |
| Affected user | Victim |
| Key processes | `aaa.exe` (17 instances), `7z.exe`/`cmd.exe` (staging), `WerFault.exe` (1 crash) |
| Key network activity | 7× TCP to 94.156.177.41:80 |
| Key files | `C:\Users\Victim\Desktop\New folder\7e9e...4b5c6c.exe` (extracted, then renamed `aaa.exe`) |
| Key IOCs | SHA256 `7E9E014B4127363351FF22D500DE90A9872A8D8FCAB328277FABD7FC1F4B5C6C`; MD5 `B5F1B1E2ED61F80EDA38FF8263732D41`; IMPHASH `F34D5F2D4577ED6D9CEEC516C1F5A744`; IP `94.156.177.41:80` |
| MITRE ATT&CK | T1204.002 (User Execution: Malicious File) — analyst-initiated in this lab context; T1036.005 (Masquerading: Match Legitimate Name/Location); T1071.001 (Application Layer Protocol: Web) suspected from port 80 but **not confirmed** at payload level in this telemetry |
| Stages observed | Sample staging/detonation → Execution → Command and Control |
| Stages *not* evidenced here | Persistence, Credential Access, Collection, Exfiltration, Lateral Movement — absence noted, not assumed |
| Appears active at end of capture? | **Indeterminate.** Last beacon 10:57:32Z; no further activity through end of log (11:09:36Z); no captured terminate for the final instance. Should not be scored as confidently ACTIVE or confidently RESOLVED — see `evaluation_methodology.md` |
| Confidence in scenario boundary | HIGH for the process/network core; MEDIUM for the single garbled DNS query's meaning; the family label "LokiBot" is carried over from prior investigation, not independently re-derived here |

### Unrelated / benign / ambiguous

- **Benign (408 of the 472 curated events, and the overwhelming majority of the full 3,720):** VM
  provisioning, OS housekeeping, analyst tooling (FakeNet-NG, 7-Zip, ping.exe testing), Office/Edge telemetry,
  and lab-infrastructure traffic (ELK/INetSim on the private `192.168.56.0/24` subnet). See §1.1.
- **Deliberate false-positive traps within the "benign" set** — each individually resembles a known
  attack technique but is independently verified benign: Run-key writes (persistence-shaped), temp-folder
  `.exe` execution via `DismHost.exe` (dropped-payload-shaped), `certutil.exe` usage (LOLBin-shaped),
  `CreateRemoteThread` via `CtrlRoutine` (injection-shaped), the `a7a.com` domain family (DGA-shaped),
  Sysmon's own `RuleName` tags of "Suspicious"/"T1060,RunKey" on `RegistryObjectCreateDelete` events
  (upstream-label-shaped), and regular-interval connections to the private ELK/INetSim hosts
  (beacon-cadence-shaped). A correlation engine that pattern-matches on surface shape alone, without checking
  process lineage/destination/signer context, should be expected to mis-flag some of these — that is the
  point of including them.
- **Ambiguous / UNKNOWN (8 events):** 6 `CreateRemoteThread` events with unresolved `StartModule`/
  `StartFunction` (source `VBoxTray.exe`→PID 568, and `EdgeUpdate`-related), and 2 `WerFault.exe` crash-dump
  events for a PID (3684, 2026-06-29) whose originating process could not be resolved in this capture. Neither
  correlates temporally or by process lineage to CAMP-001. Left as `UNKNOWN` rather than forced into either
  bucket, per the task brief's instruction not to force uncertain events into a scenario.

## 3. Notes on scope and limitations

- This is a **single-host, single-session-per-day** dataset. There is no lateral movement, multi-host, or
  privilege-escalation evidence to evaluate — a correlation engine's handling of those stages cannot be
  meaningfully tested against this specific file, only against the presence/absence determination itself.
- Sysmon EventID 7 (ImageLoad) and 10 (ProcessAccess) are absent from this export's configuration, which caps
  how much can be said about in-memory injection or DLL-level tradecraft; this is called out rather than
  inferred around.
- The garbled DNS query (§1.2 step 3) and the exact cause of `aaa.exe`'s repeated crashing/relaunching are the
  two lowest-confidence interpretive calls in this analysis; both are flagged with MEDIUM/LOW confidence in
  `ground_truth.json` rather than stated as fact.
