# 05 - Lessons Learned

> Phase: Post-Incident Reflection
> Outcome: Reusable insights, detection content, and improved triage methodology

---

## Summary of the Case

A symptom-driven investigation (overheating laptop) led to the discovery of a multi-service PUP consuming disproportionate system resources. The investigation followed the PICERL framework, mapped findings to MITRE ATT&CK, and produced detection content applicable to SOC environments.

### Key Numbers

| Metric                  | Value                |
|-------------------------|----------------------|
| Investigation duration  | ~45 minutes          |
| Services removed        | 8                    |
| Persistence layers      | 3 (Run, StartupApproved, AppX) |
| MITRE techniques mapped | 4 confirmed, 2 possible |
| Temperature reduction   | 23 C                 |
| CPU consumption reduction | 99.9%              |

---

## Top 5 Lessons

### Lesson 1: CPU Time Accumulator is Underrated

Most analysts default to checking *current* CPU percentage in Task Manager. This misses processes that consume small amounts of CPU continuously over long periods.

**The metric that mattered:**
CPU % of uptime = (Process_CPU_Time / (Uptime * Cores)) * 100
A process at 1.3% of total uptime CPU sounds insignificant. But it represents ~12 hours of sustained work - the signature of:
- PUPs with constant background scanning
- Cryptominers throttling to avoid detection
- Malware beacons with low jitter

**Takeaway:** Add accumulated CPU time analysis to your standard triage workflow.

---

### Lesson 2: Persistence Has Multiple Layers

Windows has at least 4 distinct persistence mechanisms that must all be checked:

1. **Standard Run keys** (`HKCU\...\Run`, `HKLM\...\Run`)
2. **StartupApproved flags** (`Explorer\StartupApproved\Run`) - the enable/disable state
3. **Scheduled Tasks** (especially with logon triggers)
4. **AppX Packages** (modern Microsoft Store apps)

Many malware authors deliberately target the less-monitored layers (StartupApproved, AppX) because traditional security tools focus on the standard Run keys.

**Takeaway:** A persistence audit that only checks `HKCU\...\Run` is incomplete. Build scripts that audit all four layers.

---

### Lesson 3: Process Tree Analysis is Essential

The `ParentProcessId` field in `Get-CimInstance Win32_Process` is one of the most powerful triage tools available.

**Red flags to look for:**

| Parent          | Child           | Concern                      |
|-----------------|-----------------|------------------------------|
| winword.exe     | cmd.exe         | Macro execution              |
| cmd.exe         | powershell.exe  | Living-off-the-land          |
| svchost.exe     | cmd.exe         | Unusual service behavior     |
| explorer.exe    | %TEMP%\*.exe    | User-mode persistence        |
| services.exe    | Unknown binary  | Service registration         |

**Takeaway:** Always check parent-child relationships when investigating suspicious processes. The lineage often tells the story better than the process name.

---

### Lesson 4: Legitimate Software Uses Adversary Techniques

ReasonLabs RAV is not malware. Yet every technique it uses (services, registry persistence, DNS interception, WSC manipulation) is documented in MITRE ATT&CK and observed in real attacks.

This challenges the binary "good vs malicious" thinking that beginners often have. Reality is more nuanced:

- **Malware** uses techniques X, Y, Z
- **Legitimate AV** also uses techniques X, Y, Z (because they need similar access)
- **PUPs** sit in the middle, often using techniques X, Y, Z without clear user benefit

**Takeaway:** Focus on *behavior in context*, not just signatures. A process running as SYSTEM with kernel access needs justification - regardless of vendor.

---

### Lesson 5: Hardening Opportunities are Hidden in Triage

While investigating the PUP, several unrelated hardening opportunities were identified:

- Background apps consuming RAM (Discord, WhatsApp, Teams)
- AutoLaunch entries from browsers
- Unnecessary OneDrive sync
- Long uptime (5+ days) suggesting need for routine reboots

**Takeaway:** Treat every incident as an opportunity to audit broader system hygiene. The same Get-Process and registry commands that found the PUP also revealed bloat that affected daily performance.

---

## Detection Engineering Output

This investigation produced reusable detection content:

### 1. Sigma Rule (Generic Reason/RAV Detection)

```yaml
title: ReasonLabs PUP Service Installation
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects ReasonLabs RAV service installation
references:
    - https://attack.mitre.org/techniques/T1543/003/
author: Ahmad Abuzarqa (@AJahmadcyber)
date: 2026/06/26
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ImagePath|contains: '\ReasonLabs\'
    condition: selection
falsepositives:
    - Intentional user installation of RAV product
level: medium
tags:
    - attack.persistence
    - attack.t1543.003
```

### 2. PowerShell Hunt Script

A reusable script (`audit-startup.ps1` in this repo) that:
- Enumerates all 4 persistence layers
- Reports enable/disable state for each entry
- Identifies entries with unsigned binaries
- Flags entries with unusual install paths

### 3. KQL Query (Microsoft Defender / Sentinel)

```kql
DeviceProcessEvents
| where InitiatingProcessFolderPath contains "ReasonLabs"
   or FolderPath contains "ReasonLabs"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## What I Would Do Differently

In hindsight, a few improvements to the methodology:

1. **Document timeline as it happens** - Real IR teams use case management tools (TheHive, etc.). Even a simple notepad with timestamps would have helped recreate the investigation order.

2. **Capture forensic artifacts before changes** - Before running the uninstaller, exporting the registry hives and listing all files in ReasonLabs folders would have preserved evidence for deeper analysis.

3. **Test detection rules** - The Sigma rule above is plausible but untested. A proper detection engineering workflow would involve installing RAV in a VM, generating events, and validating the rule fires.

4. **Network capture** - DNS interception services were identified but not analyzed at the wire level. A Wireshark capture during normal operation would have shown exactly what data was being sent to ReasonLabs infrastructure.

These are documented here as future improvements for the next case.

---

## Skills Reinforced

This investigation reinforced several core SOC skills:

- Process enumeration via PowerShell
- Registry navigation across HKCU/HKLM
- WMI/CIM query construction
- DNS configuration auditing
- Service control and management
- AppX package handling
- MITRE ATT&CK technique identification
- Sigma rule syntax
- KQL/SPL query writing

These skills transfer directly to:
- Day-to-day SOC L1 triage
- Threat hunting engagements
- DFIR investigations
- Detection engineering work

---

## Closing Thoughts

The original symptom was a hot laptop. The investigation became a complete walkthrough of:
- Incident response methodology
- Endpoint forensics
- Persistence hunting
- Behavior-based detection
- Documentation and reporting

This is the value of treating every symptom as a learning opportunity. The PUP that caused the heat was relatively benign, but the process of investigating it built skills that apply directly to real adversary scenarios.

For the next SOC analyst reading this:

> The techniques don't change. The vendor labels do. Focus on what the software *does*, not what it *claims to be*.

---

## Repository

This walkthrough is part of:

**[endpoint-triage-walkthrough](https://github.com/AJahmadcyber/endpoint-triage-walkthrough)**

- 5 documented PICERL phases
- 2 reusable PowerShell scripts
- 1 Sigma detection rule
- Full MITRE ATT&CK mapping

---

## Acknowledgments

Built as part of my journey into SOC analysis and Detection Engineering. Special thanks to the MITRE ATT&CK team for the framework that makes this kind of structured analysis possible.

---

## Connect

**Ahmad Abuzarqa** - SOC Analyst Trainee, Jordan

- GitHub: [@AJahmadcyber](https://github.com/AJahmadcyber)
- Email: ahmad.j.abuzarqa@gmail.com

> *"In cybersecurity, paranoia is a feature, not a bug."*
