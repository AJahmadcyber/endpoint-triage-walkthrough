# 04 - MITRE ATT&CK Mapping

> Phase: Analysis + Documentation
> Outcome: Behaviors mapped to industry-standard adversary techniques

---

## Why Map a PUP to MITRE ATT&CK?

ReasonLabs RAV is a legitimate commercial product, not malware. However, its behaviors overlap significantly with techniques used by adversaries. Mapping these behaviors serves three purposes:

1. **Detection engineering practice** - The same detection logic catches both legitimate PUPs and actual threats
2. **Behavioral analysis training** - Learning to recognize techniques regardless of attribution
3. **Documentation standard** - MITRE ATT&CK is the common vocabulary across SOC, IR, and threat intel teams

---

## Techniques Observed

### T1543.003 - Create or Modify System Process: Windows Service

**Tactic:** Persistence, Privilege Escalation

**Description:** Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence.

**Observed Behavior:**
- 8 Windows services installed without granular user consent during install
- Services run as `LocalSystem`, providing maximum privileges
- Services configured to start automatically on boot
- Services restart automatically if killed

**Evidence:**
```powershell
Get-CimInstance Win32_Service | Where-Object {$_.PathName -like "*Reason*"}
```

**Detection Opportunity:**
```spl
index=sysmon EventCode=7045  # Service installation
| stats count by ServiceName, ImagePath, AccountName
| where like(ImagePath, "%ReasonLabs%")
```

---

### T1547.001 - Registry Run Keys / Startup Folder

**Tactic:** Persistence, Privilege Escalation

**Description:** Adversaries may achieve persistence by adding programs to startup folders or referencing them with Registry run keys.

**Observed Behavior:**
- Multiple autostart entries identified across three registry layers:
  - Standard `HKCU\...\Run` keys
  - `StartupApproved\Run` enable/disable flags
  - AppX package manifests (for newer applications)

**Evidence:**
```powershell
# Layer 1
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Layer 2 (less monitored)
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
```

**Detection Opportunity:**
Monitor changes to Run keys via Sysmon Event ID 13 (Registry Value Set). Alert on writes from non-installer processes.

---

### T1071.004 - Application Layer Protocol: DNS

**Tactic:** Command and Control

**Description:** Adversaries may communicate using the DNS application layer protocol to avoid detection by blending in with existing traffic.

**Observed Behavior:**
- Dedicated DNS interceptor services (`rsDNSResolver`, `rsDNSSvc`)
- All DNS queries routed through ReasonLabs infrastructure
- Vendor gains visibility into every domain accessed by user
- Same architectural pattern as DNS-based C2 channels

**Evidence:**
```powershell
Get-CimInstance Win32_Service | Where-Object {$_.PathName -like "*DNS*Resolver*"}
```

**Detection Opportunity:**
```spl
index=sysmon EventCode=22  # DNS query
| stats count by Image, QueryName
| where like(Image, "%rsDNSResolver%")
```

While the legitimate use is "DNS filtering and parental controls," the technique is architecturally identical to DNS-based C2.

---

### T1562.001 - Impair Defenses: Disable or Modify Tools

**Tactic:** Defense Evasion

**Description:** Adversaries may modify and/or disable security tools to avoid detection.

**Observed Behavior:**
- `rsWSC` service interacted with Windows Security Center
- Modified how Defender's protection status was reported
- Could potentially suppress security notifications
- Behavior aligns with techniques used by ransomware to disable AV before encryption

**Evidence:**
The `rsWSC.exe` binary's purpose (Windows Security Center integration) is itself the indicator. Legitimate antivirus products use WSC integration, but the same mechanism can be abused.

**Detection Opportunity:**
Monitor changes to Defender's running state via Sysmon Event ID 13:

```spl
index=sysmon EventCode=13 
TargetObject="HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\*"
| stats count by Image, TargetObject, Details
```

---

## Secondary Techniques (Possible)

These were not definitively confirmed but are consistent with observed behaviors:

### T1546 - Event Triggered Execution

Possible via service triggers or WMI event subscriptions used by some PUP families.

### T1119 - Automated Collection

The "scanning engine" component collects file metadata system-wide, which is architecturally similar to automated collection used by malware.

### T1027 - Obfuscated Files or Information

Many PUP installers use obfuscation in their dropper components. Not analyzed in this case, but worth noting for future investigations.

---

## Complete Technique Map

| ID         | Technique                                      | Tactic                      | Confidence |
|------------|------------------------------------------------|-----------------------------|-----------|
| T1543.003  | Create or Modify System Process: Windows Service | Persistence               | Confirmed |
| T1547.001  | Registry Run Keys / Startup Folder             | Persistence                 | Confirmed |
| T1071.004  | Application Layer Protocol: DNS                | Command and Control         | Confirmed |
| T1562.001  | Impair Defenses: Disable/Modify Tools          | Defense Evasion             | Confirmed |
| T1546      | Event Triggered Execution                      | Persistence                 | Possible  |
| T1119      | Automated Collection                           | Collection                  | Possible  |

---

## The Critical Insight

Every single technique observed in ReasonLabs RAV is **also used by real malware families**:

- **T1543.003** - Used by TrickBot, Emotet, ransomware loaders
- **T1547.001** - Used by virtually all persistent malware
- **T1071.004** - Used by APT29, Sunburst, DNS tunneling tools
- **T1562.001** - Used by Ryuk, Conti, REvil before encryption

This is what makes PUPs hard to detect with signature-based approaches and why **behavioral detection** is the future of endpoint security. Legitimate or not, the techniques are the same.

---

## Sigma Rule Example

A detection rule based on this case study:

```yaml
title: ReasonLabs PUP Installation Detected
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects installation of ReasonLabs services, which are often bundled as PUPs
references:
    - https://attack.mitre.org/techniques/T1543/003/
author: Ahmad Abuzarqa (@AJahmadcyber)
date: 2026/06/26
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|contains:
            - '\ReasonLabs\'
            - 'rsEngineSvc.exe'
            - 'rsEDRSvc.exe'
            - 'rsDNSSvc.exe'
    condition: selection
falsepositives:
    - Legitimate RAV installations by user choice
level: medium
tags:
    - attack.persistence
    - attack.t1543.003
```

---

## Why This Matters for SOC Analysts

Mapping behaviors to MITRE ATT&CK transforms a triage exercise into a learning experience. The same skills used to clean up a PUP apply to investigating:

- Cryptojackers with persistent services
- Ransomware loaders with multi-stage persistence
- Backdoors with DNS-based C2
- Defender-disabling rootkits

The PUP becomes a **safe training ground** for techniques that would otherwise require malware lab access.

---

## Next Step

With techniques documented and detection logic drafted, the final phase is reflecting on lessons learned and building reusable detection content.

Continue to: [05 - Lessons Learned](./05-lessons-learned.md)
