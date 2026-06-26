# 02 - Investigation

> Phase: Identification (deeper) + Pre-Containment
> Duration: ~15 minutes
> Outcome: Mapped full scope of PUP installation across services, registry, and DNS

---

## Pivoting From Symptom to Source

Having identified `rsEngineSvc` as the outlier process, the investigation pivoted to answer three key questions:

1. What is this process and who published it?
2. What other components exist on the system?
3. How does it persist across reboots?

---

## Step 1: Service Enumeration

The process name (`rsEngineSvc`) suggested a Windows service. Initial check:

```powershell
Get-Service | Where-Object {$_.Name -like "*rs*"}
```

This returned a single match. But a broader search by binary path revealed the full picture:

```powershell
Get-CimInstance Win32_Service | 
    Where-Object {$_.PathName -like "*Reason*" -or $_.PathName -like "*RAV*"} | 
    Select-Object Name, PathName, State
```

### Result: Eight Services Discovered
rsWSC          C:\Program Files\ReasonLabs\EPP\rsWSC.exe

rsVPNSvc       C:\Program Files\ReasonLabs\VPN\rsVPNSvc.exe

rsSyncSvc      C:\Program Files\ReasonLabs\Common\rsSyncSvc.exe

rsEngineSvc    C:\Program Files\ReasonLabs\EPP\rsEngineSvc.exe

rsEDRSvc       C:\Program Files\ReasonLabs\EDR\rsEDRSvc.exe

rsDNSSvc       C:\Program Files\ReasonLabs\DNS\rsDNSSvc.exe

rsDNSResolver  C:\Program Files\ReasonLabs\DNS\rsDNSResolver.exe

rsClientSvc    C:\Program Files\ReasonLabs\EPP\rsClientSvc.exe

Name           PathName
This was not a single process - it was a full security suite from a vendor called ReasonLabs (RAV Endpoint Protection).

---

## Step 2: Component Analysis

Each service had a specific function. Mapping them revealed the scope of system access:

| Service       | Function                          | Concern Level   |
|---------------|-----------------------------------|-----------------|
| rsEngineSvc   | Core engine (scanning)            | High CPU        |
| rsClientSvc   | Client agent                      | Persistent      |
| rsEDRSvc      | EDR module                        | Kernel-level    |
| rsDNSResolver | DNS interceptor                   | Traffic visibility |
| rsDNSSvc      | DNS service                       | Traffic visibility |
| rsVPNSvc      | VPN client                        | Network manipulation |
| rsWSC         | Windows Security Center integration | Defender interference |
| rsSyncSvc     | Update/telemetry sync             | C2-like beacon  |

### Notable Findings

- **DNS Interception** - Two services dedicated to intercepting DNS queries
- **EDR Capabilities** - Kernel-level monitoring without user consent during install
- **WSC Manipulation** - Modifying how Windows Security Center reports protection status
- **Always-on Sync** - Constant telemetry to external servers

---

## Step 3: Persistence Audit

The next question was how this suite survives reboots. A multi-layer registry audit was conducted:

### Layer 1 - Standard Run Keys

```powershell
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
```

### Layer 2 - StartupApproved (Enable/Disable Status)

```powershell
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
```

This is a less-known registry path. The first byte of each entry indicates state:
- `0x02` = Enabled
- `0x03` = Disabled

### Layer 3 - Scheduled Tasks

```powershell
Get-ScheduledTask | Where-Object {$_.Actions.Execute -like "*Reason*"}
```

### Layer 4 - AppX Packages (for Microsoft Store apps)

```powershell
Get-AppxPackage *Reason* -ErrorAction SilentlyContinue
```

### Result

The ReasonLabs suite achieved persistence primarily through **services** (Layer 0 - the strongest persistence mechanism), with no scheduled tasks or AppX entries. This simplified eradication but demonstrated a technique commonly used by malware (MITRE T1543.003).

---

## Step 4: Network Component Investigation

DNS services were particularly concerning. They suggested the suite was acting as a man-in-the-middle for all DNS traffic:

```powershell
# Check active DNS configuration
Get-DnsClientServerAddress | Where-Object {$_.AddressFamily -eq 2}
```

If DNS had been redirected to localhost (127.0.0.1) or a private IP managed by `rsDNSSvc`, all browser traffic would have been observable by ReasonLabs.

---

## Step 5: Process Tree Analysis

To understand the full process hierarchy:

```powershell
Get-CimInstance Win32_Process -Filter "Name='rsEngineSvc.exe'" | 
    Select-Object ProcessId, ParentProcessId, CommandLine
```

The parent process was `services.exe` (PID 4) - the standard Windows Service Control Manager. This confirmed the process was running as a true Windows service with SYSTEM privileges.

---

## Investigation Summary

| Finding                      | Implication                              |
|------------------------------|------------------------------------------|
| 8-service deployment         | Multi-component PUP, not single binary   |
| SYSTEM privileges            | Full system access                       |
| DNS interception services    | Traffic visibility, possible MITM        |
| Windows Security Center hook | Could mask its presence from Defender    |
| Persistent across reboots    | Standard service-level persistence       |

---

## Threat Model Implications

While ReasonLabs RAV is a legitimate commercial product, its behavior would be flagged by EDR/XDR systems if encountered without context:

- 8 services from same vendor = unusual deployment pattern
- DNS interception = T1071.004 (Application Layer Protocol: DNS)
- WSC modification = T1562.001 (Impair Defenses)
- Kernel-level EDR access = elevated privilege concern

This is a textbook example of how **legitimate software can mimic malicious techniques** - a critical lesson for SOC analysts learning to balance technical signals with context.

---

## Next Step

With the full scope mapped, the next phase is safe and complete eradication.

Continue to: [03 - Eradication](./03-eradication.md)
