# 03 - Eradication

> Phase: Containment + Eradication + Recovery
> Duration: ~20 minutes
> Outcome: Complete removal of all PUP components with verified clean state

---

## Eradication Strategy

The eradication approach followed a structured order to avoid leaving artifacts behind:

1. Stop all running processes
2. Use official uninstaller (cleanest method)
3. Manual cleanup of any leftovers
4. Registry cleanup
5. Network configuration reset
6. Verification at every stage

This order matters: deleting files while services are running causes locked-file errors, and skipping the registry leaves persistence artifacts.

---

## Step 1: Discovery of Official Uninstaller

Before deleting anything manually, the registry was checked for a registered uninstaller:

```powershell
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
    Where-Object {$_.DisplayName -like "*Reason*" -or $_.DisplayName -like "*RAV*"} | 
    Select-Object DisplayName, UninstallString
```

### Result
RAV Endpoint Protection "C:\Program Files\ReasonLabs\EPP\Uninstall.exe" /uninstall

-----------             ---------------

DisplayName             UninstallString
A registered uninstaller existed. This is always preferred over manual removal because:
- It handles service registration cleanup
- It removes registry entries created during install
- It resets system configurations (DNS, firewall, etc.)
- It avoids leaving orphaned files

---

## Step 2: Execute Official Uninstaller

```powershell
Start-Process -FilePath "C:\Program Files\ReasonLabs\EPP\Uninstall.exe" `
              -ArgumentList "/uninstall" `
              -Wait
```

The uninstaller opened a GUI prompting for:
- Reason for uninstallation (any selection acceptable)
- Confirmation to remove all data

Total runtime: ~3 minutes.

---

## Step 3: Post-Uninstall Verification

After the uninstaller completed, the system was checked for residual artifacts:

### Services Check

```powershell
Get-Service rs* -ErrorAction SilentlyContinue
```

Result: No services found - clean.

### Process Check

```powershell
Get-Process rs* -ErrorAction SilentlyContinue
```

Result: No processes - clean.

### File System Check

```powershell
# Main installation directory
Get-ChildItem "C:\Program Files\ReasonLabs\" -ErrorAction SilentlyContinue

# Hidden ProgramData
Get-ChildItem "C:\ProgramData\" -Filter "*Reason*" -ErrorAction SilentlyContinue

# User AppData
Get-ChildItem "$env:LOCALAPPDATA\" -Filter "*Reason*" -ErrorAction SilentlyContinue
Get-ChildItem "$env:APPDATA\" -Filter "*Reason*" -ErrorAction SilentlyContinue
```

### Result
Mode                 LastWriteTime         Length Name
Directory: C:\Users\ThinkPad\AppData\Roaming
d-----          1/5/2026   7:33 PM                ReasonLabs
One leftover folder in `AppData\Roaming` - cleaned up manually:

```powershell
Remove-Item -Path "$env:APPDATA\ReasonLabs" -Recurse -Force
```

---

## Step 4: Registry Verification

The uninstaller should have cleaned all registry entries, but verification is mandatory:

```powershell
Test-Path "HKLM:\SOFTWARE\ReasonLabs"
Test-Path "HKLM:\SOFTWARE\WOW6432Node\ReasonLabs"
Test-Path "HKCU:\SOFTWARE\ReasonLabs"
```

All returned `False` - registry was clean.

---

## Step 5: DNS Configuration Reset

Because the suite included DNS interception services, the DNS configuration was verified:

```powershell
Get-DnsClientServerAddress | 
    Where-Object {$_.AddressFamily -eq 2 -and $_.ServerAddresses}
```

### Result
Wi-Fi          {192.168.100.1}

Ethernet       {1.1.1.1, 8.8.8.8}

InterfaceAlias ServerAddresses
DNS was already pointing to legitimate servers (Cloudflare and Google) - the uninstaller properly restored configuration. If suspicious DNS entries had been found, the fix would be:

```powershell
Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | ForEach-Object {
    Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses
}
```

---

## Step 6: Windows Defender Status Check

Since the `rsWSC` service was designed to modify Windows Security Center reporting, Defender's status needed verification:

```powershell
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AMServiceEnabled
```

### Result

AntivirusEnabled RealTimeProtectionEnabled AMServiceEnabled
True                      True             True
Defender was fully operational - no manual re-enablement needed.

---

## Step 7: Additional Hardening (Bonus)

While performing the cleanup, the opportunity was taken to harden the startup configuration:

### Identified Bloat in Startup

```powershell
Get-CimInstance Win32_StartupCommand | Select-Object Name, Location
```

Found and removed from startup:
- Discord (DiscordPTB)
- Chrome AutoLaunch
- Edge AutoLaunch
- Teams (new client)
- OneDrive (optional)
- WhatsApp Desktop (uninstalled completely)

### Three-Layer Removal Pattern

For each unwanted startup entry, three layers had to be checked:

```powershell
# Layer 1: Direct Run key
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "AppName"

# Layer 2: StartupApproved status flag
$disabled = [byte[]](0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" `
                 -Name "AppName" -Value $disabled

# Layer 3: AppX package (for Microsoft Store apps)
Get-AppxPackage *AppName* | Remove-AppxPackage
```

---

## Final Verification

After all cleanup, a final system check was performed:

```powershell
# CPU consumers
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name, CPU

# Temperature
Get-CimInstance -Namespace "root/wmi" -ClassName MSAcpi_ThermalZoneTemperature | 
    Select-Object @{N="Temp(C)";E={[math]::Round(($_.CurrentTemperature - 2732)/10, 2)}}
```

### Before vs After Metrics

| Metric                  | Before     | After      | Change      |
|-------------------------|------------|------------|-------------|
| Top CPU consumer        | 44,392 sec | 25 sec     | -99.9%      |
| Temperature (idle)      | 76 C       | 53 C       | -23 C       |
| Memory Compression      | 1.1 GB     | < 200 MB   | -82%        |
| WebView2 instances      | 13         | 0          | -100%       |
| Background services     | 8 PUP      | 0          | -100%       |

---

## Lessons From Eradication

1. **Always try the official uninstaller first** - Manual cleanup risks leaving artifacts
2. **Verify at every layer** - Files, services, registry, DNS, AppData
3. **Hardening opportunity** - Use cleanup events to audit broader system state
4. **Restart afterward** - Some changes only take effect after reboot

---

## Next Step

With the system clean and verified, the investigation moved to documenting the techniques observed and mapping them to industry frameworks.

Continue to: [04 - MITRE ATT&CK Mapping](./04-mitre-mapping.md)
