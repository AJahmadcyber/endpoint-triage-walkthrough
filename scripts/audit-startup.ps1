<#
.SYNOPSIS
    Multi-layer Windows persistence audit script.

.DESCRIPTION
    Enumerates startup persistence locations across multiple Windows registry
    paths and storage mechanisms. Designed to detect:
    
    - Standard Run keys (HKCU and HKLM)
    - RunOnce keys
    - StartupApproved entries (enable/disable flags)
    - Scheduled Tasks with logon triggers
    - AppX startup tasks
    
    MITRE ATT&CK: T1547.001 (Registry Run Keys / Startup Folder)

.NOTES
    Author:    Ahmad Abuzarqa (@AJahmadcyber)
    Version:   1.0
    Created:   June 2026
    License:   MIT

.EXAMPLE
    .\audit-startup.ps1
    
    Displays all startup persistence entries grouped by location type.

.LINK
    https://github.com/AJahmadcyber/endpoint-triage-walkthrough
#>

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  WINDOWS STARTUP PERSISTENCE AUDIT" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# ===========================================================================
# Layer 1: Registry Run Keys
# ===========================================================================

$runKeys = @(
    @{Name="HKCU Run";              Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"},
    @{Name="HKLM Run";              Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"},
    @{Name="HKLM Run (WOW64)";      Path="HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"},
    @{Name="HKCU RunOnce";          Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"},
    @{Name="HKLM RunOnce";          Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"}
)

foreach ($key in $runKeys) {
    Write-Host "[$($key.Name)]" -ForegroundColor Yellow
    Write-Host "Path: $($key.Path)"
    
    try {
        $entries = Get-ItemProperty -Path $key.Path -ErrorAction Stop | 
                   Select-Object * -ExcludeProperty PS*
        
        if ($entries.PSObject.Properties.Count -eq 0) {
            Write-Host "  (empty)" -ForegroundColor Gray
        } else {
            $entries.PSObject.Properties | ForEach-Object {
                Write-Host "  - $($_.Name): $($_.Value)" -ForegroundColor White
            }
        }
    } catch {
        Write-Host "  (path not accessible or does not exist)" -ForegroundColor Gray
    }
    Write-Host ""
}

# ===========================================================================
# Layer 2: StartupApproved (Enable/Disable State)
# ===========================================================================

Write-Host "[StartupApproved - Run Key Status]" -ForegroundColor Yellow
Write-Host "Path: HKCU:\...\Explorer\StartupApproved\Run"
Write-Host "Note: First byte: 02=Enabled, 03=Disabled`n"

$approvedPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
try {
    $approved = Get-ItemProperty -Path $approvedPath -ErrorAction Stop | 
                Select-Object * -ExcludeProperty PS*
    
    $approved.PSObject.Properties | ForEach-Object {
        $status = if ($_.Value[0] -eq 2) { "ENABLED " } else { "DISABLED" }
        $color = if ($_.Value[0] -eq 2) { "Green" } else { "Red" }
        Write-Host "  [$status] $($_.Name)" -ForegroundColor $color
    }
} catch {
    Write-Host "  (no entries found)" -ForegroundColor Gray
}
Write-Host ""

# ===========================================================================
# Layer 3: Win32_StartupCommand (WMI View)
# ===========================================================================

Write-Host "[All Startup Commands (WMI)]" -ForegroundColor Yellow
Write-Host "Consolidated view via Win32_StartupCommand`n"

Get-CimInstance Win32_StartupCommand | 
    Select-Object Name, Location, User | 
    Format-Table -AutoSize

# ===========================================================================
# Layer 4: Scheduled Tasks with Logon Triggers
# ===========================================================================

Write-Host "`n[Scheduled Tasks - Logon Triggers]" -ForegroundColor Yellow
Write-Host "Tasks configured to run at user logon`n"

Get-ScheduledTask | Where-Object {
    $_.Triggers.CimClass.CimClassName -match "LogonTrigger"
} | Select-Object TaskName, TaskPath, State, Author | 
    Format-Table -AutoSize

# ===========================================================================
# Summary
# ===========================================================================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  AUDIT COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Review entries for anomalies:"
Write-Host "  - Unfamiliar executable paths (e.g., %TEMP%, %AppData%)"
Write-Host "  - Suspicious naming (random strings, mimics of system files)"
Write-Host "  - Recently added entries (correlate with timeline)"
Write-Host "  - Entries with no signature or unknown publisher"
Write-Host ""
