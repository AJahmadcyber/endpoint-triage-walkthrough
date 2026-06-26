<#
.SYNOPSIS
    Quick endpoint health check script for SOC analysts.

.DESCRIPTION
    Performs a rapid triage of a Windows endpoint, surfacing:
    - Top 10 CPU consumers (by accumulated CPU time)
    - Top 10 RAM consumers (by working set size)
    - CPU temperature (via WMI thermal zones)
    - System uptime

    Designed for initial triage when investigating performance anomalies,
    suspicious activity, or routine health audits.

.NOTES
    Author:    Ahmad Abuzarqa (@AJahmadcyber)
    Version:   1.0
    Created:   June 2026
    License:   MIT
    
    Requires:  PowerShell 5.1+
    Tested on: Windows 10, Windows 11

.EXAMPLE
    .\check-system.ps1
    
    Runs a full system health check and displays results in the console.

.LINK
    https://github.com/AJahmadcyber/endpoint-triage-walkthrough
#>

# ===========================================================================
# Section 1: Top CPU Consumers (Accumulated CPU Time)
# ===========================================================================
# Note: The "CPU" column represents accumulated CPU seconds since process start,
# NOT current percentage. A process with disproportionately high CPU time
# relative to system uptime warrants investigation.

Write-Host "`n=== TOP 10 CPU CONSUMERS ===" -ForegroundColor Cyan
Get-Process | 
    Sort-Object CPU -Descending | 
    Select-Object -First 10 Name, CPU, Id, @{N='RAM(MB)';E={[math]::Round($_.WS/1MB,2)}} | 
    Format-Table -AutoSize

# ===========================================================================
# Section 2: Top RAM Consumers (Working Set Size)
# ===========================================================================

Write-Host "`n=== TOP 10 RAM CONSUMERS ===" -ForegroundColor Cyan
Get-Process | 
    Sort-Object WS -Descending | 
    Select-Object -First 10 Name, @{N='RAM(MB)';E={[math]::Round($_.WS/1MB,2)}}, CPU | 
    Format-Table -AutoSize

# ===========================================================================
# Section 3: CPU Temperature (WMI Thermal Zones)
# ===========================================================================
# Note: Not all systems expose temperature via WMI. If unavailable,
# use third-party tools like HWiNFO64 or Core Temp for accurate readings.

Write-Host "`n=== CPU TEMPERATURE (WMI) ===" -ForegroundColor Cyan
try {
    Get-CimInstance -Namespace "root/wmi" `
                    -ClassName MSAcpi_ThermalZoneTemperature `
                    -ErrorAction Stop | 
        Select-Object @{N='Temp(C)';E={[math]::Round(($_.CurrentTemperature - 2732)/10, 2)}}, 
                      InstanceName | 
        Format-Table -AutoSize
} catch {
    Write-Host "WMI temperature not available on this system." -ForegroundColor Yellow
    Write-Host "Recommendation: Use HWiNFO64 or Core Temp for accurate readings." -ForegroundColor Yellow
}

# ===========================================================================
# Section 4: System Uptime
# ===========================================================================
# Long uptime (>7 days) may indicate need for restart to clear memory leaks
# and apply pending updates. Useful context for interpreting CPU accumulators.

Write-Host "`n=== SYSTEM UPTIME ===" -ForegroundColor Cyan
$bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$uptime = (Get-Date) - $bootTime
Write-Host "Last Boot: $bootTime"
Write-Host "Uptime:    $($uptime.Days) days, $($uptime.Hours) hours, $($uptime.Minutes) minutes"

# ===========================================================================
# Section 5: CPU Time Ratio Analysis
# ===========================================================================
# Identifies processes consuming disproportionate CPU relative to uptime.
# Outliers (>5%) often indicate runaway processes, PUPs, or malware.

Write-Host "`n=== CPU TIME RATIO ANALYSIS ===" -ForegroundColor Cyan
Write-Host "Identifying processes with high CPU usage relative to system uptime`n"

$uptimeSeconds = $uptime.TotalSeconds
$cores = $env:NUMBER_OF_PROCESSORS

Get-Process | 
    Where-Object {$_.CPU -gt 0} | 
    Select-Object Name, Id, CPU,
        @{N='CPU%_of_uptime'; E={[math]::Round(($_.CPU / ($uptimeSeconds * $cores)) * 100, 3)}} |
    Sort-Object CPU%_of_uptime -Descending | 
    Select-Object -First 10 |
    Format-Table -AutoSize

Write-Host "`n[INFO] Processes above 5% warrant investigation." -ForegroundColor Yellow
Write-Host "[INFO] Normal background processes typically stay below 1%.`n" -ForegroundColor Yellow
