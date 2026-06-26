# Scripts

PowerShell scripts for endpoint triage and persistence auditing.

## Available Scripts

### `check-system.ps1`
Quick endpoint health check. Surfaces top CPU/RAM consumers, temperature, uptime, and CPU time ratio analysis.

**Usage:**
```powershell
powershell -ExecutionPolicy Bypass -File .\check-system.ps1
```

### `audit-startup.ps1`
Multi-layer persistence audit covering Run keys, StartupApproved, WMI startup commands, and Scheduled Tasks with logon triggers.

**Usage:**
```powershell
powershell -ExecutionPolicy Bypass -File .\audit-startup.ps1
```

## Requirements

- PowerShell 5.1 or higher
- Some operations may require Administrator privileges for full visibility

## Execution Policy

If you receive an execution policy error, you can either:

1. Bypass for a single execution:
```powershell
   powershell -ExecutionPolicy Bypass -File .\script.ps1
```

2. Set for current user (persistent):
```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Safety

All scripts in this folder are **read-only** investigation tools. They do not modify system configuration, registry, or files.
