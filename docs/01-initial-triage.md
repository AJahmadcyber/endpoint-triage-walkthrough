# 01 - Initial Triage

> Phase: Identification
> Duration: ~10 minutes
> Outcome: Identified outlier process consuming disproportionate CPU resources

---

## Initial Symptoms

The investigation began with three observable symptoms on a Windows 11 ThinkPad (16 GB RAM):

1. Persistent overheating - Laptop reaching 76C even during idle periods
2. Sluggish responsiveness - System felt slow despite no heavy applications running
3. Continuous fan activity - Cooling fans running at high RPM consistently

These symptoms suggested a runaway background process, but Task Manager did not reveal an obvious culprit at first glance.

---


---

##  PICERL Framework Visualization

```mermaid
flowchart LR
    A[ Preparation] --> B[ Identification]
    B --> C[ Containment]
    C --> D[ Eradication]
    D --> E[ Recovery]
    E --> F[ Lessons Learned]
    F -.feedback loop.-> A
    
    style A fill:#3498db,color:#fff
    style B fill:#e74c3c,color:#fff
    style C fill:#f39c12,color:#fff
    style D fill:#27ae60,color:#fff
    style E fill:#9b59b6,color:#fff
    style F fill:#34495e,color:#fff
```

This case study follows the **PICERL framework**  the industry-standard incident response methodology. Each stage in this documentation corresponds to one phase above.

---

## Triage Approach

Rather than relying on visual inspection of Task Manager, the investigation pivoted to PowerShell-based enumeration for more granular data.

### Step 1: Process Enumeration by CPU Time

```powershell
Get-Process | 
    Sort-Object CPU -Descending | 
    Select-Object -First 10 Name, CPU, Id, @{N="RAM(MB)";E={[math]::Round($_.WS/1MB,2)}}
```

Why this matters: Task Manager shows current CPU percentage, which can miss processes that have been quietly consuming CPU over time. The CPU property in Get-Process returns accumulated CPU seconds since process start - a more reliable metric for finding long-running outliers.

### Step 2: Initial Output
msedge                 130.843750 5636  443.77

Memory Compression     410.937500 3036 1165.97

System                  18.359375    4    1.46

chrome                  90.953125 9504  160.18

rsEngineSvc          44392.484375 4520  169.46

Name                       CPU    Id RAM(MB)
The outlier was immediately obvious: rsEngineSvc had accumulated 44,392 seconds of CPU time - orders of magnitude more than any other process.

---

## The Key Metric: CPU Time Ratio

To quantify how anomalous this was, the CPU time accumulator ratio was calculated:
CPU % of uptime = (Process_CPU_Time / (System_Uptime * CPU_Cores)) * 100
For rsEngineSvc:
- CPU Time: 44,392 seconds
- System Uptime: ~5 days (432,000 seconds)
- CPU Cores: 8
CPU% = ~1.3% sustained over uptime

CPU% = (44,392 / (432,000 * 8)) * 100
While 1.3% sounds small, it represents ~12 hours of pure CPU consumption by a single process - a strong indicator of either:
- A poorly-written application with resource leaks
- A process performing constant background work (scans, beaconing, mining)
- A misconfigured service

---

## Triage Rules of Thumb

| CPU % of Uptime | Assessment            | Action                        |
|-----------------|-----------------------|-------------------------------|
| < 0.5%          | Normal background     | No action needed              |
| 0.5% - 2%       | Active but reasonable | Worth noting, check process   |
| 2% - 5%         | Suspicious            | Investigate process purpose   |
| > 5%            | Strong outlier        | Treat as priority for triage  |
| > 10%           | Critical              | Likely PUP, malware, or bug   |

---

## Tools Used

- PowerShell 5.1+ (Get-Process, Sort-Object, Select-Object)
- Built-in Windows process metrics
- No third-party tools required

---

## Key Takeaway

> When investigating performance anomalies, accumulated CPU time often reveals what real-time monitoring misses. A process consuming consistent low percentages adds up to massive total consumption - the kind of pattern that defines PUPs, cryptominers, and certain malware families.

---

## Next Step

Now that we have identified rsEngineSvc as the outlier, the next phase is to investigate what this process is, what services it runs, and what other artifacts exist on the system.

Continue to: [02 - Investigation](./02-investigation.md)
