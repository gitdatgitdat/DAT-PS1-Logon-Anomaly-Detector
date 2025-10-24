# PowerShell Logon Anomally Detector

A PowerShell-based security auditing utility that scans Windows Event Logs for suspicious or abnormal logon activity.  
It detects bursts of failed logons, off-hours admin access, and new source hosts or IPs for known users to help identify potential intrusions or compromised accounts.  

---

# Overview

Get-LogonAnomalies.ps1 analyzes the local Windows Security logs (Event ID 4624, 4625, 4672) within a defined time window and applies configurable detection rules defined in policy.json.  
It outputs all findings to structured JSON and CSV files for easy reporting or downstream analysis.  
New-LogonReport.ps1 then converts those results into a clean, sortable HTML dashboard for visual review.  

---

# Basic usage

Collect (local machine):  
.\Get-LogonAnomalies.ps1 -Policy .\policy.json -Json out.json -UpdateBaseline  

-Policy — path to the JSON policy file defining rules and thresholds  
-Json — output path for structured findings  
-UpdateBaseline — updates the baseline of known users and sources (baseline.json) so the tool learns over time  

Make an HTML report:    
.\New-LogonReport.ps1 -InputPath .\out.json -Open  

- Opens a sortable HTML table showing anomalies by computer, severity, and rule type.

---

# Policy Configuration

The policy.json file defines how detection rules behave. For example:

```
{
  "windowHours": 24,
  "businessHours": { "start": 8, "end": 18, "weekdaysOnly": true },
  "rules": {
    "FailedBurstPerIP":   { "enabled": true, "threshold": 10, "minutes": 15, "sev": "Medium" },
    "FailedBurstPerUser": { "enabled": true, "threshold": 8,  "minutes": 15, "sev": "Medium" },
    "OffHoursAdmin":      { "enabled": true, "sev": "High" },
    "NewSourceForUser":   { "enabled": true, "sev": "Low" }
  }
}
```

Parameters:  

- windowHours — how far back to collect events  
- businessHours — normal login times; off-hours logons outside this are flagged  
- rules — per-rule thresholds and severity levels

---

# Baseline File

baseline.json tracks known IPs and hostnames per user.
When -UpdateBaseline is used, new trusted sources are added automatically so repeated access from them won’t trigger alerts. For example:

```
{
  "Administrator": { "IPs": ["10.0.0.10"], "Hosts": ["SERVER01"] },
  "dthorsnes": { "IPs": ["10.0.0.42"], "Hosts": ["ALFRED"] }
}
```

---

# Output Files

File	| Description
out.json	| Raw structured anomaly output
out.csv	| Optional CSV export (via -Csv out.csv)
reports\LogonReport.html |	Human-readable HTML dashboard
baseline.json	Persistent | known sources per user
