# Basic usage

Collect (local machine):
.\Get-LogonAnomalies.ps1 -Policy .\policy.json -Json out.json -UpdateBaseline

Make a report
.\New-LogonReport.ps1 -InputPath .\out.json -Open

---
