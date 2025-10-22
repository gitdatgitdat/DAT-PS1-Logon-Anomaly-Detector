[CmdletBinding()]
param(
  [string[]]$ComputerName,
  [string]$HostsCsv,
  [pscredential]$Credential,
  [string]$Policy = ".\policy.json",
  [int]$WindowHours,
  [string]$BaselinePath = ".\baseline.json",
  [switch]$UpdateBaseline,
  [string]$Json,
  [string]$Csv
)

function Normalize-Policy {
  param([object]$p)
  if (-not $p) { $p = @{} }
  elseif ($p -is [string]) { try { $p = ConvertFrom-Json -InputObject $p -AsHashtable } catch { $p = @{} } }
  elseif ($p -isnot [hashtable]) { $p = $p | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable }

  if (-not $p.windowHours) { $p.windowHours = 24 }
  if (-not $p.businessHours) { $p.businessHours = @{ start=8; end=18; weekdaysOnly=$true } }
  if (-not $p.rules) { $p.rules = @{} }
  foreach ($k in 'FailedBurstPerIP','FailedBurstPerUser','OffHoursAdmin','NewSourceForUser') {
    if (-not $p.rules.$k) { $p.rules.$k = @{} }
    if (-not $p.rules.$k.enabled) { $p.rules.$k.enabled = $true }
    if (-not $p.rules.$k.sev)     { $p.rules.$k.sev     = 'Low' }
  }
  $p
}

function Load-Policy {
  param([string]$Path)
  $base = @{
    windowHours = 24
    businessHours = @{ start=8; end=18; weekdaysOnly=$true }
    rules = @{
      FailedBurstPerIP   = @{ enabled=$true; threshold=10; minutes=15; sev='Medium' }
      FailedBurstPerUser = @{ enabled=$true; threshold=8;  minutes=15; sev='Medium' }
      OffHoursAdmin      = @{ enabled=$true; sev='High' }
      NewSourceForUser   = @{ enabled=$true; sev='Low' }
    }
  }
  if ($Path -and (Test-Path -LiteralPath $Path)) {
    $raw = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -AsHashtable
    # shallow merges for convenience
    if ($raw.windowHours)           { $base.windowHours = [int]$raw.windowHours }
    if ($raw.businessHours)         { $base.businessHours = @{} + $base.businessHours + $raw.businessHours }
    if ($raw.rules)                 { $base.rules = @{} + $base.rules + $raw.rules }
  }
  Normalize-Policy $base
}

function Load-Baseline {
  param([string]$Path)
  if (Test-Path -LiteralPath $Path) {
    try { return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -AsHashtable } catch { return @{} }
  }
  @{}
}
function Save-Baseline {
  param([hashtable]$Baseline,[string]$Path)
  ($Baseline | ConvertTo-Json -Depth 10) | Out-File -Encoding utf8 $Path
}

# -- Event parsing helpers -----------------------------------------------------
function Get-WindowStart([int]$h){ (Get-Date).AddHours(-$h) }

function Parse-XmlEvent {
  param($evt)
  $xml = [xml]$evt.ToXml()
  $data = @{}
  foreach($n in $xml.Event.EventData.Data){
    if ($n.Name) { $data[$n.Name] = [string]$n.'#text' }
  }
  [pscustomobject]@{
    RecordId      = $xml.Event.System.EventRecordID
    Id            = [int]$xml.Event.System.EventID
    TimeCreated   = [datetime]$xml.Event.System.TimeCreated.SystemTime
    TargetUser    = $data['TargetUserName']
    TargetDomain  = $data['TargetDomainName']
    IpAddress     = $data['IpAddress']
    Workstation   = $data['WorkstationName']
    LogonType     = [int]($data['LogonType'] | ForEach-Object { if ($_ -match '^\d+$'){$_} else {0} })
    PrivList      = $data['PrivilegeList']
  }
}

function Get-LogonEventsLocal {
  param([int]$WindowHours)
  $start = Get-WindowStart $WindowHours
  $ids   = 4624,4625,4672
  $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$ids; StartTime=$start} -ErrorAction SilentlyContinue
  $events | ForEach-Object { Parse-XmlEvent $_ }
}

# -- Detection rules -----------------------------------------------------------
function Is-OffHours([datetime]$dt,[hashtable]$bh){
  if ($bh.weekdaysOnly -and ($dt.DayOfWeek -in @('Saturday','Sunday'))) { return $true }
  if ($bh.start -isnot [int] -or $bh.end -isnot [int]) { return $false }
  return ($dt.Hour -lt [int]$bh.start) -or ($dt.Hour -ge [int]$bh.end)
}

function Detect-Anomalies {
  param([object[]]$E,[hashtable]$Policy,[hashtable]$Baseline)

  $rules = $Policy.rules
  $findings=@()

  # 1) Failed bursts by IP
  if ($rules.FailedBurstPerIP.enabled) {
    $span = [int]$rules.FailedBurstPerIP.minutes
    $thr  = [int]$rules.FailedBurstPerIP.threshold
    $sev  = $rules.FailedBurstPerIP.sev
    $fails = $E | Where-Object Id -eq 4625 | Where-Object IpAddress
    foreach($g in $fails | Group-Object IpAddress){
      $times = $g.Group.TimeCreated | Sort-Object
      if ($times.Count -eq 0) { continue }
      $first = $times[0]; $last = $times[-1]
      # simple sliding-window approx
      $windowCount = ($times | Where-Object { $_ -ge $last.AddMinutes(-$span) }).Count
      if ($windowCount -ge $thr) {
        $findings += [pscustomobject]@{
          Rule='FailedBurstPerIP'; Severity=$sev; User='*'; SourceIp=$g.Name; Workstation='*'
          Count=$windowCount; FirstSeen=$first; LastSeen=$last
          Reason="≥$thr failed logons from $($g.Name) in $span min"
        }
      }
    }
  }

  # 2) Failed bursts by user
  if ($rules.FailedBurstPerUser.enabled) {
    $span = [int]$rules.FailedBurstPerUser.minutes
    $thr  = [int]$rules.FailedBurstPerUser.threshold
    $sev  = $rules.FailedBurstPerUser.sev
    $fails = $E | Where-Object Id -eq 4625 | Where-Object TargetUser
    foreach($g in $fails | Group-Object TargetUser){
      $times = $g.Group.TimeCreated | Sort-Object
      if ($times.Count -eq 0) { continue }
      $last = $times[-1]
      $windowCount = ($times | Where-Object { $_ -ge $last.AddMinutes(-$span) }).Count
      if ($windowCount -ge $thr) {
        $findings += [pscustomobject]@{
          Rule='FailedBurstPerUser'; Severity=$sev; User=$g.Name; SourceIp='*'; Workstation='*'
          Count=$windowCount; FirstSeen=$times[0]; LastSeen=$last
          Reason="≥$thr failed logons for user '$($g.Name)' in $span min"
        }
      }
    }
  }

  # 3) Off-hours admin logons (4624 + 4672 or LogonType interactive/remote)
  if ($rules.OffHoursAdmin.enabled) {
    $sev  = $rules.OffHoursAdmin.sev
    $bh   = $Policy.businessHours
    $adminish = $E | Where-Object {
      ($_ .Id -eq 4672) -or (($_.Id -eq 4624) -and ($_.LogonType -in 2,10))
    }
    foreach($ev in $adminish){
      if (Is-OffHours $ev.TimeCreated $bh) {
        $findings += [pscustomobject]@{
          Rule='OffHoursAdmin'; Severity=$sev; User=$ev.TargetUser; SourceIp=$ev.IpAddress; Workstation=$ev.Workstation
          Count=1; FirstSeen=$ev.TimeCreated; LastSeen=$ev.TimeCreated
          Reason="Admin/special logon outside business hours"
        }
      }
    }
  }

  # 4) New source (IP/Workstation) for user on success 4624 network-type
  if ($rules.NewSourceForUser.enabled) {
    $sev = $rules.NewSourceForUser.sev
    $succ = $E | Where-Object { $_.Id -eq 4624 -and ($_.LogonType -in 3,10) -and $_.TargetUser }
    foreach($ev in $succ){
      $u = $ev.TargetUser
      if (-not $Baseline.ContainsKey($u)) { $Baseline[$u] = @{ IPs=@(); Hosts=@() } }
      $known = $Baseline[$u]
      $isNewIp   = ($ev.IpAddress)     -and ($known.IPs  -notcontains $ev.IpAddress)
      $isNewHost = ($ev.Workstation)   -and ($known.Hosts -notcontains $ev.Workstation)
      if ($isNewIp -or $isNewHost) {
        $which = @()
        if ($isNewIp)   { $which += "IP=$($ev.IpAddress)" }
        if ($isNewHost) { $which += "Host=$($ev.Workstation)" }
        $findings += [pscustomobject]@{
          Rule='NewSourceForUser'; Severity=$sev; User=$u; SourceIp=$ev.IpAddress; Workstation=$ev.Workstation
          Count=1; FirstSeen=$ev.TimeCreated; LastSeen=$ev.TimeCreated
          Reason="New source for user: $(($which -join ', '))"
        }
        if ($UpdateBaseline) {
          if ($isNewIp)   { $known.IPs  += $ev.IpAddress }
          if ($isNewHost) { $known.Hosts += $ev.Workstation }
        }
      }
    }
  }

  $findings
}

# ---------------- main ----------------
$pol = Load-Policy -Path $Policy
if ($PSBoundParameters.ContainsKey('WindowHours')) { $pol.windowHours = [int]$WindowHours }

# targets (local-only scaffold; expand later if you want remoting)
$targets=@()
if     ($HostsCsv)     { $targets += (Import-Csv -LiteralPath $HostsCsv).ComputerName }
elseif ($ComputerName) { $targets += $ComputerName }
if (-not $targets)     { $targets = @($env:COMPUTERNAME) }

$baseline = Load-Baseline -Path $BaselinePath

$all=@()
foreach($t in $targets){
  if ($t -ne $env:COMPUTERNAME) { Write-Warning "Remote collection not implemented in the scaffold; scanning local for now."; continue }
  $ev = Get-LogonEventsLocal -WindowHours $pol.windowHours
  $fx = Detect-Anomalies -E $ev -Policy $pol -Baseline $baseline
  if (-not $fx) {
    $all += [pscustomobject]@{
      ComputerName=$t; Rule='None'; Severity='Info'; User=''; SourceIp=''; Workstation='';
      Count=0; FirstSeen=$null; LastSeen=$null; Reason='No anomalies';
      WindowHours=$pol.windowHours; CollectedAt=[datetime]::UtcNow; Compliance='Compliant'
    }
  } else {
    foreach($f in $fx){
      $all += [pscustomobject]@{
        ComputerName=$t; Rule=$f.Rule; Severity=$f.Severity; User=$f.User; SourceIp=$f.SourceIp; Workstation=$f.Workstation;
        Count=$f.Count; FirstSeen=$f.FirstSeen; LastSeen=$f.LastSeen; Reason=$f.Reason;
        WindowHours=$pol.windowHours; CollectedAt=[datetime]::UtcNow;
        Compliance= (if ($f.Severity -in 'Medium','High') {'NonCompliant'} else {'Warn'})
      }
    }
  }
}

# outputs
$all | Sort-Object ComputerName, @{e='Severity';d=$true}, Rule | Format-Table -AutoSize ComputerName,Severity,Rule,User,SourceIp,Workstation,Count,Reason
if ($Json) { $all | ConvertTo-Json -Depth 6 | Out-File -Encoding utf8 $Json }
if ($Csv)  { $all | Export-Csv -NoTypeInformation -Encoding UTF8 $Csv }

if ($UpdateBaseline) { Save-Baseline -Baseline $baseline -Path $BaselinePath }

# exit codes
if ($all | Where-Object { $_.Compliance -eq 'NonCompliant' }) { exit 1 } else { exit 0 }
