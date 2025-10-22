[CmdletBinding()]
param(
  [Parameter(Mandatory)][string[]]$InputPath,
  [string]$OutHtml = ".\reports\LogonAnomalies.html",
  [switch]$Open
)

function HE([object]$x){ if ($null -eq $x) { '' } else { [System.Net.WebUtility]::HtmlEncode([string]$x) } }

function Read-Records {
  $files = foreach ($p in $InputPath) { Get-ChildItem -Path $p -File -ErrorAction Stop }
  $all=@()
  foreach($f in $files){
    if ($f.Extension -match 'json'){ $all += @(Get-Content -Raw $f.FullName | ConvertFrom-Json) }
    elseif ($f.Extension -match 'csv'){ $all += @(Import-Csv $f.FullName) }
  }
  $all
}

$sevOrder = @{ Info=0; Warn=1; Low=1; Medium=2; High=3 }
$data = Read-Records
$rows = foreach($r in ($data | Sort-Object @{e={ $sevOrder[$_.Severity] };d=$true}, ComputerName)) {
  $cls = switch ($r.Severity.ToString()) { 'High'{'bad'} 'Medium'{'med'} 'Low'{'low'} 'Warn'{'low'} default{'ok'} }
  $tfs = if ($r.FirstSeen) { (Get-Date $r.FirstSeen -Format 'yyyy-MM-dd HH:mm:ss') } else { '' }
  $tls = if ($r.LastSeen)  { (Get-Date $r.LastSeen  -Format 'yyyy-MM-dd HH:mm:ss') } else { '' }
@"
<tr class="$cls" data-sev="$($sevOrder[$r.Severity])" data-win="$([int]$r.WindowHours)" data-ts="$(Get-Date $r.CollectedAt -UFormat %s)">
  <td>$(HE $r.ComputerName)</td>
  <td class="sev"><span class="dot"></span>$(HE $r.Severity)</td>
  <td>$(HE $r.Rule)</td>
  <td>$(HE $r.User)</td>
  <td>$(HE $r.SourceIp)</td>
  <td>$(HE $r.Workstation)</td>
  <td class="num">$(HE $r.Count)</td>
  <td class="reasons">$(if ($r.Reason){HE $r.Reason}else{'<span class="muted">—</span>'})</td>
  <td>$tfs</td>
  <td>$tls</td>
  <td>$([int]$r.WindowHours)</td>
  <td>$(Get-Date $r.CollectedAt -Format 'yyyy-MM-dd HH:mm:ss')</td>
</tr>
"@
}

$html = @"
<!doctype html><meta charset="utf-8"><title>Logon Anomalies</title>
<style>
:root{--ok:#22c55e;--low:#06b6d4;--med:#f59e0b;--bad:#ef4444;--muted:#6b7280}
body{font-family:ui-sans-serif,Segoe UI,Roboto,Arial;margin:24px}
h1{margin:0 0 6px;font-size:24px}.sub{color:var(--muted);margin-bottom:12px}
table{border-collapse:collapse;width:100%}
th,td{padding:10px;border-bottom:1px solid #eee}
tbody tr:nth-child(odd){background:#f3f4f6} tbody tr:hover{background:#ececec}
th{position:sticky;top:0;background:#fff;z-index:1;cursor:pointer;user-select:none}
td.num{text-align:right}.reasons{max-width:640px;overflow-wrap:anywhere}
.sev .dot{display:inline-block;width:.6rem;height:.6rem;border-radius:50%;margin-right:.5rem;vertical-align:middle}
tr.ok  .dot{background:var(--ok)} tr.low .dot{background:var(--low)} tr.med .dot{background:var(--med)} tr.bad .dot{background:var(--bad)}
.muted{color:var(--muted)}
</style>
<h1>Logon Anomalies</h1>
<div class="sub">Generated $(Get-Date)</div>

<table id="t"><thead>
<tr>
  <th data-key="computer">Computer</th>
  <th data-key="sev">Severity</th>
  <th data-key="rule">Rule</th>
  <th>User</th>
  <th>Source IP</th>
  <th>Workstation</th>
  <th data-key="count" class="num">Count</th>
  <th>Reason</th>
  <th>First Seen</th>
  <th>Last Seen</th>
  <th data-key="win" class="num">Window (h)</th>
  <th data-key="ts">Collected</th>
</tr></thead><tbody>
$($rows -join "")
</tbody></table>

<script>
document.querySelectorAll("th[data-key]").forEach(th=>{
  th.addEventListener("click",()=>{
    const key=th.dataset.key, tb=th.closest("table").tBodies[0], rows=[...tb.rows];
    const dir=th.dataset.dir = th.dataset.dir==="asc" ? "desc":"asc";
    rows.sort((a,b)=>{
      const va=a.dataset[key] ?? a.cells[th.cellIndex].innerText.trim();
      const vb=b.dataset[key] ?? b.cells[th.cellIndex].innerText.trim();
      const na=Number(va), nb=Number(vb);
      const cmp=(!isNaN(na)&&!isNaN(nb)) ? (na-nb) : va.localeCompare(vb,undefined,{numeric:true,sensitivity:"base"});
      return dir==="asc"?cmp:-cmp;
    });
    rows.forEach(r=>tb.appendChild(r));
  });
});
</script>
"@
$dir = Split-Path -Parent $OutHtml
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
$html | Out-File -Encoding utf8 $OutHtml
Write-Host "[OK] Wrote HTML -> $OutHtml"
if ($Open) { Start-Process $OutHtml | Out-Null }
