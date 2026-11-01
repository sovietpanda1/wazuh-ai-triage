<#
.SYNOPSIS
  Send a sample Wazuh alert to the n8n webhook, to test the workflow.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\send-alert.ps1
  powershell -ExecutionPolicy Bypass -File scripts\send-alert.ps1 -File samples\alerts\02-web-sql-injection.json
  powershell -ExecutionPolicy Bypass -File scripts\send-alert.ps1 -Test   # editor "listen" mode

.NOTES
  The secret is read from WEBHOOK_SECRET in .env.
  Each send gets a fresh alert id (use -KeepId to send the file as it is). The same
  sample sent again within DEDUP_WINDOW_SECONDS is still grouped with the first one.
  HTTP 202 means "accepted for analysis", not "Telegram message sent".
#>
param(
  [string]$File = "samples\alerts\01-ssh-bruteforce.json",
  [string]$Url = "http://localhost:5678/webhook/wazuh-alert",
  [string]$EnvFile = ".env",
  [switch]$Test,
  [switch]$KeepId
)

if ($Test) { $Url = $Url -replace '/webhook/', '/webhook-test/' }

$secret = ""
if (Test-Path $EnvFile) {
  $line = Get-Content $EnvFile | Where-Object { $_ -match '^\s*WEBHOOK_SECRET\s*=' } | Select-Object -First 1
  if ($line) { $secret = ($line -split '=', 2)[1].Trim() }
}
$headers = @{}
if ($secret) { $headers["X-Wazuh-Token"] = $secret }

$text = [System.IO.File]::ReadAllText((Resolve-Path $File), [System.Text.Encoding]::UTF8)
if (-not $KeepId) {
  $alert = $text | ConvertFrom-Json
  $alert.id = "test-" + [DateTime]::UtcNow.Ticks
  $text = $alert | ConvertTo-Json -Depth 20 -Compress
}
$body = [System.Text.Encoding]::UTF8.GetBytes($text)
try {
  $resp = Invoke-RestMethod -Method Post -Uri $Url -ContentType "application/json; charset=utf-8" -Headers $headers -Body $body
  Write-Host "Sent $File -> $Url" -ForegroundColor Green
  Write-Host "n8n answered: $($resp | ConvertTo-Json -Compress)"
  Write-Host "Accepted for analysis. Open n8n > Executions to see the result (and check Telegram)."
} catch {
  Write-Host "Failed: $($_.Exception.Message)" -ForegroundColor Red
  $code = $null
  if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
  switch ($code) {
    401 { Write-Host "The secret does not match WEBHOOK_SECRET in n8n's .env." }
    503 { Write-Host "WEBHOOK_SECRET is empty in n8n's .env: the webhook refuses everything until it is set." }
    default { Write-Host "Is n8n running (docker ps)? Is the workflow published? In the editor, use -Test after clicking 'Execute workflow'." }
  }
}
