<#
.SYNOPSIS
  Send a sample Wazuh alert to the n8n webhook, to test the workflow.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\send-alert.ps1
  powershell -ExecutionPolicy Bypass -File scripts\send-alert.ps1 -File samples\alerts\02-web-sql-injection.json
  powershell -ExecutionPolicy Bypass -File scripts\send-alert.ps1 -Test   # editor "listen" mode

.NOTES
  The secret is read from WEBHOOK_SECRET in .env.
  The same alert sent twice within DEDUP_WINDOW_SECONDS is dropped on purpose.
#>
param(
  [string]$File = "samples\alerts\01-ssh-bruteforce.json",
  [string]$Url = "http://localhost:5678/webhook/wazuh-alert",
  [string]$EnvFile = ".env",
  [switch]$Test
)

if ($Test) { $Url = $Url -replace '/webhook/', '/webhook-test/' }

$secret = ""
if (Test-Path $EnvFile) {
  $line = Get-Content $EnvFile | Where-Object { $_ -match '^\s*WEBHOOK_SECRET\s*=' } | Select-Object -First 1
  if ($line) { $secret = ($line -split '=', 2)[1].Trim() }
}
$headers = @{}
if ($secret) { $headers["X-Wazuh-Token"] = $secret }

$body = [System.IO.File]::ReadAllBytes((Resolve-Path $File))
try {
  $resp = Invoke-RestMethod -Method Post -Uri $Url -ContentType "application/json; charset=utf-8" -Headers $headers -Body $body
  Write-Host "Sent $File -> $Url" -ForegroundColor Green
  Write-Host "n8n answered: $($resp | ConvertTo-Json -Compress)"
  Write-Host "Now open n8n > Executions to see the result (and check Telegram)."
} catch {
  Write-Host "Failed: $($_.Exception.Message)" -ForegroundColor Red
  Write-Host "Is n8n running (docker ps)? Is the workflow published? In the editor, use -Test after clicking 'Execute workflow'."
}
