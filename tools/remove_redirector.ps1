<#
.SYNOPSIS
  Undoes install_redirector.ps1: removes the hosts entry and the local dev CA (if installed).
#>
#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
$marker    = "# fifa17-friendlies"
$hostsFile = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"

if (Test-Path $hostsFile) {
    $lines = @(Get-Content $hostsFile | Where-Object { $_ -notmatch [regex]::Escape($marker) })
    Set-Content -Path $hostsFile -Value $lines -Encoding ASCII
    Write-Host "Removed fifa17-friendlies entries from hosts."
}

# The CA may never have been installed, so a failing certutil is fine here.
$ErrorActionPreference = "Continue"
certutil -delstore Root "FIFA17 Friendlies Local Dev CA" | Out-Null
Write-Host "Removed local dev CA from the Root store (if it was there)."
ipconfig /flushdns | Out-Null
