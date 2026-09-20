<#
.SYNOPSIS
  Points the FIFA 17 redirector hostname at this machine (hosts file) and generates local certs.

.DESCRIPTION
  * Generates certs/ (a throwaway local CA + server certificate).
  * Adds ONE line to the Windows hosts file:  127.0.0.1 winter15.gosredirector.ea.com
  * Optionally (-InstallCA) trusts the throwaway CA in the Windows certificate store.
    This is a real security trade-off: anyone holding certs\ca.key could then impersonate
    websites to this PC. Old EA games usually ship their own CA list, so it often does not
    help. Start WITHOUT -InstallCA and only add it if the logs show the client rejected the
    certificate. Undo everything with tools\remove_redirector.ps1.

.PARAMETER Ip
  Address to put in the hosts file (default 127.0.0.1). A friend connecting to YOUR server
  would use your public/VPN IP here on THEIR machine.
#>
#Requires -RunAsAdministrator
param(
    [switch]$InstallCA,
    [string]$Ip = "127.0.0.1",
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$root     = Split-Path -Parent $PSScriptRoot
$hostName = "winter15.gosredirector.ea.com"
$marker   = "# fifa17-friendlies"
$hostsFile = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"

Push-Location $root
try {
    & $Python -m pip install --quiet -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw "pip install failed" }
    & $Python -m fifa17srv certs
    if ($LASTEXITCODE -ne 0) { throw "certificate generation failed" }

    if ($InstallCA) {
        certutil -addstore -f Root (Join-Path $root "certs\ca.pem") | Out-Null
        Write-Host "Local CA added to the Windows Root store (remove with remove_redirector.ps1)."
    } else {
        Write-Host "Skipping CA installation (use -InstallCA only if the logs say the certificate was rejected)."
    }

    $lines = @()
    if (Test-Path $hostsFile) {
        $lines = @(Get-Content $hostsFile | Where-Object { $_ -notmatch [regex]::Escape($marker) })
    }
    $lines += "$Ip $hostName $marker"
    Set-Content -Path $hostsFile -Value $lines -Encoding ASCII
    ipconfig /flushdns | Out-Null
    Write-Host "hosts: $Ip $hostName"
    Write-Host ""
    Write-Host "Next:  python -m fifa17srv run      then start FIFA 17."
}
finally {
    Pop-Location
}
