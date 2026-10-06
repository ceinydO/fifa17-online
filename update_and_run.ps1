# Pulls the latest code for the current branch and starts the server. Usage: .\update_and_run.ps1
Set-Location $PSScriptRoot
git pull
python -m fifa17srv run
