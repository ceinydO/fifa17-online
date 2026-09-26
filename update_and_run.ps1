# Aktualizuje repo z brancha serwera i odpala serwer. Uzycie: .\update_and_run.ps1
Set-Location $PSScriptRoot
git pull origin claude/new-session-ab3wdx
python -m fifa17srv run
