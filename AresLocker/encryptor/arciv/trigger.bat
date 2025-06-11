@echo off
setlocal enabledelayedexpansion
set "trigger_datetime=20250605094600"  
set "process1=main.exe"
set "process2=disable.exe"
set "kill_switch=https://example.com"

for /f "usebackq delims=" %%I in (`powershell -NoProfile -Command "Get-Date -Format 'yyyyMMddHHmmss'"`) do set "current_datetime=%%I"

echo Aktuelles Datum/Zeit: !current_datetime!
echo Trigger-Datum/Zeit: %trigger_datetime%

if "!current_datetime!" geq "%trigger_datetime%" (
    echo Trigger ausgelöst!
    REM === Killswitch ===
    :: Killswitch-wenn erreichbar -> Programme beenden
    :: Prozesse, die beendet werden sollen
    echo Prüfe Verfügbarkeit von %kill_switch%...
    :: Website-Check mit PowerShell
    powershell -Command "try { $r = Invoke-WebRequest -Uri '%kill_switch%' -UseBasicParsing -TimeoutSec 5; exit 0 } catch { exit 1 }"
    if %errorlevel% equ 0 (
        echo Website ist erreichbar! Killswitch aktiviert.
        echo Beende Prozess...
        exit
    ) else (
        echo Website nicht erreichbar. Programme bleiben aktiv.
        start "" "!process1!"
        start "" "!process2!"
        echo Prozesse gestartet: %process1% und %process2%
        exit
    )
    endlocal
    exit /b 0
) else (
    echo Trigger noch nicht erreicht.
)
endlocal
exit