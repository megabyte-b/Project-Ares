@echo off

REM Stop any running processes related to the program
taskkill /IM "run.exe" /F >nul 2>&1
taskkill /IM "note.exe" /F >nul 2>&1
taskkill /IM "trigger.exe" /F >nul 2>&1

echo Lösche Programmdateien...

REM Delete all files and folders related to the program
del /F /Q "e:\encryptor\*.*" >nul 2>&1
del /F /Q "e:\decryptor\*.*" >nul 2>&1
rd /S /Q "e:\encryptor" >nul 2>&1
rd /S /Q "e:\decryptor" >nul 2>&1

REM Remove any autostart entries
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "trigger" /f >nul 2>&1
schtasks /Delete /TN "trigger" /F >nul 2>&1

echo Programm erfolgreich gelöscht.
exit