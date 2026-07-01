"""BenguelaShield — Serviço em modo processo (sem SCM).

Corre todos os módulos em background como processo normal.
Equivalente ao serviço Windows mas sem precisar de admin.

Executa: python run_service.py
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import time

from modules.antivirus.config import AntiVirusConfig
from modules.antivirus.database import DatabaseManager
from services.clamd_service import ClamDService
from modules.realtime.monitor import RealtimeMonitor
from modules.realtime.usb_guard import USBGuard
from modules.realtime.download_guard import DownloadGuard
from modules.antiransom.folder_shield import FolderShield
from modules.antiransom.config import AntiRansomConfig
from modules.scheduler.scheduler import ScanScheduler
from modules.scheduler.config import SchedulerConfig
from services.benguelashield_service import AlertServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("BenguelaShield")

_parar = False


def _signal_handler(sig, frame):
    global _parar
    logger.info("Sinal recebido — a encerrar...")
    _parar = True


def main() -> None:
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    config = AntiVirusConfig()
    db = DatabaseManager(config.db_path)

    print("=" * 60)
    print("  BenguelaShield — Serviço em execução")
    print("  Motor: ClamAV", end=" ")
    try:
        import subprocess
        proc = subprocess.run(
            [str(config.clamscan_binary), "--version"],
            capture_output=True, text=True, timeout=5,
            encoding="utf-8", errors="replace",
        )
        print(proc.stdout.strip())
    except Exception:
        print("desconhecido")

    print("  Base dados:", config.db_path)
    print("  Quarentena:", config.quarantine_dir)
    print("  Para parar: Ctrl+C")
    print("=" * 60)

    on_threat = lambda fp, t, q: logger.warning("AMEACA: %s -> %s", os.path.basename(fp), t)

    clamd = ClamDService(config)
    if clamd.iniciar():
        print("\n  [OK] clamd activo na porta", config.clamd_port)
    else:
        print("\n  [!!] clamd não iniciou — scans manuais apenas")

    alert_server = AlertServer(config, db)
    alert_server.iniciar()
    print("  [OK] Alert server na porta", config.clamd_port + 1)

    monitor = RealtimeMonitor(config, db, on_threat)
    monitor.iniciar()
    pastas = monitor._pastas_padrao()
    print(f"  [OK] Monitor em tempo real — {len(pastas)} pasta(s)")

    usb_guard = USBGuard(config, db, on_threat)
    usb_guard.iniciar()
    print("  [OK] USB Guard activo")

    download_guard = DownloadGuard(config, db, on_threat)
    download_guard.iniciar()
    print("  [OK] Download Guard activo")

    ar_config = AntiRansomConfig(base_dir=config.base_dir)
    shield = FolderShield(ar_config)
    honeypots = shield.iniciar()
    print(f"  [OK] Anti-Ransomware activo — {honeypots} honeypot(s)")

    sched_config = SchedulerConfig()
    scheduler = ScanScheduler(sched_config)
    scheduler.iniciar()
    print(f"  [OK] Scan agendado — próximo rápido: {scheduler.get_status()['proximo_rapido']}")
    print(f"       Próximo completo: {scheduler.get_status()['proximo_completo']}")

    print("\n  Todos os módulos activos. Sistema protegido.\n")

    try:
        while not _parar:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    print("\n  A encerrar módulos...")
    scheduler.parar()
    shield.parar()
    download_guard.parar()
    usb_guard.parar()
    monitor.parar()
    alert_server.parar()
    clamd.parar()
    db.close()
    print("  BenguelaShield encerrado.\n")


if __name__ == "__main__":
    main()
