"""Serviço BenguelaShield — ficheiro único para pythonservice.exe.

Este ficheiro resolve TODOS os paths antes de qualquer import,
garantindo que o pythonservice.exe encontra os módulos.
"""

import os
import sys

# ═══ RESOLUÇÃO DE PATHS ═══
# pythonservice.exe muda o CWD para o directorio do Python.
# Precisamos de adicionar o projecto ao sys.path ANTES de tudo.

_service_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(_service_dir)

for p in [_project_root, _service_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

os.chdir(_project_root)
# ═══════════════════════════

import logging
import time
import signal
import threading
import socket

import win32api
import win32event
import win32service
import win32serviceutil
import servicemanager

from modules.antivirus.config import AntiVirusConfig
from modules.antivirus.database import DatabaseManager
from modules.realtime.monitor import RealtimeMonitor
from modules.realtime.usb_guard import USBGuard
from modules.realtime.download_guard import DownloadGuard
from services.clamd_service import ClamDService
from services.benguelashield_service import AlertServer

logger = logging.getLogger("BenguelaShield")


class BenguelaShieldService(win32serviceutil.ServiceFramework):
    _svc_name_ = "BenguelaShield"
    _svc_display_name_ = "BenguelaShield - Antivirus em Tempo Real"
    _svc_description_ = "Servico de proteccao em tempo real do BenguelaShield."
    _svc_can_stop_ = True
    _svc_can_pause_continue_ = False

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self._parar = win32event.CreateEvent(None, 0, 0, None)
        self._config = AntiVirusConfig()
        self._db = None
        self._clamd = None
        self._monitor = None
        self._usb = None
        self._download = None
        self._alert = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        for mod in [self._download, self._usb, self._monitor, self._alert]:
            if mod:
                try:
                    mod.parar()
                except Exception:
                    pass
        if self._clamd:
            try:
                self._clamd.parar()
            except Exception:
                pass
        if self._db:
            self._db.close()
        win32event.SetEvent(self._parar)

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        self._executar()

    def _executar(self):
        diag = self._config.base_dir / "logs" / "service_diag.log"
        diag.parent.mkdir(parents=True, exist_ok=True)

        def log(msg):
            with open(str(diag), "a", encoding="utf-8") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
            logger.info(msg)

        try:
            log("A iniciar servico...")

            self._db = DatabaseManager(self._config.db_path)
            log("BD OK")

            self._clamd = ClamDService(self._config)
            ok = self._clamd.iniciar()
            log(f"clamd: {'activo' if ok else 'falhou'}")

            on_threat = lambda fp, t, q: log(f"AMEACA: {os.path.basename(fp)} -> {t}")

            self._monitor = RealtimeMonitor(self._config, self._db, on_threat)
            self._monitor.iniciar()
            pastas = self._monitor._pastas_padrao()
            log(f"Monitor: {len(pastas)} pasta(s)")

            self._usb = USBGuard(self._config, self._db, on_threat)
            self._usb.iniciar()
            log("USB Guard: activo")

            self._download = DownloadGuard(self._config, self._db, on_threat)
            self._download.iniciar()
            log("Download Guard: activo")

            log("Todos os modulos iniciados")
        except Exception as e:
            log(f"ERRO ao iniciar: {e}")

        while True:
            if win32event.WaitForSingleObject(self._parar, 30000) == win32event.WAIT_OBJECT_0:
                break


def _configurar_logging():
    log_dir = AntiVirusConfig().base_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(str(log_dir / "service.log"), encoding="utf-8"),
        ],
    )


if __name__ == "__main__":
    _configurar_logging()
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(BenguelaShieldService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(BenguelaShieldService)
