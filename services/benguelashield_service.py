"""Serviço Windows principal do BenguelaShield.

Corre como serviço do Windows, mantém clamd activo, e monitoriza
o sistema de ficheiros em tempo real.

Instalação: python benguelashield_service.py install
Arranque:   python benguelashield_service.py start
Parar:      python benguelashield_service.py stop
Remover:    python benguelashield_service.py remove
"""

from __future__ import annotations

import logging
import logging.handlers
import hmac
import os
import secrets
import sys
import threading
import time
import socket
from pathlib import Path

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

logger = logging.getLogger("BenguelaShield")


class BenguelaShieldService(win32serviceutil.ServiceFramework):
    """Serviço Windows do BenguelaShield."""

    _svc_name_ = "BenguelaShield"
    _svc_display_name_ = "BenguelaShield — Antivírus em Tempo Real"
    _svc_description_ = "Serviço de protecção em tempo real do BenguelaShield. Mantém o ClamAV activo e monitoriza o sistema de ficheiros."
    _svc_can_stop_ = True
    _svc_can_pause_continue_ = False

    def __init__(self, args: list[str] | None = None) -> None:
        if args is None:
            args = []
        win32serviceutil.ServiceFramework.__init__(self, args)
        self._parar = win32event.CreateEvent(None, 0, 0, None)
        self._config = AntiVirusConfig()
        self._db: DatabaseManager | None = None
        self._clamd: ClamDService | None = None
        self._monitor: RealtimeMonitor | None = None
        self._usb_guard: USBGuard | None = None
        self._download_guard: DownloadGuard | None = None
        self._alert_server: AlertServer | None = None

    def SvcStop(self) -> None:
        """Handler para parar o serviço."""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        logger.info("BenguelaShield a parar...")

        if self._download_guard:
            self._download_guard.parar()
        if self._usb_guard:
            self._usb_guard.parar()
        if self._monitor:
            self._monitor.parar()
        if self._clamd:
            self._clamd.parar()
        if self._alert_server:
            self._alert_server.parar()
        if self._db:
            self._db.close()

        win32event.SetEvent(self._parar)
        logger.info("BenguelaShield parado")

    def SvcDoRun(self) -> None:
        """Handler principal do serviço."""
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        logger.info("BenguelaShield iniciado")
        self._executar()

    def _executar(self) -> None:
        """Ciclo principal do serviço."""
        self._db = DatabaseManager(self._config.db_path)

        self._alert_server = AlertServer(self._config, self._db)
        self._alert_server.iniciar()

        self._clamd = ClamDService(self._config)
        if not self._clamd.iniciar():
            logger.error("Falha ao iniciar clamd — serviço a funcionar sem scan")

        self._monitor = RealtimeMonitor(
            self._config, self._db, self._on_threat
        )
        self._monitor.iniciar()

        self._usb_guard = USBGuard(self._config, self._db, self._on_threat)
        self._usb_guard.iniciar()

        self._download_guard = DownloadGuard(self._config, self._db, self._on_threat)
        self._download_guard.iniciar()

        logger.info("Todos os módulos iniciados")

        while True:
            resultado = win32event.WaitForSingleObject(self._parar, 30000)
            if resultado == win32event.WAIT_OBJECT_0:
                break

    def _on_threat(self, filepath: str, threat: str, quarantine_id: str | None) -> None:
        """Callback chamado quando uma ameaça é detetada."""
        logger.warning("AMEAÇA DETETADA: %s → %s (quarantine: %s)", filepath, threat, quarantine_id)

        if self._alert_server:
            self._alert_server.enviar_alerta(filepath, threat, quarantine_id)


class AlertServer:
    """Servidor TCP local que envia alertas para a GUI.

    Usa shared-secret para autenticar clientes. O token e gerado
    no arranque e passado a GUI via ficheiro partilhado.
    """

    def __init__(self, config: AntiVirusConfig, db: DatabaseManager) -> None:
        self.config = config
        self.db = db
        self._socket: socket.socket | None = None
        self._parar = False
        self._thread: threading.Thread | None = None
        self._clientes: list[socket.socket] = []
        self._lock = threading.Lock()
        self._secret = secrets.token_hex(32)

    def _write_secret(self) -> None:
        """Escreve o token num ficheiro para a GUI ler."""
        secret_file = self.config.base_dir / "config" / ".alert_secret"
        if not getattr(sys, 'frozen', False):
            secret_file = Path(os.environ.get('PROGRAMDATA', r'C:\ProgramData')) / 'BenguelaShield' / 'config' / '.alert_secret'
        secret_file.parent.mkdir(parents=True, exist_ok=True)
        secret_file.write_text(self._secret, encoding="utf-8")

    def iniciar(self) -> None:
        try:
            self._write_secret()
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind(("127.0.0.1", self.config.clamd_port + 1))
            self._socket.listen(5)
            self._socket.settimeout(1.0)
            self._parar = False
            self._thread = threading.Thread(target=self._aceitar_clientes, daemon=True)
            self._thread.start()
            logger.info("Alert server iniciado na porta %d", self.config.clamd_port + 1)
        except Exception as e:
            logger.warning("Erro ao iniciar alert server: %s", e)

    def parar(self) -> None:
        self._parar = True
        with self._lock:
            for c in self._clientes:
                try:
                    c.close()
                except Exception:
                    pass
            self._clientes.clear()
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
        secret_file = Path(os.environ.get('PROGRAMDATA', r'C:\ProgramData')) / 'BenguelaShield' / 'config' / '.alert_secret'
        try:
            secret_file.unlink(missing_ok=True)
        except Exception:
            pass

    def _aceitar_clientes(self) -> None:
        while not self._parar:
            try:
                cliente, addr = self._socket.accept()
                try:
                    cliente.settimeout(5.0)
                    token = cliente.recv(64).decode("utf-8", errors="ignore").strip()
                    if not hmac.compare_digest(token, self._secret):
                        logger.warning("Alert server: cliente com token invalido rejeitado")
                        cliente.close()
                        continue
                except Exception:
                    cliente.close()
                    continue
                cliente.settimeout(None)
                with self._lock:
                    self._clientes.append(cliente)
            except socket.timeout:
                continue
            except Exception:
                break

    def enviar_alerta(self, filepath: str, threat: str, quarantine_id: str | None) -> None:
        """Envia alerta para todos os clientes conectados (GUI)."""
        import json
        alerta = json.dumps({
            "type": "threat",
            "filepath": filepath,
            "threat": threat,
            "quarantine_id": quarantine_id,
            "timestamp": time.time(),
        }) + "\n"

        with self._lock:
            removidos = []
            for c in self._clientes:
                try:
                    c.sendall(alerta.encode("utf-8"))
                except Exception:
                    removidos.append(c)
            for c in removidos:
                self._clientes.remove(c)


import threading


def _configurar_logging() -> None:
    import traceback
    programdata = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
    log_dir = Path(programdata) / "BenguelaShield" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "service.log"

    handler = logging.handlers.RotatingFileHandler(
        str(log_file), maxBytes=10*1024*1024, backupCount=5, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logging.root.addHandler(handler)
    logging.root.setLevel(logging.INFO)

    def _crash_hook(exc_type, exc_value, exc_tb):
        tb = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        logging.getLogger("BenguelaShield").critical("CRASH: %s\n%s", exc_type.__name__, tb)

    def _thread_crash_hook(args):
        if args.exc_value:
            tb = "".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback))
            logging.getLogger("BenguelaShield").critical("CRASH THREAD: %s\n%s", args.thread_name, tb)

    sys.excepthook = _crash_hook
    threading.excepthook = _thread_crash_hook


if __name__ == "__main__":
    _configurar_logging()
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(BenguelaShieldService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(BenguelaShieldService)
