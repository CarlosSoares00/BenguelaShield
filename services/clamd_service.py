"""Wrapper do clamd como processo gerido pelo serviço BenguelaShield.

O clamd corre como sub-processo e é reiniciado automaticamente se crashar.
"""

from __future__ import annotations

import logging
import os
import subprocess
import threading
import time

from modules.antivirus.config import AntiVirusConfig

logger = logging.getLogger(__name__)


class ClamDService:
    """Gestor do processo clamd."""

    def __init__(self, config: AntiVirusConfig) -> None:
        self.config = config
        self._processo: subprocess.Popen | None = None
        self._parar = False
        self._watchdog: threading.Thread | None = None
        self._config_ficheiro: str = ""

    def iniciar(self) -> bool:
        """Inicia o clamd daemon.

        Returns:
            ``True`` se o clamd iniciou com sucesso.
        """
        clamd_bin = self.config.engine_dir / "clamd.exe"
        if not clamd_bin.exists():
            logger.error("clamd.exe não encontrado: %s", clamd_bin)
            return False

        self._config_ficheiro = self._criar_config()
        if not self._config_ficheiro:
            return False

        cmd = [str(clamd_bin), f"--config-file={self._config_ficheiro}"]

        try:
            self._processo = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            time.sleep(2)

            if self._processo.poll() is not None:
                stderr = self._processo.stderr
                if stderr:
                    erro = stderr.read().decode("utf-8", errors="replace")
                    logger.error("clamd falhou ao iniciar: %s", erro)
                return False

            self._parar = False
            self._watchdog = threading.Thread(target=self._vigiar, daemon=True)
            self._watchdog.start()

            logger.info("clamd iniciado (PID: %d)", self._processo.pid)
            return True

        except Exception as e:
            logger.error("Erro ao iniciar clamd: %s", e)
            return False

    def parar(self) -> None:
        """Para o clamd daemon."""
        self._parar = True
        if self._processo and self._processo.poll() is None:
            try:
                self._processo.terminate()
                self._processo.wait(timeout=10)
            except Exception:
                try:
                    self._processo.kill()
                except Exception:
                    pass
            logger.info("clamd parado")

    def esta_activo(self) -> bool:
        """Verifica se o clamd está a correr."""
        return self._processo is not None and self._processo.poll() is None

    def _vigiar(self) -> None:
        """Watchdog que reinicia o clamd se crashar."""
        while not self._parar:
            time.sleep(10)
            if self._parar:
                break

            if not self.esta_activo():
                logger.warning("clamd crashed — a reiniciar...")
                try:
                    clamd_bin = self.config.engine_dir / "clamd.exe"
                    cmd = [str(clamd_bin), f"--config-file={self._config_ficheiro}"]
                    self._processo = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                    time.sleep(2)
                    if self._processo.poll() is None:
                        logger.info("clamd reiniciado (PID: %d)", self._processo.pid)
                    else:
                        logger.error("clamd falhou ao reiniciar")
                except Exception as e:
                    logger.error("Erro ao reiniciar clamd: %s", e)

    def _criar_config(self) -> str:
        """Cria ficheiro de configuração do clamd."""
        db_dir = self.config.engine_dir.parent / "db"
        db_dir.mkdir(parents=True, exist_ok=True)

        log_dir = self.config.base_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        config_path = self.config.base_dir / "config" / "clamd_runtime.conf"
        config_path.parent.mkdir(parents=True, exist_ok=True)

        content = f"""# BenguelaShield — clamd runtime config
TCPSocket {self.config.clamd_port}
TCPAddr {self.config.clamd_host}
MaxThreads 4
DatabaseDirectory {db_dir}
LogFile {log_dir / 'clamd.log'}
LogTime yes
PidFile {self.config.base_dir / 'config' / 'clamd.pid'}
Foreground yes
"""
        config_path.write_text(content, encoding="utf-8")
        return str(config_path)
