"""Pastas-isco (honeypots) — ficheiros falsos que detetam ransomware."""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent
from watchdog.observers import Observer

from .config import AntiRansomConfig


@dataclass
class HoneypotAlert:
    """Alerta disparado por um honeypot."""
    filepath: str
    timestamp: float
    event_type: str
    process_info: str


_HONEYPOT_CONTENT = {
    "Fotos_familia.xlsx": b"\x00" * 2048,
    "Relatorio_financeiro.docx": b"\x00" * 1536,
    "Plano_negocios.pdf": b"\x00" * 1024,
    "Contrato_aluguer.docx": b"\x00" * 1280,
    "Dados_bancarios.csv": b"IBAN,Conta,Saldo\nPT500000000000000000000000,12345,5000.00\n",
    "Backup_fotos.zip": b"\x00" * 4096,
    "Projecto_final.pptx": b"\x00" * 1792,
    "Curriculo_vitae.pdf": b"\x00" * 896,
    "Receitas_cozinha.docx": b"\x00" * 640,
    "Passwords_importantes.txt": b"WiFi: senha123\nEmail: user@ex.com\n",
}


class HoneypotEventHandler(FileSystemEventHandler):
    """Handler que detecta acesso a ficheiros honeypot."""

    def __init__(self, honeypots: set[str], on_alert: callable) -> None:
        super().__init__()
        self._honeypots = honeypots
        self._on_alert = on_alert
        self._alertas_recentes: dict[str, float] = {}
        self._cooldown = 5.0

    def on_modified(self, event: FileModifiedEvent) -> None:
        self._verificar(event.src_path, "modified")

    def on_created(self, event: FileCreatedEvent) -> None:
        if not event.is_directory:
            self._verificar(event.src_path, "created")

    def on_deleted(self, event) -> None:
        self._verificar(event.src_path, "deleted")

    def _verificar(self, filepath: str, event_type: str) -> None:
        nome = Path(filepath).name
        if nome not in self._honeypots:
            return

        now = time.time()
        last = self._alertas_recentes.get(nome, 0)
        if (now - last) < self._cooldown:
            return
        self._alertas_recentes[nome] = now

        alert = HoneypotAlert(
            filepath=filepath,
            timestamp=now,
            event_type=event_type,
            process_info=f"Processo modificou honeypot: {nome}",
        )
        self._on_alert(alert)


class HoneypotManager:
    """Gestor de ficheiros honeypot nas pastas protegidas."""

    def __init__(self, config: AntiRansomConfig) -> None:
        self.config = config
        self._honeypots_criados: dict[str, str] = {}
        self._observers: list[Observer] = []
        self._on_alert: callable | None = None

    def set_alert_callback(self, callback: callable) -> None:
        self._on_alert = callback

    def criar_honeypots(self) -> int:
        """Cria ficheiros honeypot em todas as pastas protegidas.

        Returns:
            Número de honeypots criados.
        """
        if not self.config.honeypot_enabled:
            return 0

        total = 0
        for pasta in self.config.protected_dirs:
            for nome, conteudo in _HONEYPOT_CONTENT.items():
                caminho = os.path.join(pasta, f"{self.config.honeypot_prefix}{nome}")
                if not os.path.exists(caminho):
                    try:
                        with open(caminho, "wb") as f:
                            f.write(conteudo)
                        self._honeypots_criados[caminho] = pasta
                        total += 1
                    except Exception:
                        pass
        return total

    def remover_honeypots(self) -> int:
        """Remove todos os ficheiros honeypot."""
        total = 0
        for caminho in list(self._honeypots_criados.keys()):
            if os.path.exists(caminho):
                try:
                    os.remove(caminho)
                    total += 1
                except Exception:
                    pass
        self._honeypots_criados.clear()
        return total

    def iniciar_monitorizacao(self) -> None:
        """Inicia a monitorização dos honeypots via watchdog."""
        if not self.config.honeypot_enabled:
            return

        nomes_honeypot = {
            f"{self.config.honeypot_prefix}{nome}"
            for nome in _HONEYPOT_CONTENT
        }

        pastas_monitorizar = set(self._honeypots_criados.values())

        for pasta in pastas_monitorizar:
            if os.path.isdir(pasta):
                handler = HoneypotEventHandler(nomes_honeypot, self._on_honeypot_alert)
                observer = Observer()
                observer.schedule(handler, pasta, recursive=False)
                observer.start()
                self._observers.append(observer)

    def parar_monitorizacao(self) -> None:
        """Para todos os observers."""
        for obs in self._observers:
            obs.stop()
            obs.join(timeout=5)
        self._observers.clear()

    def _on_honeypot_alert(self, alert: HoneypotAlert) -> None:
        """Handler chamado quando um honeypot é acedido."""
        if self._on_alert:
            self._on_alert(alert)

    def honeypots_activos(self) -> int:
        """Número de honeypots actualmente no disco."""
        count = 0
        for caminho in self._honeypots_criados:
            if os.path.exists(caminho):
                count += 1
        return count
