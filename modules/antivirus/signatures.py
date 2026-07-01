"""Gestão de actualização de assinaturas do BenguelaShield.

Utiliza o freshclam para actualizar as bases de assinaturas do ClamAV.
"""

from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .config import AntiVirusConfig

logger = logging.getLogger(__name__)


class SignatureUpdateError(Exception):
    """Erro na actualização de assinaturas."""


@dataclass
class UpdateResult:
    """Resultado de uma operação de actualização.

    Attributes:
        success: Se a actualização foi bem sucedida.
        message: Mensagem descritiva do resultado.
        signatures_added: Número de assinaturas adicionadas.
        new_version: Nova versão das assinaturas, se disponível.
    """

    success: bool
    message: str
    signatures_added: int = 0
    new_version: str | None = None


@dataclass
class SignatureManager:
    """Gestor de assinaturas do ClamAV.

    Args:
        config: Configurações do módulo anti-vírus.
    """

    config: AntiVirusConfig

    def update(self) -> UpdateResult:
        """Executa o freshclam para actualizar as assinaturas.

        Returns:
            Resultado da actualização.

        Raises:
            SignatureUpdateError: Se o binário freshclam não foi encontrado.
        """
        freshclam = str(self.config.freshclam_binary)
        if not os.path.isfile(freshclam):
            raise SignatureUpdateError(
                f"Binário freshclam não encontrado: {freshclam}"
            )

        cmd = [freshclam]
        config_path = str(self.config.freshclam_config)
        if os.path.isfile(config_path):
            cmd.extend(["--config-file", config_path])

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                encoding="utf-8",
                errors="replace",
            )

            output = proc.stdout + proc.stderr

            if proc.returncode == 0:
                added = self._parse_signatures_added(output)
                version = self._parse_new_version(output)
                return UpdateResult(
                    success=True,
                    message="Assinaturas actualizadas com sucesso",
                    signatures_added=added,
                    new_version=version,
                )
            elif proc.returncode == 1:
                return UpdateResult(
                    success=False,
                    message=f"Actualização falhou (código {proc.returncode}): {output[:500]}",
                )
            elif proc.returncode == 52:
                return UpdateResult(
                    success=True,
                    message="Não há actualizações disponíveis",
                )
            else:
                return UpdateResult(
                    success=False,
                    message=f"Actualização falhou (código {proc.returncode}): {output[:500]}",
                )

        except subprocess.TimeoutExpired:
            return UpdateResult(
                success=False,
                message="Actualização excedeu o timeout de 300 segundos",
            )
        except FileNotFoundError:
            raise SignatureUpdateError(
                f"Binário freshclam não encontrado: {freshclam}"
            )

    def check_version(self) -> str | None:
        """Devolve a versão actual das assinaturas.

        Tenta obter a versão a partir do ficheiro de versão no directório
        de bases de dados.

        Returns:
            String com a versão, ou ``None`` se não foi possível obter.
        """
        db_dir = self.config.engine_dir.parent / "db"
        if not db_dir.exists():
            db_dir = self.config.engine_dir / "db"

        for ext in ("db", "hsb", "hdu", "hdb"):
            for cvd_file in db_dir.glob(f"*.{ext}"):
                version = self._read_cvd_version(cvd_file)
                if version:
                    return version

        clamscan = str(self.config.clamscan_binary)
        if os.path.isfile(clamscan):
            try:
                proc = subprocess.run(
                    [clamscan, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    encoding="utf-8",
                    errors="replace",
                )
                return proc.stdout.strip() or proc.stderr.strip() or None
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return None

    def last_update(self) -> datetime | None:
        """Devolve a data da última actualização de assinaturas.

        Verifica a data de modificação do ficheiro de versão mais recente.

        Returns:
            ``datetime`` da última actualização, ou ``None``.
        """
        db_dir = self.config.engine_dir.parent / "db"
        if not db_dir.exists():
            db_dir = self.config.engine_dir / "db"

        latest_mtime: float = 0
        for f in db_dir.glob("*.cvd"):
            mtime = f.stat().st_mtime
            if mtime > latest_mtime:
                latest_mtime = mtime

        for f in db_dir.glob("*.cld"):
            mtime = f.stat().st_mtime
            if mtime > latest_mtime:
                latest_mtime = mtime

        if latest_mtime > 0:
            return datetime.fromtimestamp(latest_mtime, tz=timezone.utc)
        return None

    @staticmethod
    def _parse_signatures_added(output: str) -> int:
        """Extrai o número de assinaturas adicionadas da saída do freshclam.

        Args:
            output: Saída do freshclam.

        Returns:
            Número de assinaturas, ou 0 se não foi possível extrair.
        """
        for line in output.splitlines():
            lower = line.lower()
            if "added" in lower:
                words = line.split()
                for i, word in enumerate(words):
                    if word.lower() == "added" and i > 0:
                        try:
                            return int(words[i - 1].replace(",", ""))
                        except (ValueError, IndexError):
                            pass
        return 0

    @staticmethod
    def _parse_new_version(output: str) -> str | None:
        """Extrai a nova versão da saída do freshclam.

        Args:
            output: Saída do freshclam.

        Returns:
            String com a versão, ou ``None``.
        """
        for line in output.splitlines():
            if "updated" in line.lower() or "new version" in line.lower():
                return line.strip()
        return None

    @staticmethod
    def _read_cvd_version(path: Path) -> str | None:
        """Lê a versão de um ficheiro CVD/CLD.

        Os primeiros 512 bytes do ficheiro contêm o cabeçalho com a versão.
        Formato: ``ClamAV-VDB:versão:...``

        Args:
            path: Caminho para o ficheiro CVD/CLD.

        Returns:
            Versão extraída, ou ``None``.
        """
        try:
            with open(path, "rb") as f:
                header = f.read(512)
            text = header.decode("utf-8", errors="replace")
            if "ClamAV" in text:
                for line in text.splitlines():
                    if line.startswith("ClamAV"):
                        parts = line.split(":")
                        if len(parts) >= 2:
                            version = parts[1].strip()
                            if version:
                                return version
        except (OSError, IndexError):
            pass
        return None
