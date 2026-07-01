"""Wrapper do motor ClamAV para o BenguelaShield.

Este módulo comunica com o clamd via socket TCP (porta 3310) para
realizar scans de ficheiros e pastas. Para scans rápidos, pode usar
o binário clamscan via subprocesso.
"""

from __future__ import annotations

import logging
import os
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

from .config import AntiVirusConfig

logger = logging.getLogger(__name__)

_CLAMD_TIMEOUT = 10


class ClamAVConnectionError(Exception):
    """Erro de ligação ao clamd."""


class ScanTimeoutError(Exception):
    """Timeout durante um scan."""


@dataclass
class ScanResult:
    """Resultado de um scan de ficheiro.

    Attributes:
        filepath: Caminho do ficheiro analisado.
        status: Estado do scan (``OK``, ``FOUND``, ``ERROR``).
        threat_name: Nome da ameaça, se detetada.
        scan_time: Duração do scan em segundos.
        action_taken: Acção tomada (``quarantined``, ``deleted``, ``none``).
        error_message: Mensagem de erro, se houve falha.
    """

    filepath: str
    status: str
    threat_name: str | None = None
    scan_time: float = 0.0
    action_taken: str | None = None
    error_message: str | None = None


@dataclass
class ClamAVScanner:
    """Scanner anti-vírus que comunica com o clamd.

    Args:
        config: Configurações do módulo anti-vírus.
    """

    config: AntiVirusConfig
    _connection_errors: int = field(default=0, init=False, repr=False)

    def ping(self) -> bool:
        """Verifica se o clamd está a correr e a escutar.

        Returns:
            ``True`` se o clamd respondeu ao PING, ``False`` caso contrário.
        """
        try:
            with socket.create_connection(
                (self.config.clamd_host, self.config.clamd_port),
                timeout=_CLAMD_TIMEOUT,
            ) as sock:
                sock.sendall(b"PING\n")
                response = sock.recv(1024).decode("utf-8", errors="replace").strip()
                return response == "PONG"
        except (OSError, socket.timeout) as exc:
            logger.warning("PING ao clamd falhou: %s", exc)
            return False

    def get_version(self) -> str | None:
        """Devolve a versão do clamd.

        Returns:
            String com a versão, ou ``None`` se não foi possível obter.
        """
        try:
            with socket.create_connection(
                (self.config.clamd_host, self.config.clamd_port),
                timeout=_CLAMD_TIMEOUT,
            ) as sock:
                sock.sendall(b"VERSION\n")
                response = sock.recv(4096).decode("utf-8", errors="replace").strip()
                if response.startswith("VERSION:"):
                    return response[len("VERSION:") :].strip()
                return response
        except (OSError, socket.timeout) as exc:
            logger.warning("VERSION ao clamd falhou: %s", exc)
            return None

    def scan_file(self, path: str) -> ScanResult:
        """Analisa um único ficheiro via clamd.

        Args:
            path: Caminho completo do ficheiro a analisar.

        Returns:
            Resultado do scan.

        Raises:
            ClamAVConnectionError: Se não é possível ligar ao clamd.
        """
        filepath = str(Path(path).resolve())
        if not os.path.isfile(filepath):
            return ScanResult(
                filepath=filepath,
                status="ERROR",
                error_message="Ficheiro não encontrado",
            )

        start = time.monotonic()
        try:
            response = self._clamd_inscan(filepath)
        except PermissionError as exc:
            return ScanResult(
                filepath=filepath,
                status="ERROR",
                error_message=f"Sem permissão de leitura: {exc}",
            )
        except (OSError, socket.timeout) as exc:
            raise ClamAVConnectionError(
                f"Não foi possível ligar ao clamd: {exc}"
            ) from exc
        elapsed = time.monotonic() - start

        status, threat_name = self._parse_clamd_response(response)
        return ScanResult(
            filepath=filepath,
            status=status,
            threat_name=threat_name,
            scan_time=elapsed,
        )

    def scan_files(self, paths: list[str]) -> list[ScanResult]:
        """Analisa múltiplos ficheiros via clamd.

        Args:
            paths: Lista de caminhos de ficheiros.

        Returns:
            Lista de resultados do scan.
        """
        results: list[ScanResult] = []
        for path in paths:
            try:
                result = self.scan_file(path)
                results.append(result)
            except ClamAVConnectionError:
                results.append(
                    ScanResult(
                        filepath=str(Path(path).resolve()),
                        status="ERROR",
                        error_message="ClamAV indisponível",
                    )
                )
        return results

    def quick_scan(self) -> list[ScanResult]:
        """Realiza um scan rápido das pastas críticas do Windows.

        Analisa: pasta Temp, Downloads e Pasta de Arranque do utilizador.

        Returns:
            Lista de resultados do scan.
        """
        all_results: list[ScanResult] = []
        for scan_path in self.config.quick_scan_paths:
            if not os.path.exists(scan_path):
                continue
            if os.path.isfile(scan_path):
                try:
                    all_results.append(self.scan_file(scan_path))
                except ClamAVConnectionError:
                    all_results.append(
                        ScanResult(
                            filepath=scan_path,
                            status="ERROR",
                            error_message="ClamAV indisponível",
                        )
                    )
            elif os.path.isdir(scan_path):
                all_results.extend(self._scan_directory_clamd(scan_path))
        return all_results

    def full_scan(self, drive: str = "C:") -> list[ScanResult]:
        """Realiza um scan completo de uma unidade.

        Usa o binário clamscan via subprocesso para scans recursivos.

        Args:
            drive: Letra da unidade a analisar (ex: ``C:``).

        Returns:
            Lista de resultados do scan.
        """
        clamscan = str(self.config.clamscan_binary)
        if not os.path.isfile(clamscan):
            return [
                ScanResult(
                    filepath=drive,
                    status="ERROR",
                    error_message=f"Binário clamscan não encontrado: {clamscan}",
                )
            ]

        cmd = [
            clamscan,
            "-r",
            "--force-to-disk",
            "--infected",
            "--move=" + str(self.config.quarantine_dir),
            f"{drive}\\",
        ]

        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.scan_timeout * 100,
                encoding="utf-8",
                errors="replace",
            )
            elapsed = time.monotonic() - start
            return self._parse_clamscan_output(proc.stdout, elapsed)
        except subprocess.TimeoutExpired:
            return [
                ScanResult(
                    filepath=drive,
                    status="ERROR",
                    error_message="Scan completo excedeu o timeout",
                )
            ]
        except FileNotFoundError:
            return [
                ScanResult(
                    filepath=drive,
                    status="ERROR",
                    error_message=f"Binário clamscan não encontrado: {clamscan}",
                )
            ]

    def custom_scan(self, paths: list[str]) -> list[ScanResult]:
        """Realiza um scan personalizado de pastas/ficheiros escolhidos pelo utilizador.

        Args:
            paths: Lista de caminhos a analisar.

        Returns:
            Lista de resultados do scan.
        """
        all_results: list[ScanResult] = []
        for scan_path in paths:
            resolved = str(Path(scan_path).resolve())
            if not os.path.exists(resolved):
                all_results.append(
                    ScanResult(
                        filepath=resolved,
                        status="ERROR",
                        error_message="Caminho não encontrado",
                    )
                )
                continue
            if os.path.isfile(resolved):
                try:
                    all_results.append(self.scan_file(resolved))
                except ClamAVConnectionError:
                    all_results.append(
                        ScanResult(
                            filepath=resolved,
                            status="ERROR",
                            error_message="ClamAV indisponível",
                        )
                    )
            elif os.path.isdir(resolved):
                all_results.extend(self._scan_directory_clamd(resolved))
        return all_results

    def _clamd_inscan(self, filepath: str) -> str:
        """Envia um ficheiro ao clamd via INSCAN e devolve a resposta.

        Args:
            filepath: Caminho do ficheiro.

        Returns:
            Resposta do clamd.

        Raises:
            OSError: Erro de socket.
            socket.timeout: Timeout na ligação.
        """
        with socket.create_connection(
            (self.config.clamd_host, self.config.clamd_port),
            timeout=self.config.scan_timeout,
        ) as sock:
            header = f"INSCAN {filepath}\n".encode("utf-8")
            sock.sendall(header)

            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    sock.sendall(chunk)

            sock.shutdown(socket.SHUT_WR)

            response_parts: list[bytes] = []
            while True:
                try:
                    data = sock.recv(65536)
                    if not data:
                        break
                    response_parts.append(data)
                except socket.timeout:
                    break

            return b"".join(response_parts).decode("utf-8", errors="replace").strip()

    def _scan_directory_clamd(self, directory: str) -> list[ScanResult]:
        """Analisa um directório usando CONTSCAN via clamd.

        Args:
            directory: Caminho do directório.

        Returns:
            Lista de resultados do scan.
        """
        results: list[ScanResult] = []
        start = time.monotonic()
        try:
            with socket.create_connection(
                (self.config.clamd_host, self.config.clamd_port),
                timeout=self.config.scan_timeout,
            ) as sock:
                command = f"CONTSCAN {directory}\n".encode("utf-8")
                sock.sendall(command)

                buffer = b""
                while True:
                    try:
                        data = sock.recv(65536)
                        if not data:
                            break
                        buffer += data
                    except socket.timeout:
                        break

            elapsed = time.monotonic() - start
            text = buffer.decode("utf-8", errors="replace")
            for line in text.strip().splitlines():
                line = line.strip()
                if not line or line == "OK":
                    continue
                filepath, status, *rest = line.split(None, 2)
                filepath = filepath.rstrip(":")
                if status == "FOUND":
                    threat = rest[0] if rest else "UNKNOWN"
                    results.append(
                        ScanResult(
                            filepath=filepath,
                            status="FOUND",
                            threat_name=threat,
                            scan_time=elapsed,
                        )
                    )
                elif status == "OK":
                    pass  # Ignorar ficheiros limpos no CONTSCAN
                else:
                    results.append(
                        ScanResult(
                            filepath=filepath,
                            status="ERROR",
                            error_message=line,
                        )
                    )
        except (OSError, socket.timeout) as exc:
            results.append(
                ScanResult(
                    filepath=directory,
                    status="ERROR",
                    error_message=f"Erro no CONTSCAN: {exc}",
                )
            )
        return results

    @staticmethod
    def _parse_clamd_response(response: str) -> tuple[str, str | None]:
        """Analisa a resposta do clamd a um INSCAN.

        Args:
            response: Resposta textual do clamd.

        Returns:
            Tuplo ``(status, threat_name)``.
        """
        response = response.strip()
        if not response:
            return "ERROR", "Resposta vazia do clamd"

        if ": OK" in response or response.endswith(": OK"):
            return "OK", None

        if " FOUND" in response:
            parts = response.split(":")
            if len(parts) >= 2:
                threat = parts[-1].replace(" FOUND", "").strip()
                return "FOUND", threat
            return "FOUND", response

        return "ERROR", response

    @staticmethod
    def _parse_clamscan_output(output: str, elapsed: float) -> list[ScanResult]:
        """Analisa a saída do binário clamscan.

        Args:
            output: Saída stdout do clamscan.
            elapsed: Tempo total do scan em segundos.

        Returns:
            Lista de resultados do scan.
        """
        results: list[ScanResult] = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("-----------") or line.startswith("Scanned"):
                continue

            if ": " in line:
                parts = line.split(": ", 1)
                if len(parts) == 2:
                    filepath, result = parts
                    if result.endswith(" FOUND"):
                        threat = result.replace(" FOUND", "")
                        results.append(
                            ScanResult(
                                filepath=filepath,
                                status="FOUND",
                                threat_name=threat,
                                scan_time=elapsed,
                            )
                        )
                    elif result == "OK":
                        pass
                    else:
                        results.append(
                            ScanResult(
                                filepath=filepath,
                                status="ERROR",
                                error_message=result,
                            )
                        )
        return results
