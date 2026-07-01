"""Gestão de quarentena do BenguelaShield.

Ficheiros infectados são encriptados com AES-256-CBC antes de serem
movidos para o directório de quarentena. O IV aleatório é armazenado
no início de cada ficheiro encriptado.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from .config import AntiVirusConfig
from .database import DatabaseManager


class QuarantineError(Exception):
    """Erro na operação de quarentena."""


@dataclass
class QuarantineEntry:
    """Uma entrada na quarentena.

    Attributes:
        id: UUID único da quarentena.
        original_path: Caminho original do ficheiro.
        filename: Nome do ficheiro.
        threat_name: Nome da ameaça detetada.
        date_quarantined: Data e hora da quarentena.
        file_hash: Hash SHA-256 do ficheiro original.
        file_size: Tamanho em bytes do ficheiro original.
    """

    id: str
    original_path: str
    filename: str
    threat_name: str
    date_quarantined: datetime
    file_hash: str
    file_size: int


@dataclass
class QuarantineManager:
    """Gestor de quarentena do BenguelaShield.

    Args:
        config: Configurações do módulo anti-vírus.
        db: Gestor da base de dados.
    """

    config: AntiVirusConfig
    db: DatabaseManager

    def quarantine_file(self, filepath: str, threat_name: str) -> str:
        """Move um ficheiro infectado para a quarentena.

        O ficheiro é encriptado com AES-256-CBC antes de ser movido.
        O registo é criado na base de dados.

        Args:
            filepath: Caminho do ficheiro a quarantinar.
            threat_name: Nome da ameaça detetada.

        Returns:
            ID da quarentena (UUID).

        Raises:
            QuarantineError: Se ocorreu um erro durante a operação.
        """
        src = Path(filepath)
        if not src.exists():
            raise QuarantineError(f"Ficheiro não encontrado: {filepath}")

        quarantine_id = str(uuid.uuid4())
        file_hash = self._compute_hash(filepath)
        file_size = src.stat().st_size
        encrypted_name = f"{quarantine_id}.quarantine"
        dst = self.config.quarantine_dir / encrypted_name

        try:
            self._encrypt_file(str(src), str(dst))
        except Exception as exc:
            raise QuarantineError(f"Erro ao encriptar ficheiro: {exc}") from exc

        try:
            src.unlink()
        except OSError as exc:
            if dst.exists():
                dst.unlink()
            raise QuarantineError(f"Erro ao remover ficheiro original: {exc}") from exc

        try:
            self.db.log_quarantine_entry(
                quarantine_id=quarantine_id,
                original_path=str(src.resolve()),
                filename=src.name,
                threat_name=threat_name,
                file_hash=file_hash,
                file_size=file_size,
            )
            self.db.log_threat(
                filepath=str(src.resolve()),
                threat_name=threat_name,
                action="quarantined",
                status="FOUND",
                file_hash=file_hash,
                file_size=file_size,
            )
        except Exception as exc:
            raise QuarantineError(
                f"Erro ao registar quarentena na base de dados: {exc}"
            ) from exc

        return quarantine_id

    def restore_file(self, quarantine_id: str) -> str:
        """Restaura um ficheiro da quarentena para o seu caminho original.

        Args:
            quarantine_id: UUID da quarentena.

        Returns:
            Caminho onde o ficheiro foi restaurado.

        Raises:
            QuarantineError: Se ocorreu um erro durante a restauração.
        """
        entries = self.db.get_quarantine_entries()
        entry_data = None
        for e in entries:
            if e["quarantine_id"] == quarantine_id:
                entry_data = e
                break

        if entry_data is None:
            raise QuarantineError(f"Entrada de quarentena não encontrada: {quarantine_id}")

        encrypted_path = self.config.quarantine_dir / f"{quarantine_id}.quarantine"
        if not encrypted_path.exists():
            raise QuarantineError(f"Ficheiro encriptado não encontrado: {encrypted_path}")

        original_path = Path(entry_data["original_path"])
        original_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            self._decrypt_file(str(encrypted_path), str(original_path))
        except Exception as exc:
            raise QuarantineError(f"Erro ao desencriptar ficheiro: {exc}") from exc

        try:
            encrypted_path.unlink()
        except OSError:
            pass

        self.db.remove_quarantine_entry(quarantine_id)
        self.db.log_threat(
            filepath=str(original_path),
            threat_name=entry_data["threat_name"],
            action="restored",
            status="RESTORED",
        )

        return str(original_path)

    def delete_file(self, quarantine_id: str) -> None:
        """Remove permanentemente um ficheiro da quarentena.

        Args:
            quarantine_id: UUID da quarentena.

        Raises:
            QuarantineError: Se a entrada não foi encontrada.
        """
        entries = self.db.get_quarantine_entries()
        found = False
        for e in entries:
            if e["quarantine_id"] == quarantine_id:
                found = True
                break

        if not found:
            raise QuarantineError(f"Entrada de quarentena não encontrada: {quarantine_id}")

        encrypted_path = self.config.quarantine_dir / f"{quarantine_id}.quarantine"
        if encrypted_path.exists():
            encrypted_path.unlink()

        self.db.remove_quarantine_entry(quarantine_id)

    def list_files(self) -> list[QuarantineEntry]:
        """Devolve a lista de ficheiros em quarentena.

        Returns:
            Lista de ``QuarantineEntry``.
        """
        entries = self.db.get_quarantine_entries()
        result: list[QuarantineEntry] = []
        for e in entries:
            dt = datetime.fromisoformat(e["date_quarantined"])
            result.append(
                QuarantineEntry(
                    id=e["quarantine_id"],
                    original_path=e["original_path"],
                    filename=e["filename"],
                    threat_name=e["threat_name"],
                    date_quarantined=dt,
                    file_hash=e["file_hash"],
                    file_size=e["file_size"],
                )
            )
        return result

    def cleanup(self, max_age_days: int = 90) -> int:
        """Remove entradas de quarentena mais antigas que o limite.

        Args:
            max_age_days: Idade máxima em dias.

        Returns:
            Número de entradas removidas.
        """
        now = datetime.now(timezone.utc)
        entries = self.db.get_quarantine_entries()
        removed = 0

        for e in entries:
            dt = datetime.fromisoformat(e["date_quarantined"])
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age = (now - dt).days
            if age > max_age_days:
                qid = e["quarantine_id"]
                encrypted = self.config.quarantine_dir / f"{qid}.quarantine"
                if encrypted.exists():
                    encrypted.unlink()
                self.db.remove_quarantine_entry(qid)
                removed += 1

        return removed

    def _encrypt_file(self, src: str, dst: str) -> None:
        """Encripta um ficheiro com AES-256-CBC.

        O IV aleatório de 16 bytes é gravado no início do ficheiro de saída.
        O plaintext completo é lido, com PKCS7 padding aplicado uma única vez.

        Args:
            src: Caminho do ficheiro original.
            dst: Caminho do ficheiro encriptado.
        """
        iv = os.urandom(16)
        cipher = AES.new(self.config.quarantine_key, AES.MODE_CBC, iv)

        with open(src, "rb") as fin, open(dst, "wb") as fout:
            fout.write(iv)
            plaintext = fin.read()
            padded = pad(plaintext, AES.block_size)

            for i in range(0, len(padded), AES.block_size):
                block = padded[i : i + AES.block_size]
                fout.write(cipher.encrypt(block))

    def _decrypt_file(self, src: str, dst: str) -> None:
        """Desencripta um ficheiro AES-256-CBC.

        Args:
            src: Caminho do ficheiro encriptado.
            dst: Caminho de saída.
        """
        with open(src, "rb") as fin:
            iv = fin.read(16)
            ciphertext = fin.read()

        cipher = AES.new(self.config.quarantine_key, AES.MODE_CBC, iv)
        plaintext = b""
        for i in range(0, len(ciphertext), AES.block_size):
            block = ciphertext[i : i + AES.block_size]
            plaintext += cipher.decrypt(block)

        with open(dst, "wb") as fout:
            fout.write(unpad(plaintext, AES.block_size))

    @staticmethod
    def _compute_hash(filepath: str) -> str:
        """Calcula o hash SHA-256 de um ficheiro.

        Args:
            filepath: Caminho do ficheiro.

        Returns:
            Hash SHA-256 em hexadecimal.
        """
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
