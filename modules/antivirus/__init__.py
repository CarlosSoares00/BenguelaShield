"""Módulo AntiVírus BenguelaShield.

Fornece a interface Python para o motor ClamAV, incluindo:
- Scan de ficheiros e pastas
- Gestão de quarentena com encriptação AES-256
- Actualização de assinaturas via FreshClam
- Registo de acções na base de dados SQLite
"""

from .config import AntiVirusConfig
from .database import DatabaseManager
from .quarantine import QuarantineManager, QuarantineEntry, QuarantineError
from .scanner import (
    ClamAVScanner,
    ScanResult,
    ClamAVConnectionError,
    ScanTimeoutError,
)
from .signatures import SignatureManager, UpdateResult, SignatureUpdateError

__all__ = [
    "AntiVirusConfig",
    "DatabaseManager",
    "QuarantineManager",
    "QuarantineEntry",
    "QuarantineError",
    "ClamAVScanner",
    "ScanResult",
    "ClamAVConnectionError",
    "ScanTimeoutError",
    "SignatureManager",
    "UpdateResult",
    "SignatureUpdateError",
]
