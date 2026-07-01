"""Módulo Anti-Ransomware do BenguelaShield."""

from .config import AntiRansomConfig
from .folder_shield import FolderShield
from .encryption_detect import EncryptionDetector
from .honeypot import HoneypotManager
from .backup import BackupManager

__all__ = [
    "AntiRansomConfig",
    "FolderShield",
    "EncryptionDetector",
    "HoneypotManager",
    "BackupManager",
]
