"""Módulo de ferramentas do BenguelaShield."""
from .usb_vaccinator import USBVaccinator
from .file_restorer import FileRestorer
from .registry_repair import RegistryRepairer
from .win_force import WinForce
from .manual_scanner import ManualScanner
from .admin_protection import AdminProtection
from .exception_list import ExceptionList
from .process_manager import BenguelaProcessManager

__all__ = [
    "USBVaccinator", "FileRestorer", "RegistryRepairer", "WinForce",
    "ManualScanner", "AdminProtection", "ExceptionList", "BenguelaProcessManager",
]
