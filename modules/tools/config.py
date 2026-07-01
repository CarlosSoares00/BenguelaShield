"""Configuracoes do modulo de ferramentas."""
import os
import sys
from pathlib import Path

if getattr(sys, 'frozen', False):
    _DATA = Path(os.environ.get('PROGRAMDATA', r'C:\ProgramData')) / 'BenguelaShield'
else:
    _DATA = Path(__file__).parent.parent.parent

LOG_FILE = _DATA / "logs" / "tools.log"
ADMIN_PASSWORD_HASH_FILE = _DATA / "config" / "admin_hash.json"
EXCEPTIONS_FILE = _DATA / "config" / "exceptions.json"

USB_MALWARE_FILES = [
    "autorun.inf", "*.exe", "*.vbs", "*.bat", "*.cmd",
    "*.scr", "*.pif", "*.lnk",
]

AUTORUN_MALICIOUS_KEYWORDS = [
    "shellexecute", "open=", "wscript", "powershell",
    "cmd.exe", "rundll32", "mshta",
]

REPAIR_REGISTRY_KEYS = {
    "disable_task_manager": {
        "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "DisableTaskMgr", "safe_value": 0,
        "description": "Desbloquear Gestor de Tarefas"
    },
    "disable_registry_editor": {
        "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "DisableRegistryTools", "safe_value": 0,
        "description": "Desbloquear Editor de Registo"
    },
    "disable_cmd": {
        "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "DisableCMD", "safe_value": 0,
        "description": "Desbloquear Linha de Comandos"
    },
    "disable_run": {
        "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "name": "NoRun", "safe_value": 0,
        "description": "Desbloquear comando Executar"
    },
    "hide_file_extensions": {
        "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "name": "HideFileExt", "safe_value": 0,
        "description": "Mostrar extensões de ficheiros"
    },
    "hide_hidden_files": {
        "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "name": "Hidden", "safe_value": 1,
        "description": "Mostrar ficheiros ocultos"
    },
    "disable_firewall": {
        "path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
        "name": "EnableFirewall", "safe_value": 1,
        "description": "Activar Firewall"
    },
}

WINDOWS_TOOLS = {
    "task_manager": {"name": "Gestor de Tarefas", "command": "taskmgr.exe"},
    "registry_editor": {"name": "Editor de Registo", "command": "regedit.exe"},
    "cmd": {"name": "Linha de Comandos", "command": "cmd.exe"},
    "msconfig": {"name": "Configuração do Sistema", "command": "msconfig.exe"},
    "control_panel": {"name": "Painel de Controlo", "command": "control.exe"},
    "services": {"name": "Serviços", "command": "services.msc"},
    "device_manager": {"name": "Gestor de Dispositivos", "command": "devmgmt.msc"},
}

SUSPICIOUS_LOCATIONS = [
    r"C:\Users\*\AppData\Local\Temp",
    r"C:\Users\*\Downloads",
    r"C:\Users\*\Desktop",
    r"C:\ProgramData",
    r"C:\Windows\Temp",
]

TRUSTED_LOCATIONS = [
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
]
