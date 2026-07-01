"""Configuração do módulo comportamental."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# === ML (Machine Learning) ===
ML_MODEL_PATH = Path(__file__).parent / "models" / "behavior_model.pkl"
ML_CONTAMINATION = 0.05
ML_N_ESTIMATORS = 100
ML_RANDOM_STATE = 42
ML_ANOMALY_THRESHOLD = 0.7
ML_WARNING_THRESHOLD = 0.5

FEATURE_ORDER = [
    "cpu_percent", "memory_mb", "num_threads", "num_connections",
    "has_remote_connection", "remote_ip_is_private", "num_open_files",
    "process_age_seconds", "parent_is_system", "parent_is_suspicious",
    "num_children", "has_suspicious_name", "cpu_is_high",
    "memory_is_high", "has_many_connections",
]

SYSTEM_PROCESSES = frozenset({
    "system", "idle", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "lsass.exe", "services.exe", "svchost.exe",
    "dwm.exe", "conhost.exe", "fontdrvhost.exe",
})

SUSPICIOUS_PROCESS_NAMES = frozenset({
    "mimikatz.exe", "lazagne.exe", "procdump.exe", "psexec.exe",
    "nc.exe", "ncat.exe", "netcat.exe", "meterpreter.exe",
    "cobaltstrike.exe", "empire.exe", "covenant.exe",
    "bloodhound.exe", "sharphound.exe", "rubeus.exe",
    "mimilib.dll", "sekurlsa.dll",
})

LOG_FILE = Path(__file__).parent.parent.parent / "logs" / "behavioral.log"


@dataclass
class BehavioralConfig:
    """Configurações do módulo de análise comportamental."""

    scan_interval: float = 5.0

    risk_threshold_warning: int = 40
    risk_threshold_critical: int = 70
    risk_threshold_block: int = 90

    max_processes_per_minute: int = 30
    max_file_modifications_per_minute: int = 100
    max_registry_writes_per_minute: int = 20
    max_network_connections_per_minute: int = 50

    suspicious_process_names: list[str] = field(default_factory=lambda: [
        "mimikatz.exe", "lazagne.exe", "procdump.exe", "psexec.exe",
        "nc.exe", "ncat.exe", "netcat.exe", "meterpreter.exe",
        "cobaltstrike.exe", "empire.exe", "covenant.exe",
        "bloodhound.exe", "sharphound.exe", "rubeus.exe",
        "mimilib.dll", "sekurlsa.dll",
    ])

    suspicious_extensions: list[str] = field(default_factory=lambda: [
        ".scr", ".pif", ".hta", ".wsf", ".jse", ".vbe",
    ])

    suspicious_paths: list[str] = field(default_factory=lambda: [
        "\\AppData\\Local\\Temp\\",
        "\\Windows\\Temp\\",
        "\\ProgramData\\",
        "\\Users\\Public\\",
    ])

    whitelisted_processes: list[str] = field(default_factory=lambda: [
        "svchost.exe", "csrss.exe", "smss.exe", "lsass.exe",
        "services.exe", "wininit.exe", "winlogon.exe",
        "explorer.exe", "dwm.exe", "conhost.exe",
        "sihost.exe", "taskhostw.exe", "RuntimeBroker.exe",
        "ShellExperienceHost.exe", "SearchUI.exe",
        "ctfmon.exe", "dllhost.exe", "wudfhost.exe",
        "SearchIndexer.exe", "SearchProtocolHost.exe",
        "spoolsv.exe", "WmiPrvSE.exe", "msdtc.exe",
        "fontdrvhost.exe", "dashost.exe",
    ])
