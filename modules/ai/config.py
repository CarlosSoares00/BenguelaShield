from pathlib import Path
AI_DIR = Path(__file__).parent
MODELS_DIR = AI_DIR / "models"
CLASSIFIER_MODEL_PATH = MODELS_DIR / "file_classifier.lgbm"
SCANNER_TIMEOUT = 5
MAX_FILE_SIZE = 100 * 1024 * 1024
MALWARE_THRESHOLD = 0.7
SUSPICIOUS_THRESHOLD = 0.4
EXECUTABLE_EXTENSIONS = [".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".com", ".msi", ".pif", ".wsf", ".hta"]
PE_EXTENSIONS = [".exe", ".dll", ".scr", ".sys"]
HIGH_RISK_IMPORTS = [
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "NtWriteVirtualMemory", "CreateRemoteThread",
    "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext",
    "NtUnmapViewOfSection", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "OutputDebugStringA", "GetProcAddress",
    "LoadLibraryA", "LoadLibraryW", "WinExec", "ShellExecuteA", "ShellExecuteW",
    "ShellExecuteExA", "ShellExecuteExW", "CreateProcessA", "CreateProcessW",
    "InternetOpenA", "InternetOpenW", "URLDownloadToFileA", "URLDownloadToFileW",
    "WinHttpOpen", "WinHttpConnect", "WSAStartup",
    "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA",
    "RegCreateKeyExA", "RegSetValueExA", "CreateServiceA", "OpenSCManagerA",
]
LOG_FILE = Path(__file__).parent.parent.parent / "logs" / "ai.log"
LGBM_PARAMS = {
    "objective": "binary", "metric": "binary_logloss", "num_leaves": 31,
    "learning_rate": 0.05, "n_estimators": 200, "max_depth": -1,
    "min_child_samples": 20, "feature_fraction": 0.9, "bagging_fraction": 0.8,
    "bagging_freq": 5, "verbose": -1, "random_state": 42,
}
FEATURE_NAMES = [
    "num_sections", "avg_section_entropy", "max_section_entropy",
    "min_section_entropy", "num_imports", "num_high_risk_imports",
    "has_virtual_alloc", "has_write_process_memory", "has_create_remote_thread",
    "has_debugger_check", "code_size", "data_size", "has_tls_callbacks",
    "has_debug_info", "num_resources", "is_packed", "header_size",
    "timestamp", "timestamp_suspicious", "has_overlay",
    "entry_in_code_section", "entry_in_last_section",
]
