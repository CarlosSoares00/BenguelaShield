from pathlib import Path
RULES_DIR = Path(__file__).parent / "rules"
BENGUELA_RULES_DIR = RULES_DIR / "benguelashield"
COMMUNITY_RULES_DIR = RULES_DIR / "community"
RULE_EXTENSIONS = [".yar", ".yara"]
SCAN_TIMEOUT = 30
MAX_FILE_SIZE = 100 * 1024 * 1024
LOG_FILE = Path(__file__).parent.parent.parent / "logs" / "yara.log"
COMMUNITY_REPOS = [
    {"name": "Neo23x0", "url": "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip", "subdir": "signature-base-master/yara/"},
    {"name": "Yara-Rules", "url": "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip", "subdir": "rules-master/"},
]
