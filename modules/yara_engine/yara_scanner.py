"""Motor de deteccao YARA do BenguelaShield."""
from __future__ import annotations
import logging
import os
from pathlib import Path
import yara
from .config import BENGUELA_RULES_DIR, COMMUNITY_RULES_DIR, MAX_FILE_SIZE, RULE_EXTENSIONS, SCAN_TIMEOUT

logger = logging.getLogger(__name__)
IGNORED_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}

class YaraScanner:
    def __init__(self):
        self._rules = None
        self._rules_count = 0
        self._load()

    def _load(self):
        rules_dict = self._discover_rules()
        if not rules_dict:
            return
        self._rules = self._compile_rules(rules_dict)

    def _discover_rules(self):
        result = {}
        for subdir, prefix in [(COMMUNITY_RULES_DIR, ""), (BENGUELA_RULES_DIR, "bs_")]:
            if not subdir.exists():
                continue
            for root, dirs, files_list in os.walk(subdir):
                dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
                for fname in files_list:
                    if Path(fname).suffix.lower() in RULE_EXTENSIONS:
                        ns = prefix + Path(fname).stem
                        result[ns] = os.path.join(root, fname)
        return result

    def _compile_rules(self, rules_dict):
        remaining = dict(rules_dict)
        while remaining:
            try:
                compiled = yara.compile(filepaths=remaining)
                self._rules_count = len(rules_dict)
                return compiled
            except yara.SyntaxError as e:
                msg = str(e)
                bad_ns = list(remaining.keys())[0]
                for ns in remaining:
                    if ns in msg:
                        bad_ns = ns
                        break
                del remaining[bad_ns]
                logger.warning("Regra invalida removida: %s", bad_ns)
        return None

    def scan_file(self, filepath):
        if not os.path.isfile(filepath):
            raise FileNotFoundError(filepath)
        if os.path.getsize(filepath) > MAX_FILE_SIZE:
            return []
        if not self._rules:
            return []
        try:
            matches = self._rules.match(filepath, timeout=SCAN_TIMEOUT)
            return [self._fmt(m) for m in matches]
        except yara.TimeoutError:
            return []
        except yara.Error:
            return []

    def scan_bytes(self, data):
        if len(data) > MAX_FILE_SIZE or not self._rules:
            return []
        try:
            return [self._fmt(m) for m in self._rules.match(data=data, timeout=SCAN_TIMEOUT)]
        except Exception:
            return []

    def scan_directory(self, dirpath):
        all_m = []
        for root, dirs, files_list in os.walk(dirpath):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
            for fname in files_list:
                fp = os.path.join(root, fname)
                try:
                    m = self.scan_file(fp)
                    if m:
                        all_m.extend(m)
                except FileNotFoundError:
                    pass
        return all_m

    @staticmethod
    def _fmt(m):
        meta = dict(m.meta) if m.meta else {}
        strings = []
        for s in (m.strings or []):
            if isinstance(s, tuple) and len(s) >= 3:
                strings.append((hex(s[0]), s[1], s[2]))
        return {"rule": m.rule, "meta": meta, "strings": strings, "tags": list(m.tags) if m.tags else []}

    @property
    def rules_count(self):
        return self._rules_count

    @property
    def is_ready(self):
        return self._rules is not None
