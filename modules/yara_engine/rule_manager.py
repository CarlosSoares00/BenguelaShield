"""Gestao de regras YARA."""
from __future__ import annotations
import logging
import os
import shutil
from pathlib import Path
import yara
from .config import BENGUELA_RULES_DIR, COMMUNITY_RULES_DIR, RULE_EXTENSIONS

logger = logging.getLogger(__name__)

class RuleManager:
    def __init__(self):
        BENGUELA_RULES_DIR.mkdir(parents=True, exist_ok=True)
        COMMUNITY_RULES_DIR.mkdir(parents=True, exist_ok=True)

    def list_rules(self):
        rules = []
        for subdir, origin in [(BENGUELA_RULES_DIR, "benguelashield"), (COMMUNITY_RULES_DIR, "community")]:
            if not subdir.exists():
                continue
            for root, _, fl in os.walk(subdir):
                for fname in fl:
                    fp = Path(root) / fname
                    is_disabled = fname.endswith(".disabled")
                    stem = Path(fp.stem).stem if is_disabled else fp.stem
                    ext = Path(fp.stem).suffix if is_disabled else fp.suffix
                    if ext.lower() not in RULE_EXTENSIONS and not is_disabled:
                        continue
                    rc = 0
                    if not is_disabled and fp.exists():
                        try:
                            rc = len(list(yara.compile(filepath=str(fp))))
                        except Exception:
                            pass
                    rules.append({"name": stem, "origin": origin, "path": str(fp), "active": not is_disabled, "rule_count": rc, "size": fp.stat().st_size if fp.exists() else 0})
        rules.sort(key=lambda r: (r["origin"], r["name"]))
        return rules

    def disable_rule(self, rule_name):
        for subdir in [BENGUELA_RULES_DIR, COMMUNITY_RULES_DIR]:
            if not subdir.exists():
                continue
            for ext in RULE_EXTENSIONS:
                fp = subdir / f"{rule_name}{ext}"
                if fp.exists():
                    fp.rename(fp.with_suffix(f"{ext}.disabled"))
                    return True
        return False

    def enable_rule(self, rule_name):
        for subdir in [BENGUELA_RULES_DIR, COMMUNITY_RULES_DIR]:
            if not subdir.exists():
                continue
            for ext in RULE_EXTENSIONS:
                fp = subdir / f"{rule_name}{ext}.disabled"
                if fp.exists():
                    fp.rename(fp.with_suffix(""))
                    return True
        return False

    def import_rule(self, filepath, destination="benguelashield"):
        src = Path(filepath)
        if not src.exists():
            return False
        ok, msg = self.validate_rule(filepath)
        if not ok:
            return False
        dest_dir = BENGUELA_RULES_DIR if destination == "benguelashield" else COMMUNITY_RULES_DIR
        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(src), str(dest_dir / src.name))
        return True

    def export_rule(self, rule_name, destination):
        dest = Path(destination)
        for subdir in [BENGUELA_RULES_DIR, COMMUNITY_RULES_DIR]:
            if not subdir.exists():
                continue
            for ext in RULE_EXTENSIONS:
                fp = subdir / f"{rule_name}{ext}"
                if fp.exists():
                    dest.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(str(fp), str(dest / fp.name))
                    return True
        return False

    def validate_rule(self, filepath):
        try:
            yara.compile(filepath=filepath)
            return True, "OK"
        except yara.SyntaxError as e:
            return False, str(e)
        except Exception as e:
            return False, str(e)
