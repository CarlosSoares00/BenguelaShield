"""Actualizacao de regras YARA da comunidade."""
from __future__ import annotations
import io
import logging
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path
import requests
import yara
from .config import COMMUNITY_REPOS, COMMUNITY_RULES_DIR, RULE_EXTENSIONS

logger = logging.getLogger(__name__)
_STATE_FILE = COMMUNITY_RULES_DIR / "_last_update.txt"

class RuleUpdater:
    def __init__(self):
        COMMUNITY_RULES_DIR.mkdir(parents=True, exist_ok=True)

    def update_all(self):
        stats = {"total_downloaded": 0, "valid": 0, "invalid": 0, "repos_updated": 0, "errors": []}
        for repo in COMMUNITY_REPOS:
            try:
                r = self.update_repo(repo)
                stats["total_downloaded"] += r["total_downloaded"]
                stats["valid"] += r["valid"]
                stats["invalid"] += r["invalid"]
                stats["repos_updated"] += 1
            except Exception as e:
                stats["errors"].append(f"{repo[chr(110)+chr(97)+chr(109)+chr(101)]}: {e}")
        if not stats["errors"]:
            _STATE_FILE.write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")
        return stats

    def update_repo(self, repo_config):
        stats = {"total_downloaded": 0, "valid": 0, "invalid": 0}
        resp = requests.get(repo_config["url"], timeout=60)
        resp.raise_for_status()
        dest_dir = COMMUNITY_RULES_DIR / repo_config["name"]
        dest_dir.mkdir(parents=True, exist_ok=True)
        subdir = repo_config.get("subdir", "")
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            for member in zf.namelist():
                if not any(member.lower().endswith(ext) for ext in RULE_EXTENSIONS):
                    continue
                if subdir and not member.startswith(subdir):
                    continue
                stats["total_downloaded"] += 1
                fname = Path(member).name
                try:
                    content = zf.read(member).decode("utf-8", errors="replace")
                    yara.compile(source=content)
                    (dest_dir / fname).write_text(content, encoding="utf-8")
                    stats["valid"] += 1
                except Exception:
                    stats["invalid"] += 1
        return stats

    def get_last_update(self):
        if not _STATE_FILE.exists():
            return None
        try:
            return datetime.fromisoformat(_STATE_FILE.read_text(encoding="utf-8").strip())
        except Exception:
            return None

    def needs_update(self, max_age_hours=24):
        last = self.get_last_update()
        if last is None:
            return True
        return (datetime.now(timezone.utc) - last).total_seconds() > max_age_hours * 3600
