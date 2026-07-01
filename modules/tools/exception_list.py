"""Lista de exclusões do BenguelaShield."""
from __future__ import annotations
import json
import logging
from pathlib import Path

from modules.tools.config import EXCEPTIONS_FILE

logger = logging.getLogger("BenguelaShield.Tools.ExceptionList")


class ExceptionList:
    """Lista de exclusões — ficheiros, pastas, extensões, processos."""

    def __init__(self):
        self._exceptions = self._load()

    def _load(self) -> dict:
        if EXCEPTIONS_FILE.exists():
            try:
                return json.loads(EXCEPTIONS_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {"files": [], "folders": [], "extensions": [], "processes": []}

    def _save(self) -> None:
        EXCEPTIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
        EXCEPTIONS_FILE.write_text(json.dumps(self._exceptions, indent=2), encoding="utf-8")

    def add_file(self, filepath: str) -> bool:
        if filepath not in self._exceptions["files"]:
            self._exceptions["files"].append(filepath)
            self._save()
            return True
        return False

    def add_folder(self, folderpath: str) -> bool:
        if folderpath not in self._exceptions["folders"]:
            self._exceptions["folders"].append(folderpath)
            self._save()
            return True
        return False

    def add_extension(self, extension: str) -> bool:
        if not extension.startswith("."):
            extension = "." + extension
        if extension not in self._exceptions["extensions"]:
            self._exceptions["extensions"].append(extension)
            self._save()
            return True
        return False

    def add_process(self, process_name: str) -> bool:
        if process_name not in self._exceptions["processes"]:
            self._exceptions["processes"].append(process_name)
            self._save()
            return True
        return False

    def remove(self, item: str, item_type: str) -> bool:
        if item_type in self._exceptions and item in self._exceptions[item_type]:
            self._exceptions[item_type].remove(item)
            self._save()
            return True
        return False

    def is_excluded(self, filepath: str | None = None, extension: str | None = None, process_name: str | None = None) -> bool:
        if filepath:
            if filepath in self._exceptions["files"]:
                return True
            for folder in self._exceptions["folders"]:
                if filepath.startswith(folder):
                    return True
        if extension:
            if not extension.startswith("."):
                extension = "." + extension
            if extension in self._exceptions["extensions"]:
                return True
        if process_name:
            if process_name in self._exceptions["processes"]:
                return True
        return False

    def list_all(self) -> dict:
        return self._exceptions.copy()

    def clear(self) -> None:
        self._exceptions = {"files": [], "folders": [], "extensions": [], "processes": []}
        self._save()
