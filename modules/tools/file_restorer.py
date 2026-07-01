"""Restaurador de ficheiros ocultos por malware."""
from __future__ import annotations
import ctypes
import logging
import os
from pathlib import Path

logger = logging.getLogger("BenguelaShield.Tools.FileRestorer")

FILE_ATTRIBUTE_HIDDEN = 0x02
FILE_ATTRIBUTE_SYSTEM = 0x04
FILE_ATTRIBUTE_NORMAL = 0x80


class FileRestorer:
    """Restaura ficheiros e pastas escondidos por malware."""

    DOCUMENT_NAMES = {"fotos", "documents", "documentos", "faturas", "relatorio", "report", "ficheiros", "dados"}

    def scan_directory(self, directory: str) -> dict:
        result = {"directory": directory, "hidden_items": [], "suspicious_shortcuts": [], "malware_exes": [], "total_hidden": 0, "total_suspicious": 0}
        if not os.path.isdir(directory):
            return result

        for item in os.listdir(directory):
            item_path = os.path.join(directory, item)
            try:
                attrs = ctypes.windll.kernel32.GetFileAttributesW(str(item_path))
                is_hidden = bool(attrs & FILE_ATTRIBUTE_HIDDEN)
                is_system = bool(attrs & FILE_ATTRIBUTE_SYSTEM)

                if is_hidden or is_system:
                    result["hidden_items"].append({"name": item, "path": item_path, "hidden": is_hidden, "system": is_system})
                    result["total_hidden"] += 1

                if item.lower().endswith(".lnk"):
                    result["suspicious_shortcuts"].append({"name": item, "path": item_path})
                    result["total_suspicious"] += 1

                if item.lower().endswith(".exe"):
                    name_stem = Path(item).stem.lower()
                    if name_stem in self.DOCUMENT_NAMES or name_stem[0].isupper():
                        result["malware_exes"].append({"name": item, "path": item_path})

            except Exception:
                pass

        return result

    def restore_hidden(self, directory: str) -> dict:
        result = {"restored": [], "removed": [], "errors": []}
        scan = self.scan_directory(directory)

        for item in scan["hidden_items"]:
            try:
                self._remove_attributes(item["path"])
                result["restored"].append(item["name"])
            except Exception as e:
                result["errors"].append(f"Erro ao restaurar {item['name']}: {e}")

        return result

    def restore_all_removable(self) -> list[dict]:
        results = []
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            try:
                drive_type = ctypes.windll.kernel32.GetDriveTypeW(f"{letter}:\\")
                if drive_type == 2:
                    results.append(self.restore_hidden(f"{letter}:\\"))
            except Exception:
                pass
        return results

    @staticmethod
    def _remove_attributes(filepath: str) -> bool:
        FILE_ATTRIBUTE_NORMAL = 0x80
        return bool(ctypes.windll.kernel32.SetFileAttributesW(str(filepath), FILE_ATTRIBUTE_NORMAL))

    @staticmethod
    def _is_disguised_exe(filepath: str) -> bool:
        name = Path(filepath).name.lower()
        if not name.endswith(".exe"):
            return False
        doc_names = {"fotos", "documents", "documentos", "faturas", "relatorio", "report", "ficheiros", "dados", "photos", "images"}
        stem = Path(filepath).stem.lower()
        return stem in doc_names or "." in stem.replace(".", "", 1)
