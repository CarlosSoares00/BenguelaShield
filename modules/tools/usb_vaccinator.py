"""Vacinador USB do BenguelaShield — protecção avançada de USB."""
from __future__ import annotations
import ctypes
import logging
import os
from pathlib import Path

from modules.tools.config import USB_MALWARE_FILES, AUTORUN_MALICIOUS_KEYWORDS

logger = logging.getLogger("BenguelaShield.Tools.USBVaccinator")

DRIVE_REMOVABLE = 2
FILE_ATTRIBUTE_READONLY = 0x01
FILE_ATTRIBUTE_HIDDEN = 0x02
FILE_ATTRIBUTE_SYSTEM = 0x04
FILE_ATTRIBUTE_NORMAL = 0x80


class USBVaccinator:
    """Vacinador e protector USB."""

    def vaccinate(self, drive_letter: str) -> dict:
        result = {"drive": drive_letter, "vaccinated": False, "actions": [], "errors": []}
        try:
            if not self._is_drive_removable(drive_letter):
                result["errors"].append("Drive não é removível")
                return result

            autorun_path = f"{drive_letter}:\\autorun.inf"

            if os.path.exists(autorun_path):
                check = self.check_autorun(drive_letter)
                if check["is_malicious"]:
                    result["actions"].append("Removido autorun.inf malicioso")
                    os.remove(autorun_path)
                elif check["exists"]:
                    result["actions"].append("Autorun.inf existente preservado")
                    result["vaccinated"] = True
                    return result

            with open(autorun_path, "w") as f:
                f.write("[autorun]\n")
                f.write("; BenguelaShield - Vacinado\n")
                f.write("; Este ficheiro impede que malware crie o seu próprio autorun.inf\n")

            self._set_file_protected(autorun_path)
            result["vaccinated"] = True
            result["actions"].append("Autorun.inf de vacinação criado e protegido")
            logger.info("USB vacinado: %s", drive_letter)

        except Exception as e:
            result["errors"].append(str(e))
            logger.error("Erro ao vacinar USB %s: %s", drive_letter, e)

        return result

    def anti_exe_block(self, drive_letter: str) -> dict:
        result = {"drive": drive_letter, "files_found": [], "files_blocked": 0, "files_cleaned": 0}
        root = f"{drive_letter}:\\"
        if not os.path.isdir(root):
            return result

        for item in os.listdir(root):
            ext = Path(item).suffix.lower()
            if ext in (".exe", ".vbs", ".bat", ".scr", ".cmd", ".pif"):
                filepath = os.path.join(root, item)
                result["files_found"].append({"name": item, "path": filepath, "extension": ext})
                result["files_blocked"] += 1
                logger.warning("Executável suspeito na raiz USB: %s", filepath)

        return result

    def clean_usb(self, drive_letter: str) -> dict:
        result = {"drive": drive_letter, "malware_removed": [], "files_restored": [], "errors": []}
        root = f"{drive_letter}:\\"
        if not os.path.isdir(root):
            return result

        autorun_path = os.path.join(root, "autorun.inf")
        if os.path.exists(autorun_path):
            check = self.check_autorun(drive_letter)
            if check["is_malicious"]:
                os.remove(autorun_path)
                result["malware_removed"].append("autorun.inf")

        suspicious = ["RECYCLER", "System Volume Information"]
        for name in suspicious:
            path = os.path.join(root, name)
            if os.path.exists(path) and not os.listdir(path):
                try:
                    os.rmdir(path)
                    result["malware_removed"].append(name)
                except OSError:
                    pass

        for item in os.listdir(root):
            item_path = os.path.join(root, item)
            try:
                attrs = ctypes.windll.kernel32.GetFileAttributesW(str(item_path))
                if attrs & FILE_ATTRIBUTE_HIDDEN and attrs & FILE_ATTRIBUTE_SYSTEM:
                    ctypes.windll.kernel32.SetFileAttributesW(str(item_path), FILE_ATTRIBUTE_NORMAL)
                    result["files_restored"].append(item)
            except Exception:
                pass

        return result

    def check_autorun(self, drive_letter: str) -> dict:
        autorun_path = f"{drive_letter}:\\autorun.inf"
        result = {"exists": False, "is_malicious": False, "content": "", "suspicious_lines": [], "verdict": "INEXISTENTE"}

        if not os.path.exists(autorun_path):
            return result

        result["exists"] = True
        try:
            with open(autorun_path, "r", encoding="utf-8", errors="ignore") as f:
                result["content"] = f.read()
        except Exception:
            return result

        content_lower = result["content"].lower()
        for keyword in AUTORUN_MALICIOUS_KEYWORDS:
            if keyword in content_lower:
                result["suspicious_lines"].append(keyword)

        if "BenguelaShield" in result["content"]:
            result["verdict"] = "SEGURO"
            return result

        if result["suspicious_lines"]:
            result["is_malicious"] = True
            result["verdict"] = "MALICIOSO"
        else:
            result["verdict"] = "SEGURO"

        return result

    def vaccinate_all_removable(self) -> list[dict]:
        results = []
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if self._is_drive_removable(letter):
                results.append(self.vaccinate(letter))
        return results

    def auto_vaccinate_on_insert(self, drive_letter: str) -> dict:
        result = {"drive": drive_letter, "vaccination": None, "anti_exe": None, "clean": None}
        result["vaccination"] = self.vaccinate(drive_letter)
        result["anti_exe"] = self.anti_exe_block(drive_letter)
        result["clean"] = self.clean_usb(drive_letter)
        logger.info("Auto-vacinação USB: %s", drive_letter)
        return result

    @staticmethod
    def _is_drive_removable(drive_letter: str) -> bool:
        try:
            return ctypes.windll.kernel32.GetDriveTypeW(f"{drive_letter}:\\") == DRIVE_REMOVABLE
        except Exception:
            return False

    @staticmethod
    def _set_file_protected(filepath: str) -> bool:
        attrs = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
        return bool(ctypes.windll.kernel32.SetFileAttributesW(str(filepath), attrs))
