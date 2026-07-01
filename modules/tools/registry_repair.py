"""Reparador de Registry do BenguelaShield."""
from __future__ import annotations
import logging
import subprocess
import time
from pathlib import Path
from typing import Optional

from modules.tools.config import REPAIR_REGISTRY_KEYS

logger = logging.getLogger("BenguelaShield.Tools.RegistryRepair")

try:
    import winreg
except ImportError:
    winreg = None


class RegistryRepairer:
    """Reparador de Registry — detecta e repara alterações maliciosas."""

    def scan(self) -> dict:
        issues = []
        if winreg is None:
            return {"issues_found": 0, "issues": [], "clean": True}

        for key_id, key_info in REPAIR_REGISTRY_KEYS.items():
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_info["path"], 0, winreg.KEY_READ)
                try:
                    value, _ = winreg.QueryValueEx(key, key_info["name"])
                except FileNotFoundError:
                    value = key_info["safe_value"]
                winreg.CloseKey(key)

                if value != key_info["safe_value"]:
                    issues.append({
                        "key": key_id,
                        "description": key_info["description"],
                        "current_value": value,
                        "safe_value": key_info["safe_value"],
                        "path": key_info["path"],
                        "name": key_info["name"],
                        "needs_repair": True,
                    })
            except FileNotFoundError:
                pass
            except Exception as e:
                logger.warning("Erro ao verificar %s: %s", key_id, e)

        return {"issues_found": len(issues), "issues": issues, "clean": len(issues) == 0}

    def repair(self, issues: list[dict] | None = None) -> dict:
        result = {"repaired": [], "skipped": [], "errors": [], "backup_created": ""}

        if issues is None:
            scan_result = self.scan()
            issues = scan_result["issues"]

        if not issues:
            return result

        result["backup_created"] = self.backup_registry_keys()

        if winreg is None:
            result["errors"].append("winreg não disponível")
            return result

        for issue in issues:
            if not issue.get("needs_repair", True):
                result["skipped"].append(issue["key"])
                continue

            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, issue["path"], 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, issue["name"], 0, winreg.REG_DWORD, issue["safe_value"])
                winreg.CloseKey(key)
                result["repaired"].append(issue["key"])
                logger.info("Registry reparado: %s = %d", issue["name"], issue["safe_value"])
            except Exception as e:
                result["errors"].append(f"Erro ao reparar {issue['key']}: {e}")

        return result

    def scan_and_repair_all(self, auto_repair: bool = False) -> dict:
        scan_result = self.scan()
        if auto_repair and scan_result["issues_found"] > 0:
            repair_result = self.repair(scan_result["issues"])
            return {**scan_result, **repair_result}
        return scan_result

    def backup_registry_keys(self) -> str:
        backup_dir = Path(__file__).parent.parent.parent / "backups"
        backup_dir.mkdir(exist_ok=True)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        backup_file = backup_dir / f"backup_registry_{timestamp}.reg"

        try:
            with open(backup_file, "w") as f:
                f.write("Windows Registry Editor Version 5.00\n\n")
                for key_id, key_info in REPAIR_REGISTRY_KEYS.items():
                    f.write(f"[HKEY_CURRENT_USER\\{key_info['path']}]\n")
                    f.write(f'"{key_info["name"]}"=dword:0\n\n')
            return str(backup_file)
        except Exception as e:
            logger.error("Erro ao criar backup: %s", e)
            return ""

    def remove_malicious_startup(self) -> list[dict]:
        removed = []
        run_keys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ]

        if winreg is None:
            return removed

        for reg_path in run_keys:
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        if "Temp" in value or "Downloads" in value or "AppData" in value:
                            removed.append({"name": name, "path": value, "registry": reg_path})
                            winreg.DeleteValue(key, name)
                            logger.warning("Startup malicioso removido: %s = %s", name, value)
                        else:
                            i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except FileNotFoundError:
                pass
            except Exception as e:
                logger.warning("Erro ao verificar %s: %s", reg_path, e)

        return removed
