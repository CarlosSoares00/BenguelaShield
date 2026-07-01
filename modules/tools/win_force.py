"""Win-Force — abre ferramentas do Windows bloqueadas por malware."""
from __future__ import annotations
import logging
import subprocess

from modules.tools.config import WINDOWS_TOOLS
from modules.tools.registry_repair import RegistryRepairer

logger = logging.getLogger("BenguelaShield.Tools.WinForce")

BLOCKED_REGISTRY = {
    "task_manager": (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr"),
    "registry_editor": (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools"),
    "cmd": (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "DisableCMD"),
}


class WinForce:
    """Abre ferramentas do Windows bloqueadas por malware."""

    def __init__(self):
        self._repairer = RegistryRepairer()

    def open_tool(self, tool_key: str) -> dict:
        tool = WINDOWS_TOOLS.get(tool_key)
        if not tool:
            return {"tool": tool_key, "was_blocked": False, "unblocked": False, "opened": False, "error": "Ferramenta desconhecida"}

        result = {"tool": tool["name"], "was_blocked": False, "unblocked": False, "opened": False, "error": None}

        if tool_key in BLOCKED_REGISTRY:
            reg_path, reg_name = BLOCKED_REGISTRY[tool_key]
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_READ)
                try:
                    value, _ = winreg.QueryValueEx(key, reg_name)
                    if value == 1:
                        result["was_blocked"] = True
                        winreg.SetValueEx(key, reg_name, 0, winreg.REG_DWORD, 0)
                        result["unblocked"] = True
                except FileNotFoundError:
                    pass
                winreg.CloseKey(key)
            except FileNotFoundError:
                pass
            except Exception as e:
                logger.warning("Erro ao verificar %s: %s", tool_key, e)

        try:
            subprocess.Popen(tool["command"], shell=True)
            result["opened"] = True
        except Exception as e:
            result["error"] = str(e)

        return result

    def open_all_blocked(self) -> list[dict]:
        return [self.open_tool(k) for k in WINDOWS_TOOLS if self._is_tool_blocked(k)]

    def check_all_blocked(self) -> dict:
        return {k: {"blocked": self._is_tool_blocked(k), "description": v["name"]} for k, v in WINDOWS_TOOLS.items()}

    def _is_tool_blocked(self, tool_key: str) -> bool:
        if tool_key not in BLOCKED_REGISTRY:
            return False
        try:
            import winreg
            reg_path, reg_name = BLOCKED_REGISTRY[tool_key]
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_READ)
            value, _ = winreg.QueryValueEx(key, reg_name)
            winreg.CloseKey(key)
            return value == 1
        except (FileNotFoundError, OSError):
            return False
