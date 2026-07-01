"""Editor de configurações do sistema — repara alterações de vírus."""
from __future__ import annotations
import logging

from modules.tools.registry_repair import RegistryRepairer
from modules.tools.win_force import WinForce

logger = logging.getLogger("BenguelaShield.Tools.SystemEditor")


class SystemEditor:
    """Repara configurações alteradas por vírus."""

    def __init__(self):
        self._registry = RegistryRepairer()
        self._win_force = WinForce()

    def full_repair(self) -> dict:
        registry_result = self._registry.scan_and_repair_all(auto_repair=True)
        blocked_tools = self._win_force.open_all_blocked()
        startup_result = self._registry.remove_malicious_startup()

        return {
            "registry": registry_result,
            "tools_unblocked": len(blocked_tools),
            "tools_details": blocked_tools,
            "startup_removed": len(startup_result),
            "startup_details": startup_result,
        }

    def repair_registry(self) -> dict:
        return self._registry.scan_and_repair_all(auto_repair=True)

    def unblock_tools(self) -> list[dict]:
        return self._win_force.open_all_blocked()

    def remove_malicious_startup(self) -> list[dict]:
        return self._registry.remove_malicious_startup()

    def get_system_status(self) -> dict:
        registry = self._registry.scan()
        tools = self._win_force.check_all_blocked()
        blocked_count = sum(1 for v in tools.values() if v["blocked"])
        return {
            "registry_issues": registry["issues_found"],
            "tools_blocked": blocked_count,
            "tools_total": len(tools),
            "system_clean": registry["clean"] and blocked_count == 0,
        }
