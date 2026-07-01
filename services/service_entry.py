"""Entry point para o serviço Windows — adiciona o projecto ao sys.path."""

import os
import sys

_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from services.benguelashield_service import BenguelaShieldService, _configurar_logging

if __name__ == "__main__":
    _configurar_logging()
    if len(sys.argv) == 1:
        import servicemanager
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(BenguelaShieldService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        import win32serviceutil
        win32serviceutil.HandleCommandLine(BenguelaShieldService)
