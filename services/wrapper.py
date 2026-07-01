"""Wrapper para pythonservice.exe — resolve path antes de qualquer import."""

import os
import sys

# Resolver paths ANTES de qualquer import
_dir = os.path.dirname(os.path.abspath(__file__))
_root = os.path.dirname(_dir)
if _root not in sys.path:
    sys.path.insert(0, _root)
if _dir not in sys.path:
    sys.path.insert(0, _dir)

os.chdir(_root)

from benguelashield_service import BenguelaShieldService, _configurar_logging
import win32serviceutil

if __name__ == "__main__":
    _configurar_logging()
    win32serviceutil.HandleCommandLine(BenguelaShieldService)
