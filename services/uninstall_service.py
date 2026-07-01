"""Script de desinstalação do serviço BenguelaShield.

Executa: python uninstall_service.py
Requer: Executar como Administrador
"""

from __future__ import annotations

import os
import sys


def verificar_admin() -> bool:
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def desinstalar() -> None:
    print("=" * 50)
    print("  BenguelaShield — Desinstalação do Serviço")
    print("=" * 50)

    if not verificar_admin():
        print("\n[ERRO] Este script requer privilégios de Administrador.")
        print("  Clique com o botão direito → 'Executar como administrador'")
        sys.exit(1)

    print("\n[1/2] A parar serviço...")
    script = os.path.join(os.path.dirname(__file__), "benguelashield_service.py")
    os.system(f'python "{script}" stop')
    print("  [OK] Serviço parado")

    print("\n[2/2] A remover serviço...")
    exit_code = os.system(f'python "{script}" remove')
    if exit_code != 0:
        print("[ERRO] Falha ao remover serviço")
        sys.exit(1)
    print("  [OK] Serviço removido")

    print("\n" + "=" * 50)
    print("  Desinstalação concluída!")
    print("  BenguelaShield foi removido do sistema.")
    print("=" * 50)


if __name__ == "__main__":
    desinstalar()
