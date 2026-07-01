"""Script de instalação do serviço BenguelaShield.

Executa: python install_service.py
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


def instalar() -> None:
    print("=" * 50)
    print("  BenguelaShield — Instalação do Serviço")
    print("=" * 50)

    if not verificar_admin():
        print("\n[ERRO] Este script requer privilégios de Administrador.")
        print("  Clique com o botão direito → 'Executar como administrador'")
        sys.exit(1)

    print("\n[1/3] A instalar serviço BenguelaShield...")
    script = os.path.join(os.path.dirname(__file__), "benguelashield_service.py")

    exit_code = os.system(f'python "{script}" install')
    if exit_code != 0:
        print("[ERRO] Falha ao instalar serviço")
        sys.exit(1)
    print("  [OK] Serviço instalado")

    print("\n[2/3] A iniciar serviço...")
    exit_code = os.system(f'python "{script}" start')
    if exit_code != 0:
        print("[AVISO] Serviço instalado mas não iniciou automaticamente")
    else:
        print("  [OK] Serviço iniciado")

    print("\n[3/3] A configurar arranque automático...")
    os.system(f'sc config BenguelaShield start= auto')
    print("  [OK] Arranque automático configurado")

    print("\n" + "=" * 50)
    print("  Instalação concluída!")
    print("  Serviço: BenguelaShield")
    print("  Estado: Activo")
    print("  Arranque: Automático")
    print("=" * 50)


if __name__ == "__main__":
    instalar()
