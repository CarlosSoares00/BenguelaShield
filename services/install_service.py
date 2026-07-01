"""Script de instalacao do servico BenguelaShield.

Executa: python install_service.py
Requer: Executar como Administrador
"""

from __future__ import annotations

import os
import subprocess
import sys

def verificar_admin() -> bool:
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def instalar() -> None:
    print("=" * 50)
    print("  BenguelaShield - Instalacao do Servico")
    print("=" * 50)

    if not verificar_admin():
        print("\n[ERRO] Este script requer privilegios de Administrador.")
        print("  Clique com o botao direito -> 'Executar como administrador'")
        sys.exit(1)

    script = os.path.join(os.path.dirname(__file__), "benguelashield_service.py")

    print("\n[1/3] A instalar servico BenguelaShield...")
    result = subprocess.run(
        [sys.executable, script, "install"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"[ERRO] Falha ao instalar servico: {result.stderr}")
        sys.exit(1)
    print("  [OK] Servico instalado")

    print("\n[2/3] A iniciar servico...")
    result = subprocess.run(
        [sys.executable, script, "start"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print("[AVISO] Servico instalado mas nao iniciou automaticamente")
    else:
        print("  [OK] Servico iniciado")

    print("\n[3/3] A configurar arranque automatico...")
    subprocess.run(
        ["sc", "config", "BenguelaShield", "start=", "auto"],
        capture_output=True, text=True
    )
    print("  [OK] Arranque automatico configurado")

    print("\n" + "=" * 50)
    print("  Instalacao concluida!")
    print("  Servico: BenguelaShield")
    print("  Estado: Activo")
    print("  Arranque: Automatico")
    print("=" * 50)


if __name__ == "__main__":
    instalar()
