"""Demo interactiva do BenguelaShield — mostra o módulo anti-vírus a funcionar.

Executa: python demo.py
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
from pathlib import Path

from modules.antivirus.config import AntiVirusConfig
from modules.antivirus.database import DatabaseManager
from modules.antivirus.quarantine import QuarantineManager
from modules.antivirus.scanner import ScanResult

SEPARATOR = "=" * 60
SUBSEP = "-" * 40


def criar_ficheiros_teste(diretorio: Path) -> list[Path]:
    """Cria ficheiros de exemplo para o demo."""
    ficheiros = {}

    ficheiros["limpo.txt"] = diretorio / "limpo.txt"
    ficheiros["limpo.txt"].write_text(
        "Este e um ficheiro de texto normal.\nNao contem malware.\n",
        encoding="utf-8",
    )

    ficheiros["documento.pdf"] = diretorio / "documento.pdf"
    ficheiros["documento.pdf"].write_bytes(b"%PDF-1.4 fake pdf content")

    ficheiros["programa.exe"] = diretorio / "programa.exe"
    ficheiros["programa.exe"].write_bytes(b"MZ" + b"\x00" * 500)

    ficheiros["script.bat"] = diretorio / "script.bat"
    ficheiros["script.bat"].write_text(
        '@echo off\necho "Ola mundo"\npause\n',
        encoding="utf-8",
    )

    ficheiros["dados.json"] = diretorio / "dados.json"
    ficheiros["dados.json"].write_text(
        '{"nome": "BenguelaShield", "versao": "1.0"}',
        encoding="utf-8",
    )

    return list(ficheiros.values())


def mostrar_resultado(r: ScanResult, indice: int) -> None:
    """Mostra um resultado de scan formatado."""
    if r.status == "FOUND":
        icon = "[!]"
        cor = "VERMELHO"
    elif r.status == "OK":
        icon = "[+]"
        cor = "VERDE"
    else:
        icon = "[?]"
        cor = "AMARELO"

    nome = Path(r.filepath).name
    ameaca = r.threat_name or "-"
    tempo = f"{r.scan_time * 1000:.1f}ms"

    print(f"  {icon} {indice:2d}. {nome:<20s} | {cor:<8s} | {ameaca:<25s} | {tempo}")


def demo_database(db: DatabaseManager) -> None:
    """Demonstra a base de dados."""
    print(f"\n{SUBSEP}")
    print("BASE DE DADOS — Registar ameaças simuladas")
    print(SUBSEP)

    ameacas = [
        ("C:\\Users\\user\\Downloads\\virus.exe", "Trojan.GenericKD.48741", "quarantined"),
        ("C:\\Users\\user\\Desktop\\malware.doc", "Macro.Trojan.Emotet", "quarantined"),
        ("C:\\Temp\\suspicious.dll", "Riskware.Tool.CK", "deleted"),
    ]

    for caminho, ameaca, accao in ameacas:
        tid = db.log_threat(caminho, ameaca, accao, "FOUND")
        print(f"  [+] Registo #{tid}: {Path(caminho).name} -> {ameaca} ({accao})")

    db.log_scan("quick", 150, 3, 12.5)
    db.log_scan("full", 45230, 0, 1847.3)
    print(f"  [+] 2 scans registados")

    stats = db.get_stats()
    print(f"\n  ESTATISTICAS:")
    print(f"    Ameacas totais:      {stats['total_threats']}")
    print(f"    Quarentenados:       {stats['quarantined']}")
    print(f"    Eliminados:          {stats['deleted']}")
    print(f"    Scans realizados:    {stats['total_scans']}")
    print(f"    Ficheiros analisados: {stats['total_files_scanned']:,}")


def demo_quarentena(config: AntiVirusConfig, db: DatabaseManager) -> None:
    """Demonstra a quarentena com encriptação real."""
    print(f"\n{SUBSEP}")
    print("QUARENTENA — Encriptar, restaurar, eliminar")
    print(SUBSEP)

    qm = QuarantineManager(config, db)

    diretorio_teste = Path(tempfile.mkdtemp(prefix="benguela_demo_"))
    ficheiros = criar_ficheiros_teste(diretorio_teste)

    print(f"\n  Ficheiros de teste criados em: {diretorio_teste}")
    for f in ficheiros:
        print(f"    - {f.name} ({f.stat().st_size} bytes)")

    ficheiro_alvo = ficheiros[3]
    print(f"\n  A quarantinar '{ficheiro_alvo.name}' (simulando deteccao de virus)...")
    qid = qm.quarantine_file(str(ficheiro_alvo), "Trojan.GenericKD.48741")
    print(f"  [+] Quarentena criada: {qid}")
    print(f"  [+] Original eliminado: {not ficheiros[3].exists()}")

    encrypted = config.quarantine_dir / f"{qid}.quarantine"
    if encrypted.exists():
        print(f"  [+] Ficheiro encriptado: {encrypted}")
        print(f"  [+] Tamanho encriptado: {encrypted.stat().st_size} bytes")
        with open(encrypted, "rb") as f:
            header = f.read(32)
        print(f"  [+] Primeiros 32 bytes (hex): {header.hex()}")

    print(f"\n  Entradas em quarentena:")
    for entry in qm.list_files():
        print(f"    - {entry.filename} ({entry.threat_name}) — {entry.date_quarantined.strftime('%d/%m/%Y %H:%M')}")

    print(f"\n  A restaurar '{ficheiro_alvo.name}'...")
    restored = qm.restore_file(qid)
    print(f"  [+] Restaurado para: {restored}")
    conteudo = Path(restored).read_text(encoding="utf-8")
    print(f"  [+] Conteudo: {conteudo.strip()[:50]}...")

    shutil.rmtree(diretorio_teste, ignore_errors=True)


def demo_scanner_mock() -> None:
    """Demonstra o scanner com resposta simulada (sem clamd real)."""
    print(f"\n{SUBSEP}")
    print("SCANNER — Simulacao de scan (sem clamd)")
    print(SUBSEP)

    diretorio_teste = Path(tempfile.mkdtemp(prefix="benguela_scan_"))
    ficheiros = criar_ficheiros_teste(diretorio_teste)

    resultados = [
        ScanResult(filepath=str(ficheiros[0]), status="OK", scan_time=0.003),
        ScanResult(filepath=str(ficheiros[1]), status="OK", scan_time=0.012),
        ScanResult(filepath=str(ficheiros[2]), status="FOUND", threat_name="Trojan.GenericKD.48741", scan_time=0.045),
        ScanResult(filepath=str(ficheiros[3]), status="FOUND", threat_name="Script.Malware.BAT", scan_time=0.008),
        ScanResult(filepath=str(ficheiros[4]), status="OK", scan_time=0.002),
    ]

    print(f"\n  Ficheiros a analisar: {len(resultados)}")
    print(f"  {'IND':<4s} {'FICHEIRO':<20s} {'ESTADO':<8s} {'AMEACA':<25s} {'TEMPO'}")
    print(f"  {'---':<4s} {'--------':<20s} {'------':<8s} {'------':<25s} {'-----'}")

    for i, r in enumerate(resultados, 1):
        mostrar_resultado(r, i)

    encontrados = sum(1 for r in resultados if r.status == "FOUND")
    limpos = sum(1 for r in resultados if r.status == "OK")
    tempo_total = sum(r.scan_time for r in resultados)

    print(f"\n  RESUMO: {limpos} limpos, {encontrados} ameaacas, {tempo_total * 1000:.1f}ms total")

    shutil.rmtree(diretorio_teste, ignore_errors=True)


def demo_config() -> None:
    """Mostra a configuração actual."""
    print(f"\n{SUBSEP}")
    print("CONFIGURACAO")
    print(SUBSEP)

    config = AntiVirusConfig()
    print(f"  clamd_host:       {config.clamd_host}")
    print(f"  clamd_port:       {config.clamd_port}")
    print(f"  scan_timeout:     {config.scan_timeout}s")
    print(f"  engine_dir:       {config.engine_dir}")
    print(f"  quarantine_dir:   {config.quarantine_dir}")
    print(f"  db_path:          {config.db_path}")
    print(f"  quick_scan_paths: {len(config.quick_scan_paths)} pastas")
    for p in config.quick_scan_paths:
        print(f"    - {p}")
    print(f"  quarantine_key:   {len(config.quarantine_key)} bytes (AES-256)")


def main() -> None:
    print(f"\n{SEPARATOR}")
    print("  BENGUELASHIELD — Demo do Modulo AntiVirus")
    print("  Municipio de Benguela, Angola")
    print(SEPARATOR)

    config = AntiVirusConfig()
    db = DatabaseManager(config.db_path)

    demo_config()
    demo_database(db)
    demo_quarentena(config, db)
    demo_scanner_mock()

    print(f"\n{SEPARATOR}")
    print("  Demo concluida com sucesso!")
    print(f"  Base de dados: {config.db_path}")
    print(f"  Quarentena:    {config.quarantine_dir}")
    print(SEPARATOR)

    db.close()


if __name__ == "__main__":
    main()
