"""BenguelaShield — Programa principal com fluxo completo integrado.

Scan → Deteccao → Quarentena → Registo → Notificacao

Executa: python main.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from modules.antivirus.config import AntiVirusConfig
from modules.antivirus.database import DatabaseManager
from modules.antivirus.quarantine import QuarantineManager, QuarantineError
from modules.antivirus.scanner import ClamAVScanner, ScanResult
from modules.antivirus.signatures import SignatureManager

SEPARATOR = "=" * 70
SUBSEP = "-" * 50

QUICK_SCAN_PATHS = [
    os.environ.get("TEMP", ""),
    os.path.join(os.environ.get("USERPROFILE", ""), "Downloads"),
    os.path.join(
        os.environ.get("APPDATA", ""),
        "Microsoft", "Windows", "Start Menu", "Programs", "Startup",
    ),
]


# ── Notificacoes ──────────────────────────────────────────────

def notificar(msg: str, tipo: str = "info") -> None:
    """Mostra uma notificacao no terminal."""
    icones = {"info": "[i]", "ok": "[+]", "alerta": "[/!\\]", "erro": "[!!]"}
    icone = icones.get(tipo, "[i]")
    print(f"    {icone} {msg}")


# ── Verificacao ───────────────────────────────────────────────

def banner() -> None:
    print(f"""
{SEPARATOR}
  BENGUELASHIELD — Antivirus Open Source
  Municipio de Benguela, Angola
  Motor: ClamAV 1.5.2 (Cisco Talos)
{SEPARATOR}""")


def verificar_clamav(config: AntiVirusConfig) -> bool:
    """Verifica se os binarios do ClamAV existem."""
    print(f"\n{SUBSEP}")
    print("VERIFICAR CLAMAV")
    print(SUBSEP)

    clamscan = config.clamscan_binary
    freshclam = config.freshclam_binary
    clamd = config.engine_dir / "clamd.exe"

    ok = True
    for nome, caminho in [
        ("clamscan", clamscan),
        ("freshclam", freshclam),
        ("clamd", clamd),
    ]:
        if caminho.exists():
            notificar(f"{nome}: {caminho}", "ok")
        else:
            notificar(f"{nome}: NAO ENCONTRADO — {caminho}", "erro")
            ok = False

    if ok:
        try:
            proc = subprocess.run(
                [str(clamscan), "--version"],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace",
            )
            notificar(f"Versao: {proc.stdout.strip()}", "ok")
        except Exception as e:
            notificar(f"Erro ao obter versao: {e}", "erro")
            ok = False

    return ok


def actualizar_assinaturas(config: AntiVirusConfig) -> None:
    """Actualiza as assinaturas do ClamAV via freshclam."""
    print(f"\n{SUBSEP}")
    print("ACTUALIZAR ASSINATURAS")
    print(SUBSEP)

    sig = SignatureManager(config)
    versao = sig.check_version()
    if versao:
        notificar(f"Versao actual: {versao}", "info")
    else:
        notificar("Sem assinaturas locais", "info")

    notificar("A executar freshclam...", "info")
    try:
        resultado = sig.update()
        if resultado.success:
            notificar(resultado.message, "ok")
            if resultado.signatures_added:
                notificar(f"Assinaturas adicionadas: {resultado.signatures_added}", "ok")
        else:
            notificar(resultado.message, "erro")
    except Exception as e:
        notificar(f"Erro: {e}", "erro")


# ── Scan + Quarentena integrados ──────────────────────────────

def _parse_clamscan_output(stdout: str) -> tuple[list[ScanResult], int]:
    """Analisa a saida do clamscan e devolve resultados + num ficheiros."""
    resultados: list[ScanResult] = []
    ficheiros = 0

    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("---"):
            continue

        if "Scanned files:" in line:
            try:
                ficheiros = int(line.split(":")[1].strip())
            except (ValueError, IndexError):
                pass
            continue

        if ": " in line:
            parts = line.split(": ", 1)
            if len(parts) == 2:
                filepath, result = parts
                if result.endswith(" FOUND"):
                    threat = result.replace(" FOUND", "")
                    resultados.append(ScanResult(
                        filepath=filepath,
                        status="FOUND",
                        threat_name=threat,
                    ))
                elif result == "OK":
                    pass
                else:
                    resultados.append(ScanResult(
                        filepath=filepath,
                        status="ERROR",
                        error_message=result,
                    ))

    return resultados, ficheiros


def quarantinar_ameacas(
    config: AntiVirusConfig,
    db: DatabaseManager,
    resultados: list[ScanResult],
) -> int:
    """Quarentena automaticamente todas as ameacas encontradas.

    Devolve o numero de ficheiros quarantinados com sucesso.
    """
    ameacas = [r for r in resultados if r.status == "FOUND"]
    if not ameacas:
        return 0

    qm = QuarantineManager(config, db)
    quarantinados = 0

    print(f"\n  A quarantinar {len(ameacas)} ameaca(s)...")
    for r in ameacas:
        nome = Path(r.filepath).name
        try:
            qid = qm.quarantine_file(r.filepath, r.threat_name or "UNKNOWN")
            db.log_threat(
                filepath=r.filepath,
                threat_name=r.threat_name,
                action="quarantined",
                status="FOUND",
            )
            notificar(f"QUARENTENA: {nome} -> {r.threat_name} [ID: {qid[:8]}...]", "alerta")
            quarantinados += 1
        except QuarantineError as e:
            db.log_threat(
                filepath=r.filepath,
                threat_name=r.threat_name,
                action="failed",
                status="FOUND",
            )
            notificar(f"FALHOU: {nome} — {e}", "erro")
        except Exception as e:
            notificar(f"ERRO inesperado: {nome} — {e}", "erro")

    return quarantinados


def executar_scan(
    config: AntiVirusConfig,
    db: DatabaseManager,
    caminho: str,
    nome_scan: str,
) -> list[ScanResult]:
    """Executa scan real + quarentena automatica + registo na BD.

    Fluxo completo: clamscan → parse → quarantinar → log → notificar.
    """
    if not os.path.exists(caminho):
        notificar(f"Pasta nao encontrada: {caminho}", "erro")
        return []

    print(f"\n  A analisar: {caminho}")

    cmd = [
        str(config.clamscan_binary),
        "-r",
        "--force-to-disk",
        "--no-summary",
        caminho,
    ]

    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            encoding="utf-8",
            errors="replace",
        )
        elapsed = time.monotonic() - start

        resultados, ficheiros = _parse_clamscan_output(proc.stdout)
        ameacas = [r for r in resultados if r.status == "FOUND"]

        # Contar erros de leitura no stderr (ficheiros em uso, sem permissao)
        erros_leitura = 0
        for line in proc.stderr.splitlines():
            if "Can't open" in line or "Permission denied" in line or "ERROR" in line:
                erros_leitura += 1

        # Registar scan na BD
        db.log_scan(nome_scan, ficheiros, len(ameacas), elapsed)

        # Mostrar resumo do scan
        partes = []
        if ficheiros > 0:
            partes.append(f"{ficheiros} ficheiros")
        if erros_leitura > 0:
            partes.append(f"{erros_leitura} inacessiveis")
        partes.append(f"{elapsed:.1f}s")
        notificar(f"Scan concluido: {', '.join(partes)}", "ok")

        if ameacas:
            notificar(f"AMEACAS DETETADAS: {len(ameacas)}", "alerta")
            quarantinar_ameacas(config, db, resultados)
        else:
            notificar("Nenhuma ameaca encontrada", "ok")

        return resultados

    except subprocess.TimeoutExpired:
        notificar("Scan excedeu timeout de 600s", "erro")
        return []
    except Exception as e:
        notificar(f"Erro no scan: {e}", "erro")
        return []


# ── Scans especificos ─────────────────────────────────────────

def scan_rapido(config: AntiVirusConfig, db: DatabaseManager) -> None:
    """Scan rapido das pastas criticas do Windows."""
    print(f"\n{SUBSEP}")
    print("SCAN RAPIDO — Pastas criticas")
    print(SUBSEP)

    todos: list[ScanResult] = []
    for path in QUICK_SCAN_PATHS:
        if path and os.path.exists(path):
            resultados = executar_scan(config, db, path, "quick")
            todos.extend(resultados)

    ameacas = [r for r in todos if r.status == "FOUND"]
    print(f"\n  {'=' * 50}")
    print(f"  SCAN RAPIDO CONCLUIDO")
    print(f"  Ameacas encontradas: {len(ameacas)}")
    if ameacas:
        print(f"  Ficheiros quarantinados automaticamente")
    print(f"  {'=' * 50}")


def scan_personalizado(config: AntiVirusConfig, db: DatabaseManager) -> None:
    """Pede ao utilizador um caminho e faz scan."""
    try:
        caminho = input("\n  Caminho a analisar: ").strip().strip('"')
    except (EOFError, KeyboardInterrupt):
        return

    if not caminho:
        notificar("Caminho vazio.", "erro")
        return

    executar_scan(config, db, caminho, "custom")


def scan_completo(config: AntiVirusConfig, db: DatabaseManager) -> None:
    """Scan completo do disco C:"""
    print(f"\n{SUBSEP}")
    print("SCAN COMPLETO — Disco C:\\")
    print(SUBSEP)
    notificar("AVISO: Scan completo pode demorar varios minutos...", "info")

    executar_scan(config, db, "C:\\", "full")


# ── Quarentena ────────────────────────────────────────────────

def listar_quarentena(config: AntiVirusConfig, db: DatabaseManager) -> None:
    """Lista todos os ficheiros em quarentena."""
    print(f"\n{SUBSEP}")
    print("QUARENTENA")
    print(SUBSEP)

    qm = QuarantineManager(config, db)
    entradas = qm.list_files()

    if not entradas:
        notificar("Quarentena vazia", "info")
        return

    print(f"\n  {'IND':<4s} {'FICHEIRO':<25s} {'AMEACA':<30s} {'DATA'}")
    print(f"  {'---':<4s} {'--------':<25s} {'------':<30s} {'----'}")
    for i, e in enumerate(entradas, 1):
        data = e.date_quarantined.strftime("%d/%m/%Y %H:%M")
        print(f"  {i:<4d} {e.filename:<25s} {e.threat_name:<30s} {data}")

    print(f"\n  Total: {len(entradas)} ficheiro(s)")

    # Opcao de restaurar ou eliminar
    try:
        accao = input("\n  (R)estaurar / (E)liminar / (Enter) Voltar: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return

    if accao in ("r", "e"):
        try:
            idx = int(input("  Numero do ficheiro: ").strip()) - 1
        except (ValueError, IndexError):
            notificar("Indice invalido", "erro")
            return

        if 0 <= idx < len(entradas):
            eid = entradas[idx].id
            if accao == "r":
                try:
                    caminho = qm.restore_file(eid)
                    notificar(f"Restaurado para: {caminho}", "ok")
                except QuarantineError as e:
                    notificar(f"Erro ao restaurar: {e}", "erro")
            elif accao == "e":
                try:
                    qm.delete_file(eid)
                    notificar(f"Eliminado permanentemente", "ok")
                except QuarantineError as e:
                    notificar(f"Erro ao eliminar: {e}", "erro")


# ── Estatisticas ──────────────────────────────────────────────

def mostrar_estatisticas(db: DatabaseManager) -> None:
    """Mostra estatisticas da base de dados."""
    print(f"\n{SUBSEP}")
    print("ESTATISTICAS")
    print(SUBSEP)

    stats = db.get_stats()
    print(f"  Ameacas total:        {stats['total_threats']}")
    print(f"  Quarentenados:        {stats['quarantined']}")
    print(f"  Eliminados:           {stats['deleted']}")
    print(f"  Scans realizados:     {stats['total_scans']}")
    print(f"  Ficheiros analisados: {stats['total_files_scanned']:,}")

    ameacas = db.get_threats(limit=10)
    if ameacas:
        print(f"\n  ULTIMAS AMEACAS:")
        for a in ameacas:
            nome = Path(a["filepath"]).name
            accao = a["action"] or "-"
            print(f"    {a['timestamp'][:19]} | {nome:<25s} | {a['threat_name'] or '-':<25s} | {accao}")


# ── Menu ──────────────────────────────────────────────────────

def menu() -> str:
    """Mostra menu e devolve opcao do utilizador."""
    print(f"""
{SUBSEP}
MENU PRINCIPAL
{SUBSEP}
  1. Scan rapido (Temp, Downloads, Startup)
  2. Scan personalizado (escolher pasta)
  3. Scan completo (disco C:\\ — demorado)
  4. Actualizar assinaturas
  5. Ver quarentena
  6. Ver estatisticas
  7. Sair
{SUBSEP}""")

    try:
        opcao = input("  Escolha (1-7): ").strip()
    except (EOFError, KeyboardInterrupt):
        opcao = "7"
    return opcao


# ── Programa principal ────────────────────────────────────────

def main() -> None:
    banner()

    config = AntiVirusConfig()
    db = DatabaseManager(config.db_path)

    notificar(f"Motor: {config.clamscan_binary}", "info")
    notificar(f"Base dados: {config.db_path}", "info")
    notificar(f"Quarentena: {config.quarantine_dir}", "info")

    if not verificar_clamav(config):
        notificar("Binarios do ClamAV nao encontrados.", "erro")
        notificar(f"Coloque os executaveis em: {config.engine_dir}", "erro")
        db.close()
        sys.exit(1)

    while True:
        opcao = menu()

        if opcao == "1":
            scan_rapido(config, db)
        elif opcao == "2":
            scan_personalizado(config, db)
        elif opcao == "3":
            scan_completo(config, db)
        elif opcao == "4":
            actualizar_assinaturas(config)
        elif opcao == "5":
            listar_quarentena(config, db)
        elif opcao == "6":
            mostrar_estatisticas(db)
        elif opcao == "7":
            notificar("A encerrar BenguelaShield...", "info")
            break
        else:
            notificar("Opcao invalida.", "erro")

    db.close()
    print("  Ate logo!\n")


if __name__ == "__main__":
    main()
