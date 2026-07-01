"""Scan real — testa o ClamAV a funcionar com ficheiros reais."""

import subprocess
import time
import os
from pathlib import Path

from modules.antivirus.config import AntiVirusConfig
from modules.antivirus.database import DatabaseManager

SEP = "=" * 60

config = AntiVirusConfig()
db = DatabaseManager(config.db_path)

print(f"\n{SEP}")
print("  BENGUELASHIELD — Scan Real com ClamAV 1.5.2")
print(f"  Assinaturas: 3.6M virus conhecidos")
print(SEP)

# Scan do proprio directório BenguelaShield (rapido, poucos ficheiros)
pasta = str(Path(__file__).parent / "modules")
print(f"\n  A analisar: {pasta}")

cmd = [
    str(config.clamscan_binary),
    "-r", "--no-summary",
    pasta,
]

start = time.monotonic()
proc = subprocess.run(
    cmd, capture_output=True, text=True, timeout=120,
    encoding="utf-8", errors="replace",
)
elapsed = time.monotonic() - start

ameacas = 0
ficheiros_ok = 0
for line in proc.stdout.strip().splitlines():
    line = line.strip()
    if ": FOUND" in line:
        ameacas += 1
        print(f"  [!] AMEACA: {line}")
    elif ": OK" in line:
        ficheiros_ok += 1

# Parse do resumo
ficheiros_total = ficheiros_ok
data_scanned = ""
for line in proc.stdout.splitlines():
    if "Scanned files:" in line:
        try:
            ficheiros_total = int(line.split(":")[1].strip())
        except (ValueError, IndexError):
            pass
    if "Data scanned:" in line:
        data_scanned = line.split(":")[1].strip()

db.log_scan("modules_scan", ficheiros_total, ameacas, elapsed)

print(f"\n  RESULTADO:")
print(f"    Ficheiros analisados: {ficheiros_total}")
print(f"    Ameacas encontradas:  {ameacas}")
if data_scanned:
    print(f"    Dados analisados:     {data_scanned}")
print(f"    Duracao:              {elapsed:.1f}s")

if ameacas == 0:
    print(f"\n  [OK] Todos os ficheiros estao limpos!")
else:
    print(f"\n  [!!] {ameacas} ameaca(s) detetada(s)!")

# Estatisticas da BD
stats = db.get_stats()
print(f"\n{SEP}")
print("  ESTATISTICAS TOTAIS")
print(SEP)
print(f"  Scans realizados:     {stats['total_scans']}")
print(f"  Ficheiros analisados: {stats['total_files_scanned']:,}")
print(f"  Ameacas encontradas:  {stats['total_threats_found']}")
print(SEP)

db.close()
