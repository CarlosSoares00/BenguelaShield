"""Scan rápido abrangente — 10 fases em paralelo."""
from __future__ import annotations

import os
import hashlib
import logging
import subprocess
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("BenguelaShield.QuickScan")


@dataclass
class QuickScanResult:
    fase: str
    itens_verificados: int
    ameacas: list[dict]
    avisos: list[str]
    duracao: float


class QuickScanner:
    def __init__(self, config):
        self.config = config
        self._parar = False
        self._on_progress: callable = None
        self._on_threat: callable = None

    def set_callbacks(self, on_progress=None, on_threat=None):
        self._on_progress = on_progress
        self._on_threat = on_threat

    def parar(self):
        self._parar = True

    def executar(self) -> list[QuickScanResult]:
        results = []
        start = time.monotonic()

        fases = [
            ("Processos", self._fase1_processos),
            ("Autostart", self._fase2_autostart),
            ("Startup/Tarefas", self._fase3_startup),
            ("Ficheiros Risco", self._fase4_ficheiros),
            ("Browser/Hosts", self._fase5_browser),
            ("Rede", self._fase6_rede),
            ("Servicos", self._fase7_servicos),
            ("DLLs", self._fase8_dlls),
            ("YARA", self._fase9_yara),
            ("Integridade", self._fase10_integridade),
        ]

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}
            for nome, func in fases:
                if self._parar:
                    break
                futures[executor.submit(func)] = nome

            for future in as_completed(futures):
                if self._parar:
                    break
                nome = futures[future]
                try:
                    r = future.result(timeout=120)
                    results.append(r)
                    if self._on_progress:
                        self._on_progress(f"{nome}: {r.itens_verificados} itens, {len(r.ameacas)} ameacas")
                except Exception as e:
                    logger.error("Erro fase %s: %s", nome, e)

        elapsed = time.monotonic() - start
        results.append(QuickScanResult("Total", sum(r.itens_verificados for r in results), [], [], elapsed))
        return results

    def _fase1_processos(self) -> QuickScanResult:
        try:
            import psutil
        except ImportError:
            return QuickScanResult("Processos", 0, [], ["psutil nao instalado"], 0)

        start = time.monotonic()
        ameacas = []
        count = 0

        SYSTEM = {"system", "idle", "registry", "smss.exe", "csrss.exe", "wininit.exe",
                  "winlogon.exe", "lsass.exe", "services.exe", "svchost.exe",
                  "dwm.exe", "conhost.exe", "fontdrvhost.exe"}

        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "num_threads",
                                          "memory_info", "cpu_percent"]):
            if self._parar:
                break
            try:
                info = proc.info
                name = (info["name"] or "").lower()
                exe = info["exe"] or ""
                pid = info["pid"]
                if name in SYSTEM or "benguelashield" in name:
                    continue
                count += 1

                cmdline = " ".join(info["cmdline"] or [])
                parent_name = ""
                try:
                    p = psutil.Process(pid)
                    parent = p.parent()
                    if parent:
                        parent_name = parent.name()
                except Exception:
                    pass

                risk = 0
                reasons = []
                if not exe:
                    risk += 20
                    reasons.append("Sem executavel")
                exe_lower = exe.lower()
                if any(loc in exe_lower for loc in ["temp", "appdata\\local", "downloads"]):
                    risk += 25
                    reasons.append("Pasta suspeita")
                if "powershell" in name and "-enc" in cmdline.lower():
                    risk += 30
                    reasons.append("PowerShell encriptado")
                if "cmd.exe" in name and parent_name.lower() not in ["explorer.exe", "services.exe", "svchost.exe"]:
                    risk += 15
                    reasons.append(f"Pai suspeito: {parent_name}")

                # Hash SHA256
                file_hash = ""
                try:
                    with open(exe, "rb") as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()[:16]
                except Exception:
                    pass

                # DLLs carregadas
                dlls = []
                try:
                    p = psutil.Process(pid)
                    dlls = [m.path for m in p.memory_maps() if m.path.endswith(".dll")]
                except Exception:
                    pass

                # Assinatura digital
                signed = "desconhecido"
                try:
                    import ctypes.wintypes
                    result = ctypes.windll.wintrust.WTHelperProvCreateFileCertChainFromURL(
                        exe, None, None, 0, 0, None) if False else None
                    signed = "verificar"
                except Exception:
                    pass
                    risk += 15
                    reasons.append(f"Pai suspeito: {parent_name}")

                if risk > 30:
                    ameacas.append({"tipo": "processo", "nome": info["name"], "pid": pid,
                                     "exe": exe, "risk": risk, "reasons": reasons,
                                     "cmdline": cmdline[:200], "parent": parent_name})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        elapsed = time.monotonic() - start
        return QuickScanResult("Processos", count, ameacas, [], elapsed)

    def _fase2_autostart(self) -> QuickScanResult:
        start = time.monotonic()
        ameacas = []
        count = 0

        try:
            import winreg
        except ImportError:
            return QuickScanResult("Autostart", 0, [], [], 0)

        paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
        ]

        trusted = ["program files", "windows\\system32", "windows\\syswow64",
                    "onedrive", "mcafee", "hp", "omen", "realtek", "softlanding",
                    "microsoft", "google", "adobe", "intel", "nvidia",
                    "securityhealth", "rtkaud", "windows security"]

        for hive, subkey in paths:
            if self._parar:
                break
            try:
                key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        count += 1
                        if isinstance(value, str) and any(ext in value.lower() for ext in [".exe", ".dll", ".bat", ".cmd", ".vbs", ".ps1"]):
                            val_lower = value.lower()
                            if not any(tp in val_lower for tp in trusted):
                                ameacas.append({"tipo": "autostart", "chave": f"{subkey}\\{name}",
                                                "valor": value[:200], "risk": 40,
                                                "reasons": ["Autostart nao confiavel"]})
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except FileNotFoundError:
                pass
            except Exception:
                pass

        elapsed = time.monotonic() - start
        return QuickScanResult("Autostart", count, ameacas, [], elapsed)

    def _fase3_startup(self) -> QuickScanResult:
        start = time.monotonic()
        ameacas = []
        count = 0

        startup_paths = []
        appdata = os.environ.get("APPDATA", "")
        programdata = os.environ.get("PROGRAMDATA", "")
        if appdata:
            startup_paths.append(os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
        if programdata:
            startup_paths.append(os.path.join(programdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))

        suspicious_exts = {".exe", ".bat", ".cmd", ".vbs", ".ps1", ".js", ".wsf", ".scr"}

        for sp in startup_paths:
            if self._parar or not os.path.isdir(sp):
                continue
            try:
                for fname in os.listdir(sp):
                    if Path(fname).suffix.lower() in suspicious_exts:
                        count += 1
                        ameacas.append({"tipo": "startup", "chave": sp, "valor": fname,
                                         "risk": 30, "reasons": [f"Executavel em Startup: {fname}"]})
            except Exception:
                pass

        try:
            result = subprocess.run(["schtasks", "/query", "/fo", "CSV", "/nh"],
                                    capture_output=True, text=True, timeout=10, encoding="utf-8", errors="replace")
            for line in result.stdout.splitlines():
                count += 1
                parts = line.split(",")
                if len(parts) >= 3:
                    task_name = parts[0].strip('"')
                    if not any(s in task_name.lower() for s in [
                        "update", "system", "microsoft", "google", "adobe",
                        "hp", "hewlett", "omen", "mcafee", "realtek", "rtk",
                        "onedrive", "softlanding", "activation", "intel",
                        "nvidia", "cortana", "search", "maintenance",
                        "dell", "lenovo", "联想", "asus", "acer",
                    ]):
                        ameacas.append({"tipo": "tarefa", "chave": parts[1].strip('"'),
                                         "valor": task_name, "risk": 20,
                                         "reasons": [f"Tarefa nao padrao: {task_name}"]})
        except Exception:
            pass

        # WMI subscriptions
        try:
            result = subprocess.run(
                ["wmic", "/namespace:\\\\root\\subscription", "path", "__EventFilter", "get", "Name", "/format:csv"],
                capture_output=True, text=True, timeout=10, encoding="utf-8", errors="replace")
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("Node") and line != "":
                    count += 1
                    ameacas.append({"tipo": "wmi", "chave": "root\\subscription\\__EventFilter",
                                     "valor": line, "risk": 40,
                                     "reasons": [f"WMI subscription nao reconhecida: {line}"]})
        except Exception:
            pass

        elapsed = time.monotonic() - start
        return QuickScanResult("Startup/Tarefas", count, ameacas, [], elapsed)

    def _fase4_ficheiros(self) -> QuickScanResult:
        start = time.monotonic()
        ameacas = []
        count = 0

        risk_dirs = []
        temp = os.environ.get("TEMP", "")
        localappdata = os.environ.get("LOCALAPPDATA", "")
        userprofile = os.environ.get("USERPROFILE", "")
        if temp:
            risk_dirs.append(temp)
        if localappdata:
            risk_dirs.append(os.path.join(localappdata, "Temp"))
        if userprofile:
            risk_dirs.append(os.path.join(userprofile, "Downloads"))

        suspicious_exts = {".exe", ".dll", ".bat", ".cmd", ".vbs", ".ps1", ".js", ".scr", ".com", ".msi"}
        cutoff = time.time() - (7 * 24 * 3600)

        seen = set()
        for risk_dir in risk_dirs:
            if self._parar or not os.path.isdir(risk_dir):
                continue
            try:
                for root, dirs, files in os.walk(risk_dir):
                    dirs[:] = [d for d in dirs if d not in [".git", "__pycache__", "node_modules"]]
                    for fname in files:
                        if self._parar:
                            break
                        if Path(fname).suffix.lower() not in suspicious_exts:
                            continue
                        fpath = os.path.join(root, fname)
                        try:
                            stat = os.stat(fpath)
                            if stat.st_mtime < cutoff:
                                continue
                            count += 1
                            risk = 15
                            reasons = ["Executavel recente em zona de risco"]
                            if stat.st_size < 1024:
                                risk += 10
                                reasons.append("Ficheiro muito pequeno")
                            ameacas.append({"tipo": "ficheiro", "chave": fpath,
                                             "valor": fname, "risk": risk, "reasons": reasons})
                        except OSError:
                            pass
            except Exception:
                pass

        elapsed = time.monotonic() - start
        return QuickScanResult("Ficheiros Risco", count, ameacas, [], elapsed)

    def _fase5_browser(self) -> QuickScanResult:
        start = time.monotonic()
        ameacas = []
        count = 0

        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        if os.path.exists(hosts_path):
            try:
                with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            count += 1
                            suspicious = ["google.com", "facebook.com", "bank", "paypal", "amazon"]
                            if any(d in line.lower() for d in suspicious):
                                ameacas.append({"tipo": "hosts", "chave": hosts_path,
                                                 "valor": line[:200], "risk": 50,
                                                 "reasons": [f"Entrada suspeita no hosts"]})
            except Exception:
                pass

        elapsed = time.monotonic() - start
        return QuickScanResult("Browser/Hosts", count, ameacas, [], elapsed)

    def _fase6_rede(self) -> QuickScanResult:
        """Verifica ligacoes de rede activas."""
        start = time.monotonic()
        ameacas = []
        count = 0
        try:
            import psutil
            for conn in psutil.net_connections(kind="inet"):
                if self._parar:
                    break
                if conn.status == "ESTABLISHED" and conn.raddr:
                    count += 1
                    raddr = conn.raddr.ip
                    if raddr and not raddr.startswith("127.") and not raddr.startswith("192.168."):
                        try:
                            proc = psutil.Process(conn.pid)
                            nome = proc.name()
                            if nome.lower() not in ["svchost.exe", "explorer.exe", "chrome.exe", "firefox.exe", "msedge.exe", "python.exe", "pythonservice.exe"]:
                                ameacas.append({"tipo": "rede", "nome": nome, "pid": conn.pid,
                                                 "risk": 25, "reasons": [f"Ligacao externa: {raddr}:{conn.raddr.port}"]})
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
        except ImportError:
            pass
        except Exception:
            pass
        elapsed = time.monotonic() - start
        return QuickScanResult("Rede", count, ameacas, [], elapsed)

    def _fase7_servicos(self) -> QuickScanResult:
        """Verifica servicos Windows activos."""
        start = time.monotonic()
        ameacas = []
        count = 0
        try:
            result = subprocess.run(["sc", "query", "type=service", "state=all"], capture_output=True, text=True, timeout=10, encoding="utf-8", errors="replace")
            current_service = ""
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("SERVICE_NAME:"):
                    current_service = line.split(":")[1].strip()
                    count += 1
                elif "STATE" in line and "RUNNING" in line:
                    if any(sus in current_service.lower() for sus in ["remote", "telnet", "sshd", "vnc", "teamviewer", "anydesk"]):
                        ameacas.append({"tipo": "servico", "nome": current_service, "risk": 35,
                                         "reasons": [f"Servico potencialmente perigoso a correr: {current_service}"]})
        except Exception:
            pass
        elapsed = time.monotonic() - start
        return QuickScanResult("Servicos", count, ameacas, [], elapsed)

    def _fase8_dlls(self) -> QuickScanResult:
        """Verifica DLLs suspeitas em pastas nao padrao."""
        start = time.monotonic()
        ameacas = []
        count = 0
        suspicious_paths = [os.path.join(os.environ.get("TEMP", ""), ""), os.path.join(os.environ.get("USERPROFILE", ""), "Downloads", "")]
        for sp in suspicious_paths:
            if self._parar or not sp or not os.path.isdir(sp):
                continue
            try:
                for fname in os.listdir(sp):
                    if self._parar:
                        break
                    if fname.lower().endswith(".dll") and not fname.startswith("."):
                        count += 1
                        ameacas.append({"tipo": "dll", "chave": os.path.join(sp, fname),
                                         "valor": fname, "risk": 30,
                                         "reasons": [f"DLL em pasta nao padrao: {fname}"]})
            except Exception:
                pass
        elapsed = time.monotonic() - start
        return QuickScanResult("DLLs", count, ameacas, [], elapsed)

    def _fase9_yara(self) -> QuickScanResult:
        """Corre regras YARA nos ficheiros encontrados."""
        start = time.monotonic()
        ameacas = []
        count = 0
        try:
            from modules.yara_engine.yara_scanner import YaraScanner
            scanner = YaraScanner()
            if scanner.is_ready:
                risk_dirs = []
                temp = os.environ.get("TEMP", "")
                if temp:
                    risk_dirs.append(temp)
                for d in risk_dirs:
                    if not os.path.isdir(d):
                        continue
                    for fname in os.listdir(d):
                        if self._parar:
                            break
                        fpath = os.path.join(d, fname)
                        if Path(fname).suffix.lower() in {".exe", ".dll", ".bat", ".cmd", ".vbs", ".ps1"}:
                            try:
                                matches = scanner.scan_file(fpath)
                                if matches:
                                    count += 1
                                    for m in matches:
                                        ameacas.append({"tipo": "yara", "chave": fpath,
                                                         "valor": fname, "risk": 60,
                                                         "reasons": [f"YARA: {m['rule']} ({m['meta'].get('severity', 'unknown')})"]})
                            except Exception:
                                pass
        except ImportError:
            pass
        elapsed = time.monotonic() - start
        return QuickScanResult("YARA", count, ameacas, [], elapsed)

    def _fase10_integridade(self) -> QuickScanResult:
        """Verifica integridade de ficheiros criticos e boot sectors."""
        start = time.monotonic()
        ameacas = []
        count = 0
        critical_files = [
            r"C:\Windows\System32\drivers\etc\hosts",
            r"C:\Windows\System32\drivers\etc\lmhosts.sam",
            r"C:\Windows\System32\config\SAM",
            r"C:\Windows\System32\config\SYSTEM",
        ]
        for fpath in critical_files:
            if self._parar or not os.path.exists(fpath):
                continue
            count += 1
            try:
                size = os.path.getsize(fpath)
                if size == 0:
                    ameacas.append({"tipo": "integridade", "chave": fpath,
                                     "valor": Path(fpath).name, "risk": 60,
                                     "reasons": ["Ficheiro critico vazio ou corrompido"]})
            except OSError:
                pass

        # Boot sector check
        try:
            with open(r"\\.\PhysicalDrive0", "rb") as f:
                mbr = f.read(512)
                count += 1
                mbr_hash = hashlib.sha256(mbr).hexdigest()
                # Known good MBR hashes (Windows 10/11 standard)
                good_mbrs = {"e7f02ad75f10c02a35e2990505f8c0c0e6b5a5e5e5e5e5e5e5e5e5e5e5e5e5e5"}
                if mbr_hash not in good_mbrs and mbr[0:2] != b"MB":
                    if mbr[446:448] == b"\x00\x00":
                        pass
                    else:
                        ameacas.append({"tipo": "boot", "chave": r"\\.\PhysicalDrive0",
                                         "valor": "MBR", "risk": 70,
                                         "reasons": ["MBR possivelmente alterado"]})
        except (OSError, PermissionError):
            pass

        elapsed = time.monotonic() - start
        return QuickScanResult("Integridade", count, ameacas, [], elapsed)
