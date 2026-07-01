import logging, time, math
from pathlib import Path
try:
    import lief
except ImportError:
    lief = None
from modules.ai.config import MAX_FILE_SIZE, PE_EXTENSIONS, HIGH_RISK_IMPORTS, FEATURE_NAMES

logger = logging.getLogger("BenguelaShield.AI.Features")

class FeatureExtractor:
    def __init__(self):
        if lief is None:
            logger.warning("lief nao instalado")

    def extract(self, filepath: str) -> dict | None:
        if lief is None:
            return None
        try:
            p = Path(filepath)
            if not p.exists() or p.stat().st_size > MAX_FILE_SIZE:
                return None
            if p.suffix.lower() not in PE_EXTENSIONS:
                return None
            binary = lief.parse(filepath)
            if binary is None:
                return None
            sections = list(binary.sections)
            section_entropies = [self._calc_ent(s.content) for s in sections if len(s.content) > 0]
            avg_ent = sum(section_entropies) / len(section_entropies) if section_entropies else 0
            max_ent = max(section_entropies) if section_entropies else 0
            min_ent = min(section_entropies) if section_entropies else 0
            imports = set()
            for lib in binary.imports:
                for entry in lib.entries:
                    if entry.name:
                        imports.add(entry.name)
            hr_count, hr_flags = self._count_high_risk(imports)
            code_size = 0
            data_size = 0
            for s in sections:
                name = s.name.lower() if s.name else ""
                if name in (".text", ".code", "CODE"):
                    code_size = s.size
                elif name in (".data", ".rdata", "DATA"):
                    data_size += s.size
            has_tls = 1 if hasattr(binary, "has_tls") and binary.has_tls else 0
            has_debug = 1 if hasattr(binary, "has_debug") and binary.has_debug else 0
            num_res = 0
            try:
                if hasattr(binary, "resources"):
                    num_res = len(list(binary.resources))
            except Exception:
                pass
            is_packed = 1 if max_ent > 7.0 else 0
            header_size = 0
            try:
                if hasattr(binary, "optional_header") and hasattr(binary.optional_header, "sizeof_headers"):
                    header_size = binary.optional_header.sizeof_headers
            except Exception:
                pass
            ts = 0
            try:
                if hasattr(binary, "header") and hasattr(binary.header, "time_date_stamps"):
                    ts = binary.header.time_date_stamps
            except Exception:
                pass
            ts_susp = 1 if ts == 0 or ts > int(time.time()) else 0
            has_overlay = 1 if hasattr(binary, "has_overlay") and binary.has_overlay else 0
            entry_in_code = 0
            entry_in_last = 0
            if sections:
                try:
                    ep = binary.optional_header.addressof_entrypoint if hasattr(binary, "optional_header") and hasattr(binary.optional_header, "addressof_entrypoint") else 0
                    if ep > 0:
                        last = sections[-1]
                        if last.virtual_address <= ep < last.virtual_address + last.size:
                            entry_in_last = 1
                        elif sections[0].virtual_address <= ep < sections[0].virtual_address + sections[0].size:
                            entry_in_code = 1
                except Exception:
                    pass
            return {
                "num_sections": len(sections),
                "avg_section_entropy": round(avg_ent, 4),
                "max_section_entropy": round(max_ent, 4),
                "min_section_entropy": round(min_ent, 4),
                "num_imports": len(imports),
                "num_high_risk_imports": hr_count,
                "has_virtual_alloc": hr_flags.get("has_virtual_alloc", 0),
                "has_write_process_memory": hr_flags.get("has_write_process_memory", 0),
                "has_create_remote_thread": hr_flags.get("has_create_remote_thread", 0),
                "has_debugger_check": hr_flags.get("has_debugger_check", 0),
                "code_size": code_size,
                "data_size": data_size,
                "has_tls_callbacks": has_tls,
                "has_debug_info": has_debug,
                "num_resources": num_res,
                "is_packed": is_packed,
                "header_size": header_size,
                "timestamp": ts,
                "timestamp_suspicious": ts_susp,
                "has_overlay": has_overlay,
                "entry_in_code_section": entry_in_code,
                "entry_in_last_section": entry_in_last,
            }
        except Exception as e:
            logger.warning("Erro extrair %s: %s", filepath, e)
            return None

    def extract_to_vector(self, filepath: str) -> list[float] | None:
        feat = self.extract(filepath)
        if feat is None:
            return None
        return [float(feat[n]) for n in FEATURE_NAMES]

    def _count_high_risk(self, imports: set) -> tuple[int, dict]:
        count = 0
        for imp in imports:
            if imp in HIGH_RISK_IMPORTS:
                count += 1
        flags = {}
        flags["has_virtual_alloc"] = 1 if any(i in imports for i in ["VirtualAlloc", "VirtualAllocEx"]) else 0
        flags["has_write_process_memory"] = 1 if "WriteProcessMemory" in imports else 0
        flags["has_create_remote_thread"] = 1 if "CreateRemoteThread" in imports else 0
        flags["has_debugger_check"] = 1 if "IsDebuggerPresent" in imports else 0
        return count, flags

    def _calc_ent(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        length = len(data)
        ent = 0.0
        for f in freq:
            if f > 0:
                p = f / length
                ent -= p * math.log2(p)
        return ent

    @property
    def feature_names(self) -> list[str]:
        return FEATURE_NAMES

    @property
    def num_features(self) -> int:
        return len(FEATURE_NAMES)