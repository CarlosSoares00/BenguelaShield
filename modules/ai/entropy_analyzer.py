import math, logging
from pathlib import Path
from modules.ai.config import MAX_FILE_SIZE

class EntropyAnalyzer:
    def __init__(self, block_size: int = 256):
        self.block_size = block_size

    def analyze(self, filepath: str) -> dict | None:
        try:
            p = Path(filepath)
            if not p.exists() or p.stat().st_size > MAX_FILE_SIZE:
                return None
            data = p.read_bytes()
            if not data:
                return None
            entropies = []
            for i in range(0, len(data), self.block_size):
                block = data[i:i + self.block_size]
                entropies.append(self._calculate_entropy(block))
            if not entropies:
                return None
            high = sum(1 for e in entropies if e > 7.0)
            return {
                "average_entropy": sum(entropies) / len(entropies),
                "max_entropy": max(entropies),
                "min_entropy": min(entropies),
                "median_entropy": sorted(entropies)[len(entropies) // 2],
                "file_size": len(data),
                "block_size": self.block_size,
                "num_blocks": len(entropies),
                "high_entropy_blocks": high,
                "high_entropy_percentage": high / len(entropies) * 100,
            }
        except Exception:
            return None

    def is_packed(self, filepath: str, threshold: float = 6.8) -> bool:
        r = self.analyze(filepath)
        return r is not None and r["average_entropy"] > threshold

    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        length = len(data)
        entropy = 0.0
        for f in freq:
            if f > 0:
                p = f / length
                entropy -= p * math.log2(p)
        return entropy