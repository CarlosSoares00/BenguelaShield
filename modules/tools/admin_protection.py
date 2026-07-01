"""Protecção por palavra-passe do BenguelaShield."""
from __future__ import annotations
import hashlib
import hmac
import json
import logging
import secrets
import time
from pathlib import Path

from modules.tools.config import ADMIN_PASSWORD_HASH_FILE

logger = logging.getLogger("BenguelaShield.Tools.AdminProtection")


class AdminProtection:
    """Protecção por password de administrador."""

    def __init__(self):
        self._hash_file = ADMIN_PASSWORD_HASH_FILE
        self._hash_file.parent.mkdir(parents=True, exist_ok=True)

    def set_password(self, password: str) -> bool:
        salt = secrets.token_hex(16)
        h = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
        data = {"salt": salt, "hash": h, "created": time.strftime("%Y-%m-%dT%H:%M:%S")}
        try:
            self._hash_file.write_text(json.dumps(data), encoding="utf-8")
            return True
        except Exception as e:
            logger.error("Erro ao definir password: %s", e)
            return False

    def verify_password(self, password: str) -> bool:
        if not self._hash_file.exists():
            return True
        try:
            data = json.loads(self._hash_file.read_text(encoding="utf-8"))
            h = hashlib.sha256((data["salt"] + password).encode("utf-8")).hexdigest()
            return hmac.compare_digest(h, data["hash"])
        except Exception:
            return False

    def is_password_set(self) -> bool:
        return self._hash_file.exists()

    def remove_password(self, current_password: str) -> bool:
        if self.verify_password(current_password):
            try:
                self._hash_file.unlink()
                return True
            except Exception:
                return False
        return False

    def require_password(self, action: str) -> bool:
        if not self.is_password_set():
            return True
        return False
