"""Proteccao por palavra-passe do BenguelaShield."""
from __future__ import annotations
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from pathlib import Path

from modules.tools.config import ADMIN_PASSWORD_HASH_FILE

logger = logging.getLogger("BenguelaShield.Tools.AdminProtection")


class AdminProtection:
    """Proteccao por password de administrador com scrypt."""

    def __init__(self):
        self._hash_file = ADMIN_PASSWORD_HASH_FILE
        self._hash_file.parent.mkdir(parents=True, exist_ok=True)
        self._authenticated = False

    def set_password(self, password: str) -> bool:
        salt = secrets.token_bytes(32)
        h = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32
        )
        data = {
            "salt": salt.hex(),
            "hash": h.hex(),
            "algo": "scrypt",
            "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
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
            salt = bytes.fromhex(data["salt"])
            stored_hash = bytes.fromhex(data["hash"])
            algo = data.get("algo", "scrypt")

            if algo == "scrypt":
                h = hashlib.scrypt(
                    password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32
                )
            else:
                h = hashlib.sha256((salt.hex() + password).encode("utf-8")).digest()

            return hmac.compare_digest(h, stored_hash)
        except Exception:
            return False

    def is_password_set(self) -> bool:
        return self._hash_file.exists()

    def remove_password(self, current_password: str) -> bool:
        if self.verify_password(current_password):
            try:
                self._hash_file.unlink()
                self._authenticated = False
                return True
            except Exception:
                return False
        return False

    def authenticate(self, password: str) -> bool:
        """Autentica o utilizador e guarda o estado de sessao."""
        if not self.is_password_set():
            self._authenticated = True
            return True
        if self.verify_password(password):
            self._authenticated = True
            return True
        return False

    def is_authenticated(self) -> bool:
        """Verifica se o utilizador esta autenticado nesta sessao."""
        if not self.is_password_set():
            return True
        return self._authenticated

    def logout(self) -> None:
        """Termina a sessao de autenticacao."""
        self._authenticated = False

    def require_password(self, action: str) -> bool:
        """Verifica autenticacao. Retorna True se acesso permitido."""
        if not self.is_password_set():
            return True
        return self._authenticated
