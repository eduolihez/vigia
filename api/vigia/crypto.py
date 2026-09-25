"""Symmetric encryption for secrets stored at rest (`ApiKey.encrypted_value` — brief
section 8). Key material is derived from `VIGIA_SECRET_KEY` so nothing new needs to
be provisioned for a dev/self-hosted setup; changing `VIGIA_SECRET_KEY` invalidates
any previously stored keys (same tradeoff as any secret-derived encryption key).
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet


def _fernet(secret_key: str) -> Fernet:
    digest = hashlib.sha256(secret_key.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt(secret_key: str, plaintext: str) -> bytes:
    return _fernet(secret_key).encrypt(plaintext.encode("utf-8"))


def decrypt(secret_key: str, ciphertext: bytes) -> str:
    return _fernet(secret_key).decrypt(ciphertext).decode("utf-8")
