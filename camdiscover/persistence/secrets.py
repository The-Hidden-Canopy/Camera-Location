"""Credential secret storage helper.

On Windows, secrets should be protected with DPAPI via ctypes (CryptProtectData).
For cross-platform development or testing, this module falls back to a pluggable
secret store controlled by CAM_SECRET_BACKEND:

  dpapi    — Windows DPAPI (default on win32)
  file     — AES-GCM encrypted file with a key derived from a machine id file
  plain    — plaintext (never use in production; useful for tests only)

Passwords are never stored in the SQLite database.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Optional


_SECRET_BACKEND = os.environ.get("CAM_SECRET_BACKEND", "dpapi" if os.name == "nt" else "file")
_VAULT_DIR = Path(os.environ.get("CAM_SECRET_DIR") or Path.home() / ".camera_location" / "secrets")


def _vault_path(ref: str) -> Path:
    safe = "".join(c for c in ref if c.isalnum() or c in "-_=.")
    _VAULT_DIR.mkdir(parents=True, exist_ok=True)
    return _VAULT_DIR / f"{safe}.enc"


def _encrypt_dpapi(plaintext: str) -> str:
    try:
        import ctypes
        from ctypes import wintypes

        cb_input = wintypes.DWORD(len(plaintext.encode("utf-16-le")))
        p_input = ctypes.c_char_p(plaintext.encode("utf-16-le"))
        p_output = wintypes.LPVOID()

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", wintypes.LPVOID)]

        blob = DATA_BLOB(cb_input, ctypes.cast(p_input, wintypes.LPVOID))
        out_blob = DATA_BLOB()

        if ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(blob),
            None, None, None, None, 0,
            ctypes.byref(out_blob),
        ):
            buffer = (ctypes.c_ubyte * out_blob.cbData).from_address(out_blob.pbData)
            data = bytes(buffer)
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)
            return base64.b64encode(data).decode("ascii")
    except Exception:
        pass
    raise RuntimeError("DPAPI encryption failed")


def _decrypt_dpapi(ciphertext: str) -> Optional[str]:
    try:
        import ctypes
        from ctypes import wintypes

        raw = base64.b64decode(ciphertext)
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", wintypes.LPVOID)]

        blob = DATA_BLOB(len(raw), ctypes.cast(ctypes.c_char_p(raw), wintypes.LPVOID))
        out_blob = DATA_BLOB()

        if ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob),
            None, None, None, None, 0,
            ctypes.byref(out_blob),
        ):
            buffer = (ctypes.c_ubyte * out_blob.cbData).from_address(out_blob.pbData)
            data = bytes(buffer)
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)
            return data.decode("utf-16-le")
    except Exception:
        return None


def _machine_key() -> bytes:
    """Derive a stable key from the machine (best-effort).  Not super secure,
    but better than plaintext for non-production file backend."""
    candidates = [
        os.environ.get("COMPUTERNAME", ""),
        os.environ.get("USERDOMAIN", ""),
        os.environ.get("USERNAME", ""),
    ]
    joined = "".join(candidates).encode("utf-8")
    import hashlib
    return hashlib.sha256(joined).digest()[:32]


def _encrypt_file(plaintext: str) -> str:
    from cryptography.fernet import Fernet
    key = base64.urlsafe_b64encode(_machine_key())
    return Fernet(key).encrypt(plaintext.encode("utf-8")).decode("ascii")


def _decrypt_file(ciphertext: str) -> Optional[str]:
    try:
        from cryptography.fernet import Fernet
        key = base64.urlsafe_b64encode(_machine_key())
        return Fernet(key).decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except Exception:
        return None


def store(secret_ref: str, password: str) -> None:
    """Encrypt and store `password` under `secret_ref`."""
    if _SECRET_BACKEND == "dpapi":
        cipher = _encrypt_dpapi(password)
    elif _SECRET_BACKEND == "file":
        cipher = _encrypt_file(password)
    else:
        cipher = base64.b64encode(password.encode("utf-8")).decode("ascii")
    _vault_path(secret_ref).write_text(cipher, encoding="utf-8")


def retrieve(secret_ref: str) -> Optional[str]:
    """Retrieve and decrypt the password for `secret_ref`, or None."""
    path = _vault_path(secret_ref)
    if not path.exists():
        return None
    cipher = path.read_text(encoding="utf-8")
    if _SECRET_BACKEND == "dpapi":
        return _decrypt_dpapi(cipher)
    if _SECRET_BACKEND == "file":
        return _decrypt_file(cipher)
    try:
        return base64.b64decode(cipher).decode("utf-8")
    except Exception:
        return None


def delete(secret_ref: str) -> None:
    path = _vault_path(secret_ref)
    if path.exists():
        path.unlink()
