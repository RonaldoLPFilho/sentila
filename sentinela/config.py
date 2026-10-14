"""Preferências do usuário. A chave da API do VirusTotal é protegida com DPAPI (só este usuário do Windows lê)."""
from __future__ import annotations

import base64
import ctypes
import json
import os
from ctypes import wintypes
from pathlib import Path

APP_NAME = "Sentinela"
DATA_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / APP_NAME
CONFIG_FILE = DATA_DIR / "config.json"
WORK_ROOT = Path(os.environ.get("TEMP", str(Path.home()))) / APP_NAME


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, protect: bool) -> bytes:
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    buf = ctypes.create_string_buffer(data, len(data))
    src = _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out = _Blob()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    if not fn(ctypes.byref(src), None, None, None, None, 0, ctypes.byref(out)):
        raise OSError("DPAPI falhou")
    addr = ctypes.cast(out.pbData, ctypes.c_void_p).value
    try:
        return ctypes.string_at(addr, out.cbData)
    finally:
        kernel32.LocalFree(addr)


class Settings:
    DEFAULTS = {
        "vt_key_enc": "",
        "auto_sandbox": True,
        "sandbox_network": False,
        "sandbox_seconds": 60,
        "sandbox_protected": False,
        "proc_seconds": 60,        # janela de observação da verificação de processos
        "proc_vt": True,           # consultar o VirusTotal (só hash) para programas sem assinatura
        "proc_ignore": [],         # [{"sha256", "name", "motivo"}] programas em que o usuário confia
        "proc_suspended": [],      # [{"pid", "create_time", "name", "exe"}] processos que o app suspendeu
    }

    def __init__(self) -> None:
        self.data = {k: (list(v) if isinstance(v, list) else v) for k, v in self.DEFAULTS.items()}
        try:
            self.data.update(json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass

    @property
    def vt_key(self) -> str:
        env = os.environ.get("SENTINELA_VT_KEY", "").strip()
        if env:
            return env
        enc = self.data.get("vt_key_enc", "")
        if not enc:
            return ""
        try:
            return _dpapi(base64.b64decode(enc), protect=False).decode("utf-8")
        except (OSError, ValueError):
            return ""

    @vt_key.setter
    def vt_key(self, value: str) -> None:
        value = value.strip()
        self.data["vt_key_enc"] = (
            base64.b64encode(_dpapi(value.encode("utf-8"), protect=True)).decode("ascii") if value else ""
        )

    def __getitem__(self, key: str):
        return self.data[key]

    def __setitem__(self, key: str, value) -> None:
        self.data[key] = value

    def save(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
