"""Drivers de kernel: vulneráveis/maliciosos conhecidos (lista do LOLDrivers, empacotada) e drivers registrados a partir de pastas de usuário.

Driver vulnerável é assinado e legítimo, mas deixa qualquer programa com administrador chegar ao kernel (BYOVD): é risco, não malware,
por isso só gera Atenção. Driver de kernel registrado a partir de Downloads/Temp/AppData é o padrão de cracks com hipervisor próprio
e de rootkits: Atenção, e Perigoso se a assinatura não for válida. Tudo legível sem administrador (Win32_SystemDriver).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from . import procscan as ps
from .checks import run_powershell, verify_signatures
from .scoring import Finding

LIST_PATH = Path(__file__).resolve().parent / "vulndrivers.json"
MAX_SIZE = 64 << 20

_PS_DRV = r"""
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
ConvertTo-Json -InputObject @(Get-CimInstance Win32_SystemDriver | ForEach-Object { [pscustomobject]@{n=[string]$_.Name; p=[string]$_.PathName; s=[string]$_.State} }) -Compress
"""

_PS_VER = r"""
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$o=@{}
foreach($p in (ConvertFrom-Json $env:SENT_PATHS)){ $v=(Get-Item -LiteralPath $p).VersionInfo; $o[$p]=([string]$v.CompanyName + ' | ' + [string]$v.ProductName).Trim(' |') }
ConvertTo-Json -InputObject $o -Compress
"""


@dataclass
class Driver:
    name: str
    path: str
    running: bool
    sha256: str = ""


def load_list(path: Path | None = None) -> dict:
    """{sha256: [nome, 'v'|'m']} ou {} se a lista faltar/estiver corrompida."""
    try:
        d = json.loads((path or LIST_PATH).read_text(encoding="utf-8"))
        h = d.get("sha256") if isinstance(d, dict) else None
        return h if isinstance(h, dict) else {}
    except (OSError, ValueError):
        return {}


def norm_driver_path(p: str) -> str:
    """Converte os formatos de ImagePath (\\SystemRoot\\..., system32\\..., \\??\\C:\\...) para caminho Win32."""
    root = os.environ.get("SystemRoot", r"C:\Windows")
    p = (p or "").strip().strip('"')
    if p.startswith("\\??\\"):
        p = p[4:]
    low = p.lower()
    if low.startswith("\\systemroot\\"):
        p = root + p[len("\\systemroot"):]
    elif low.startswith("system32\\") or low.startswith("syswow64\\"):
        p = os.path.join(root, p)
    elif re.match(r"^\\windows\\", low):
        p = root[:2] + p
    return p


_USER_DIR = re.compile(r"(?i)^[a-z]:\\users\\[^\\]+\\|\\temp\\|\\downloads\\|\\appdata\\")


def in_user_folder(p: str) -> bool:
    return bool(_USER_DIR.search(p or ""))


def list_drivers(cancelled=lambda: False) -> list[Driver] | None:
    raw = run_powershell(_PS_DRV, timeout=60, cancelled=cancelled)
    if raw is None:
        return None
    try:
        data = json.loads(raw or "[]")
    except ValueError:
        return None
    data = [data] if isinstance(data, dict) else data
    out = []
    for d in data if isinstance(data, list) else []:
        if isinstance(d, dict) and d.get("p"):
            out.append(Driver(ps.clean_text(d.get("n") or "", 80), norm_driver_path(str(d["p"])), str(d.get("s")) == "Running"))
    return out


def _sha256(p: str) -> str:
    try:
        if os.path.getsize(p) > MAX_SIZE:
            return ""
        h = hashlib.sha256()
        with open(p, "rb") as f:
            while c := f.read(1 << 20):
                h.update(c)
        return h.hexdigest()
    except OSError:
        return ""


def _owners(paths: list[str], cancelled) -> dict:
    if not paths:
        return {}
    try:
        d = json.loads(run_powershell(_PS_VER, {"SENT_PATHS": json.dumps(paths)}, timeout=60, cancelled=cancelled) or "{}")
    except ValueError:
        return {}
    return {k: ps.clean_text(str(v), 120) for k, v in d.items()} if isinstance(d, dict) else {}


def judge(drivers: list[Driver], vuln: dict, sigs: dict, owners: dict) -> list[Finding]:
    """Achados (puro, testável). sigs: {caminho: {'status': 'Valid'|...}}; owners: {caminho: 'Empresa | Produto'}."""
    fs: list[Finding] = []
    for d in drivers:
        base = os.path.basename(d.path) or d.name
        who = owners.get(d.path) or "origem desconhecida"
        where = f"{ps.clean_text(d.path, 260)} · serviço {d.name} · {who} · " + ("CARREGADO agora" if d.running else "registrado, não carregado")
        hit = vuln.get(d.sha256) if d.sha256 else None
        if hit and hit[1] == "m":
            fs.append(Finding("kernel", f"Driver MALICIOSO conhecido: {base}", where + ". Hash idêntico a um driver malicioso catalogado no LOLDrivers. "
                              "Não confie neste PC até investigar; analise o arquivo no Sentinela.", 60, "critical"))
            continue
        if hit:
            fs.append(Finding("kernel", f"Driver vulnerável conhecido: {base}" + (f" ({ps.clean_text(hit[0], 40)})" if hit[0] and hit[0].lower() != base.lower() else ""),
                              where + ". É legítimo, mas tem falha que dá acesso ao kernel a qualquer programa com administrador (usado por malware e cheats). "
                              "Atualize ou desinstale o programa que o instalou.", 20 if d.running else 8, "medium" if d.running else "low"))
        if in_user_folder(d.path):
            sg = sigs.get(d.path) or {}
            st = str(sg.get("status", ""))
            if st == "Valid":       # ferramentas legítimas (HWiNFO, monitores de hardware) extraem o driver na Temp: só nota
                signer = ps.clean_text(re.sub(r"^CN=|,.*$", "", str(sg.get("subject", ""))), 60) or "?"
                fs.append(Finding("kernel", f"Driver de kernel em pasta de usuário, assinado: {base}",
                                  where + f". Assinatura válida ({signer}). Comum em monitores de hardware; confira se você usa esse programa.", 5, "low"))
                continue
            bad = st not in ("", "CheckFailed")      # CheckFailed/sem leitura = a checagem não terminou: não condena
            fs.append(Finding("kernel", f"Driver de kernel registrado a partir de pasta de usuário: {base}",
                              where + ". Drivers do sistema ficam em C:\\Windows; driver em Downloads/Temp/AppData é o padrão de cracks com hipervisor e rootkits"
                              + (f". A assinatura NÃO é válida ({ps.clean_text(st, 30)})." if bad else ", e a assinatura não pôde ser conferida."),
                              55 if bad else 25, "high" if bad else "medium"))
    return fs


def scan(cancelled=lambda: False) -> tuple[list[Finding], list[str], bool]:
    """(achados, notas, leu os drivers?)."""
    vuln = load_list()
    notes = [] if vuln else ["Lista de drivers vulneráveis ausente ou corrompida: a checagem de drivers vulneráveis não rodou."]
    drivers = list_drivers(cancelled)
    if drivers is None:
        return [], notes, False
    for d in drivers:
        if cancelled():
            raise InterruptedError
        d.sha256 = _sha256(d.path) if os.path.isfile(d.path) else ""
    flagged = [d for d in drivers if (d.sha256 and d.sha256 in vuln) or in_user_folder(d.path)]
    paths = sorted({d.path for d in flagged if os.path.isfile(d.path)})
    sigs = verify_signatures([p for p in paths if in_user_folder(p)], cancelled) if any(in_user_folder(p) for p in paths) else {}
    fs = judge(drivers, vuln, sigs, _owners(paths, cancelled))
    unread = sum(1 for d in drivers if not d.sha256)
    if unread:
        notes.append(f"{unread} driver(s) registrados não puderam ser lidos (arquivo ausente ou protegido) e não foram comparados com a lista.")
    return fs, notes, True
