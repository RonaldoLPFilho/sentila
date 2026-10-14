"""Motores e zonas da "Verificar computador": Defender (MpCmdRun + log de eventos), ClamAV (a partir de cópia privada verificada) e
descoberta das pastas de risco. Saída de qualquer scanner é tratada como entrada hostil: tetos de bytes/linhas, clean_text, nada é executado."""
from __future__ import annotations

import ctypes
import json
import os
import re
import subprocess
import tempfile
import time
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path

from . import components as comp
from . import procscan as ps
from .checks import CREATE_NO_WINDOW, find_mpcmdrun, run_powershell
from .config import DATA_DIR

CLAM_DB = DATA_DIR / "clamdb"
MAX_OUT = 4 << 20                     # teto da saída de um scanner
BELOW_NORMAL = 0x4000

# ---------------------------------------------------------------- Job Object: mata a árvore inteira (inclusive se o Sentinela cair)
_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.CreateJobObjectW.restype = wintypes.HANDLE
_k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
_k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
_k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
_k32.CloseHandle.argtypes = [wintypes.HANDLE]


class _BASIC(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64), ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t), ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]


class _IO(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint64) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _EXT(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _BASIC), ("IoInfo", _IO), ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


def _make_job(mem_limit: int = 0):
    h = _k32.CreateJobObjectW(None, None)
    if not h:
        return None
    info = _EXT()
    info.BasicLimitInformation.LimitFlags = 0x2000          # KILL_ON_JOB_CLOSE
    if mem_limit:
        info.BasicLimitInformation.LimitFlags |= 0x100      # JOB_MEMORY
        info.JobMemoryLimit = mem_limit
    _k32.SetInformationJobObject(h, 9, ctypes.byref(info), ctypes.sizeof(info))
    return h


@dataclass
class RunResult:
    code: int | None
    out: str
    truncated: bool = False
    timed_out: bool = False
    cancelled: bool = False


def run_limited(cmd: list[str], timeout: float, cancelled=lambda: False, cwd: str | None = None, env: dict | None = None,
                max_bytes: int = MAX_OUT, mem_limit: int = 0, low_priority: bool = True) -> RunResult:
    """Executa um scanner: prioridade baixa, sem janela, árvore num Job Object (morre se o app morrer), saída limitada, cancelável."""
    tmp = tempfile.TemporaryFile()
    job = _make_job(mem_limit)
    try:
        proc = subprocess.Popen(cmd, stdout=tmp, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, cwd=cwd, env=env,
                                creationflags=CREATE_NO_WINDOW | (BELOW_NORMAL if low_priority else 0))
    except OSError as e:
        tmp.close()
        return RunResult(None, f"não foi possível executar: {e.__class__.__name__}")
    if job:
        _k32.AssignProcessToJobObject(job, wintypes.HANDLE(int(proc._handle)))
    deadline = time.time() + timeout
    res = RunResult(None, "")
    try:
        while proc.poll() is None:
            if cancelled():
                res.cancelled = True
                break
            if time.time() > deadline:
                res.timed_out = True
                break
            if tmp.tell() > max_bytes:
                res.truncated = True
                break
            time.sleep(0.25)
    finally:
        if proc.poll() is None:
            if job:
                _k32.CloseHandle(job)       # KILL_ON_JOB_CLOSE mata a árvore toda
                job = None
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                pass
        elif job:
            _k32.CloseHandle(job)
            job = None
        res.code = proc.returncode
        tmp.seek(0)
        res.out = tmp.read(max_bytes + 1).decode("utf-8", "replace")[:max_bytes]
        tmp.close()
    if res.truncated:
        res.out += "\n[saída truncada]"
    return res


# ---------------------------------------------------------------- detecções

@dataclass
class Detection:
    engine: str          # defender | clamav
    name: str
    path: str
    severity: int = 0    # severidade do Defender (1..5) quando houver
    when: float = 0.0


_DEF_GENERIC = re.compile(r"(?i)(wacatac|casdet|sabsik|zpevdo|ceprolad|fuery|bearfoos|tiggre|occamy|phonzy|spursint|cloxer|contebrew|trojan:\w+/\w+\.(?:gen|a|b|c)\b|"
                          r"!ml\b|\.gen\b|generic|heur|suspicious|behavior:|^program:|^pua:|^hacktool:|^riskware|unwanted|softwarebundler|tool:)")
_CLAM_GENERIC = re.compile(r"(?i)(heuristics\.|^pua\.|\.generic|generic|suspicious|\.unknown|packed\.|\.packer|\.crypt|encrypted|win\.(trojan|malware)\.agent-\d+$)")
_TEST = re.compile(r"(?i)eicar|test[-_ ]file|standard_antimalware_test")


def classify_name(engine: str, name: str) -> str:
    """'test' (arquivo de teste), 'generic' (heurística/PUA/família genérica) ou 'family' (nome específico de família/variante)."""
    if _TEST.search(name):
        return "test"
    rx = _DEF_GENERIC if engine == "defender" else _CLAM_GENERIC
    return "generic" if rx.search(name) else "family"


# ---------------------------------------------------------------- Defender

_PS_EVENTS = r"""
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$since=[datetime]::Parse($env:SENT_SINCE,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)
$out=@()
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116; StartTime=$since} -MaxEvents 500 | ForEach-Object {
  $x=[xml]$_.ToXml(); $d=@{}; foreach($n in $x.Event.EventData.Data){ $d[$n.Name]=[string]$n.'#text' }
  $out += [pscustomobject]@{ name=$d['Threat Name']; path=$d['Path']; sev=$d['Severity ID']; time=$_.TimeCreated.ToUniversalTime().ToString('o') }
}
ConvertTo-Json -InputObject @($out) -Compress
"""


def defender_events(since_utc_iso: str, cancelled=lambda: False) -> list[Detection] | None:
    """Detecções do Defender (evento 1116) desde `since`. None = log ilegível (vira lacuna, nunca 'nada achado')."""
    raw = run_powershell(_PS_EVENTS, {"SENT_SINCE": since_utc_iso}, timeout=60, cancelled=cancelled)
    if raw is None:
        return None
    try:
        data = json.loads(raw or "[]")
    except ValueError:
        return None
    if isinstance(data, dict):
        data = [data]
    out, seen = [], set()
    for d in data if isinstance(data, list) else []:
        if not isinstance(d, dict):
            continue
        name = ps.clean_text(d.get("name") or "", 120)
        path = str(d.get("path") or "")
        path = path.split("file:_")[-1] if "file:_" in path else path
        path = path.split("->")[0].strip()
        if not name or (name, path) in seen:
            continue
        seen.add((name, path))
        try:
            sev = int(d.get("sev") or 0)
        except (TypeError, ValueError):
            sev = 0
        out.append(Detection("defender", name, path, sev))
    return out


def defender_update(cancelled=lambda: False) -> tuple[bool, str]:
    mp = find_mpcmdrun()
    if not mp:
        return False, "MpCmdRun não encontrado"
    r = run_limited([str(mp), "-SignatureUpdate"], 300, cancelled)
    return r.code == 0, ("assinaturas do Defender atualizadas" if r.code == 0 else "não foi possível atualizar as assinaturas do Defender")


def defender_scan(kind: int, status=lambda m: None, cancelled=lambda: False, timeout: float = 4 * 3600) -> tuple[list[Detection] | None, str]:
    """kind 1 = rápida, 2 = completa. Devolve (detecções | None, nota). Funciona sem administrador (medido)."""
    mp = find_mpcmdrun()
    if not mp:
        return None, "Defender não encontrado"
    since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 2))
    t0 = time.time()
    holder = {"done": False}

    def cb() -> bool:
        status(f"Defender {'rápida' if kind == 1 else 'completa'}: {int(time.time() - t0)} s…")
        return cancelled()

    r = run_limited([str(mp), "-Scan", "-ScanType", str(kind)], timeout, cb, low_priority=True)
    if r.cancelled:
        raise InterruptedError
    if r.timed_out:
        return None, "A varredura do Defender excedeu o tempo limite"
    if r.code not in (0, 2):
        return None, f"O Defender não concluiu a varredura (código {r.code})"
    dets = defender_events(since, cancelled)
    if dets is None:
        return None, "A varredura terminou, mas o log do Defender não pôde ser lido: o resultado não é conclusivo"
    return dets, "ok"


# ---------------------------------------------------------------- ClamAV

CLAM_ARGS = ["--infected", "--no-summary", "--max-filesize=100M", "--max-scansize=200M", "--max-files=1000", "--max-recursion=8", "--max-dir-recursion=15"]


def clam_db_state() -> tuple[bool, float]:
    """(base existe?, idade em dias do arquivo mais novo)."""
    files = [p for p in CLAM_DB.glob("*.c[vl]d")] if CLAM_DB.is_dir() else []
    if not any(p.name.lower().startswith(("daily", "main")) for p in files):
        return False, 0.0
    return True, (time.time() - max(p.stat().st_mtime for p in files)) / 86400


def clam_update(run: comp.PinnedRun, status=lambda m: None, cancelled=lambda: False) -> tuple[bool, str]:
    """freshclam com config gerada pelo app: sem DatabaseCustomURL, sem proxy herdado, destino fixo. Resultado só por código de saída."""
    CLAM_DB.mkdir(parents=True, exist_ok=True)
    conf = Path(run.dir) / "freshclam.conf"
    conf.write_text(f"DatabaseDirectory {CLAM_DB}\nDatabaseMirror database.clamav.net\nConnectTimeout 30\nReceiveTimeout 120\nMaxAttempts 3\n"
                    "Checks 1\nScriptedUpdates yes\nLogVerbose no\n", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
    t0 = time.time()
    r = run_limited([run.exe("freshclam.exe"), f"--config-file={conf}", "--stdout", "--no-warnings"], 1800,
                    lambda: (status(f"Baixando as assinaturas do ClamAV… {int(time.time() - t0)} s"), cancelled())[1], cwd=str(run.dir), env=env)
    if r.cancelled:
        raise InterruptedError
    ok = r.code == 0
    return ok, "assinaturas do ClamAV atualizadas" if ok else f"não foi possível atualizar as assinaturas do ClamAV (código {r.code})"


_CLAM_BLOCKED = re.compile(r"Can't open file (.+?): (\d+)\s*$", re.M)
_CLAM_LINE = re.compile(r"^(.*): ([^:\r\n]+) FOUND\s*$")


def parse_clam_output(out: str, limit: int = 2000) -> list[Detection]:
    res = []
    for line in out.splitlines()[:20000]:
        m = _CLAM_LINE.match(line)
        if m and len(res) < limit:
            res.append(Detection("clamav", ps.clean_text(m.group(2), 120), m.group(1).strip()))
    return res


def clam_scan(run: comp.PinnedRun, files: list[str], db_dir: Path | None = None, status=lambda m: None, cancelled=lambda: False,
              batch: int = 3000, per_batch_timeout: float = 2400) -> tuple[list[Detection], int, list[str]]:
    """Varre `files` em lotes. Devolve (detecções, nº de arquivos varridos, erros). Exit 0/1 = ok; 2 = erro do lote (vira lacuna)."""
    db = db_dir or CLAM_DB
    dets: list[Detection] = []
    errors: list[str] = []
    done = 0
    for i in range(0, len(files), batch):
        part = files[i:i + batch]
        lst = Path(run.dir) / f"lista_{i}.txt"
        lst.write_text("\n".join(part), encoding="utf-8")
        status(f"ClamAV: {done}/{len(files)} arquivos…")
        r = run_limited([run.exe("clamscan.exe"), f"--database={db}", f"--file-list={lst}", *CLAM_ARGS], per_batch_timeout, cancelled, cwd=str(run.dir))
        if r.cancelled:
            raise InterruptedError
        blocked = _CLAM_BLOCKED.findall(r.out)
        other_err = [ln for ln in r.out.splitlines() if ln.strip() and "Can't open file" not in ln and not ln.endswith("FOUND") and "LibClamAV Warning" not in ln
                     and not ln.startswith("WARNING") and "[saída truncada]" not in ln]
        if r.code in (0, 1) or (r.code == 2 and blocked and not other_err and not r.timed_out):
            dets += parse_clam_output(r.out)
            done += len(part)
            for path, code in blocked:       # 225/226: o antivírus em tempo real barrou a abertura (já registrou a detecção no log)
                if code in ("225", "226"):
                    dets.append(Detection("defender", "Bloqueado pelo antivírus em tempo real", path.strip()))
        else:
            errors.append(f"lote {i // batch + 1}: " + ("tempo excedido" if r.timed_out else f"código {r.code}: " + ps.clean_text(" ".join(r.out.split())[-200:], 200)))
        try:
            lst.unlink()
        except OSError:
            pass
    return dets, done, errors


# ---------------------------------------------------------------- zonas de risco

EXEC_EXT = {".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".lnk", ".msi", ".jar", ".py", ".com", ".cpl", ".pif"}
ATTR_REPARSE, ATTR_OFFLINE, ATTR_RECALL_OPEN, ATTR_RECALL_DATA = 0x400, 0x1000, 0x40000, 0x400000
MAX_FILE = 200 << 20


@dataclass
class ZoneResult:
    files: list = field(default_factory=list)
    skipped_cloud: int = 0
    skipped_big: int = 0
    skipped_reparse: int = 0
    skipped_error: int = 0
    skipped_nonlocal: int = 0
    truncated: bool = False
    roots: list = field(default_factory=list)


def steam_library_dirs() -> list[Path]:
    out: list[Path] = []
    for base in (os.environ.get("ProgramFiles(x86)", ""), os.environ.get("ProgramFiles", "")):
        vdf = Path(base) / "Steam" / "steamapps" / "libraryfolders.vdf"
        try:
            text = vdf.read_text(encoding="utf-8", errors="ignore")[:200000]
        except OSError:
            continue
        for m in re.finditer(r'"path"\s+"([^"]+)"', text):
            out.append(Path(m.group(1).replace("\\\\", chr(92))) / "steamapps" / "common")
    return out


def hot_zones(mode: str, extra: list[str] | None = None) -> list[Path]:
    home = Path(os.environ.get("USERPROFILE", str(Path.home())))
    la, ra = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local")), Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
    z = [home / "Downloads", home / "Desktop", Path(os.environ.get("TEMP", la / "Temp")), Path(os.environ.get("ProgramData", r"C:\ProgramData")),
         Path(os.environ.get("PUBLIC", r"C:\Users\Public")), Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Temp"]
    if mode != "quick":
        z += [la, ra, home / "Documents"] + steam_library_dirs()
        for p in (r"C:\Program Files\Epic Games", r"C:\Program Files (x86)\GOG Galaxy\Games", r"C:\GOG Games", r"C:\Games"):
            z.append(Path(p))
    z += [Path(x) for x in (extra or [])]
    seen, out = set(), []
    for p in z:
        k = ps.norm_path(p)
        if k and k not in seen and p.is_dir():
            seen.add(k)
            out.append(p)
    return out


def enumerate_zone(roots: list[Path], max_files: int = 150000, modified_within_days: int | None = None, skip_dirs: tuple = (), cancelled=lambda: False) -> ZoneResult:
    """Lista executáveis/scripts. NÃO segue junctions/symlinks, NÃO abre placeholders de nuvem (OneDrive) e só olha discos fixos locais."""
    zr = ZoneResult(roots=[str(r) for r in roots])
    skip = tuple(ps.norm_path(s) for s in skip_dirs if s)
    cutoff = time.time() - modified_within_days * 86400 if modified_within_days else 0
    seen: set[str] = set()
    stack = [str(r) for r in roots]
    while stack:
        if cancelled():
            raise InterruptedError
        d = stack.pop()
        nd = ps.norm_path(d)
        if any(nd == s or nd.startswith(s + chr(92)) for s in skip):
            continue
        if ps.path_kind(d) != "local":
            zr.skipped_nonlocal += 1
            continue
        try:
            with os.scandir(d) as it:
                entries = list(it)
        except OSError:
            zr.skipped_error += 1
            continue
        for e in entries:
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                zr.skipped_error += 1
                continue
            attrs = getattr(st, "st_file_attributes", 0)
            if attrs & ATTR_REPARSE:
                zr.skipped_reparse += 1
                continue
            if attrs & (ATTR_OFFLINE | ATTR_RECALL_OPEN | ATTR_RECALL_DATA):
                zr.skipped_cloud += 1
                continue
            if e.is_dir(follow_symlinks=False):
                stack.append(e.path)
                continue
            if os.path.splitext(e.name)[1].lower() not in EXEC_EXT:
                continue
            if st.st_size > MAX_FILE:
                zr.skipped_big += 1
                continue
            if cutoff and st.st_mtime < cutoff:
                continue
            k = ps.norm_path(e.path)
            if k in seen:
                continue
            seen.add(k)
            zr.files.append(e.path)
            if len(zr.files) >= max_files:
                zr.truncated = True
                return zr
    return zr
