"""Verificações estáticas: hash, tipo, origem, VirusTotal, Defender, assinatura, extração segura e heurísticas."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import struct
import subprocess
import tempfile
import time
import unicodedata
import zipfile
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib import error, parse, request

from .scoring import Finding, gap

CREATE_NO_WINDOW = 0x08000000

EXEC_KINDS = {
    ".exe": "exe", ".scr": "exe", ".com": "exe", ".msi": "msi", ".bat": "bat", ".cmd": "bat", ".ps1": "ps1",
    ".vbs": "wsh", ".vbe": "wsh", ".js": "wsh", ".jse": "wsh", ".wsf": "wsh", ".wsh": "wsh", ".hta": "hta", ".lnk": "lnk",
}
SCRIPT_EXT = {".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta"}
LIB_EXT = {".dll", ".sys", ".ocx", ".asi", ".drv", ".pyd", ".node", ".cpl", ".xll"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".iso", ".img", ".vhd", ".vhdx", ".cab", ".wim",
               ".msix", ".appx", ".msixbundle", ".appxbundle"}
CONTAINER_EXT = {".jar", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".apk", ".vsix", ".nupkg", ".odt", ".ods"}
# Conteúdo que não roda no sandbox mas PODE ser perigoso: é inspecionado estaticamente (ou vira lacuna se não der)
INSPECT_EXT = {".jar", ".py", ".pyw", ".reg", ".url", ".inf", ".scf", ".sct", ".chm", ".doc", ".xls", ".ppt", ".docm", ".xlsm",
               ".pptm", ".dotm", ".xlam", ".cpl", ".xll", ".pyd", ".node", ".lnk", ".gadget",
               ".rtf", ".pdf", ".rdp", ".msc", ".settingcontent-ms", ".application", ".diagcab", ".psm1", ".psd1", ".sh", ".ps1xml", ".appref-ms"}
UNINSPECTABLE_EXT = {".chm", ".gadget", ".diagcab", ".application", ".appref-ms", ".msc"}
# Lista POSITIVA: só estes tipos são considerados dados inertes (sem conteúdo executável). Qualquer outra extensão
# desconhecida vira "não verificado" em vez de "sem conteúdo executável".
INERT_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tga", ".dds", ".webp", ".ico", ".svg", ".psd", ".tif", ".tiff", ".exr", ".hdr", ".cur", ".ani",
    ".ogg", ".mp3", ".wav", ".flac", ".wma", ".m4a", ".opus", ".mid", ".bank", ".wem", ".bnk", ".fsb", ".xwm",
    ".mp4", ".webm", ".mkv", ".avi", ".mov", ".bik", ".bk2", ".wmv",
    ".ttf", ".otf", ".woff", ".woff2", ".fnt",
    ".txt", ".md", ".ini", ".cfg", ".conf", ".json", ".xml", ".yaml", ".yml", ".csv", ".log", ".toml", ".css",
    # formatos comuns de mods/jogos/projetos (dados ou código que só roda dentro do próprio jogo/ferramenta)
    ".pex", ".psc", ".seq", ".strings", ".dlstrings", ".ilstrings", ".swf", ".tri", ".egm", ".lip", ".fuz", ".meta", ".gfx", ".ymt", ".rel",
    ".nbt", ".snbt", ".pdb", ".mdb", ".manifest", ".config", ".info", ".pyi", ".typed", ".lock", ".ipynb", ".ts", ".ytyp", ".ycd", ".mcmeta",
    ".gitignore", ".gitattributes", ".editorconfig", ".sig", ".sha256", ".md5", ".crt", ".pem",
    ".license", ".nfo", ".diz", ".srt", ".ass", ".properties", ".lang", ".map", ".mcmeta", ".dat", ".bin", ".db", ".sqlite", ".sav", ".save",
    ".pak", ".bsa", ".ba2", ".esp", ".esm", ".esl", ".unity3d", ".assets", ".resource", ".resS", ".bundle", ".nif", ".hkx", ".kf", ".mesh",
    ".material", ".shader", ".fx", ".hlsl", ".glsl", ".obj", ".fbx", ".blend", ".gltf", ".glb", ".pk3", ".wad", ".vpk", ".gcf", ".rpf", ".ytd",
    ".ydr", ".yft", ".ydd", ".ymap", ".ybn", ".awc", ".rpa", ".xnb", ".tmx", ".tsx", ".atlas", ".skel", ".scml", ".cache", ".ldb",
}
# Parecem dados, mas executam código no programa que os abre: não são "inertes"; são inspecionados por padrões de risco,
# sem exigir que o resto do pacote perca a confiança só por existirem (muito comuns em mods e jogos).
SOFT_CODE_EXT = {".lua", ".rpy", ".html", ".htm", ".svg"}
KIND_LABEL = {
    "exe": "Executável Windows", "msi": "Instalador MSI", "bat": "Script em lote", "ps1": "Script PowerShell",
    "wsh": "Script Windows (VBS/JS)", "hta": "Aplicação HTML", "lnk": "Atalho", "archive": "Arquivo compactado",
    "lib": "Biblioteca (DLL)", "dll": "Biblioteca (teste via rundll32)", "jar": "Pacote Java (.jar)", "other": "Arquivo",
}

MAX_EXTRACT_BYTES = 2 * 1024**3
MAX_FILES = 20000
MIN_VT_AGE_DAYS = 30


def _create_file_error(path: Path) -> int:
    """Abre o arquivo direto pela API do Windows para ler o erro real (o open() do Python o esconde atrás de EINVAL)."""
    try:
        import ctypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateFileW.restype = ctypes.c_void_p
        k32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        h = k32.CreateFileW(str(path), 0x80000000, 7, None, 3, 0x80, None)
        if h in (None, ctypes.c_void_p(-1).value):
            return ctypes.get_last_error()
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        k32.CloseHandle(h)
    except Exception:
        pass
    return 0


def av_blocked(e: OSError, path: Path | None = None) -> bool:
    """True só quando o antivírus em tempo real barrou o acesso (ERROR_VIRUS_INFECTED = 225 / 226 = PUA).
    Arquivo ausente, nome inválido ou permissão NÃO contam: isso é erro comum, não malware."""
    if getattr(e, "winerror", 0) in (225, 226):
        return True
    if e.errno == 22 and path is not None and not isinstance(e, FileNotFoundError):
        return _create_file_error(path) in (225, 226)
    return False


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


# ---------------------------------------------------------------- identificação

def hash_file(path: Path) -> dict[str, str]:
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(4 << 20):
            md5.update(chunk), sha1.update(chunk), sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def sniff_magic(path: Path) -> str:
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError:
        return "other"
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] == b"PK\x03\x04" or head[:4] == b"PK\x05\x06":
        return "zip"
    if head[:4] == b"Rar!":
        return "rar"
    if head[:4] == b"7z\xbc\xaf":
        return "7z"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:4] == b"\xd0\xcf\x11\xe0":
        return "ole"
    if head[:4] == b"%PDF":
        return "pdf"
    return "other"


def classify(path: Path, magic: str) -> str:
    ext = path.suffix.lower()
    if ext in ARCHIVE_EXT or magic in ("rar", "7z", "gzip") or (magic == "zip" and ext not in CONTAINER_EXT):
        return "archive"
    if ext == ".jar":
        return "jar"
    if ext in EXEC_KINDS:
        return EXEC_KINDS[ext]
    if ext in LIB_EXT:
        return "lib"
    if magic == "pe":
        return "exe"
    return "other"


_DOUBLE_EXT = re.compile(r"\.(jpe?g|png|gif|pdf|docx?|xlsx?|pptx?|txt|mp3|mp4|zip|rar|7z|iso)\.(exe|scr|bat|cmd|com|vbs|js|ps1|msi|lnk|hta)$", re.I)
_DOC_EXT = {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".mp3", ".mp4", ".bmp", ".ini", ".json", ".cfg"}


def name_tricks(path: Path, magic: str) -> list[Finding]:
    out: list[Finding] = []
    name = path.name
    if "\u202e" in name:
        out.append(Finding("static", "Nome com caractere de inversão (RTL)", "Técnica para esconder a extensão real.", 40, "high"))
    if _DOUBLE_EXT.search(name):
        out.append(Finding("static", "Dupla extensão enganosa", f"“{name}” parece um documento, mas é executável.", 30, "high"))
    if magic == "pe" and path.suffix.lower() in _DOC_EXT:
        out.append(Finding("static", "Extensão não corresponde ao conteúdo",
                           f"Termina em {path.suffix} mas contém um executável Windows.", 35, "high"))
    return out


# ---------------------------------------------------------------- origem (Mark of the Web)

# Só sites controlados pelo próprio fabricante dão crédito. Hospedagens de conteúdo de terceiros (GitHub, Nexus, CurseForge,
# itch.io, Steam Workshop…) já distribuíram malware: são apenas informativas, sem crédito.
_TRUSTED_HOSTS = ("microsoft.com", "mozilla.org", "videolan.org", "7-zip.org", "python.org", "gog.com", "epicgames.com", "steampowered.com")
_UGC_HOSTS = ("github.com", "githubusercontent.com", "nexusmods.com", "steamcommunity.com", "gamebanana.com", "moddb.com",
              "curseforge.com", "modrinth.com", "itch.io", "mediafire.com", "mega.nz", "drive.google.com", "dropbox.com", "discordapp.com")
_RISKY_HOSTS = ("bit.ly", "tinyurl.com", "ouo.io", "linkvertise.com", "adf.ly", "pastebin.com", "anonfiles", "gofile.io")


def origin_check(path: Path) -> list[Finding]:
    try:
        with open(str(path) + ":Zone.Identifier", "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return []
    def host_of(key: str) -> str:
        m = re.search(rf"{key}=(\S+)", text)
        return (parse.urlparse(m.group(1)).hostname or "").lower() if m else ""

    host = host_of("HostUrl")  # servidor de onde o arquivo foi baixado (o ReferrerUrl é só a página e não conta)
    page = host_of("ReferrerUrl")
    if not host:
        return [Finding("origin", "Baixado da internet", "O Windows marcou o arquivo, mas sem registrar o servidor de origem.", 0, "info")]
    on = lambda hosts: any(host == t or host.endswith("." + t) for t in hosts)
    if on(_TRUSTED_HOSTS):
        return [Finding("origin", f"Baixado do site do fabricante: {host}", "Site controlado pelo próprio fornecedor.", -5, "low")]
    if any(r in host for r in _RISKY_HOSTS):
        return [Finding("origin", f"Origem via encurtador/hospedagem anônima: {host}",
                        "Esses serviços são muito usados para distribuir adware e malware.", 8, "low")]
    if on(_UGC_HOSTS):
        return [Finding("origin", f"Hospedagem de conteúdo de terceiros: {host}",
                        "Qualquer pessoa pode publicar aqui, inclusive malware. Não é prova de segurança." + (f" Página: {page}" if page else ""), 0, "info")]
    return [Finding("origin", f"Origem: {host}", "Site sem classificação conhecida.", 0, "info")]


# ---------------------------------------------------------------- VirusTotal

MAJOR_ENGINES = {
    "Microsoft", "Kaspersky", "ESET-NOD32", "BitDefender", "Sophos", "Symantec", "CrowdStrike", "McAfee", "Trellix", "TrendMicro",
    "Avast", "AVG", "Malwarebytes", "Fortinet", "Google", "Palo Alto Networks", "Emsisoft", "F-Secure", "GData", "DrWeb",
    "Avira", "ClamAV", "Elastic", "SentinelOne", "Panda", "K7AntiVirus", "Cylance", "Ikarus", "Arcabit", "VIPRE", "eScan",
}


def is_major(engine: str) -> bool:
    """Os nomes no VT variam ('Avira (no cloud)', 'Trellix (ENS)', 'SentinelOne (Static ML)'): compara só o prefixo."""
    base = re.split(r"\s*\(", engine, maxsplit=1)[0].strip()
    return engine in MAJOR_ENGINES or base in MAJOR_ENGINES


# Detecções genéricas/heurísticas (alta chance de falso positivo). NÃO inclui nomes de família (Agent, Kryptik, RedLine…).
_GENERIC = re.compile(r"(?i)(generic|\bheur\b|heur:|heuristic|!ml\b|\bml\.|\.ml\b|unsafe|suspicious|\bsusp\b|malware\.?ai|gen:variant|"
                      r"riskware|\bpua\b|unwanted|potentially|artemis|undefined|packed\.)")


class VirusTotal:
    """Consulta por hash (o arquivo nunca é enviado). Respeita o limite gratuito de 4 req/min."""

    def __init__(self, key: str) -> None:
        self.key = key
        self._stamps: deque[float] = deque()
        self.cache: dict[str, dict] = {}

    def _wait_slot(self, status, cancelled) -> None:
        while True:
            now = time.time()
            while self._stamps and now - self._stamps[0] > 60:
                self._stamps.popleft()
            if len(self._stamps) < 4:
                self._stamps.append(now)
                return
            wait = 60 - (now - self._stamps[0]) + 0.5
            for _ in range(int(wait * 2) + 1):
                if cancelled():
                    raise InterruptedError
                status(f"Aguardando limite gratuito da API ({max(0, wait - _ / 2):.0f} s)…")
                time.sleep(0.5)

    def lookup(self, sha256: str, status=lambda m: None, cancelled=lambda: False) -> dict:
        if sha256 in self.cache:
            return self.cache[sha256]
        self._wait_slot(status, cancelled)
        req = request.Request(f"https://www.virustotal.com/api/v3/files/{sha256}",
                              headers={"x-apikey": self.key, "accept": "application/json", "User-Agent": "Sentinela/1.0"})
        result: dict
        try:
            with request.urlopen(req, timeout=30) as r:
                attrs = json.loads(r.read())["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            engines = {k: v for k, v in attrs.get("last_analysis_results", {}).items()}
            result = {
                "found": True, "stats": stats, "engines": engines, "first_seen": attrs.get("first_submission_date"),
                "name": attrs.get("meaningful_name"), "link": f"https://www.virustotal.com/gui/file/{sha256}",
            }
        except error.HTTPError as e:
            if e.code == 404:
                result = {"found": False}
            elif e.code in (401, 403):
                result = {"error": "Chave de API do VirusTotal inválida."}
            elif e.code == 429:
                result = {"error": "Limite da API do VirusTotal excedido (tente em 1 minuto)."}
            else:
                result = {"error": f"VirusTotal respondeu HTTP {e.code}."}
        except (error.URLError, TimeoutError, OSError, ValueError) as e:
            result = {"error": f"Sem conexão com o VirusTotal ({e.__class__.__name__})."}
        if "error" not in result:
            self.cache[sha256] = result
        return result


def vt_findings(res: dict, label: str, executable: bool) -> tuple[list[Finding], str]:
    """Converte o resultado do VT em achados ponderados. Retorna (achados, resumo curto)."""
    pre = f"{label}: " if label else ""
    if "error" in res:
        return [Finding("vt", pre + "VirusTotal indisponível", res["error"], 0, "info", gap=True)], res["error"]
    if not res.get("found"):
        pts = 10 if executable else 0
        return ([Finding("vt", pre + "Arquivo nunca visto pelo VirusTotal",
                         "Sem histórico de reputação. É normal em mods novos, mas também em malware recém-compilado.", pts,
                         "low" if pts else "info", gap=True)], "desconhecido no VirusTotal")
    stats = res["stats"]
    mal = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total = sum(stats.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
    hits = {n: v for n, v in res["engines"].items() if v.get("category") in ("malicious", "suspicious")}
    generic = {n for n, v in hits.items() if _GENERIC.search(v.get("result") or "")}
    major = [n for n in hits if is_major(n)]
    specific_major = [n for n in major if n not in generic]
    sample = "; ".join(f"{n}: {hits[n].get('result')}" for n in list(hits)[:6])
    ratio = f"{mal}/{total}"
    detail = sample + "\n" + res.get("link", "")
    if len(specific_major) >= 2 or (mal >= 12 and len(generic) < 0.7 * len(hits)):
        f = Finding("vt", pre + f"Detectado por {ratio} antivírus", detail, 80, "critical")
    elif mal >= 12:  # muitas detecções, mas quase todas genéricas: típico de trainer/crack legítimo compactado
        f = Finding("vt", pre + f"{ratio} detecções, a maioria genéricas", "Provável falso positivo, mas confira a origem.\n" + detail, 35, "high")
    elif len(major) >= 3 or mal >= 5:
        f = Finding("vt", pre + f"Detectado por {ratio} antivírus", detail, 45, "high")
    elif mal >= 1:
        if all(n in generic or not is_major(n) for n in hits):
            f = Finding("vt", pre + f"{ratio} detecções genéricas (provável falso positivo)",
                        "Só antivírus menores ou com nomes genéricos (heurística). " + detail, 6, "low")
        else:
            f = Finding("vt", pre + f"{ratio} detecções, incluindo antivírus conhecidos", detail, 20, "medium")
    elif total >= 40:
        first = res.get("first_seen")
        age_days = (time.time() - first) / 86400 if isinstance(first, (int, float)) and first > 0 else None
        if age_days is not None and age_days >= MIN_VT_AGE_DAYS:
            f = Finding("vt", pre + f"Limpo em {total} antivírus há {int(age_days)} dias", "Nenhum motor sinalizou o arquivo.\n" + res.get("link", ""),
                        -15, "info", trust=True)
        else:
            # "pré-aquecido": um arquivo recém-enviado com 0 detecções ainda não tem reputação (assinaturas demoram dias para surgir)
            idade = "idade desconhecida" if age_days is None else f"visto pela 1ª vez há {max(0, int(age_days))} dia(s)"
            f = Finding("vt", pre + f"Limpo em {total} antivírus, mas o registro é recente ({idade})",
                        f"Menos de {MIN_VT_AGE_DAYS} dias de histórico: ainda não conta como reputação.\n" + res.get("link", ""), 0, "info", gap=True)
    else:
        f = Finding("vt", pre + f"Sem detecções ({total} motores)", res.get("link", ""), 0, "info")
    return [f], f"{ratio} detecções"


# ---------------------------------------------------------------- Defender

@dataclass
class DefenderResult:
    ran: bool
    threats: list[str] = field(default_factory=list)
    error: str = ""


def find_mpcmdrun() -> Path | None:
    base = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft" / "Windows Defender" / "Platform"
    key = lambda p: [int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", p.parent.name)]
    cands = sorted(base.glob("*/MpCmdRun.exe"), key=key, reverse=True)
    if cands:
        return cands[0]
    p = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender" / "MpCmdRun.exe"
    return p if p.exists() else None


def defender_scan(target: Path, timeout: int = 900) -> DefenderResult:
    mp = find_mpcmdrun()
    if not mp:
        return DefenderResult(False, error="Microsoft Defender não encontrado.")
    try:
        p = subprocess.run([str(mp), "-Scan", "-ScanType", "3", "-File", str(target), "-DisableRemediation"],
                           capture_output=True, text=True, errors="replace", timeout=timeout, creationflags=CREATE_NO_WINDOW)
    except subprocess.TimeoutExpired:
        return DefenderResult(False, error="A verificação do Defender excedeu o tempo limite.")
    except OSError as e:
        return DefenderResult(False, error=str(e))
    out = (p.stdout or "") + (p.stderr or "")
    threats = [t.strip() for t in re.findall(r"(?im)^\s*(?:Threat|Amea[cç]a)\s*:\s*(.+?)\s*$", out)]
    # "found no threats" / "found 2 threats" (o código de saída 2 também é usado para erros, então não basta)
    m = re.search(r"found\s+(\d+)\s+threat", out, re.I)
    count = int(m.group(1)) if m else 0
    if threats or count > 0:
        return DefenderResult(True, threats or [f"{count} ameaça(s) detectada(s) (nome não informado)"])
    if p.returncode == 0 and re.search(r"found\s+no\s+threat", out, re.I):
        return DefenderResult(True)
    if p.returncode == 0:
        return DefenderResult(True)
    return DefenderResult(False, error=f"O Defender não concluiu a verificação (código {p.returncode}).")


# ---------------------------------------------------------------- assinatura digital

_PS_SIG = r"""
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$paths = $env:SENT_PATHS | ConvertFrom-Json
$res = foreach ($p in $paths) {
  $s = Get-AuthenticodeSignature -LiteralPath $p
  [pscustomobject]@{ path=$p; status=[string]$s.Status; subject=[string]$s.SignerCertificate.Subject }
}
ConvertTo-Json -InputObject @($res) -Compress
"""


def check_signatures(paths: list[Path]) -> dict[str, dict]:
    if not paths:
        return {}
    env = dict(os.environ, SENT_PATHS=json.dumps([str(p) for p in paths]))
    try:
        p = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _PS_SIG], env=env,
                           capture_output=True, timeout=180, creationflags=CREATE_NO_WINDOW)
        data = json.loads(p.stdout.decode("utf-8", "replace") or "[]")
    except (subprocess.SubprocessError, ValueError, OSError):
        return {}
    return {d["path"]: d for d in data if isinstance(d, dict) and "path" in d}


def publisher(subject: str) -> str:
    m = re.search(r'CN=("([^"]+)"|([^,]+))', subject or "")
    return (m.group(2) or m.group(3)).strip() if m else "publicador desconhecido"


_PS_SIG_EX = r"""
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$paths = $env:SENT_PATHS | ConvertFrom-Json
$res = foreach ($p in $paths) {
  $s = Get-AuthenticodeSignature -LiteralPath $p
  $c = $s.SignerCertificate
  [pscustomobject]@{ path=$p; status=[string]$s.Status; subject=[string]$c.Subject; issuer=[string]$c.Issuer; thumb=[string]$c.Thumbprint }
}
ConvertTo-Json -InputObject @($res) -Compress
"""


def run_powershell(script: str, env_extra: dict | None = None, timeout: float = 60, cancelled=lambda: False) -> str | None:
    """Roda um script PowerShell sem janela. Devolve a saída, ou None se falhou/estourou o tempo/foi cancelado (nunca lança)."""
    env = dict(os.environ, **(env_extra or {}))
    try:
        proc = subprocess.Popen(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
    except OSError:
        return None
    deadline = time.time() + timeout
    out = b""
    while True:
        try:
            out, _ = proc.communicate(timeout=0.25)
            return out.decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            if cancelled() or time.time() > deadline:
                proc.kill()
                proc.communicate()
                return None


def verify_signatures(paths: list[str], cancelled=lambda: False, batch: int = 40, timeout: float = 90) -> dict[str, dict]:
    """Assinatura Authenticode em lotes. Distingue 'verificado' de 'a verificação falhou':
    cada caminho recebe verified=True (status veio do Windows) ou verified=False/status 'CheckFailed' (lote que estourou o tempo)."""
    out: dict[str, dict] = {}
    for i in range(0, len(paths), batch):
        part = paths[i:i + batch]
        if cancelled():
            raise InterruptedError
        raw = run_powershell(_PS_SIG_EX, {"SENT_PATHS": json.dumps(part)}, timeout, cancelled)
        data = None
        if raw is not None:
            try:
                data = json.loads(raw or "[]")
            except ValueError:
                data = None
        got = {d["path"]: d for d in data if isinstance(d, dict) and isinstance(d.get("path"), str)} if isinstance(data, list) else {}
        if cancelled():
            raise InterruptedError
        for p in part:
            d = got.get(p)
            if d is None:
                out[p] = {"path": p, "status": "CheckFailed", "subject": "", "issuer": "", "thumb": "", "verified": False}
            else:
                out[p] = {"path": p, "status": str(d.get("status") or ""), "subject": str(d.get("subject") or ""),
                          "issuer": str(d.get("issuer") or ""), "thumb": str(d.get("thumb") or ""), "verified": True}
    return out


def dn_fields(dn: str) -> dict[str, str]:
    """Campos de um Distinguished Name (CN, O, L, C…). Compare sempre vários campos, nunca só o CN."""
    fields: dict[str, str] = {}
    for m in re.finditer(r'(?:^|,\s*)([A-Za-z]+)=("(?:[^"]|"")*"|[^,]*)', dn or ""):
        v = m.group(2).strip()
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1].replace('""', '"')
        fields.setdefault(m.group(1).upper(), v)
    return fields


# ---------------------------------------------------------------- extração segura

@dataclass
class ExtractResult:
    tool: str = ""
    files: int = 0
    bytes: int = 0
    encrypted: bool = False
    bomb: bool = False
    slip: int = 0
    blocked: list[str] = field(default_factory=list)
    error: str = ""
    listed: int = 0  # nº de arquivos que o parser diz existirem (para comparar com outro parser)
    names: set = field(default_factory=set)  # nomes ASCII (normalizados) que o parser diz existirem
    entries: object = None  # Counter de (tamanho, CRC32) por arquivo: independe de como cada leitor decodifica os nomes


def norm_name(n: str) -> str:
    return unicodedata.normalize("NFC", n.replace("\\", "/").strip("/")).lower()


def ascii_names(names) -> set:
    """Só nomes ASCII entram na comparação: acentos/CJK podem ser decodificados de forma diferente por cada leitor (não é ataque)."""
    return {n for n in names if n.isascii()}


def dir_size(path: Path) -> int:
    total = 0
    try:
        with os.scandir(path) as it:
            for e in it:
                try:
                    total += dir_size(Path(e.path)) if e.is_dir(follow_symlinks=False) else e.stat(follow_symlinks=False).st_size
                except OSError:
                    pass
    except OSError:
        pass
    return total


def _extract_zip(src: Path, dest: Path) -> ExtractResult:
    r = ExtractResult(tool="zipfile")
    try:
        zf = zipfile.ZipFile(src)
    except (zipfile.BadZipFile, OSError) as e:
        r.error = f"ZIP inválido ou corrompido ({e.__class__.__name__})."
        return r
    with zf:
        infos = zf.infolist()
        total = sum(i.file_size for i in infos)
        comp = sum(i.compress_size for i in infos) or 1
        if len(infos) > MAX_FILES or total > MAX_EXTRACT_BYTES or (total > 200 << 20 and total / comp > 500):
            r.bomb = True
            r.error = f"{len(infos)} itens, {human_size(total)} descompactado (taxa {total / comp:.0f}x)."
            return r
        base = dest.resolve()
        for info in infos:
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                r.encrypted = True
                continue
            if ":" in info.filename:
                r.slip += 1
                continue
            target = (dest / info.filename).resolve()
            if base not in target.parents:
                r.slip += 1
                continue
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as s, open(target, "wb") as d:
                    while chunk := s.read(1 << 20):
                        r.bytes += len(chunk)
                        if r.bytes > MAX_EXTRACT_BYTES:
                            r.bomb = True
                            r.error = "Conteúdo real excede o limite de segurança."
                            return r
                        d.write(chunk)
                r.files += 1
            except OSError as e:
                if av_blocked(e, target):
                    r.blocked.append(info.filename)
                else:
                    r.error = r.error or f"Falha ao extrair {info.filename} ({e.__class__.__name__})."
        r.listed = sum(1 for i in infos if not i.is_dir())
        r.names = ascii_names(norm_name(i.filename) for i in infos if not i.is_dir())
        r.entries = Counter((i.file_size, i.CRC) for i in infos if not i.is_dir())
    return r


def _find_7z() -> str | None:
    for p in (shutil.which("7z"), r"C:\Program Files\7-Zip\7z.exe", r"C:\Program Files (x86)\7-Zip\7z.exe"):
        if p and Path(p).exists():
            return p
    return None


def list_7z(src: Path) -> dict | None:
    """Lista o arquivo com o 7-Zip (parser independente). Retorna {'files': n, 'encrypted': bool, 'unreadable': bool}."""
    sz = _find_7z()
    if not sz:
        return None
    try:
        p = subprocess.run([sz, "l", "-slt", "-bd", "-sccUTF-8", str(src)], stdin=subprocess.DEVNULL, capture_output=True,
                           timeout=120, creationflags=CREATE_NO_WINDOW)
    except (subprocess.SubprocessError, OSError):
        return None
    out = (p.stdout or b"").decode("utf-8", "replace")
    low = (out + (p.stderr or b"").decode("utf-8", "replace")).lower()
    if "----------" not in out:  # não conseguiu nem listar (cabeçalho cifrado, corrompido…)
        enc = any(k in low for k in ("enter password", "wrong password", "break signaled", "encrypted", "cannot open encrypted"))
        return {"files": 0, "encrypted": enc, "unreadable": True}
    body = out.split("----------", 1)[1]
    blocks = [b for b in re.split(r"\r?\n\r?\n", body) if "Path = " in b]
    names, entries, files = set(), Counter(), 0
    for b in blocks:
        if re.search(r"(?m)^Folder = -", b):
            files += 1
            m = re.search(r"(?m)^Path = (.+?)\r?$", b)
            if m:
                names.add(norm_name(m.group(1)))
            size = re.search(r"(?m)^Size = (\d+)", b)
            crc = re.search(r"(?m)^CRC = ([0-9A-Fa-f]+)", b)
            entries[(int(size.group(1)) if size else 0, int(crc.group(1), 16) if crc else 0)] += 1
    return {"files": files, "names": ascii_names(names), "entries": entries,
            "encrypted": bool(re.search(r"(?m)^Encrypted = \+", body)), "unreadable": False}


def _extract_external(src: Path, dest: Path, cancelled) -> ExtractResult:
    r = ExtractResult()
    sevenzip = _find_7z()
    info = list_7z(src) if sevenzip else None
    if info:
        r.listed = info["files"]
        if info["encrypted"]:
            r.encrypted = True
            if info["unreadable"]:
                r.error = "Cabeçalho do arquivo cifrado: nem a lista de arquivos pode ser lida."
                return r
    if sevenzip:
        cmd, r.tool = [sevenzip, "x", "-y", "-bd", "-bso0", "-bsp0", f"-o{dest}", str(src)], "7-Zip"
    else:
        tar = Path(os.environ.get("windir", r"C:\Windows")) / "System32" / "tar.exe"
        if not tar.exists():
            r.error = "Nenhum extrator disponível (instale o 7-Zip para RAR/7z)."
            return r
        cmd, r.tool = [str(tar), "-xf", str(src), "-C", str(dest)], "tar"
    with tempfile.TemporaryFile() as log:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, creationflags=CREATE_NO_WINDOW)
        while proc.poll() is None:
            time.sleep(0.5)
            if cancelled():
                proc.kill()
                raise InterruptedError
            if dir_size(dest) > MAX_EXTRACT_BYTES:
                proc.kill()
                r.bomb = True
                r.error = "Conteúdo descompactado excede o limite de segurança."
                break
        log.seek(0)
        text = log.read().decode("utf-8", "replace").lower()
    if not r.bomb and proc.returncode not in (0, None):
        if any(k in text for k in ("password", "senha", "encrypted", "break signaled")):
            r.encrypted = True
        else:
            r.error = "Falha ao extrair (arquivo corrompido ou formato não suportado)."
    for p in dest.rglob("*"):
        if p.is_file():
            r.files += 1
            r.bytes += p.stat().st_size
    return r


def extract_archive(src: Path, dest: Path, magic: str, cancelled=lambda: False) -> ExtractResult:
    dest.mkdir(parents=True, exist_ok=True)
    if magic == "zip":
        return _extract_zip(src, dest)
    return _extract_external(src, dest, cancelled)


# ---------------------------------------------------------------- heurísticas estáticas

_API_GROUPS = {
    "injeção de código": ([b"WriteProcessMemory", b"CreateRemoteThread", b"VirtualAllocEx", b"NtUnmapViewOfSection", b"QueueUserAPC"], 3, 15),
    "captura de teclado/área de transferência": ([b"SetWindowsHookEx", b"GetAsyncKeyState", b"GetKeyboardState", b"GetClipboardData"], 3, 10),
    "marcadores de ransomware": ([b"CryptEncrypt", b"BCryptEncrypt", b".onion", b"bitcoin", b"YOUR FILES", b"README_DECRYPT"], 3, 15),
}
_ALL_NAMES = [n for names, _, _ in _API_GROUPS.values() for n in names]
MAX_PE_SCAN = 512 << 20


def _is_word_char(b: bytes) -> bool:
    return bool(b) and (b.isalnum() or b == b"_")


def _has_word(data: bytes, name: bytes) -> bool:
    """Procura `name` como palavra inteira (com sufixo A/W opcional): 'CryptEncrypt' não casa dentro de 'BCryptEncrypt'."""
    start = 0
    while (i := data.find(name, start)) >= 0:
        before = data[i - 1:i] if i else b""
        after = data[i + len(name): i + len(name) + 2]
        if not _is_word_char(before):
            a = after[:1]
            if not _is_word_char(a) or (a in (b"A", b"W") and not _is_word_char(after[1:2])):
                return True
        start = i + 1
    return False


def _find_names(path: Path, names: list[bytes]) -> tuple[set[bytes], bool]:
    """Varre o arquivo inteiro (até MAX_PE_SCAN) em janelas, em ASCII e UTF-16. Retorna (achados, truncado)."""
    found: set[bytes] = set()
    wide = {n: n.decode("latin-1").encode("utf-16le") for n in names}
    carry, total = b"", 0
    with open(path, "rb") as f:
        while chunk := f.read(8 << 20):
            total += len(chunk)
            data = carry + chunk
            for n in names:
                if n not in found and (_has_word(data, n) or data.find(wide[n]) >= 0):
                    found.add(n)
            carry = data[-256:]
            if total >= MAX_PE_SCAN:
                return found, True
    return found, False


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


# (regex, título, pontos, severidade, extensões onde vale (None = todas))
_SCRIPT_RULES: list[tuple[str, str, int, str, set | None]] = [
    (r"-e[a-z]{0,15}\s+[A-Za-z0-9+/=]{20,}|frombase64string", "Comando codificado em Base64", 15, "medium", None),
    (r"invoke-expression|\biex\b", "Execução dinâmica de código (PowerShell)", 10, "medium", None),
    (r"\b(eval|execute|executeglobal)\s*\(", "Execução dinâmica de código", 10, "medium", {".vbs", ".vbe", ".wsf", ".wsh", ".hta"}),
    (r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|urldownloadtofile|certutil.*-urlcache|bitsadmin.*/transfer",
     "Baixa arquivos da internet", 15, "medium", None),
    (r"vssadmin.*delete\s+shadows|wmic.*shadowcopy.*delete|bcdedit.*(recoveryenabled|ignoreallfailures)",
     "Apaga cópias de segurança do Windows", 90, "critical", None),
    (r"set-mppreference.*disable|disablerealtimemonitoring|disableantispyware", "Desativa a proteção do Defender", 90, "critical", None),
    (r"add-mppreference.*exclusion|set-mppreference.*exclusion", "Cria exclusão no Defender", 45, "high", None),
    (r"net\s+user\s+\S+\s+\S+\s+/add", "Cria usuário no Windows", 85, "critical", None),
    (r"schtasks.*/create|reg\s+add.*\\run\b|currentversion\\run", "Cria persistência (inicia com o Windows)", 10, "medium", None),
    (r"\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup", "Escreve na pasta Inicializar", 15, "medium", None),
    (r"image file execution options", "Sequestra programas (IFEO)", 40, "high", None),
]


def _decode_text(raw: bytes) -> str:
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "ignore")
    if raw[:200].count(b"\x00") > 20:  # UTF-16 sem BOM
        return raw.decode("utf-16le", "ignore")
    return raw.decode("utf-8", "ignore")


# (regex de UMA ocorrência, título, pontos, mínimo de ocorrências no arquivo)
_OBFUSCATION: list[tuple[str, str, int, int]] = [
    # lookahead: conta cada junção 'curto'+'curto' mesmo quando encadeadas ('a'+'b'+'c')
    (r"(?=['\"][^'\"\r\n]{1,6}['\"]\s*\+\s*['\"][^'\"\r\n]{1,6}['\"])['\"]", "Strings montadas por concatenação (ofuscação)", 14, 4),
    (r"\[char\]\s*\d+|\[char\[\]\]|\bchr\w?\(\s*\d+\s*\)", "Texto montado por códigos de caracteres (ofuscação)", 14, 3),
    (r"(?:%[a-z0-9_]{1,12}(?::~[-\d,]+)?%){3,}", "Comandos montados por variáveis encadeadas (ofuscação em .bat)", 14, 1),
    (r"\[array\]::reverse|-join\s*['\"]['\"]|\.split\([^)]*\)\s*\|\s*%", "Texto invertido/remontado em tempo de execução (ofuscação)", 12, 1),
]


OBF_EXT = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".sct"}


def _obfuscation(text: str, name: str, strong_only: bool, ext: str = "") -> list[Finding]:
    """Só vale para linguagens de script do Windows: em Python/shell/Lua concatenar strings é código normal."""
    if strong_only or ext not in OBF_EXT:
        return []
    return [Finding("static", f"{name}: {title}", "", pts, "medium")
            for pattern, title, pts, need in _OBFUSCATION if len(re.findall(pattern, text, re.I)) >= need]


def analyze_text(text: str, name: str, ext: str, strong_only: bool = False) -> list[Finding]:
    """Aplica as regras ao texto original e a uma versão sem os escapes mais comuns de ofuscação (^ e `)."""
    variants = (text, text.replace("^", "").replace("`", "").replace('"', ""))
    out, seen = _obfuscation(text, name, strong_only, ext), set()
    for pattern, title, pts, sev, exts in _SCRIPT_RULES:
        if title in seen or (exts and ext not in exts) or (strong_only and pts < 35):
            continue
        if any(re.search(pattern, v, re.I) for v in variants):
            seen.add(title)
            out.append(Finding("static", f"{name}: {title}", "", pts, sev))
    return out


def analyze_pe(path: Path) -> list[Finding]:
    out: list[Finding] = []
    try:
        with open(path, "rb") as f:
            head = f.read(1024)
            if head[:2] != b"MZ":
                return out
            pe = struct.unpack_from("<I", head, 0x3C)[0]
            f.seek(pe)
            hdr = f.read(24)
            if hdr[:4] != b"PE\0\0":
                return out
            nsec, optsize = struct.unpack_from("<H", hdr, 6)[0], struct.unpack_from("<H", hdr, 20)[0]
            f.seek(pe + 24 + optsize)
            secs = []
            for _ in range(min(nsec, 40)):
                s = f.read(40)
                if len(s) < 40:
                    break
                name = s[:8].rstrip(b"\0").decode("latin-1", "replace")
                raw_size, raw_ptr = struct.unpack_from("<II", s, 16)
                secs.append((name, raw_size, raw_ptr))
            packed = []
            for name, size, ptr in secs:
                if size < 16384:
                    continue
                f.seek(ptr)
                e = _entropy(f.read(min(size, 2 << 20)))
                if e > 7.3:
                    packed.append(f"{name} ({e:.2f})")
            names = {n.lower() for n, _, _ in secs}
            if names & {".themida", ".vmp0", ".vmp1", ".enigma1", ".enigma2"}:
                out.append(Finding("static", f"{path.name}: protetor/ofuscador comercial", "Themida/VMProtect/Enigma escondem o código real.", 12, "medium"))
            elif {"upx0", "upx1"} <= names:
                out.append(Finding("static", f"{path.name}: compactado com UPX", "Comum em software legítimo pequeno, mas também em malware.", 4, "low"))
            elif packed:
                out.append(Finding("static", f"{path.name}: seções com alta entropia", "Indica conteúdo compactado/criptografado: " + ", ".join(packed[:3]), 8, "low"))
        found, truncated = _find_names(path, _ALL_NAMES)
    except (OSError, struct.error):
        return out
    if truncated:
        out.append(gap(f"{path.name}: só os primeiros {MAX_PE_SCAN >> 20} MB foram varridos", "O restante do arquivo não foi inspecionado."))
    for label, (apis, need, pts) in _API_GROUPS.items():
        hit = [a.decode() for a in apis if a in found]
        if len(hit) >= need:
            out.append(Finding("static", f"{path.name}: usa APIs de {label}",
                               ", ".join(hit) + "\nTrainers e cheats legítimos também usam isso, mas é um sinal de atenção.", pts, "medium"))
    return out


def analyze_script(path: Path, strong_only: bool = False) -> list[Finding]:
    try:
        raw = path.read_bytes()[: 2 << 20]
    except OSError:
        return []
    return analyze_text(_decode_text(raw), path.name, path.suffix.lower(), strong_only)


_INTERPRETERS = re.compile(r"(?i)(powershell|cmd\.exe|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin)")


def analyze_lnk(path: Path) -> list[Finding]:
    try:
        raw = path.read_bytes()[: 1 << 20]
    except OSError:
        return []
    text = raw.decode("utf-16le", "ignore") + " " + raw.decode("latin-1")
    out = analyze_text(text, path.name, ".lnk")
    if _INTERPRETERS.search(text):
        out.append(Finding("static", f"{path.name}: o atalho executa um interpretador/ferramenta do Windows",
                           "Atalhos legítimos de jogos apontam para o .exe, não para PowerShell/cmd/mshta.", 20, "medium"))
    return out


_JAR_MARKERS: list[tuple[re.Pattern, str, int, str]] = [
    (re.compile(rb"discord(app)?\.com/api/webhooks", re.I), "envia dados para um webhook do Discord (típico de ladrão de contas)", 45, "high"),
    (re.compile(rb"Login Data|Local State|logins\.json|key4\.db|Cookies"), "lê dados de navegador (senhas/cookies)", 40, "high"),
    (re.compile(rb"java/lang/ProcessBuilder|java/lang/Runtime"), "executa processos do sistema", 12, "medium"),
    (re.compile(rb"java/net/URLClassLoader"), "carrega código remoto/dinâmico", 10, "medium"),
    (re.compile(rb"powershell|cmd\.exe\s*/c", re.I), "chama PowerShell/cmd", 15, "medium"),
]


def analyze_jar(path: Path) -> list[Finding]:
    out: list[Finding] = []
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            bad = [i.filename for i in infos if i.filename.lower().endswith((".exe", ".bat", ".cmd", ".ps1", ".vbs", ".scr", ".hta"))]
            if bad:
                out.append(Finding("static", f"{path.name}: contém executável/script do Windows embutido", ", ".join(bad[:4]), 25, "medium"))
            blob, budget = [], 24 << 20
            for i in infos:
                if i.filename.endswith((".class", ".txt", ".json", ".properties")) and i.file_size < (4 << 20) and budget > 0:
                    data = zf.read(i)
                    budget -= len(data)
                    blob.append(data)
            data = b"\n".join(blob)
    except (zipfile.BadZipFile, OSError, RuntimeError):
        return [gap(f"{path.name}: .jar ilegível ou protegido", "Não foi possível inspecionar o conteúdo.")]
    for rx, label, pts, sev in _JAR_MARKERS:
        if rx.search(data):
            out.append(Finding("static", f"{path.name}: {label}", "Mods legítimos raramente fazem isso.", pts, sev))
    return out


def analyze_office(path: Path, magic: str) -> list[Finding]:
    out: list[Finding] = []
    if magic == "zip":
        try:
            with zipfile.ZipFile(path) as zf:
                names = [n.lower() for n in zf.namelist()]
        except (zipfile.BadZipFile, OSError):
            return [gap(f"{path.name}: documento ilegível", "")]
        if any(n.endswith("vbaproject.bin") for n in names):
            out.append(Finding("static", f"{path.name}: contém macros VBA", "Macros são o vetor mais comum de malware em documentos.", 25, "medium"))
        if any("oleobject" in n or "activex" in n for n in names):
            out.append(Finding("static", f"{path.name}: contém objetos OLE/ActiveX embutidos", "", 10, "medium"))
    else:
        try:
            raw = path.read_bytes()[: 8 << 20]
        except OSError:
            return []
        both = raw + raw.replace(b"\x00", b"")
        if b"VBA" in both:
            auto = re.search(rb"AutoOpen|Auto_Open|Document_Open|Workbook_Open|AutoExec", both)
            out.append(Finding("static", f"{path.name}: contém macros VBA" + (" com execução automática" if auto else ""), "",
                               35 if auto else 20, "high" if auto else "medium"))
    return out


def analyze_content(path: Path, magic: str, strong_only: bool = False) -> tuple[list[Finding], bool]:
    """Inspeção estática por tipo. Retorna (achados, inspecionado). Não inspecionado vira lacuna no pipeline."""
    ext = path.suffix.lower()
    try:
        if ext in SCRIPT_EXT:
            return analyze_script(path, strong_only), True
        if ext == ".lnk":
            return analyze_lnk(path), True
        if ext == ".jar":
            return analyze_jar(path), True
        if ext in (".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm", ".dotm", ".xlam"):
            return analyze_office(path, magic), True
        if ext in (".reg", ".inf", ".scf", ".sct", ".url", ".py", ".pyw", ".sh", ".psm1", ".psd1", ".ps1xml", ".rdp", ".settingcontent-ms"):
            fs = analyze_text(_decode_text(path.read_bytes()[: 2 << 20]), path.name, ext)
            if ext in (".settingcontent-ms", ".rdp"):
                txt = _decode_text(path.read_bytes()[: 1 << 20])
                if re.search(r"(?i)(cmd(\.exe)?\s*/c|powershell|mshta|wscript|rundll32|alternate shell id)", txt):
                    fs.append(Finding("static", f"{path.name}: executa um programa ao abrir", "Arquivos desse tipo não deveriam chamar interpretadores.", 40, "high"))
            return fs, True
        if ext == ".pdf":
            raw = path.read_bytes()[: 8 << 20]
            fs = []
            if re.search(rb"/Launch|/JavaScript|/JS\s|/EmbeddedFile|/OpenAction", raw):
                fs.append(Finding("static", f"{path.name}: PDF com ação automática/JavaScript/anexo", "PDFs comuns não precisam disso.", 25, "medium"))
            return fs, True
        if ext == ".rtf":
            raw = path.read_bytes()[: 8 << 20]
            fs = []
            if re.search(rb"\\objdata|\\objemb|\\objautlink|\\\*\\template", raw, re.I):
                fs.append(Finding("static", f"{path.name}: RTF com objeto embutido", "Vetor clássico de exploits em documentos.", 30, "high"))
            return fs, True
        if ext in (".pyd", ".node", ".cpl", ".xll") or ext in LIB_EXT or magic == "pe":
            return analyze_pe(path), True
    except Exception:
        return [], False
    return [], ext not in UNINSPECTABLE_EXT


def is_active_content(path: Path, magic: str) -> bool:
    """O arquivo pode executar código (mesmo que o sandbox não consiga rodá-lo)?"""
    ext = path.suffix.lower()
    return ext in EXEC_KINDS or ext in LIB_EXT or ext in INSPECT_EXT or magic in ("pe", "ole")


def is_inert(path: Path, magic: str) -> bool:
    """Lista POSITIVA: dado conhecido e inofensivo (textura, áudio, texto…). Desconhecido NÃO é inerte."""
    ext = path.suffix.lower()
    if magic in ("pe", "ole") or is_active_content(path, magic):
        return False
    return ext in INERT_EXT or ext in SOFT_CODE_EXT or ext == ""


_SOFT_RUN = re.compile(r"(?i)\b(os\.execute|io\.popen|os\.system|subprocess\.|__import__|eval\s*\(|exec\s*\(|Popen\s*\(|ShellExecute|WScript\.Shell|ActiveXObject)")
_SOFT_TARGET = re.compile(r"(?i)(powershell|cmd(\.exe)?\s*/c|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|curl\s|wget\s|https?://|\.exe\b|\.bat\b|\.ps1\b)")


def analyze_soft(path: Path) -> list[Finding]:
    """Lua/Ren'Py/HTML/SVG: só acusa quando executa um programa/baixa algo (usar os.execute para abrir o próprio jogo é comum)."""
    ext = path.suffix.lower()
    try:
        text = _decode_text(path.read_bytes()[: 2 << 20])
    except OSError:
        return []
    out: list[Finding] = []
    if ext == ".svg":
        if re.search(r"(?i)<script\b|onload\s*=", text):
            out.append(Finding("static", f"{path.name}: SVG com script embutido", "Imagens não deveriam conter código.", 20, "medium"))
        return out
    for line in text.splitlines():
        if _SOFT_RUN.search(line) and _SOFT_TARGET.search(line):
            out.append(Finding("static", f"{path.name}: executa um programa/baixa conteúdo", line.strip()[:160], 35, "high"))
            break
    out += [f for f in analyze_text(text, path.name, ext, strong_only=True) if f.points >= 35]
    return out
