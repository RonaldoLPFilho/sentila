"""Análise de processos em andamento (modo usuário, sem elevação).

Princípios (iguais aos da análise de arquivos): só "Perigoso" decide sozinho; o que não pôde ser lido é LACUNA, nunca "ok";
nenhum sinal fraco isolado condena (um exe sem assinatura numa pasta de risco, sozinho, é só informação); todo texto vindo do
sistema (nome do processo, linha de comando) é entrada hostil e passa por clean_text() antes de ir para a tela ou o relatório.

Esta camada vê o que o Windows mostra a um programa comum. NÃO vê rootkit de kernel, injeção em memória (a assinatura vale para o
arquivo em disco, não para a imagem carregada), DLL maliciosa dentro de processo assinado, mineração que dorme ou limita o uso,
nem cryptojacking dentro do navegador. "Botnet" nunca é afirmado: só indícios.
"""
from __future__ import annotations

import ctypes
import ipaddress
import json
import os
import re
import statistics
import subprocess
import tempfile
import time
import unicodedata
import winreg
from dataclasses import dataclass, field
from pathlib import Path

import psutil

from .checks import CREATE_NO_WINDOW, VirusTotal, dn_fields, hash_file, run_powershell, verify_signatures, vt_findings
from .scoring import Finding, Verdict, compute_score, gap

MAX_PROCS = 2000
MAX_HASH_BYTES = 512 << 20
MAX_VT = 12
MIN_SCORE_WINDOW = 60          # segundos mínimos de observação para pontuar consumo
UNREADABLE_LIMIT = 3           # processos de usuário com exe ilegível a partir do qual vira lacuna relevante
CMD_LIMIT = 4096               # tamanho máximo da linha de comando analisada/exibida

# ---------------------------------------------------------------- texto hostil

_DROP_CATS = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}


_INVISIBLE = {0x3164, 0x2800, 0x115F, 0x1160, 0x034F, 0x17B4, 0x17B5, 0x180B, 0x180C, 0x180D, 0x180E, 0xFFA0} | set(range(0xFE00, 0xFE10)) | set(range(0xE0100, 0xE01F0))


def clean_text(s, limit: int = 260) -> str:
    """Remove controles, bidi, zero-width, BOM e tag chars; quebras viram espaço; trunca cedo. Seguro para QLabel/relatório."""
    s = str(s if s is not None else "")[: limit * 4]
    out = []
    for ch in s:
        if ch in "\r\n\t":
            out.append(" ")
        elif unicodedata.category(ch) in _DROP_CATS or ord(ch) in _INVISIBLE:
            continue
        else:
            out.append(ch)
    t = "".join(out).strip()
    return t if len(t) <= limit else t[: limit - 1] + "…"


_REDACT = [
    (re.compile(r"(?i)(--?(?:password|passwd|pass|pwd|token|secret|api[-_]?key|apikey|auth|key)(?:=|\s+))(\S+)"), r"\1***"),
    (re.compile(r"(?i)(authorization:\s*\S+\s+)(\S+)"), r"\1***"),
    (re.compile(r"(?i)([a-z][a-z0-9+.-]*://[^/\s:@]+:)([^@\s/]+)(@)"), r"\1***\3"),
    (re.compile(r"(?i)([?&](?:key|apikey|api_key|token|access_token|secret|password|sig|signature)=)([^&\s]+)"), r"\1***"),
]


def redact(text: str) -> str:
    """Esconde segredos óbvios e o nome do usuário do Windows (para relatórios que o usuário vai compartilhar)."""
    t = str(text)
    for pat, rep in _REDACT:
        t = pat.sub(rep, t)
    user = os.environ.get("USERNAME", "")
    if len(user) >= 2:
        t = re.sub(r"(?i)([\\/]users[\\/])" + re.escape(user), r"\1<usuario>", t)
    return t


# ---------------------------------------------------------------- caminhos

def norm_path(p) -> str:
    s = os.path.expandvars(str(p or "").strip().strip('"'))
    if s.startswith("\\\\?\\UNC\\"):
        s = "\\\\" + s[8:]
    elif s.startswith("\\\\?\\") or s.startswith("\\\\.\\"):
        s = s[4:]
    return os.path.normcase(os.path.normpath(s)) if s else ""


_WIN = norm_path(os.environ.get("SystemRoot", r"C:\Windows"))
_SYS32 = _WIN + "\\system32"
_SYSWOW = _WIN + "\\syswow64"
_PROGDATA = norm_path(os.environ.get("ProgramData", r"C:\ProgramData"))
_APPDATA = norm_path(os.environ.get("APPDATA", ""))
_LOCALAPPDATA = norm_path(os.environ.get("LOCALAPPDATA", ""))
_PF = [norm_path(os.environ.get(k, "")) for k in ("ProgramFiles", "ProgramFiles(x86)")]

_RISKY_MARKERS = ("\\temp\\", "\\downloads\\", "\\$recycle.bin\\", "\\users\\public\\")


def path_kind(path: str) -> str:
    """'local' (disco fixo), 'remote' (UNC/rede), 'removable' ou 'unknown'. Não abre o arquivo."""
    raw = str(path or "")
    if raw.startswith("\\\\?\\UNC\\") or (raw.startswith("\\\\") and not raw.startswith("\\\\?\\") and not raw.startswith("\\\\.\\")):
        return "remote"
    p = norm_path(raw)
    if len(p) >= 2 and p[1] == ":":
        try:
            t = ctypes.windll.kernel32.GetDriveTypeW(p[:2] + "\\")
        except Exception:
            return "unknown"
        return {3: "local", 6: "local", 4: "remote", 2: "removable", 5: "removable"}.get(t, "unknown")
    return "unknown"


def is_risky_dir(path: str) -> bool:
    p = norm_path(path)
    if any(m in p + "\\" for m in _RISKY_MARKERS) or "\\appdata\\local\\temp\\" in p:
        return True
    if _PROGDATA and p.startswith(_PROGDATA + "\\") and "\\" not in p[len(_PROGDATA) + 1:]:
        return True
    return False


def is_user_dir(path: str) -> bool:
    p = norm_path(path)
    return any(base and p.startswith(base + "\\") for base in (_APPDATA, _LOCALAPPDATA, _PROGDATA))


def is_private_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified or a.is_reserved


# ---------------------------------------------------------------- identidade

# nome -> (onde pode existir, crítico?)   'sys' = System32/SysWOW64   'win' = pasta do Windows
SYSTEM_PROCS: dict[str, tuple[str, bool]] = {
    "smss": ("sys", True), "csrss": ("sys", True), "wininit": ("sys", True), "services": ("sys", True), "lsass": ("sys", True),
    "winlogon": ("sys", True), "svchost": ("sys", False), "spoolsv": ("sys", False), "taskhostw": ("sys", False),
    "runtimebroker": ("sys", False), "dllhost": ("sys", False), "conhost": ("sys", False), "sihost": ("sys", False),
    "fontdrvhost": ("sys", False), "dwm": ("sys", False), "ctfmon": ("sys", False),
    "audiodg": ("sys", False), "taskmgr": ("sys", False), "werfault": ("sys", False), "wermgr": ("sys", False), "searchindexer": ("sys", False), "lsm": ("sys", False), "explorer": ("win", False),
    "wmiprvse": ("wbem", False),
}
# pais esperados (só nas relações estáveis)
EXPECTED_PARENT: dict[str, set[str]] = {
    "svchost": {"services"}, "lsass": {"wininit"}, "services": {"wininit"},
    "taskhostw": {"svchost"}, "runtimebroker": {"svchost"}, "sihost": {"svchost"},
}
# processos que não têm arquivo executável (kernel/virtualização): não contam como "ilegíveis"
NO_EXE = {"system", "registry", "memory compression", "secure system", "system idle process", "system interrupts", "idle",
          "vmmem", "vmmemwsl", "vmmemwindowssandbox", "vmcompute", "vmwp"}

_HOMOGLYPHS = str.maketrans({
    "\u0430": "a", "\u0441": "c", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0445": "x", "\u0443": "y", "\u0455": "s",
    "\u0456": "i", "\u0458": "j", "\u04cf": "l", "\u0501": "d", "\u051b": "q", "\u051d": "w", "\u043d": "h", "\u043c": "m",
    "\u0442": "t", "\u043a": "k", "\u03bf": "o", "\u03b1": "a", "\u03bd": "v", "\u03c1": "p", "\u03b9": "i", "\u03ba": "k",
    "\u0131": "i", "\u2113": "l",
})


def skeleton(s: str) -> str:
    """Forma canônica para comparar nomes parecidos: remove zero-width, dobra homóglifos e confusões comuns (rn=m, i/1/|=l, 0=o)."""
    t = unicodedata.normalize("NFKC", str(s))
    t = "".join(ch for ch in t if unicodedata.category(ch) not in ("Cf", "Mn") and ord(ch) not in _INVISIBLE).lower().translate(_HOMOGLYPHS)
    return t.replace("rn", "m").replace("1", "l").replace("|", "l").replace("i", "l").replace("0", "o")


def lev1(a: str, b: str) -> bool:
    """True se a e b diferem por exatamente uma inserção, remoção ou troca."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
        if len(diff) == 1:
            return True
        # troca de duas letras vizinhas ("scvhost" por "svchost") conta como um erro só
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    if len(a) > len(b):
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


_STEMS = {s: skeleton(s) for s in SYSTEM_PROCS}
_BS = chr(92)
_DIRS = {"sys": {_SYS32, _SYSWOW}, "win": {_WIN}, "wbem": {_SYS32 + _BS + "wbem", _SYSWOW + _BS + "wbem"}}
_WINAPPS = norm_path(os.environ.get("ProgramFiles", r"C:\Program Files")) + _BS + "windowsapps" + _BS


def stem_of(name: str) -> str:
    n = str(name or "").strip().lower()
    for ext in (".exe", ".scr", ".com", ".pif"):
        if n.endswith(ext):
            return n[: -len(ext)]
    return n


# ---------------------------------------------------------------- mineração / rede

_MINER_NAME = re.compile(r"^(xmrig|xmr-stak|nbminer|t-rex|phoenixminer|lolminer|gminer|srbminer|teamredminer|cpuminer|minerd|bfgminer|"
                         r"cgminer|ethminer|nanominer|wildrig|kawpowminer|ccminer|nicehashminer|z-enemy)(?:[-_.\d].*)?$")
_MINER_FLAGS = re.compile(r"stratum2?\+(?:tcp|ssl|tls)://|--donate-level|--rig-id|\s-o\s+[\w.-]+\.[a-z]{2,}:\d{3,5}.{0,120}\s-u\s", re.I | re.S)
_XMR_ADDR = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
_POOL_NAME = re.compile(r"(?i)(?:^|\.)(?:nanopool|ethermine|2miners|f2pool|hashvault|supportxmr|minexmr|moneroocean|unmineable|herominers|"
                        r"nicehash|miningpoolhub|slushpool|poolin|antpool|viabtc|ezil|flexpool|hiveon|c3pool|xmrpool|monerohash|minergate|"
                        r"crazypool)\.|stratum")
MINING_PORTS = {3333, 4444, 14444, 14433, 45560}
IRC_TOR_PORTS = {6667, 6697, 9001, 9050, 9150}
SCAN_PORTS = {445, 23, 22, 3389, 2323, 5555}
BROWSERS = {"chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "iexplore", "chromium", "waterfox", "librewolf", "tor", "arc"}
OFFICE_PARENTS = {"winword", "excel", "powerpnt", "outlook", "msaccess", "mspub", "acrord32", "acrobat", "foxitreader", "sumatrapdf"}
CMD_INTERPRETERS = {"powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "vssadmin",
                    "wmic", "net", "net1", "bcdedit", "taskkill", "sc", "schtasks"}
TRUST_BLOCKED = CMD_INTERPRETERS | {"python", "pythonw", "py", "node", "java", "javaw", "bash", "sh", "wsl", "ruby", "perl", "php", "deno", "bun"}
SCRIPT_CHILDREN = {"powershell", "pwsh", "wscript", "cscript", "mshta"}

# ---------------------------------------------------------------- linha de comando (regras de ALTA confiança para processo vivo)
# (as de persistência, como "reg add ...\run" e "schtasks /create", ficam de fora: em processo vivo são banais)

LIVE_CMD_RULES: list[tuple[str, str, int, str]] = [
    (r"vssadmin(\.exe)?\"?\s+delete\s+shadows|wmic(\.exe)?\"?\s+shadowcopy\s+delete|bcdedit.{0,80}(recoveryenabled\s+no|ignoreallfailures)",
     "Apaga cópias de segurança / desativa a recuperação do Windows", 90, "critical"),
    (r"set-mppreference.{0,120}-disable|add-mppreference.{0,60}-exclusion|disablerealtimemonitoring|taskkill.{0,60}msmpeng",
     "Tenta desativar ou contornar o Defender", 60, "critical"),
    (r"net1?(\.exe)?\"?\s+user\s+\S+\s+\S+\s+/add", "Cria uma conta de usuário", 45, "high"),
    (r"certutil.{0,80}(-urlcache|-decode)|bitsadmin.{0,80}/transfer|mshta(\.exe)?\"?\s+https?:|regsvr32.{0,80}(/i:https?|scrobj)",
     "Baixa ou executa conteúdo remoto por ferramenta do Windows", 35, "high"),
    (r"(powershell|pwsh)\S{0,12}\s(?:.{0,200}\s)?-e[a-z]{0,15}\s+[A-Za-z0-9+/=]{20,}",
     "PowerShell com comando codificado (ofuscado)", 30, "high"),
]
_LIVE_RX = [(re.compile(p, re.I | re.S), t, pts, sev) for p, t, pts, sev in LIVE_CMD_RULES]


_PS_CMD = re.compile(r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\"?\s")
_PS_FETCH = re.compile(r"(?i)downloadstring|downloadfile|invoke-webrequest|\biwr\b|invoke-restmethod|net\.webclient|start-bitstransfer")
_PS_EXEC = re.compile(r"(?i)\biex\b|invoke-expression|start-process|\.exe\b|frombase64string")
_URL = re.compile(r"(?i)https?://")


def live_cmd_findings(cmdline: str) -> list[Finding]:
    cmd = str(cmdline or "")[:CMD_LIMIT]
    out = [Finding("proc", title, clean_text(cmd, 220), pts, sev) for rx, title, pts, sev in _LIVE_RX if rx.search(cmd)]
    # Invoke-Expression sozinho é banal (ferramentas de automação o usam para embrulhar comandos): só vale baixar E executar uma URL
    if _PS_CMD.search(cmd) and _URL.search(cmd) and _PS_FETCH.search(cmd):
        if _PS_EXEC.search(cmd):
            out.append(Finding("proc", "PowerShell baixando e executando conteúdo da internet", clean_text(cmd, 220), 35, "high"))
        else:
            out.append(Finding("proc", "PowerShell baixando conteúdo da internet", clean_text(cmd, 220), 8, "low"))
    return out


# ---------------------------------------------------------------- modelo

@dataclass
class Proc:
    pid: int
    name: str
    exe: str = ""
    cmdline: str = ""
    ppid: int = 0
    create_time: float = 0.0
    user: str = ""
    denied: set = field(default_factory=set)       # campos que o Windows não deixou ler
    kind: str = "local"                             # local | remote | removable | unknown
    exists: bool = True
    stat0: tuple | None = None
    stat1: tuple | None = None
    sig: dict | None = None                         # resultado de verify_signatures
    sha256: str = ""
    has_window: bool = False
    foreground: bool = False                        # tinha a janela em primeiro plano ao fim da observação
    persist: list = field(default_factory=list)     # onde este exe se registra para iniciar
    cpu: list = field(default_factory=list)         # % de UM núcleo por amostra
    gpu_compute: list = field(default_factory=list)  # % por amostra (engines compute/cuda)
    gpu_3d: list = field(default_factory=list)
    remote_ips: set = field(default_factory=set)    # IPs externos contatados
    arrivals: dict = field(default_factory=dict)    # (ip, porta) -> instantes em que uma conexão NOVA apareceu (aba Rede)
    dests: dict = field(default_factory=dict)       # (ip, porta) -> nº de conexões distintas vistas (aba Rede)
    c2_hits: set = field(default_factory=set)       # destinos que estão numa lista de C2 fornecida (aba Rede)
    remote_ports: set = field(default_factory=set)
    scan_ips: set = field(default_factory=set)      # IPs contatados nas portas de varredura
    syn: list = field(default_factory=list)         # nº de conexões SYN_SENT por amostra
    syn_nets: set = field(default_factory=set)      # /24 distintos em SYN_SENT
    listen_public: set = field(default_factory=set)
    findings: list = field(default_factory=list)
    status: str = ""                                # verified | reputation | user | unverified | unreadable | failed | remote | system
    note: str = ""
    score: int = 0
    level: str = "ok"                               # ok | caution | danger
    publisher: str = ""

    @property
    def key(self) -> tuple:
        return (self.pid, round(self.create_time, 2))

    @property
    def stem(self) -> str:
        return stem_of(self.name)


@dataclass
class Ctx:
    by_pid: dict = field(default_factory=dict)
    dns: dict = field(default_factory=dict)         # ip -> {nomes}
    ncores: int = max(1, psutil.cpu_count(logical=True) or 1)
    window: int = 0                                  # segundos efetivamente observados
    trusted: dict = field(default_factory=dict)      # sha256 -> {name, motivo} (lista "Confiar" do usuário)


def sig_state(p: Proc) -> str:
    """ms | signed | unsigned | invalid | failed | na (sem exe legível) | remote"""
    if not p.exe or p.kind == "none":
        return "na"
    if p.kind == "remote":
        return "remote"
    if not p.sig:
        return "failed"
    if not p.sig.get("verified"):
        return "failed"
    st = p.sig.get("status", "")
    if st == "Valid":
        return "ms" if is_microsoft(p) else "signed"
    if st == "NotSigned":
        return "packaged" if norm_path(p.exe).startswith(_WINAPPS) else "unsigned"
    if st in ("HashMismatch", "NotTrusted"):
        return "invalid"
    return "failed"


def is_microsoft(p: Proc) -> bool:
    if not p.sig or p.sig.get("status") != "Valid":
        return False
    f = dn_fields(p.sig.get("subject", ""))
    iss = dn_fields(p.sig.get("issuer", ""))
    if f.get("O") != "Microsoft Corporation" or f.get("C") != "US" or not iss.get("CN", "").startswith("Microsoft"):
        return False
    d = norm_path(p.exe)
    if any(d.startswith(_WIN + _BS + x + _BS) for x in ("temp", "tasks", "tracing", "debug", "registration")):
        return False
    return d.startswith(_WIN + "\\") or any(pf and d.startswith(pf + "\\") for pf in _PF) or d.startswith(_PROGDATA + "\\microsoft\\")


def publisher_of(p: Proc) -> str:
    if sig_state(p) == "packaged":
        return "Pacote de app do Windows"
    if not p.sig or p.sig.get("status") != "Valid":
        return ""
    f = dn_fields(p.sig.get("subject", ""))
    return clean_text(f.get("O") or f.get("CN") or "publicador desconhecido", 80)


# ---------------------------------------------------------------- estatística de consumo

def cpu_stats(samples: list, ncores: int) -> dict | None:
    if not samples:
        return None
    tot = [s / ncores for s in samples]
    n = len(samples)
    return {"avg": sum(tot) / n, "med": statistics.median(tot), "frac_total": sum(t >= 60 for t in tot) / n,
            "frac_core": sum(s >= 90 for s in samples) / n, "n": n}


def sustained_cpu(samples: list, ncores: int, window: int) -> bool:
    st = cpu_stats(samples, ncores)
    if not st or window < MIN_SCORE_WINDOW or st["n"] < 25:
        return False
    return (st["med"] >= 60 and st["frac_total"] >= 0.8) or st["frac_core"] >= 0.8


def sustained_gpu(samples: list, window: int) -> bool:
    if window < MIN_SCORE_WINDOW or len(samples) < 25:
        return False
    return sum(s >= 60 for s in samples) / len(samples) >= 0.8


# ---------------------------------------------------------------- regras

def _signals(p: Proc, cmd_bad: bool) -> list[str]:
    s = []
    if p.remote_ips and not p.has_window:
        s.append("conexão externa sem janela visível")
    if p.persist:
        s.append("inicia com o Windows")
    if cmd_bad:
        s.append("linha de comando suspeita")
    if p.kind == "remote":
        s.append("executa de local remoto")
    if not p.exists and p.exe:
        s.append("arquivo apagado")
    return s


def analyze_proc(p: Proc, ctx: Ctx) -> list[Finding]:
    fs: list[Finding] = list(p.findings)
    st = sig_state(p)
    name_l = p.name.lower()
    stem = p.stem
    exe_n = norm_path(p.exe) if p.exe else ""
    unsigned = st in ("unsigned", "invalid")
    risky = bool(exe_n) and is_risky_dir(exe_n)
    userdir = bool(exe_n) and is_user_dir(exe_n)
    label = clean_text(p.name, 80)

    # --- identidade
    flagged_path = False
    in_system_dirs_early = bool(exe_n) and (exe_n.startswith(_WIN + _BS) or any(pf and exe_n.startswith(pf + _BS) for pf in _PF))
    spec = SYSTEM_PROCS.get(stem)
    if spec and exe_n:
        allowed = _DIRS[spec[0]]
        if os.path.dirname(exe_n) not in allowed:
            flagged_path = True
            fs.append(Finding("proc", f"{label} fora do local do Windows",
                              f"O Windows só executa este processo em {', '.join(sorted(allowed))}. Aqui: {clean_text(p.exe, 200)}. "
                              "Malware usa esses nomes para se disfarçar.", 90 if spec[1] else 55, "critical" if spec[1] else "high"))
    if spec and not flagged_path:
        exp = EXPECTED_PARENT.get(stem)
        par = ctx.by_pid.get(p.ppid)
        if exp and par and par.create_time <= p.create_time and par.stem not in exp:
            fs.append(Finding("proc", f"{label} iniciado por um processo inesperado",
                              f"Pai: {clean_text(par.name, 60)} (esperado: {', '.join(sorted(exp))}).", 40, "high"))
    if stem not in SYSTEM_PROCS:
        sk = skeleton(stem)
        for sysname, sysk in _STEMS.items():
            if sk == sysk and stem != sysname:
                fs.append(Finding("proc", f"Nome imita o processo do Windows \"{sysname}\"",
                                  f"{label} usa caracteres parecidos (zero-width, homóglifos, rn/m…) para parecer {sysname}.exe.", 55, "high"))
                break
            if (len(sysname) >= 4 and lev1(stem, sysname) and unsigned and not in_system_dirs_early
                    and sysname not in ("taskmgr", "wermgr")):
                fs.append(Finding("proc", f"Nome quase igual ao processo do Windows \"{sysname}\"",
                                  f"{label} difere de {sysname}.exe por um caractere, não tem assinatura e roda fora das pastas do Windows. "
                                  "Pode ser coincidência (nome genérico), por isso só gera atenção.", 25, "medium"))
                break

    # --- arquivo
    if p.exe and not p.exists and p.kind == "local":
        if risky:
            fs.append(Finding("proc", "O executável foi apagado, mas o processo continua rodando",
                              "Em pasta de risco isso é típico de malware que se apaga depois de iniciar.", 40, "high"))
        else:
            fs.append(Finding("proc", "O arquivo executável não existe mais no disco",
                              "É comum durante atualizações e desinstalações.", 0, "info"))
    if p.kind == "remote":
        fs.append(Finding("proc", "Executando a partir de um local remoto (rede)",
                          f"{clean_text(p.exe, 200)}. O arquivo não foi aberto para não expor suas credenciais à rede.", 25, "medium"))
    elif p.kind == "removable":
        fs.append(Finding("proc", "Executando a partir de mídia removível", clean_text(p.exe, 200), 0, "info"))
    if p.stat0 and p.stat1 and p.stat0 != p.stat1:
        if unsigned:
            fs.append(Finding("proc", "O arquivo executável foi alterado durante a observação",
                              "Programas sem assinatura que se reescrevem enquanto rodam merecem atenção.", 20, "medium"))
        else:
            fs.append(Finding("proc", "O arquivo executável foi atualizado durante a observação", "Comum em atualizadores.", 0, "info"))
    if st == "invalid" and p.sig and p.sig.get("status") == "HashMismatch":
        fs.append(Finding("proc", "Assinatura digital inválida: o arquivo foi alterado depois de assinado",
                          clean_text(p.sig.get("subject", ""), 160), 25, "medium"))

    # --- linha de comando
    # Regras de linha de comando só valem para interpretadores/ferramentas do Windows ou para programas FORA das pastas do sistema
    # (um shell/editor em Program Files cuja linha de comando apenas CONTÉM um texto suspeito, como um script, não o executa).
    in_system_dirs = bool(exe_n) and (exe_n.startswith(_WIN + _BS) or any(pf and exe_n.startswith(pf + _BS) for pf in _PF))
    cmd_fs = live_cmd_findings(p.cmdline) if (p.cmdline and (stem in CMD_INTERPRETERS or not in_system_dirs)) else []
    cmd_bad = any(f.points >= 30 for f in cmd_fs)
    fs += cmd_fs
    par = ctx.by_pid.get(p.ppid)
    if par and par.create_time <= p.create_time and par.stem in OFFICE_PARENTS and stem in SCRIPT_CHILDREN:
        fs.append(Finding("proc", f"{clean_text(par.name, 40)} abriu {label}",
                          "Documentos e leitores de PDF raramente precisam iniciar scripts. Pode ser macro maliciosa (ou automação legítima).", 20, "medium"))

    # --- origem + segundo sinal (um sinal fraco isolado nunca condena)
    sigs = _signals(p, cmd_bad)
    if unsigned:
        if risky:
            if len(sigs) >= 2:
                fs.append(Finding("proc", "Sem assinatura, em pasta de risco, com vários sinais",
                                  f"{label}: " + "; ".join(sigs) + ".", 40, "high"))
            elif sigs:
                fs.append(Finding("proc", "Sem assinatura, em pasta de risco e " + sigs[0],
                                  f"{label} roda de {clean_text(os.path.dirname(p.exe), 160)}.", 20, "medium"))
            else:
                fs.append(Finding("proc", "Sem assinatura, rodando de pasta de risco",
                                  f"{clean_text(p.exe, 200)}. Comum em trainers, mods e programas portáteis; sozinho isto não indica malware.", 0, "info"))
        elif userdir and len(sigs) >= 2:
            fs.append(Finding("proc", "Sem assinatura, em pasta do usuário, com vários sinais",
                              f"{label}: " + "; ".join(sigs) + ".", 25, "medium"))
        elif p.persist:
            fs.append(Finding("proc", "Sem assinatura e inicia com o Windows", "; ".join(clean_text(x, 120) for x in p.persist[:3]), 0, "info"))

    # --- mineração
    miner_name = bool(_MINER_NAME.match(stem))
    miner_cmd = bool(p.cmdline and (_MINER_FLAGS.search(p.cmdline[:CMD_LIMIT]) or _XMR_ADDR.search(p.cmdline[:CMD_LIMIT])))
    heavy_cpu = sustained_cpu(p.cpu, ctx.ncores, ctx.window)
    heavy_gpu = sustained_gpu(p.gpu_compute, ctx.window)
    mining_port = bool(p.remote_ports & MINING_PORTS)
    foreground = p.has_window and p.foreground
    verified_sig = st in ("ms", "signed", "packaged")
    pools = sorted({n for ip in p.remote_ips for n in ctx.dns.get(ip, ()) if _POOL_NAME.search(n)})
    if miner_cmd or (miner_name and (pools or ((heavy_cpu or heavy_gpu) and not foreground))):
        why = []
        if miner_name:
            why.append("nome de minerador conhecido")
        if miner_cmd:
            why.append("parâmetros de mineração (pool/carteira)")
        if pools:
            why.append("conexão com pool")
        if heavy_cpu or heavy_gpu:
            why.append("uso contínuo de CPU/GPU")
        fs.append(Finding("proc", "Programa de mineração de criptomoeda", f"{label}: " + " e ".join(why) +
                          ". Se foi você quem instalou, use \"Confiar\".", 60, "high"))
    elif miner_name:
        fs.append(Finding("proc", "Nome de programa de mineração", f"{label} tem nome de minerador conhecido, mas nada indica que esteja minerando "
                          "agora (sem pool, sem parâmetros, sem consumo contínuo). Pode ser um jogo/ferramenta com nome parecido.", 30, "medium"))
    if pools:
        if stem in BROWSERS or verified_sig:
            fs.append(Finding("proc", "Acessa endereço que também é de pool de mineração",
                              ", ".join(clean_text(x, 60) for x in pools[:3]) + ". Endereços de CDN são compartilhados por muitos sites; sozinho não indica nada.", 0, "info"))
        elif not miner_cmd and not miner_name:
            fs.append(Finding("proc", "Conexão com pool de mineração (pelo DNS)", f"{label} → " + ", ".join(clean_text(x, 60) for x in pools[:3]) +
                              ". O DNS não prova qual programa pediu o nome; confira se há consumo estranho.", 30, "medium"))
    if (heavy_cpu or heavy_gpu) and unsigned and st != "ms" and not foreground:
        if mining_port or pools:
            fs.append(Finding("proc", "Consumo alto e contínuo + porta/endereço típico de mineração",
                              f"{label} usa muita {'GPU' if heavy_gpu and not heavy_cpu else 'CPU'} há {ctx.window} s e conecta num destino típico de pool. "
                              "Jogos e servidores usam essas portas também; confirme.", 35, "medium"))
        else:
            what = "CPU" if heavy_cpu else "GPU (compute)"
            fs.append(Finding("proc", f"Consumo alto e contínuo de {what} por programa sem assinatura",
                              f"{label} manteve uso elevado durante os {ctx.window} s observados. Pode ser jogo, render ou compilação; "
                              "mineradores escondidos também fazem isso.", 20, "medium"))

    # --- rede
    if unsigned and (p.remote_ports & IRC_TOR_PORTS):
        fs.append(Finding("proc", "Conexão em porta de IRC/Tor", f"{label}: portas {sorted(p.remote_ports & IRC_TOR_PORTS)}. "
                          "Botnets antigas usam IRC para receber ordens; Tor esconde o destino.", 20, "medium"))
    max_syn = max(p.syn, default=0)
    if unsigned and ((max_syn >= 100 and len(p.syn_nets) >= 20) or len(p.scan_ips) >= 200):
        fs.append(Finding("proc", "Padrão de varredura de rede",
                          f"{label} tentou conectar a {max(max_syn, len(p.scan_ips))} endereços em /24 diferentes (portas 22/23/445/3389…). "
                          "É o comportamento de malware que procura outras máquinas para infectar.", 60, "high"))
    if p.listen_public and unsigned:
        high = sorted(x for x in p.listen_public if x >= 1024)
        if (risky or userdir) and not p.has_window and high:
            fs.append(Finding("proc", "Sem assinatura, escutando conexões de fora e sem janela",
                              f"{label}: portas {high[:5]}. Servidores de jogo e ferramentas de desenvolvimento fazem isso; confira se é seu.", 20, "medium"))
        else:
            fs.append(Finding("proc", "Programa sem assinatura aceitando conexões", f"{label}: portas {sorted(p.listen_public)[:5]}.", 0, "info"))
    return fs


def classify_status(p: Proc, ctx: Ctx) -> str:
    st = sig_state(p)
    if (p.stem in NO_EXE and not p.exe) or p.kind == "none" or (not p.exe and p.stem.startswith("vmmem")):
        return "system"
    if p.sha256 and p.sha256 in ctx.trusted:
        return "user"
    if st in ("ms", "signed", "packaged"):
        return "verified"
    if st == "na":
        return "unreadable"
    if st == "remote":
        return "remote"
    if st == "failed":
        return "failed"
    if any(f.trust for f in p.findings):
        return "reputation"
    return "unverified"


def level_of(fs: list[Finding]) -> tuple[int, str]:
    score = compute_score(fs)
    if any(f.severity == "critical" for f in fs) or score >= 45:
        return score, "danger"
    if score >= 20 or any(f.points > 0 and f.severity in ("medium", "high", "critical") for f in fs):
        return score, "caution"
    return score, "ok"


def analyze_all(procs: list[Proc], ctx: Ctx) -> None:
    ctx.by_pid = {p.pid: p for p in procs}
    for p in procs:
        if p.stem in TRUST_BLOCKED and p.sha256 in ctx.trusted:
            ctx.trusted = {k: v for k, v in ctx.trusted.items() if k != p.sha256}
        p.status = classify_status(p, ctx)
        p.publisher = publisher_of(p)
        fs = analyze_proc(p, ctx)
        if p.status == "user":
            # "Confiar": o usuário assumiu este arquivo (por SHA-256). Só o que é crítico na linha de comando continua valendo.
            note = ctx.trusted.get(p.sha256, {})
            fs = [f for f in fs if f.severity == "critical"] + [
                Finding("proc", "Marcado como confiável por você", clean_text(note.get("motivo", "") or p.sha256[:16], 120), 0, "info", trust=True)]
        p.findings = fs
        p.score, p.level = level_of(fs)


# ---------------------------------------------------------------- veredito geral

def scan_verdict(procs: list[Proc], machine: list[Finding], gaps: list[Finding]) -> Verdict:
    all_f = [f for p in procs for f in p.findings] + machine
    score = max([p.score for p in procs] + [compute_score(machine)])
    danger = [p for p in procs if p.level == "danger"]
    caution = [p for p in procs if p.level == "caution"]
    m_level = level_of(machine)[1]
    if danger or m_level == "danger":
        names = ", ".join(clean_text(p.name, 40) for p in danger[:3])
        return Verdict(score, "danger", "Perigoso",
                       f"Sinais fortes de comportamento malicioso{' em: ' + names if names else ''}. Não encerre nada às cegas: "
                       "veja os motivos abaixo, analise o arquivo e, se confirmar, desconecte o PC da internet.")
    if caution or m_level == "caution":
        return Verdict(score, "caution", "Atenção",
                       f"{len(caution)} processo(s) com pontos suspeitos que não bastam para condenar. Confira os motivos e a origem de cada um.")
    if gaps:
        missing = "; ".join(g.title for g in gaps[:3]) + (f" (+{len(gaps) - 3})" if len(gaps) > 3 else "")
        return Verdict(score, "unknown", "Inconclusivo",
                       "Nenhum sinal forte, mas isso NÃO significa que o PC está limpo. Faltou verificar: " + missing + ".")
    return Verdict(score, "safe", "Sem indícios (parcial)",
                   "Nenhum sinal de malware nos testes realizados. Isto não prova que o PC está limpo: rootkits, injeção em memória e "
                   "mineração que se disfarça não são vistos por esta análise.")


# ---------------------------------------------------------------- coleta

def _ft(stat: os.stat_result | None) -> tuple | None:
    return (stat.st_size, stat.st_mtime_ns) if stat else None


def _safe_stat(path: str):
    try:
        return os.stat(path)
    except OSError:
        return None


def _file_gone(path: str) -> bool:
    try:
        os.stat(path)
        return False
    except (FileNotFoundError, NotADirectoryError):
        return True
    except OSError:
        return False  # sem permissão não é "apagado"


def collect_inventory(cancelled=lambda: False) -> tuple[list[Proc], list[Finding]]:
    """Lista os processos. Campo ilegível vira Proc.denied (não erro). Ignora este app e seus filhos."""
    me = os.getpid()
    rows = []
    attrs = ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]
    for pr in psutil.process_iter(attrs, ad_value=None):
        if cancelled():
            raise InterruptedError
        rows.append(pr.info)
    parents = {r["pid"]: r.get("ppid") or 0 for r in rows}

    def descends(pid: int) -> bool:
        seen = 0
        while pid and seen < 64:
            if pid == me:
                return True
            pid = parents.get(pid, 0)
            seen += 1
        return False

    gaps: list[Finding] = []
    procs: list[Proc] = []
    for r in rows:
        # ignora só este app e os PowerShell/conhost que ELE lança para consultar o Windows; outros filhos (ex.: um arquivo
        # aberto pelo botão "Abrir") continuam sendo verificados
        if r["pid"] == 0 or r["pid"] == me or (descends(r["pid"]) and stem_of(r.get("name") or "") in ("powershell", "pwsh", "conhost")):
            continue
        denied = {k for k in ("exe", "cmdline", "username") if r.get(k) is None}
        exe = r.get("exe") or ""
        cmd = r.get("cmdline")
        cmdline = subprocess.list2cmdline(cmd) if isinstance(cmd, list) else ""
        p = Proc(pid=r["pid"], name=clean_text(r.get("name") or "?", 120), exe=exe, cmdline=cmdline[:CMD_LIMIT],
                 ppid=r.get("ppid") or 0, create_time=float(r.get("create_time") or 0.0), user=clean_text(r.get("username") or "", 80),
                 denied=denied)
        if exe:
            p.kind = path_kind(exe)
            if p.kind == "unknown":
                p.kind = "none"      # 'Registry', 'MemCompression'…: nome de imagem do kernel, sem arquivo
            if p.kind in ("local", "removable"):
                st = _safe_stat(exe)
                p.exists = st is not None or not _file_gone(exe)
                p.stat0 = _ft(st)
        procs.append(p)
    if len(procs) > MAX_PROCS:
        gaps.append(gap(f"Há {len(procs)} processos: só os primeiros {MAX_PROCS} foram analisados"))
        procs = procs[:MAX_PROCS]
    return procs, gaps


def visible_window_pids() -> set:
    pids: set = set()
    try:
        u = ctypes.WinDLL("user32", use_last_error=True)
        proto = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
        u.IsWindowVisible.argtypes = [ctypes.c_void_p]
        u.GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        u.EnumWindows.argtypes = [proto, ctypes.c_void_p]

        def cb(hwnd, _lp):
            if u.IsWindowVisible(hwnd):
                pid = ctypes.c_ulong()
                u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                pids.add(pid.value)
            return True

        u.EnumWindows(proto(cb), None)
    except Exception:
        pass
    return pids


def foreground_pid() -> int:
    try:
        u = ctypes.WinDLL("user32")
        u.GetForegroundWindow.restype = ctypes.c_void_p
        u.GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        pid = ctypes.c_ulong()
        u.GetWindowThreadProcessId(u.GetForegroundWindow(), ctypes.byref(pid))
        return pid.value
    except Exception:
        return 0


_CMD_TARGET = re.compile(r'[A-Za-z]:\\[^"<>|\x00\r\n]{2,260}?\.(?:exe|scr|com|bat|cmd|ps1|vbs|js)\b', re.I)


def command_targets(cmd: str) -> set:
    """Caminhos de programas citados num comando de inicialização (Run, serviço, tarefa agendada, atalho)."""
    out = set()
    s = os.path.expandvars(str(cmd or "").strip())
    if s.startswith('"') and '"' in s[1:]:
        out.add(norm_path(s[1:s.index('"', 1)]))
    for m in _CMD_TARGET.finditer(s):
        out.add(norm_path(m.group(0)))
    m = re.match(r"^(.*?\.exe)\b", s, re.I)
    if m:
        out.add(norm_path(m.group(1)))
    out.discard("")
    return out


def collect_persistence() -> list[tuple[str, str, str]]:
    """(tipo, onde, comando). Só leitura, sem administrador. O que não for legível é ignorado."""
    found: list[tuple[str, str, str]] = []
    run_keys = [(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")]
    for hive, sub in run_keys:
        try:
            with winreg.OpenKey(hive, sub) as k:
                i = 0
                while True:
                    try:
                        n, v, _t = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    if isinstance(v, str):
                        found.append(("Run", sub.rsplit("\\", 1)[-1] + ": " + n, v))
        except OSError:
            continue
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services") as k:
            n = winreg.QueryInfoKey(k)[0]
            for i in range(n):
                try:
                    svc = winreg.EnumKey(k, i)
                    with winreg.OpenKey(k, svc) as sk:
                        img, _t = winreg.QueryValueEx(sk, "ImagePath")
                    if isinstance(img, str):
                        found.append(("Serviço", svc, img))
                except OSError:
                    continue
    except OSError:
        pass
    startups = [Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
                Path(os.environ.get("ProgramData", "")) / r"Microsoft\Windows\Start Menu\Programs\StartUp"]
    for d in startups:
        try:
            for f in d.iterdir():
                text = str(f)
                try:
                    if f.suffix.lower() == ".lnk" and f.stat().st_size < 65536:
                        data = f.read_bytes()
                        text += " " + data.decode("utf-16le", "ignore") + " " + data.decode("latin-1")
                except OSError:
                    pass
                found.append(("Pasta Inicializar", f.name, text))
        except OSError:
            continue
    tasks = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Tasks"
    try:
        for f in tasks.rglob("*"):
            try:
                if f.is_file() and f.stat().st_size < 200_000:
                    raw = f.read_bytes()
                    xml = (raw.decode("utf-16", "ignore") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8", "ignore"))
                    cmds = re.findall(r"<Command>(.*?)</Command>", xml, re.S)
                    for c in cmds:
                        found.append(("Tarefa agendada", f.name, c.strip()))
            except OSError:
                continue
    except OSError:
        pass
    return found


def attach_persistence(procs: list[Proc], entries: list[tuple[str, str, str]]) -> None:
    idx: dict[str, list[str]] = {}
    for kind, where, cmd in entries:
        for t in command_targets(cmd):
            idx.setdefault(t, []).append(f"{kind}: {clean_text(where, 80)}")
    for p in procs:
        if p.exe:
            p.persist = idx.get(norm_path(p.exe), [])[:5]


# ---------------------------------------------------------------- amostragem

_PS_GPU = r"""
$ErrorActionPreference='SilentlyContinue'
$n=[int]$env:SENT_N
Get-Counter -Counter '\GPU Engine(*)\Utilization Percentage' -SampleInterval 2 -MaxSamples $n | ForEach-Object {
  '#'
  $_.CounterSamples | Where-Object { $_.CookedValue -gt 0.5 } | ForEach-Object { '{0}|{1}' -f $_.InstanceName, [math]::Round($_.CookedValue,1) }
}
"""
_GPU_RX = re.compile(r"pid_(\d+)_.*?engtype_([a-z0-9 _]+)", re.I)


def parse_gpu_output(text: str) -> dict[int, list[tuple[float, float]]]:
    """pid -> [(máx. 3D, máx. compute/cuda)] por amostra. Usa o MÁXIMO entre engines do mesmo tipo (soma enganaria)."""
    samples: list[dict[int, list[float]]] = []
    cur: dict[int, list[float]] | None = None
    for line in text.splitlines():
        line = line.strip()
        if line == "#":
            cur = {}
            samples.append(cur)
            continue
        if cur is None or "|" not in line:
            continue
        inst, _, val = line.rpartition("|")
        m = _GPU_RX.search(inst)
        if not m:
            continue
        try:
            v = float(val.replace(",", "."))
        except ValueError:
            continue
        pid, typ = int(m.group(1)), m.group(2).lower()
        slot = cur.setdefault(pid, [0.0, 0.0])
        if typ.startswith("3d"):
            slot[0] = max(slot[0], v)
        elif typ.startswith("compute") or typ.startswith("cuda"):
            slot[1] = max(slot[1], v)
    pids = {pid for s in samples for pid in s}
    return {pid: [tuple(s.get(pid, [0.0, 0.0])) for s in samples] for pid in pids}


class GpuSampler:
    def __init__(self, seconds: int) -> None:
        self.n = max(2, seconds // 2)
        self.tmp = tempfile.TemporaryFile()
        self.proc = None
        try:
            self.proc = subprocess.Popen(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _PS_GPU],
                                         env=dict(os.environ, SENT_N=str(self.n)), stdout=self.tmp, stderr=subprocess.DEVNULL,
                                         creationflags=CREATE_NO_WINDOW)
        except OSError:
            self.proc = None

    def finish(self, cancelled=lambda: False) -> dict:
        if not self.proc:
            return {}
        deadline = time.time() + 30
        while self.proc.poll() is None and time.time() < deadline and not cancelled():
            time.sleep(0.2)
        if self.proc.poll() is None:
            self.proc.kill()
        try:
            self.tmp.seek(0)
            return parse_gpu_output(self.tmp.read().decode("utf-8", "replace"))
        finally:
            self.tmp.close()

    def abort(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
        try:
            self.tmp.close()
        except OSError:
            pass


def sample_behavior(procs: list[Proc], seconds: int, status=lambda m: None, cancelled=lambda: False, interval: float = 2.0) -> int:
    """Observa CPU, GPU e rede por `seconds`. Identidade = (pid, create_time): amostra de processo cujo create_time mudou é descartada."""
    index = {p.key: p for p in procs}
    pid_key = {p.pid: p.key for p in procs}
    for _ in psutil.process_iter(["pid", "cpu_percent"]):  # prepara os medidores
        pass
    gpu = GpuSampler(seconds)
    n = max(1, int(seconds / interval))
    done = 0
    try:
        for i in range(n):
            t_end = time.time() + interval
            while time.time() < t_end:
                if cancelled():
                    raise InterruptedError
                time.sleep(0.1)
            status(f"Observando o comportamento… {int((i + 1) * interval)}/{seconds} s")
            alive = {}
            for pr in psutil.process_iter(["pid", "create_time", "cpu_percent"]):
                inf = pr.info
                key = (inf["pid"], round(float(inf.get("create_time") or 0.0), 2))
                alive[inf["pid"]] = key
                p = index.get(key)
                if p is not None and inf.get("cpu_percent") is not None:
                    p.cpu.append(float(inf["cpu_percent"]))
            syn_now: dict[int, int] = {}
            try:
                conns = psutil.net_connections("inet")
            except (psutil.Error, OSError):
                conns = []
            for c in conns:
                if not c.pid or c.pid not in alive or alive[c.pid] != pid_key.get(c.pid):
                    continue
                p = index.get(alive[c.pid])
                if p is None:
                    continue
                if c.status == "LISTEN":
                    if c.laddr and c.laddr.ip in ("0.0.0.0", "::"):
                        p.listen_public.add(c.laddr.port)
                    continue
                if not c.raddr:
                    continue
                ip, port = c.raddr.ip, c.raddr.port
                if is_private_ip(ip):
                    continue
                p.remote_ips.add(ip)
                p.remote_ports.add(port)
                if port in SCAN_PORTS:
                    p.scan_ips.add(ip)
                if c.status == "SYN_SENT":
                    syn_now[p.pid] = syn_now.get(p.pid, 0) + 1
                    p.syn_nets.add(".".join(ip.split(".")[:3]) if "." in ip else ip.rsplit(":", 1)[0])
            for p in procs:
                p.syn.append(syn_now.get(p.pid, 0))
            done += 1
        for pid, rows in gpu.finish(cancelled).items():
            p = index.get(pid_key.get(pid, (None, None)))
            if p is not None:
                p.gpu_3d = [r[0] for r in rows]
                p.gpu_compute = [r[1] for r in rows]
    except BaseException:
        gpu.abort()
        raise
    wins = visible_window_pids()
    fg = foreground_pid()
    for p in procs:
        if p.pid in wins:
            p.has_window = True
        p.foreground = p.pid == fg
        if p.exe and p.kind in ("local", "removable"):
            p.stat1 = _ft(_safe_stat(p.exe))
    return int(done * interval)


def read_dns_cache(cancelled=lambda: False) -> dict:
    raw = run_powershell("$ErrorActionPreference='SilentlyContinue'; Get-DnsClientCache | Where-Object { $_.Type -in 1,28 } | "
                         "Select-Object Entry,Data | ConvertTo-Json -Compress", timeout=20, cancelled=cancelled)
    out: dict = {}
    try:
        data = json.loads(raw or "[]")
    except ValueError:
        return out
    if isinstance(data, dict):
        data = [data]
    for d in data if isinstance(data, list) else []:
        if isinstance(d, dict) and isinstance(d.get("Entry"), str) and isinstance(d.get("Data"), str):
            out.setdefault(d["Data"], set()).add(d["Entry"].lower()[:200])
    return out


# ---------------------------------------------------------------- máquina (Defender, hosts)

_PS_DEF = r"""
$ErrorActionPreference='SilentlyContinue'
$s = Get-MpComputerStatus; $p = Get-MpPreference
[pscustomobject]@{ ok=($null -ne $s); rt=$s.RealTimeProtectionEnabled; age=$s.AntivirusSignatureAge; tamper=$s.IsTamperProtected;
  mode=[string]$s.AMRunningMode; excl=@($p.ExclusionPath)+@($p.ExclusionProcess)+@($p.ExclusionExtension) } | ConvertTo-Json -Compress
"""
_HOSTS_AV = re.compile(r"(?:^|\.)(?:windowsupdate\.com|update\.microsoft\.com|download\.microsoft\.com|ctldl\.windowsupdate\.com|"
                       r"smartscreen[\w.-]*\.microsoft\.com|wdcp\.microsoft\.com|defender\.microsoft\.com|virustotal\.com|kaspersky\.com|avast\.com|avg\.com|"
                       r"eset\.com|bitdefender\.com|malwarebytes\.com|mcafee\.com|norton\.com|symantec\.com|sophos\.com|trendmicro\.com|"
                       r"f-secure\.com|drweb\.com|avira\.com|comodo\.com|pandasecurity\.com)$", re.I)
DEFENDER_EXCL_GAP = "Exclusões do Defender não verificadas (só administrador consegue ler)"


def defender_findings(raw: str | None) -> tuple[list[Finding], list[Finding], bool]:
    """(achados, lacunas relevantes, exclusões_legíveis). `raw` = JSON do PowerShell (None se falhou)."""
    try:
        d = json.loads(raw) if raw else None
    except ValueError:
        d = None
    if not isinstance(d, dict) or not d.get("ok"):
        return [], [gap("Estado do Defender indisponível")], False
    out: list[Finding] = []
    mode = str(d.get("mode") or "")
    if d.get("rt") is False:
        if mode and mode.lower() not in ("normal", ""):
            out.append(Finding("machine", "Defender em modo passivo", "Outro antivírus parece estar ativo. Confirme que ele está ligado.", 0, "info"))
        else:
            out.append(Finding("machine", "Proteção em tempo real do Defender desligada",
                               "Malware costuma desligar o Defender. Se foi você, reative em Segurança do Windows.", 40, "high"))
    age = d.get("age")
    if isinstance(age, (int, float)) and not isinstance(age, bool):
        if age > 30:
            out.append(Finding("machine", f"Assinaturas do Defender com {int(age)} dias", "Atualize o Defender para detectar ameaças recentes.", 15, "medium"))
        elif age > 7:
            out.append(Finding("machine", f"Assinaturas do Defender com {int(age)} dias", "Atualize o Defender.", 5, "low"))
    if d.get("tamper") is False:
        out.append(Finding("machine", "Proteção contra Adulteração do Defender desativada", "Ela impede que malware mude as configurações do Defender.", 0, "info"))
    excl = d.get("excl")
    excl = [x for x in excl if isinstance(x, str)] if isinstance(excl, list) else ([excl] if isinstance(excl, str) else [])
    readable = not any(x.strip().upper().startswith("N/A") for x in excl)
    if readable and excl:
        out.append(Finding("machine", f"O Defender tem {len(excl)} exclusão(ões)",
                           "; ".join(clean_text(x, 80) for x in excl[:5]) + "\nMalware costuma criar exclusões para não ser escaneado.", 10, "low"))
    return out, [], readable


def hosts_findings(text: str | None) -> list[Finding]:
    if not text:
        return []
    hits = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        parts = line.split()
        if len(parts) >= 2:
            hits += [h for h in parts[1:] if _HOSTS_AV.search(h)]
    if hits:
        return [Finding("machine", "O arquivo hosts bloqueia/redireciona sites de segurança ou atualização",
                        ", ".join(clean_text(h, 60) for h in hits[:5]) + "\nMalware faz isso para impedir antivírus e atualizações.", 25, "medium")]
    return []


def machine_checks(cancelled=lambda: False) -> tuple[list[Finding], list[Finding], list[str]]:
    """(achados, lacunas relevantes, limites conhecidos permanentes)."""
    raw = run_powershell(_PS_DEF, timeout=40, cancelled=cancelled)
    fs, gaps, excl_ok = defender_findings(raw)
    limits = [] if excl_ok else [DEFENDER_EXCL_GAP]
    try:
        hosts = (Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts").read_text(errors="ignore")[:5_000_000]
    except OSError:
        hosts = None
        gaps.append(gap("Arquivo hosts ilegível"))
    return fs + hosts_findings(hosts), gaps, limits


# ---------------------------------------------------------------- orquestração

@dataclass
class ScanReport:
    procs: list
    machine: list
    gaps: list
    limits: list
    verdict: Verdict
    seconds: int
    elapsed: float
    top: list
    stats: dict


def _top_consumers(procs: list[Proc], ncores: int, k: int = 8) -> list[tuple[Proc, float, float]]:
    rows = []
    for p in procs:
        st = cpu_stats(p.cpu, ncores)
        cpu = st["avg"] if st else 0.0
        gpu = (sum(p.gpu_compute) + sum(p.gpu_3d)) / max(1, len(p.gpu_3d)) if p.gpu_3d else 0.0
        if cpu >= 3 or gpu >= 10:
            rows.append((p, cpu, gpu))
    rows.sort(key=lambda r: r[1] + r[2] * 0.5, reverse=True)
    return rows[:k]


def run_scan(settings, vt: VirusTotal | None, seconds: int, step=lambda i, msg="": None, cancelled=lambda: False) -> ScanReport:
    """Executa a verificação completa. `step(i, msg)` informa o passo (0..4) e o texto de status."""
    t0 = time.time()
    ctx = Ctx()
    ctx.trusted = {e["sha256"]: e for e in settings.data.get("proc_ignore", []) if isinstance(e, dict) and e.get("sha256")}

    step(0, "Lendo a lista de processos…")
    procs, gaps = collect_inventory(cancelled)
    attach_persistence(procs, collect_persistence())

    step(1, "Verificando assinaturas digitais…")
    local = sorted({p.exe for p in procs if p.exe and p.kind in ("local", "removable") and p.exists})
    sigs = verify_signatures(local, cancelled) if local else {}
    for p in procs:
        p.sig = sigs.get(p.exe)
    unsigned = [p for p in procs if sig_state(p) in ("unsigned", "invalid") and p.exists]
    for p in unsigned:
        if cancelled():
            raise InterruptedError
        try:
            if os.path.getsize(p.exe) <= MAX_HASH_BYTES:
                p.sha256 = hash_file(Path(p.exe))["sha256"]
        except OSError:
            p.denied.add("hash")

    step(2, "Consultando a reputação no VirusTotal…")
    vt_skipped = 0
    candidates = [p for p in unsigned if p.sha256 and p.sha256 not in ctx.trusted]
    if use_vt := bool(settings.data.get("proc_vt", True)) and vt is not None and candidates:
        candidates.sort(key=lambda p: (not is_risky_dir(p.exe), not bool(p.persist), p.name.lower()))
        for i, p in enumerate(candidates):
            if i >= MAX_VT:
                vt_skipped = len(candidates) - MAX_VT
                break
            res = vt.lookup(p.sha256, lambda m: step(2, m), cancelled)
            fs, _ = vt_findings(res, "", True)
            for f in fs:
                f.stage = "vt"
            p.findings += fs
    elif candidates:
        vt_skipped = len(candidates)

    step(3, "Observando o comportamento…")
    ctx.window = sample_behavior(procs, seconds, lambda m: step(3, m), cancelled)
    ctx.dns = read_dns_cache(cancelled)

    step(4, "Analisando os resultados…")
    machine, mgaps, limits = machine_checks(cancelled)
    analyze_all(procs, ctx)
    for p in procs:  # processos com alerta ganham hash (permite "Confiar" também para assinados)
        if p.level != "ok" and not p.sha256 and p.exe and p.kind == "local" and p.exists:
            try:
                if os.path.getsize(p.exe) <= MAX_HASH_BYTES:
                    p.sha256 = hash_file(Path(p.exe))["sha256"]
            except OSError:
                pass

    unreadable = [p for p in procs if p.status == "unreadable"]
    failed = [p for p in procs if p.status == "failed"]
    unverified = [p for p in procs if p.status == "unverified"]
    if failed:
        gaps.append(gap(f"A verificação de assinatura falhou para {len(failed)} processo(s)",
                        ", ".join(clean_text(p.name, 40) for p in failed[:8])))
    if len(unreadable) >= UNREADABLE_LIMIT:
        gaps.append(gap(f"{len(unreadable)} processos não puderam ser inspecionados (acesso negado sem administrador)",
                        ", ".join(clean_text(p.name, 40) for p in unreadable[:8])))
    if unverified:
        why = "" if use_vt else " (VirusTotal desligado ou sem chave)"
        gaps.append(gap(f"{len(unverified)} processo(s) sem assinatura e sem reputação conhecida{why}",
                        ", ".join(clean_text(p.name, 40) for p in unverified[:10])))
    if vt_skipped and use_vt:
        gaps.append(gap(f"{vt_skipped} processo(s) ficaram sem consulta ao VirusTotal (limite da cota)"))
    gaps += mgaps
    if ctx.window < MIN_SCORE_WINDOW:
        limits.append(f"Janela de {ctx.window} s: curta demais para avaliar consumo contínuo (use 60 s ou mais).")
    verdict = scan_verdict(procs, machine, gaps)
    stats = {"total": len(procs), "unreadable": len(unreadable), "unverified": len(unverified), "failed": len(failed),
             "verified": sum(p.status == "verified" for p in procs), "ncores": ctx.ncores,
             "trusted": [(clean_text(p.name, 60), p.sha256[:16]) for p in procs if p.status == "user"]}
    top = _top_consumers(procs, ctx.ncores)
    return ScanReport(procs, machine, gaps, limits, verdict, ctx.window, time.time() - t0, top, stats)


# ---------------------------------------------------------------- ações (nunca automáticas)

PROTECTED_NAMES = {"csrss", "lsass", "smss", "wininit", "services", "winlogon", "dwm", "explorer", "system", "registry", "svchost",
                   "fontdrvhost", "sihost", "ctfmon", "audiodg", "lsm", "memory compression", "secure system", "spoolsv"}
WARN_NAMES = re.compile(r"(?i)^(msmpeng|nissrv|securityhealth|mbam|avast|avg|bdagent|ekrn|kav|vgc|vgtray|easyanticheat|beservice|battleye|"
                        r"faceit|esea|xigncode|gameguard|ace-)")

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
PROCESS_TERMINATE, PROCESS_SUSPEND_RESUME, PROCESS_QUERY_LIMITED = 0x0001, 0x0800, 0x1000


def _open(pid: int, access: int):
    _k32.OpenProcess.restype = ctypes.c_void_p
    _k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    return _k32.OpenProcess(access, 0, pid)


def _handle_identity(h) -> tuple[float, str]:
    """(create_time epoch, caminho do exe) lidos pelo MESMO handle usado depois para agir."""
    class FT(ctypes.Structure):
        _fields_ = [("lo", ctypes.c_uint32), ("hi", ctypes.c_uint32)]
    c, e, k, u = FT(), FT(), FT(), FT()
    _k32.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(FT)] * 4
    ct = 0.0
    if _k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u)):
        ct = ((c.hi << 32) | c.lo) / 1e7 - 11644473600
    buf = ctypes.create_unicode_buffer(32768)
    size = ctypes.c_uint32(32768)
    _k32.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32)]
    path = buf.value if _k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)) else ""
    return ct, path


def action_block_reason(p: Proc) -> str:
    """'' se pode agir; senão o motivo da recusa."""
    if p.pid in (0, 4) or p.pid == os.getpid():
        return "Este processo é do sistema (ou é o próprio Sentinela)."
    exe_l = norm_path(p.exe)
    real_system = (not exe_l) or exe_l.startswith(_WIN + _BS) or any(pf and exe_l.startswith(pf + _BS) for pf in _PF)
    if p.stem in PROTECTED_NAMES and real_system:
        return "Encerrar ou suspender este processo pode travar o Windows."
    exe = norm_path(p.exe)
    if exe and exe.startswith(_WIN + "\\"):
        return "Este programa faz parte do Windows."
    try:
        sid = ctypes.c_uint32()
        if _k32.ProcessIdToSessionId(p.pid, ctypes.byref(sid)) and sid.value == 0:
            return "Processos da sessão 0 são serviços do sistema."
    except Exception:
        pass
    return ""


def action_warning(p: Proc) -> str:
    if WARN_NAMES.match(p.name):
        return "Este parece ser um antivírus ou anticheat. Encerrá-lo pode desproteger o PC ou causar banimento em jogos."
    return ""


def act_on_process(p: Proc, action: str) -> str:
    """action = 'terminate' | 'suspend' | 'resume'. Abre UM handle, confere create_time+exe nele e age nele. Devolve '' ou a mensagem de erro."""
    reason = action_block_reason(p)
    if reason:
        return reason
    access = {"terminate": PROCESS_TERMINATE, "suspend": PROCESS_SUSPEND_RESUME, "resume": PROCESS_SUSPEND_RESUME}.get(action)
    if access is None:
        return "Ação desconhecida."
    h = _open(p.pid, access | PROCESS_QUERY_LIMITED)
    if not h:
        return "Sem permissão para este processo (ele pode ser protegido ou rodar como administrador)."
    try:
        ct, path = _handle_identity(h)
        if abs(ct - p.create_time) > 1.0 or (p.exe and norm_path(path) != norm_path(p.exe)):
            return "O processo mudou desde a verificação (o número foi reutilizado). Rode a verificação de novo."
        if action == "terminate":
            ok = bool(_k32.TerminateProcess(ctypes.c_void_p(h), 1))
        else:
            nt = ctypes.WinDLL("ntdll")
            nt.NtSuspendProcess.argtypes = nt.NtResumeProcess.argtypes = [ctypes.c_void_p]
            ok = (nt.NtSuspendProcess if action == "suspend" else nt.NtResumeProcess)(ctypes.c_void_p(h)) == 0
        return "" if ok else "O Windows recusou a operação."
    finally:
        _k32.CloseHandle.argtypes = [ctypes.c_void_p]
        _k32.CloseHandle(ctypes.c_void_p(h))


# ---------------------------------------------------------------- relatório

def report_text(rep: ScanReport, redact_on: bool = True) -> str:
    """Relatório em texto. Redação ligada por padrão (caminhos do usuário, segredos em linhas de comando)."""
    fix = redact if redact_on else (lambda s: s)
    v = rep.verdict
    lines = [f"Sentinela – verificação de processos", f"Veredito: {v.headline} (pontuação {v.score})", clean_text(v.summary, 600), ""]
    for p in sorted(rep.procs, key=lambda p: -p.score):
        if p.level == "ok" and not any(f.points > 0 for f in p.findings):
            continue
        lines.append(f"[{p.level}] {clean_text(p.name, 80)} (PID {p.pid}) {fix(clean_text(p.exe, 240))}")
        if p.cmdline:
            lines.append("    cmd: " + fix(clean_text(p.cmdline, 400)))
        for f in p.findings:
            if f.points > 0 or f.severity != "info":
                lines.append(f"    - {clean_text(f.title, 160)} ({f.points:+d}): {fix(clean_text(f.detail, 300))}")
    for f in rep.machine:
        lines.append(f"[máquina] {clean_text(f.title, 160)} ({f.points:+d}): {fix(clean_text(f.detail, 300))}")
    ign = rep.stats.get("trusted") or []
    if ign:
        lines.append("")
        lines.append(f"Ignorados por você (\"Confiar\"): {len(ign)}")
        lines += [f"  - {n} (SHA-256 {h}…)" for n, h in ign]
    if rep.gaps or rep.limits:
        lines.append("")
        lines.append("Não verificado:")
        lines += [f"  - {clean_text(g.title, 200)}" for g in rep.gaps] + [f"  - {clean_text(x, 200)}" for x in rep.limits]
    return "\n".join(lines)
