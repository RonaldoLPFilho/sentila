"""Verificar computador: auditoria de persistência, higiene do Windows, triagem dos achados dos motores e orquestração dos modos.

Princípios (iguais ao resto do Sentinela): só "Perigoso" decide sozinho; lacuna nunca é "ok"; sem "PC limpo"; nada é apagado/movido sozinho;
texto vindo de scanners/arquivos/registro é hostil (clean_text). Os motores NÃO são independentes entre si (Defender e VirusTotal contam
como "um e meio"): "Perigoso" exige nome de FAMÍLIA do Defender, ou ClamAV de família + o Defender concordando no mesmo arquivo.
"""
from __future__ import annotations

import json
import os
import re
import time
import winreg
from dataclasses import dataclass, field
from pathlib import Path

from . import components as comp
from . import procscan as ps
from . import scanengines as se
from .checks import VirusTotal, hash_file, run_powershell, verify_signatures, vt_findings
from .scoring import Finding, Verdict, compute_score, gap

_BS = chr(92)
PATH_RX = re.compile(r'[A-Za-z]:' + _BS + _BS + r'[^"<>|\r\n,]{2,260}?\.(?:exe|dll|scr|com|bat|cmd|ps1|vbs|vbe|js|jse|hta|cpl|jar|msi|lnk)\b', re.I)
LOLBINS = {"rundll32", "regsvr32", "mshta", "wscript", "cscript", "powershell", "pwsh", "cmd", "msiexec", "installutil", "regasm", "msbuild", "bitsadmin", "certutil"}


# ---------------------------------------------------------------- auditoria de persistência

@dataclass
class PItem:
    kind: str                 # Run | Serviço | Pasta Inicializar | Tarefa agendada | IFEO | AppInit | Winlogon | COM | WMI | BITS
    where: str
    command: str
    targets: list = field(default_factory=list)
    flags: set = field(default_factory=set)       # hidden | ifeo | appinit | winlogon | com | wmi | bits
    note: str = ""
    findings: list = field(default_factory=list)
    level: str = "ok"
    score: int = 0


def targets_of(command: str) -> list[str]:
    cmd = os.path.expandvars(str(command or "")[:ps.CMD_LIMIT])
    out = []
    first = ps.command_targets(cmd)
    for t in list(first) + [ps.norm_path(m.group(0)) for m in PATH_RX.finditer(cmd)]:
        if t and t not in out:
            out.append(t)
    return out[:6]


def _reg_values(hive, sub: str) -> dict:
    out = {}
    try:
        with winreg.OpenKey(hive, sub) as k:
            i = 0
            while True:
                try:
                    n, v, _t = winreg.EnumValue(k, i)
                except OSError:
                    break
                i += 1
                out[n] = v
    except OSError:
        pass
    return out


def _subkeys(hive, sub: str) -> list[str]:
    try:
        with winreg.OpenKey(hive, sub) as k:
            return [winreg.EnumKey(k, i) for i in range(winreg.QueryInfoKey(k)[0])]
    except OSError:
        return []


_PS_TASKS = r"""
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$o=@(); Get-ScheduledTask | ForEach-Object { $t=$_; foreach($a in $t.Actions){ if($a.Execute){ $o += [pscustomobject]@{n=[string]$t.TaskName; h=[bool]$t.Settings.Hidden; e=[string]$a.Execute; a=[string]$a.Arguments} } } }
ConvertTo-Json -InputObject @($o) -Compress
"""


def _tasks(cancelled=lambda: False) -> tuple[list[PItem], bool]:
    """Tarefas agendadas via Get-ScheduledTask (legível sem administrador), com o atributo Hidden e os argumentos."""
    raw = run_powershell(_PS_TASKS, timeout=90, cancelled=cancelled)
    if raw is None:
        return [], False
    out = []
    for d in _json_list(raw)[:4000]:
        full = (str(d.get("e", "")) + " " + str(d.get("a", ""))).strip()
        it = PItem("Tarefa agendada", ps.clean_text(d.get("n", ""), 80), ps.clean_text(full, ps.CMD_LIMIT))
        it.targets = targets_of(full)
        if d.get("h") is True:
            it.flags.add("hidden")
        out.append(it)
    return out, True


_PS_WMI = r"""
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$o=@()
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer | ForEach-Object { $o += [pscustomobject]@{k='CommandLine'; n=$_.Name; c=[string]$_.CommandLineTemplate} }
Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer | ForEach-Object { $o += [pscustomobject]@{k='ActiveScript'; n=$_.Name; c=([string]$_.ScriptText).Substring(0,[Math]::Min(500,([string]$_.ScriptText).Length))} }
ConvertTo-Json -InputObject @($o) -Compress
"""
_PS_BITS = r"""
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$o=@(); Get-BitsTransfer | ForEach-Object { foreach($f in $_.FileList){ $o += [pscustomobject]@{n=$_.DisplayName; u=[string]$f.RemoteName; p=[string]$f.LocalName} } }
ConvertTo-Json -InputObject @($o) -Compress
"""


def _json_list(raw) -> list[dict]:
    try:
        d = json.loads(raw or "[]")
    except ValueError:
        return []
    if isinstance(d, dict):
        d = [d]
    return [x for x in d if isinstance(x, dict)] if isinstance(d, list) else []


def audit_persistence(cancelled=lambda: False) -> tuple[list[PItem], list[str]]:
    """Itens de inicialização automática. Tudo é leitura (sem administrador). Devolve (itens, lacunas de leitura)."""
    items: list[PItem] = []
    notes: list[str] = []
    for kind, where, cmd in ps.collect_persistence():
        if kind == "Tarefa agendada":
            continue                       # lidas por _tasks() (com o atributo Hidden e os argumentos)
        it = PItem(kind, ps.clean_text(where, 100), ps.clean_text(cmd, ps.CMD_LIMIT))
        it.targets = targets_of(cmd)
        items.append(it)
    tk, ok_tasks = _tasks(cancelled)
    items += tk
    if not ok_tasks:
        notes.append("As tarefas agendadas não puderam ser lidas")
    base = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    # IFEO: Debugger redireciona a execução de um programa para outro
    for root in (base, r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion"):
        for sub in _subkeys(winreg.HKEY_LOCAL_MACHINE, root + r"\Image File Execution Options"):
            vals = _reg_values(winreg.HKEY_LOCAL_MACHINE, root + r"\Image File Execution Options" + _BS + sub)
            dbg = vals.get("Debugger")
            if isinstance(dbg, str) and dbg.strip():
                it = PItem("IFEO", ps.clean_text(sub, 80), ps.clean_text(dbg, 300), targets_of(dbg), {"ifeo"})
                items.append(it)
    # AppInit_DLLs
    for root in (base, r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion"):
        vals = _reg_values(winreg.HKEY_LOCAL_MACHINE, root + r"\Windows")
        dll = vals.get("AppInit_DLLs")
        if isinstance(dll, str) and dll.strip() and int(vals.get("LoadAppInit_DLLs", 0) or 0) == 1:
            items.append(PItem("AppInit", "AppInit_DLLs", ps.clean_text(dll, 300), targets_of(dll), {"appinit"}))
    # Winlogon Shell/Userinit
    wl = _reg_values(winreg.HKEY_LOCAL_MACHINE, base + r"\Winlogon")
    shell = str(wl.get("Shell", "explorer.exe")).strip()
    userinit = str(wl.get("Userinit", "")).strip().lower().rstrip(",")
    if shell.lower() != "explorer.exe":
        items.append(PItem("Winlogon", "Shell", ps.clean_text(shell, 300), targets_of(shell) or [ps.norm_path(shell)], {"winlogon"}, "O normal é explorer.exe"))
    if userinit and userinit != (os.environ.get("SystemRoot", r"C:\Windows") + r"\system32\userinit.exe").lower():
        items.append(PItem("Winlogon", "Userinit", ps.clean_text(userinit, 300), targets_of(userinit) or [], {"winlogon"}, "O normal é só userinit.exe"))
    # COM hijacking por usuário
    for clsid in _subkeys(winreg.HKEY_CURRENT_USER, r"Software\Classes\CLSID")[:2000]:
        for srv in ("InprocServer32", "LocalServer32"):
            v = _reg_values(winreg.HKEY_CURRENT_USER, rf"Software\Classes\CLSID\{clsid}\{srv}").get("")
            if isinstance(v, str) and v.strip():
                it = PItem("COM", ps.clean_text(clsid, 60), ps.clean_text(v, 300), targets_of(v) or [ps.norm_path(v)], {"com"})
                items.append(it)
    # WMI e BITS
    raw = run_powershell(_PS_WMI, timeout=30, cancelled=cancelled)
    if raw is None:
        notes.append("Assinaturas de eventos WMI não puderam ser lidas")
    for d in _json_list(raw):
        items.append(PItem("WMI", ps.clean_text(d.get("n", ""), 80), ps.clean_text(d.get("c", ""), 500), targets_of(d.get("c", "")), {"wmi"}, str(d.get("k", ""))))
    raw = run_powershell(_PS_BITS, timeout=30, cancelled=cancelled)
    for d in _json_list(raw):
        it = PItem("BITS", ps.clean_text(d.get("n", ""), 80), ps.clean_text(f"{d.get('u', '')} -> {d.get('p', '')}", 400), targets_of(d.get("p", "")), {"bits"})
        items.append(it)
    return items, notes


def triage_persistence(items: list[PItem], sigs: dict, trusted: dict | None = None) -> None:
    """Pontua cada item com a assinatura de cada alvo. Alvo assinado por publicador válido não pesa."""
    def state_of(path: str) -> tuple[str, "ps.Proc"]:
        p = ps.Proc(pid=0, name=os.path.basename(path), exe=path)
        p.exists = os.path.exists(path)
        p.sig = sigs.get(path)
        return ps.sig_state(p), p

    def in_system(t: str) -> bool:
        n = ps.norm_path(t)
        return n.startswith(ps._WIN + chr(92)) or any(pf and n.startswith(pf + chr(92)) for pf in ps._PF)

    for it in items:
        fs: list[Finding] = []
        worst_unsigned = None
        remote = [t for t in it.targets if ps.path_kind(t) in ("remote", "removable")]
        if remote:
            # NUNCA abre o arquivo (evita SMB/NTLM e travamento): o achado é a origem
            fs.append(Finding("persist", f"{it.kind} executa a partir da rede ou de mídia removível", f"{it.where}: {ps.clean_text(remote[0], 200)}. O arquivo não foi aberto.", 25, "medium"))
            it.targets = [t for t in it.targets if t not in remote]
        for t in it.targets:
            if not os.path.isfile(t):
                continue
            st, p = state_of(t)
            if st in ("ms", "signed", "packaged"):
                continue
            if st in ("unsigned", "invalid"):
                worst_unsigned = worst_unsigned or t
        loc = lambda t: ps.is_risky_dir(t) or ps.is_user_dir(t) or not in_system(t)
        risky = [t for t in it.targets if os.path.isfile(t) and loc(t) and state_of(t)[0] in ("unsigned", "invalid")]
        mh = re.match(r'^\s*"?([^"\s]+)', it.command or "")
        lol = bool(mh) and os.path.basename(mh.group(1)).lower().split(".")[0] in LOLBINS
        cmd_f = ps.live_cmd_findings(it.command)
        fs += cmd_f
        if it.kind == "IFEO":
            ms = bool(it.targets) and all(state_of(t)[0] == "ms" for t in it.targets if os.path.isfile(t)) and any(os.path.isfile(t) for t in it.targets)
            fs.append(Finding("persist", f"Sequestro de programa (IFEO): {it.where} é redirecionado", f"Debugger = {it.command}", 0 if ms else 45, "info" if ms else "high"))
        elif it.kind == "Winlogon":
            fs.append(Finding("persist", f"Winlogon {it.where} alterado", f"{it.command}. {it.note}. Malware usa isso para rodar a cada login.", 50, "high"))
        elif it.kind == "AppInit":
            fs.append(Finding("persist", "AppInit_DLLs carrega DLLs em todo programa", it.command, 30, "medium"))
        elif it.kind == "WMI":
            fs.append(Finding("persist", f"Assinatura WMI que executa comandos ({it.note})", f"{it.where}: {it.command[:200]}. Técnica de persistência furtiva.", 45, "high"))
        elif it.kind == "BITS":
            if not re.search(r"(?i)^https?://[^/]*(microsoft|windowsupdate|office|live|google|mozilla|adobe|nvidia|steam|valvesoftware|epicgames)", it.command):
                fs.append(Finding("persist", "Tarefa de transferência em segundo plano (BITS) ativa", it.command[:240], 25, "medium"))
        elif it.kind == "COM" and risky:
            fs.append(Finding("persist", f"COM do usuário aponta para programa sem assinatura ({it.where})", it.command + ". Comum em launchers; sozinho não indica malware.", 8, "info"))
        elif risky:
            pts = 8 + (15 if "hidden" in it.flags else 0) + (12 if lol else 0)
            tit = f"{it.kind} aponta para programa sem assinatura em pasta de usuário"
            fs.append(Finding("persist", tit + (" (tarefa oculta)" if "hidden" in it.flags else ""),
                              f"{it.where}: {it.command[:220]}. Comum em programas portáteis e launchers; o que pesa é a combinação com outros sinais.", pts,
                              "info" if pts < 15 else "medium" if pts < 40 else "high"))
        elif "hidden" in it.flags and worst_unsigned:
            fs.append(Finding("persist", "Tarefa agendada oculta com programa sem assinatura", f"{it.where}: {it.command[:220]}", 15, "low"))
        elif worst_unsigned:
            fs.append(Finding("persist", f"{it.kind} com programa sem assinatura", f"{it.where}: {it.command[:200]}", 0, "info"))
        for t in it.targets:
            if not os.path.isfile(t) and it.kind not in ("IFEO", "AppInit", "Winlogon") and ps.is_user_dir(t):
                fs.append(Finding("persist", "Inicialização aponta para um arquivo que não existe mais", f"{it.where}: {t}", 0, "info"))
                break
        it.findings = fs
        it.score, it.level = ps.level_of(fs)


# ---------------------------------------------------------------- higiene do Windows

def _dword(hive, sub: str, name: str):
    try:
        with winreg.OpenKey(hive, sub) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


_PS_AV = r"""
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
ConvertTo-Json -InputObject @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { [pscustomobject]@{n=$_.displayName; s=[int]$_.productState} }) -Compress
"""
_PS_FW = r"""
$ErrorActionPreference='SilentlyContinue'
ConvertTo-Json -InputObject @(Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{n=[string]$_.Name; e=[bool]$_.Enabled} }) -Compress
"""
_PS_ADM = r"""
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
ConvertTo-Json -InputObject @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { [pscustomobject]@{n=[string]$_.Name; t=[string]$_.ObjectClass} }) -Compress
"""


def antivirus_products(cancelled=lambda: False) -> list[tuple[str, bool]]:
    """(nome, ativo?) pelo Centro de Segurança. productState: bits 0x1000 = ligado."""
    out = []
    for d in _json_list(run_powershell(_PS_AV, timeout=30, cancelled=cancelled)):
        try:
            out.append((ps.clean_text(d.get("n", "?"), 60), bool(int(d.get("s", 0)) & 0x1000)))
        except (TypeError, ValueError):
            continue
    return out


def hygiene(cancelled=lambda: False) -> tuple[list[Finding], list[Finding], list[str]]:
    """(achados, lacunas, notas de contexto)."""
    fs: list[Finding] = []
    gaps: list[Finding] = []
    notes: list[str] = []
    fw = _json_list(run_powershell(_PS_FW, timeout=30, cancelled=cancelled))
    if not fw:
        gaps.append(gap("Estado do firewall não pôde ser lido"))
    off = [ps.clean_text(d.get("n", "?"), 20) for d in fw if d.get("e") is False]
    other_av = [n for n, on in antivirus_products(cancelled) if on and "defender" not in n.lower()]
    if off and other_av:
        notes.append("Firewall do Windows desligado, mas há outro antivírus ativo (" + ", ".join(other_av) + ") que pode estar fazendo esse papel.")
        off = []
    if off:
        fs.append(Finding("hygiene", f"Firewall do Windows desligado em: {', '.join(off)}", "Sem firewall, serviços do PC ficam expostos à rede. Reative em Segurança do Windows.", 20, "medium"))
    pol = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    if _dword(winreg.HKEY_LOCAL_MACHINE, pol, "EnableLUA") == 0:
        fs.append(Finding("hygiene", "Controle de Conta de Usuário (UAC) desativado", "Qualquer programa pode obter privilégios de administrador sem pedir.", 25, "medium"))
    if _dword(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections") == 0:
        fs.append(Finding("hygiene", "Área de Trabalho Remota (RDP) habilitada", "Se você não usa, desligue: é um alvo comum de ataques de senha.", 8, "low"))
    for hive, sub, nm in ((winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware"),
                          (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring")):
        if _dword(hive, sub, nm) == 1:
            fs.append(Finding("hygiene", "Uma política desativa o Defender", f"{nm}=1 em {sub}. Malware costuma gravar isso; se você não usa outro antivírus, reverta.", 40, "high"))
    if _dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen") == 0:
        fs.append(Finding("hygiene", "SmartScreen desativado por política", "", 10, "low"))
    if _dword(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1") == 1:
        fs.append(Finding("hygiene", "SMBv1 habilitado", "Protocolo antigo e vulnerável (usado pelo WannaCry). Desative.", 15, "low"))
    adm = _json_list(run_powershell(_PS_ADM, timeout=30, cancelled=cancelled))
    if adm:
        names = [ps.clean_text(d.get("n", "?"), 40) for d in adm]
        notes.append("Administradores locais: " + ", ".join(names))
        if len(names) > 3:
            fs.append(Finding("hygiene", f"{len(names)} contas com privilégio de administrador", ", ".join(names), 8, "low"))
    else:
        gaps.append(gap("Lista de administradores locais não pôde ser lida"))
    machine, mgaps, limits = ps.machine_checks(cancelled)
    fs += machine
    gaps += mgaps
    notes += limits
    return fs, gaps, notes


# ---------------------------------------------------------------- triagem dos achados dos motores

@dataclass
class FileItem:
    path: str
    detections: list = field(default_factory=list)
    sha256: str = ""
    sig: dict | None = None
    findings: list = field(default_factory=list)
    level: str = "ok"
    score: int = 0
    status: str = ""
    exists: bool = True


def triage_detections(dets: list, trusted: dict | None = None, vt: VirusTotal | None = None, status=lambda m: None, cancelled=lambda: False) -> list[FileItem]:
    """Agrupa as detecções por arquivo, confere assinatura/hash e aplica os limiares (motores não são independentes)."""
    trusted = trusted or {}
    by: dict[str, FileItem] = {}
    for d in dets:
        key = ps.norm_path(d.path) or d.path
        by.setdefault(key, FileItem(d.path)).detections.append(d)
    items = list(by.values())
    real = [i.path for i in items if os.path.isfile(i.path)]
    sigs = verify_signatures(sorted(set(real)), cancelled) if real else {}
    for it in items:
        it.exists = os.path.isfile(it.path)
        it.sig = sigs.get(it.path)
        if it.exists:
            try:
                if os.path.getsize(it.path) <= ps.MAX_HASH_BYTES:
                    it.sha256 = hash_file(Path(it.path))["sha256"]
            except OSError:
                pass
    vt_budget = ps.MAX_VT
    for it in items:
        p = ps.Proc(pid=0, name=os.path.basename(it.path), exe=it.path)
        p.exists, p.sig = it.exists, it.sig
        st = ps.sig_state(p) if it.exists else "na"
        by_engine: dict[str, list] = {}
        for d in it.detections:
            by_engine.setdefault(d.engine, []).append(d)
        fs: list[Finding] = []
        if it.sha256 and it.sha256 in trusted:
            it.status, it.findings = "user", [Finding("scan", "Marcado como confiável por você", "", 0, "info", trust=True)]
            it.score, it.level = 0, "ok"
            continue
        ms_signed = st == "ms"
        # "ambos concordam" exige FAMÍLIA nos dois motores (genérico + família é o caso típico de trainer/mod legítimo)
        def_family = any(se.classify_name("defender", d.name) == "family" and not d.name.startswith("Bloqueado") for d in by_engine.get("defender", []))
        clam_family = any(se.classify_name("clamav", d.name) == "family" for d in by_engine.get("clamav", []))
        both = def_family and clam_family
        for engine, ds in by_engine.items():
            for d in ds:
                kind = se.classify_name(engine, d.name)
                label = ("Defender" if engine == "defender" else "ClamAV") + f": {d.name}"
                if d.name.startswith("Bloqueado pelo antivírus"):
                    if ms_signed:
                        continue
                    fs.append(Finding("scan", label, "O antivírus em tempo real barrou a abertura deste arquivo (veja o nome da ameaça no histórico do Defender).", 45, "high"))
                elif kind == "test":
                    fs.append(Finding("scan", label, "Arquivo de TESTE de antivírus (EICAR ou similar): não é malware real, mas prova que o antivírus está funcionando.", 30, "medium"))
                elif ms_signed:
                    fs.append(Finding("scan", label + " (arquivo assinado pela Microsoft)", "Detecção em arquivo assinado pela Microsoft: provável falso positivo.", 0, "info"))
                elif kind == "family" and engine == "defender":
                    fs.append(Finding("scan", label, "O Defender identificou uma família de malware pelo nome. Não abra o arquivo; analise-o no Sentinela ou mova para a quarentena.", 60, "high"))
                elif kind == "family" and engine == "clamav":
                    pts = 85 if both else 25   # 25 + um genérico do Defender (15) = 40: ainda só Atenção
                    fs.append(Finding("scan", label, "O ClamAV identificou uma família" + (" e o Defender também (família) neste mesmo arquivo." if both else ", mas só ele. O ClamAV tem muitos falsos positivos em mods e trainers: confira a origem."), pts, "critical" if both else "medium"))
                else:
                    fs.append(Finding("scan", label + " (detecção genérica)", "Detecção heurística/PUA de um único motor: comum em trainers, cracks e mods legítimos. Confira a origem.", 15 if engine == "defender" else 5,
                                      "medium" if engine == "defender" else "low"))
        if not it.exists and any(f.points > 0 for f in fs):
            # o arquivo já não existe: o Defender provavelmente já removeu/contou a ameaça (evento 1117). Vale um aviso, não um alarme.
            names = ", ".join(sorted({d.name for d in it.detections if not d.name.startswith("Bloqueado")}))[:160] or "ameaça detectada"
            fs = [Finding("scan", f"Ameaça já contida: {names}", "O arquivo não existe mais (o Defender provavelmente já o removeu ou isolou). Confira o histórico de proteção do Windows.", 20, "medium")]
        if st in ("signed", "packaged") and fs:
            fs.append(Finding("scan", "O arquivo tem assinatura digital válida", ps.publisher_of(p), -10, "info", trust=True))
        if vt and it.sha256 and st in ("unsigned", "invalid", "failed") and vt_budget > 0 and not cancelled():
            vt_budget -= 1
            res = vt.lookup(it.sha256, status, cancelled)
            vfs, _s = vt_findings(res, "VirusTotal", True)
            fs += vfs
        it.findings = fs
        it.score, it.level = ps.level_of(fs)
        it.status = "verified" if st in ("ms", "signed", "packaged") else "unverified"
    items.sort(key=lambda i: -i.score)
    return items


# ---------------------------------------------------------------- orquestração

MODES = {"quick": "Rápida", "full": "Completa"}


@dataclass
class PcReport:
    mode: str
    items: list
    persist: list
    hygiene: list
    procs: object
    gaps: list
    limits: list
    notes: list
    verdict: Verdict
    elapsed: float
    engines: dict
    stats: dict
    started: float = 0.0


def pc_verdict(items: list, persist: list, hyg: list, procs, gaps: list) -> Verdict:
    hyg_level = ps.level_of(hyg)[1]
    hyg_level = "caution" if hyg_level == "danger" else hyg_level   # configuração insegura NÃO é prova de malware: no máximo Atenção
    levels = [i.level for i in items] + [p.level for p in persist] + [hyg_level] + ([procs.verdict.level] if procs is not None and procs.verdict.level in ("danger", "caution") else [])
    score = max([i.score for i in items] + [p.score for p in persist] + [compute_score(hyg)] + ([procs.verdict.score] if procs is not None else []) + [0])
    if "danger" in levels:
        return Verdict(score, "danger", "Perigoso", "Há sinais fortes de malware (veja os achados). Não abra os arquivos apontados; analise-os no Sentinela ou mova-os para a quarentena.")
    n = sum(1 for l in levels if l == "caution")
    if n:
        return Verdict(score, "caution", "Atenção", f"{n} ponto(s) de atenção que não bastam para condenar. Confira a origem de cada um.")
    if gaps:
        missing = "; ".join(g.title for g in gaps[:3]) + (f" (+{len(gaps) - 3})" if len(gaps) > 3 else "")
        return Verdict(score, "unknown", "Inconclusivo", "Nenhum sinal forte, mas isso NÃO significa que o PC está limpo. Faltou: " + missing + ".")
    return Verdict(score, "safe", "Sem indícios (parcial)", "Nenhum sinal de malware nos testes feitos. Isto não prova que o PC está limpo: rootkits, malware só em memória e arquivos fora das pastas verificadas não são vistos.")


def run_pc_scan(settings, mode: str, vt: VirusTotal | None = None, allow_clam_update: bool = False, extra_zones: list | None = None,
                step=lambda i, msg="": None, cancelled=lambda: False, proc_seconds: int = 30) -> PcReport:
    """Executa a verificação. Ids dos passos: 0 atualização · 1 Defender · 2 processos · 3 persistência · 4 higiene · 5 ClamAV · 6 triagem."""
    t0 = time.time()
    gaps: list[Finding] = []
    limits: list[str] = []
    notes: list[str] = []
    engines: dict = {"defender": "não usado", "clamav": "não usado"}
    trusted = {e["sha256"]: e for e in settings.data.get("proc_ignore", []) if isinstance(e, dict) and e.get("sha256")}
    dets: list = []

    av = antivirus_products(cancelled)
    others = [n for n, on in av if on and "defender" not in n.lower()]
    if others:
        notes.append("Outro antivírus ativo: " + ", ".join(others) + ". O Defender fica em modo passivo (a varredura sob demanda dele continua possível, mas ele não remedia).")

    step(0, "Atualizando as assinaturas do Defender…")
    ok, msg = se.defender_update(cancelled)
    if not ok:
        gaps.append(gap("As assinaturas do Defender não puderam ser atualizadas agora"))

    step(1, "Defender: varredura " + MODES[mode].lower() + "…")
    since = time.time()
    d, note = se.defender_scan(1 if mode == "quick" else 2, lambda m: step(1, m), cancelled)
    if d is None:
        gaps.append(gap("Varredura do Defender não concluída", note))
        engines["defender"] = "falhou: " + note
    else:
        dets += d
        engines["defender"] = f"{MODES[mode].lower()} concluída"

    step(2, "Verificando os processos em execução…")
    procs = None
    try:
        procs = ps.run_scan(settings, vt, proc_seconds, lambda i, m="": step(2, m or "Verificando os processos em execução…"), cancelled)
    except InterruptedError:
        raise
    except Exception as e:  # noqa: BLE001
        import traceback
        gaps.append(gap("A verificação de processos falhou", f"{e.__class__.__name__}: {ps.clean_text(str(e), 120)} | {ps.clean_text(traceback.format_exc().splitlines()[-3] if traceback.format_exc() else '', 160)}"))
    run_exes = sorted({p.exe for p in procs.procs if p.exe and p.status in ("unverified", "failed")}) if procs else []

    step(3, "Auditando o que inicia com o Windows…")
    pitems, pnotes = audit_persistence(cancelled)
    notes += pnotes
    tgt = sorted({t for it in pitems for t in it.targets if ps.path_kind(t) == "local" and os.path.isfile(t)})
    sigs = verify_signatures(tgt, cancelled) if tgt else {}
    triage_persistence(pitems, sigs, trusted)
    persist_flagged = [p for p in pitems if p.score > 0 or p.level != "ok"]

    step(4, "Conferindo a higiene do Windows…")
    hyg, hgaps, hnotes = hygiene(cancelled)
    gaps += hgaps
    notes += hnotes

    step(5, "ClamAV: segunda opinião…")
    man = None
    try:
        man = comp.load_bundled_manifest()
    except (comp.ComponentError, OSError):
        gaps.append(gap("Lista de componentes inválida: ClamAV não usado"))
    zr = None
    if man:
        ccomp = man["components"]["clamav"]
        st = comp.detect("clamav", ccomp, man)
        if st.state != comp.OK:
            gaps.append(gap("ClamAV não está instalado e verificado: sem 2ª opinião de antivírus", "Instale pela aba Componentes."))
            engines["clamav"] = "ausente"
        else:
            se.clam_cleanup_tmp()      # sobras de uma atualização interrompida (nenhuma atualização está rodando agora)
            has_db, age, why_db = se.clam_db_state()
            with comp.PinnedRun(st, ccomp) as run:
                if (not has_db or age > 7) and allow_clam_update:
                    ok, msg = se.clam_update(run, lambda m: step(5, m), cancelled)
                    if not ok:
                        gaps.append(gap("As assinaturas do ClamAV não puderam ser atualizadas", msg))
                    has_db, age, why_db = se.clam_db_state()
                if not has_db:
                    gaps.append(gap("ClamAV sem base de assinaturas íntegra", why_db + (". Autorize o download na tela da verificação (cerca de 300 MB)." if not allow_clam_update else "")))
                    engines["clamav"] = "sem base de assinaturas íntegra"
                else:
                    if age > 7:
                        gaps.append(gap(f"Base do ClamAV com {int(age)} dias"))
                    zones = se.hot_zones(mode, extra_zones)
                    skip = (str(comp.COMP_DIR), str(se.CLAM_DB), str(comp.RUN_DIR))
                    zr = se.enumerate_zone(zones, 200000 if mode == "full" else 20000, None if mode == "full" else 30, skip, cancelled)
                    files = list(dict.fromkeys(zr.files + tgt + [e for e in run_exes if ps.path_kind(e) == "local"]))
                    cd, n, errs = se.clam_scan(run, files, None, lambda m: step(5, m), cancelled)
                    dets += cd
                    engines["clamav"] = f"{n} de {len(files)} arquivos varridos" + (f" ({len(files) - n} não verificados)" if n < len(files) else "")
                    for e in errs:
                        gaps.append(gap("O ClamAV não concluiu parte da varredura", e))
                    if zr.skipped_cloud:
                        gaps.append(gap(f"{zr.skipped_cloud} arquivo(s) só na nuvem não foram abertos (para não baixá-los)"))
                    if zr.skipped_big:
                        limits.append(f"{zr.skipped_big} arquivo(s) maiores que 100 MB foram pulados pelo ClamAV.")
                    if mode == "quick":
                        limits.append("A verificação Rápida só olha, nas pastas de risco, arquivos modificados nos últimos 30 dias (e os alvos de inicialização e programas em execução); malware antigo fica para a Completa.")
                    if zr.skipped_nonlocal:
                        gaps.append(gap(f"{zr.skipped_nonlocal} pasta(s) em unidade de rede/removível não foram verificadas"))
                    if zr.truncated:
                        gaps.append(gap("Há mais arquivos do que o limite desta varredura: parte não foi verificada"))

    step(6, "Triagem dos achados…")
    items = triage_detections(dets, trusted, vt, lambda m: step(6, m), cancelled)
    # o log do Defender também registra o bloqueio em tempo real (nome da ameaça): prefere o nome real ao genérico "Bloqueado"
    named = {ps.norm_path(i.path): i for i in items if any(not d.name.startswith("Bloqueado") for d in i.detections)}
    items = [i for i in items if not (all(d.name.startswith("Bloqueado") for d in i.detections) and ps.norm_path(i.path) in named)]

    limits += ["Rootkits de kernel, malware que só vive na memória e arquivos fora das pastas verificadas não são vistos.",
               "Sem administrador, as exclusões do Defender não podem ser lidas e áreas protegidas ficam de fora.",
               "ClamAV tem poucos sinais de malware Windows recente e muitos falsos positivos em mods; por isso um único motor genérico só gera atenção."]
    if procs is not None:
        gaps += [g for g in procs.gaps if "sem assinatura e sem reputação" not in g.title]
        notes += procs.limits[:1]
    flagged = [p for p in persist_flagged if p.level != "ok"]
    verdict = pc_verdict(items, flagged, hyg, procs, gaps)
    stats = {"detections": len(dets), "files_flagged": len([i for i in items if i.level != "ok"]), "persist_total": len(pitems), "persist_flagged": len(flagged),
             "zone_files": len(zr.files) if zr else 0, "av": av}
    return PcReport(mode, items, flagged, hyg, procs, gaps, limits, notes, verdict, time.time() - t0, engines, stats, since)


def report_text(rep: PcReport, redact_on: bool = True) -> str:
    fix = ps.redact if redact_on else (lambda s: s)
    v = rep.verdict
    lines = ["Sentinela – verificação do computador (" + MODES.get(rep.mode, rep.mode) + ")", f"Veredito: {v.headline} (pontuação {v.score})", ps.clean_text(v.summary, 600),
             f"Duração: {int(rep.elapsed // 60)} min · Motores: " + "; ".join(f"{k}: {ps.clean_text(str(x), 80)}" for k, x in rep.engines.items()), ""]
    for i in rep.items:
        if i.level == "ok" and not any(f.points > 0 for f in i.findings):
            continue
        lines.append(f"[{i.level}] {fix(ps.clean_text(i.path, 260))}  SHA-256 {i.sha256[:16]}")
        for f in i.findings:
            lines.append(f"    - {ps.clean_text(f.title, 160)} ({f.points:+d}): {fix(ps.clean_text(f.detail, 260))}")
    for p in rep.persist:
        lines.append(f"[{p.level}] Inicialização ({p.kind}) {ps.clean_text(p.where, 80)}: {fix(ps.clean_text(p.command, 240))}")
        for f in p.findings:
            if f.points > 0 or f.severity != "info":
                lines.append(f"    - {ps.clean_text(f.title, 160)} ({f.points:+d})")
    for f in rep.hygiene:
        lines.append(f"[higiene] {ps.clean_text(f.title, 160)} ({f.points:+d}): {fix(ps.clean_text(f.detail, 240))}")
    lines += ["", "Não verificado / limites:"] + [f"  - {ps.clean_text(g.title, 200)}" for g in rep.gaps] + [f"  - {ps.clean_text(x, 200)}" for x in rep.limits]
    return "\n".join(lines)
