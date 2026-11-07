"""Verificação offline do Microsoft Defender (Start-MpWDOScan): pré-requisito (WinRE), disparo elevado e leitura do resultado após o reinício.

A offline roda dentro do Ambiente de Recuperação do Windows, antes do Windows carregar: pega o que se esconde do Windows em execução.
Fluxo: grava um marcador -> pede elevação (UAC) só para o Start-MpWDOScan -> o Windows reinicia sozinho -> na próxima abertura do Sentinela,
se o PC reiniciou depois do pedido, lê as detecções do Defender desde o pedido e registra no Histórico.
O Windows não registra de forma confiável que a offline TERMINOU: o reinício é o sinal usado, e o relatório diz isso.
"""
from __future__ import annotations

import base64
import json
import os
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

import psutil

from . import procscan as ps
from . import scanengines as se
from .checks import run_powershell
from .config import DATA_DIR

MARKER = "offline_scan.json"
STALE_DAYS = 3        # pedido sem reinício há mais que isso: o Windows não chegou a rodar (descarta)

WINRE_FIX = ("Para reativar, abra o PowerShell como administrador e rode: reagentc /enable. "
             "Se falhar com \"erro 2\", rode antes: reagentc /setreimage /path C:\\Windows\\System32\\Recovery")

HRESULT_TEXT = {
    "0x80070032": "o Windows não suportou a operação (quase sempre o Ambiente de Recuperação/WinRE desativado). " + WINRE_FIX,
    "0x800106BA": "o serviço do Defender não está ativo (outro antivírus assumiu ou o Defender foi desativado).",
    "0x80070005": "acesso negado.",
}


def _marker() -> Path:
    return DATA_DIR / MARKER


# ---------------------------------------------------------------- WinRE

def winre_enabled(xml_path: Path | None = None) -> bool | None:
    """True/False pelo ReAgent.xml (InstallState 1 = ativo), legível sem administrador. None = não deu para saber."""
    p = xml_path or Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Recovery" / "ReAgent.xml"
    try:
        node = ET.parse(p).getroot().find("InstallState")
    except (OSError, ET.ParseError):
        return None
    if node is None:
        return None
    st = node.get("state")
    return True if st == "1" else False if st == "0" else None


# ---------------------------------------------------------------- disparo

_PS_INNER = r"""
$ErrorActionPreference='Stop'
$r=[ordered]@{ok=$false; code=''; msg=''}
try { Start-MpWDOScan; $r.ok=$true }
catch { $r.code=[string]$_.FullyQualifiedErrorId; $r.msg=[string]$_.Exception.Message }
[IO.File]::WriteAllText('__OUT__', ($r | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding $false))
"""

_PS_OUTER = r"""
$ErrorActionPreference='Stop'
try {
  Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand',$env:SENT_INNER
  'ran'
} catch { 'denied' }
"""


@dataclass
class StartResult:
    status: str          # started | denied | error
    message: str = ""


def explain_error(code: str, msg: str) -> str:
    m = re.search(r"0x[0-9A-Fa-f]{8}", code + " " + msg)
    hx = m.group(0).upper().replace("0X", "0x") if m else ""
    why = HRESULT_TEXT.get(hx)
    return f"O Defender recusou a verificação offline ({hx or 'sem código'}): " + (why or ps.clean_text(msg, 200) or "motivo desconhecido.")


def start(timeout: float = 300) -> StartResult:
    """Pede elevação e agenda a offline. O marcador é gravado ANTES: o Windows pode reiniciar antes de esta função voltar."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    out = DATA_DIR / "offline_start.json"
    try:
        out.unlink()
    except OSError:
        pass
    now = time.time()
    _marker().write_text(json.dumps({"requested": now, "since": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 2))}), encoding="utf-8")
    inner = _PS_INNER.replace("__OUT__", str(out).replace("'", "''"))
    enc = base64.b64encode(inner.encode("utf-16-le")).decode("ascii")
    raw = (run_powershell(_PS_OUTER, {"SENT_INNER": enc}, timeout) or "").strip()
    if raw.endswith("denied"):
        clear()
        return StartResult("denied", "A permissão de administrador foi recusada: nada foi agendado.")
    try:
        r = json.loads(out.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        r = None
    if isinstance(r, dict) and r.get("ok"):
        return StartResult("started", "Verificação offline agendada. O Windows vai reiniciar em instantes.")
    clear()
    if isinstance(r, dict):
        return StartResult("error", explain_error(str(r.get("code", "")), str(r.get("msg", ""))))
    return StartResult("error", "Não foi possível confirmar o agendamento (o PowerShell elevado não devolveu resultado).")


def clear() -> None:
    try:
        _marker().unlink()
    except OSError:
        pass


def pending() -> dict | None:
    try:
        d = json.loads(_marker().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(d, dict) or not isinstance(d.get("requested"), (int, float)) or not isinstance(d.get("since"), str):
        clear()
        return None
    return d


# ---------------------------------------------------------------- resultado

_PS_HIST = r"""
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$since=[datetime]::Parse($env:SENT_SINCE,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)
$out=@()
Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -ge $since.ToLocalTime() } | ForEach-Object {
  $t=Get-MpThreat -ThreatID $_.ThreatID
  foreach($r in @($_.Resources)){ $out += [pscustomobject]@{ name=[string]$t.ThreatName; path=[string]$r; sev=[int]$t.SeverityID } }
}
ConvertTo-Json -InputObject @($out) -Compress
"""


@dataclass
class OfflineResult:
    requested: float
    boot: float
    detections: list = field(default_factory=list)
    readable: bool = True
    level: str = "safe"
    headline: str = "Sem detecções"
    score: int = 0
    summary: str = ""


def _history_detections(since: str) -> list | None:
    raw = run_powershell(_PS_HIST, {"SENT_SINCE": since}, timeout=60)
    if raw is None:
        return None
    try:
        data = json.loads(raw or "[]")
    except ValueError:
        return None
    data = [data] if isinstance(data, dict) else data
    out = []
    for d in data if isinstance(data, list) else []:
        if not isinstance(d, dict):
            continue
        path = str(d.get("path") or "")
        path = path.split("file:_")[-1].split("->")[0].strip()
        try:
            sev = int(d.get("sev") or 0)
        except (TypeError, ValueError):
            sev = 0
        out.append(se.Detection("defender", ps.clean_text(d.get("name") or "", 120), ps.clean_text(path, 400), sev))
    return out


def judge(res: OfflineResult) -> OfflineResult:
    kinds = [se.classify_name("defender", d.name) for d in res.detections]
    if "family" in kinds:
        res.level, res.headline, res.score = "danger", "Perigoso", 80
        res.summary = f"{len(res.detections)} detecção(ões) na verificação offline, com nome de família de malware. O Defender já agiu sobre elas; confira em Segurança do Windows > Histórico de proteção."
    elif res.detections:
        res.level, res.headline, res.score = "caution", "Atenção", 40
        res.summary = f"{len(res.detections)} detecção(ões) genéricas/PUA na verificação offline. O Defender já agiu sobre elas; confira a origem de cada uma."
    elif not res.readable:
        res.level, res.headline, res.score = "unknown", "Inconclusivo", 0
        res.summary = "O PC reiniciou, mas o histórico do Defender não pôde ser lido: o resultado da offline não é conclusivo."
    else:
        res.level, res.headline, res.score = "safe", "Sem detecções", 0
        res.summary = "Nenhuma detecção do Defender desde o pedido da verificação offline. Isto não prova que o PC está limpo."
    return res


def collect(boot_time: float | None = None, now: float | None = None) -> OfflineResult | None:
    """Resultado de uma offline pedida antes do último reinício; None se não há pedido ou o PC ainda não reiniciou."""
    p = pending()
    if not p:
        return None
    boot = psutil.boot_time() if boot_time is None else boot_time
    now = time.time() if now is None else now
    if boot <= p["requested"]:
        if now - p["requested"] > STALE_DAYS * 86400:
            clear()
        return None
    ev = se.defender_events(p["since"])
    hist = _history_detections(p["since"])
    dets, seen = [], set()
    for d in (ev or []) + (hist or []):
        k = (d.name.lower(), ps.norm_path(d.path))
        if d.name and k not in seen:
            seen.add(k)
            dets.append(d)
    res = judge(OfflineResult(p["requested"], boot, dets, readable=not (ev is None and hist is None)))
    clear()
    return res


def report_text(res: OfflineResult) -> str:
    t = lambda x: time.strftime("%d/%m/%Y %H:%M", time.localtime(x))  # noqa: E731
    lines = ["Sentinela: verificação offline do Microsoft Defender", "",
             f"Pedida em: {t(res.requested)}", f"Reinício detectado em: {t(res.boot)}", "",
             f"Resultado: {res.headline}", res.summary, ""]
    if res.detections:
        lines.append("Detecções:")
        for d in res.detections:
            lines.append(f"  - {d.name}  (severidade {d.severity or '?'})  {d.path}")
        lines.append("")
    lines += ["Limites:",
              "  - O Windows não registra de forma confiável que a offline terminou; o reinício depois do pedido é o sinal usado. "
              "Se o PC reiniciou por outro motivo antes de a offline rodar, o resultado fica vazio.",
              "  - Detecções em tempo real que aconteceram entre o pedido e esta leitura também entram na lista.",
              "  - A offline já remedia sozinha (remove ou põe em quarentena); este relatório só mostra o que ela fez."]
    return "\n".join(lines)
