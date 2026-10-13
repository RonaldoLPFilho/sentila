"""Automação do Windows Sandbox: gera o .wsb, inicia, acompanha o agente e recolhe o relatório."""
from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from xml.sax.saxutils import escape

from .checks import CREATE_NO_WINDOW
from .scoring import sanitize_report

SANDBOX_EXE = Path(os.environ.get("windir", r"C:\Windows")) / "System32" / "WindowsSandbox.exe"
AGENT_SRC = Path(__file__).with_name("agent.ps1")
_PROCS = ("WindowsSandbox.exe", "WindowsSandboxClient.exe", "WindowsSandboxRemoteSession.exe", "WindowsSandboxServer.exe")


def available() -> bool:
    return SANDBOX_EXE.exists()


def _process_names() -> set[str]:
    try:
        out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, errors="replace",
                             creationflags=CREATE_NO_WINDOW, timeout=20).stdout
    except (subprocess.SubprocessError, OSError):
        return set()
    names = set()
    for line in out.splitlines():
        if line.startswith('"'):
            names.add(line.split('","', 1)[0].strip('"').lower())
    return names


def parse_running(names: set[str]) -> bool:
    """Só os processos de interface/serviço contam. A VM (vmmemWindowsSandbox) pode sobrar órfã e NÃO deve travar o app."""
    return any(p.lower() in names for p in _PROCS)


def running() -> bool:
    return parse_running(_process_names())


def orphan_vm() -> bool:
    """Existe a VM do sandbox mas nenhum cliente: sobra de um encerramento forçado."""
    names = _process_names()
    return "vmmemwindowssandbox" in names and not parse_running(names)


def _wait(cond, seconds: float) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.5)
    return cond()


def kill() -> None:
    """Encerra o sandbox primeiro de forma graciosa (fecha a janela) e só depois à força."""
    def run_taskkill(force: bool) -> None:
        args = ["taskkill"] + (["/F"] if force else [])
        for p in _PROCS:
            args += ["/IM", p]
        try:
            subprocess.run(args, capture_output=True, creationflags=CREATE_NO_WINDOW, timeout=20)
        except (subprocess.SubprocessError, OSError):
            pass

    run_taskkill(False)
    if not _wait(lambda: not running(), 8):
        run_taskkill(True)
    _wait(lambda: "vmmemwindowssandbox" not in _process_names(), 15)  # dá tempo da VM terminar de desligar


def enable_feature_elevated() -> None:
    """Abre um PowerShell como administrador (o Windows pede confirmação) para ativar o recurso."""
    cmd = ("-NoProfile -Command \"Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -NoRestart; "
           "Write-Host ''; Read-Host 'Pronto. REINICIE o computador para concluir. Pressione Enter'\"")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", "powershell.exe", cmd, None, 1)


@dataclass
class Outcome:
    ran: bool = False
    report: dict | None = None
    screenshot: bytes | None = None
    error: str = ""


MAX_REPORT = 4 << 20
MAX_SHOT = 16 << 20
_PNG_MAGIC = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])


def _read_limited(path: Path, limit: int) -> bytes:
    with open(path, "rb") as f:
        return f.read(limit + 1)


def _valid_png(data: bytes) -> bool:
    """Só aceita PNG de verdade (assinatura + IHDR com dimensões plausíveis) antes de entregar ao Qt."""
    if len(data) < 33 or data[:8] != _PNG_MAGIC or data[12:16] != b"IHDR":
        return False
    w, h = int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")
    return 0 < w <= 8192 and 0 < h <= 8192


def _wsb(sample: Path, out: Path, agent: Path, network: bool, protected: bool = False) -> str:
    def folder(host: Path, guest: str, ro: bool) -> str:
        return (f"<MappedFolder><HostFolder>{escape(str(host))}</HostFolder><SandboxFolder>{guest}</SandboxFolder>"
                f"<ReadOnly>{'true' if ro else 'false'}</ReadOnly></MappedFolder>")

    return (
        "<Configuration>"
        "<VGpu>Disable</VGpu>"
        + ("<ProtectedClient>Enable</ProtectedClient>" if protected else "") +
        f"<Networking>{'Default' if network else 'Disable'}</Networking>"
        "<ClipboardRedirection>Disable</ClipboardRedirection><PrinterRedirection>Disable</PrinterRedirection>"
        "<AudioInput>Disable</AudioInput><VideoInput>Disable</VideoInput>"
        "<MappedFolders>" + folder(sample, r"C:\Sample", True) + folder(agent, r"C:\Agent", True) + folder(out, r"C:\Out", False)
        + "</MappedFolders>"
        "<LogonCommand><Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Agent\\agent.ps1 -Params C:\\Agent\\params.json</Command></LogonCommand>"
        "</Configuration>"
    )


def run(sample_dir: Path, target_rel: str, kind: str, work: Path, network: bool, seconds: int, emit, cancelled,
        protected: bool = False) -> Outcome:
    o = Outcome()
    if not available():
        o.error = "Windows Sandbox não está ativado neste computador."
        return o
    if running():
        o.error = "Já existe um Windows Sandbox aberto. Feche-o e tente novamente."
        return o
    if orphan_vm() and not _wait(lambda: not orphan_vm(), 12):
        o.error = ("Uma máquina virtual de um sandbox anterior não encerrou (processo vmmemWindowsSandbox). "
                   "Reinicie o computador e tente de novo.")
        return o

    emit("sb_prep", "run", "Gerando configuração isolada…")
    agent_dir, out_dir = work / "agent", work / "out"
    agent_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(AGENT_SRC, agent_dir / "agent.ps1")
    token = uuid.uuid4().hex[:16]  # nomes imprevisíveis a priori (a amostra só descobre lendo params.json)
    params = {
        "ReportName": f"report_{token}.json", "DoneName": f"done_{token}.flag",
        "Target": target_rel, "Kind": kind, "Seconds": seconds, "SampleDir": r"C:\Sample", "OutDir": r"C:\Out",
        "WorkDir": r"C:\Work", "DecoyDir": r"C:\Users\WDAGUtilityAccount\Documents\Importantes", "NoShutdown": False,
        "SnapRoots": [r"C:\Users\WDAGUtilityAccount", r"C:\ProgramData", r"C:\Program Files", r"C:\Program Files (x86)", r"C:\Windows\Temp"],
    }
    (agent_dir / "params.json").write_text(json.dumps(params), encoding="utf-8")
    wsb = work / "analysis.wsb"
    wsb.write_text(_wsb(sample_dir, out_dir, agent_dir, network, protected), encoding="utf-8")
    emit("sb_prep", "ok", f"Rede {'ligada (menos seguro)' if network else 'desligada'} · pasta da amostra somente leitura · {seconds} s")

    emit("sb_run", "run", "Iniciando o Windows Sandbox (leva de 30 a 90 s)…")
    subprocess.Popen([str(SANDBOX_EXE), str(wsb)], creationflags=CREATE_NO_WINDOW)
    t0 = time.time()
    seen, gone_since = False, None
    deadline = 420 + seconds
    done = out_dir / params["DoneName"]
    while True:
        if cancelled():
            kill()
            raise InterruptedError
        if done.exists():
            break
        if running():
            seen, gone_since = True, None
        elif seen or time.time() - t0 > 60:
            gone_since = gone_since or time.time()
            if time.time() - gone_since > 10:
                o.error = "O sandbox foi fechado antes de terminar a análise." if seen else "O sandbox não iniciou (virtualização desativada na BIOS?)."
                kill()
                return o
        if time.time() - t0 > deadline:
            o.error = "Tempo limite excedido aguardando o sandbox."
            kill()
            return o
        try:
            phase = _read_limited(out_dir / "progress.txt", 64).decode("utf-8", "ignore").strip()
        except OSError:
            phase = ""
        name, _, arg = phase.partition("|")
        msg = {"boot": "Windows Sandbox iniciado, preparando…", "snapshot": "Registrando o estado do sistema antes de executar…",
               "run": f"Executando a amostra e observando ({arg or 0}/{seconds} s)…", "collect": "Comparando o estado antes/depois…"}.get(name)
        if msg:
            emit("sb_run", "run", msg)
        time.sleep(1)

    emit("sb_run", "ok", "Execução concluída. Encerrando o sandbox…")
    for _ in range(25):  # o agente desliga o sandbox sozinho
        if not running():
            break
        time.sleep(1)
    kill()

    emit("sb_collect", "run", "Lendo relatório de comportamento…")
    rp = out_dir / params["ReportName"]
    # O guest é controlado pela amostra: tudo que vem dele é entrada hostil (tamanho, tipos, profundidade).
    try:
        raw = _read_limited(rp, MAX_REPORT)
        if len(raw) > MAX_REPORT:
            raise ValueError("relatório grande demais")
        report = sanitize_report(json.loads(raw.decode("utf-8-sig", "replace")))
        if report is None:
            raise ValueError("formato inesperado")
    except (OSError, ValueError, RecursionError, MemoryError) as e:
        o.error = f"Relatório do sandbox ausente ou inválido ({e.__class__.__name__}); o resultado não é confiável."
        return o
    o.report = report
    try:
        data = _read_limited(out_dir / "screenshot.png", MAX_SHOT + 1)
        if _valid_png(data) and len(data) <= MAX_SHOT:
            o.screenshot = data
    except OSError:
        pass
    if not report["ok"]:
        o.error = f"O agente falhou: {report['error'] or 'erro desconhecido'}"
        return o
    o.ran = True
    return o
