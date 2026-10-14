"""Teste VIVO e inerte da verificação de processos: lança cópias inofensivas com nomes suspeitos e confere se a varredura real as acusa.
Nada malicioso é executado (são cópias do notepad/python que só dormem). Uso:  python tests\\live_procs.py   (leva ~1 min)"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinela import procscan as ps  # noqa: E402
from sentinela.config import Settings  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(ok), detail))


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="sent_live_"))
    procs: list[subprocess.Popen] = []
    try:
        cmd_exe = Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"
        fake_svc = tmp / "svchost.exe"
        shutil.copy2(cmd_exe, fake_svc)
        fake_miner = tmp / "xmrig.exe"
        shutil.copy2(cmd_exe, fake_miner)
        fake_cmd = tmp / "updater.exe"
        shutil.copy2(cmd_exe, fake_cmd)
        wait = "ping -n 300 127.0.0.1 >nul & rem "
        procs.append(subprocess.Popen([str(fake_svc), "/c", "ping -n 300 127.0.0.1 >nul"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        procs.append(subprocess.Popen([str(fake_miner), "/c", wait + "-o stratum+tcp://pool.example:3333 -u wallet"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        procs.append(subprocess.Popen([str(fake_cmd), "/c", wait + "powershell -enc " + "QQBCAEMA" * 8], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        time.sleep(2)

        s = Settings()
        s.data["proc_vt"] = False
        rep = ps.run_scan(s, None, 20, lambda i, m="": None)
        mine = {p.pid: p for p in rep.procs}

        def find(proc):
            return mine.get(proc.pid)

        p_svc, p_min, p_cmd = (find(x) for x in procs)
        check("L1 cópia do cmd chamada svchost.exe na pasta Temp => Perigoso",
              p_svc is not None and p_svc.level == "danger" and any("fora do local" in f.title for f in p_svc.findings),
              str([f.title for f in p_svc.findings]) if p_svc else "processo não encontrado")
        check("L2 xmrig.exe com parâmetros stratum => Perigoso",
              p_min is not None and p_min.level == "danger" and any("mineração" in f.title for f in p_min.findings),
              str([f.title for f in p_min.findings]) if p_min else "processo não encontrado")
        check("L3 updater.exe com 'powershell -enc' na linha de comando => alerta de comando codificado",
              p_cmd is not None and any("codificado" in f.title for f in p_cmd.findings),
              str([f.title for f in p_cmd.findings]) if p_cmd else "processo não encontrado")
        check("L4 veredito geral é Perigoso", rep.verdict.level == "danger", rep.verdict.headline)
        others = [p for p in rep.procs if p.pid not in {x.pid for x in procs} and p.level == "danger"]
        check("L5 nenhum OUTRO processo do PC foi acusado como Perigoso (falso positivo)", not others, ", ".join(p.name for p in others))
        text = ps.report_text(rep, True)
        check("L6 relatório gerado, com o nome de usuário escondido", "Sentinela" in text and ("<usuario>" in text or os.environ.get("USERNAME", "zz") not in text))
        # encerra com identidade conferida
        msg = ps.act_on_process(p_min, "terminate") if p_min else "?"
        time.sleep(0.6)
        check("L7 encerrar o 'minerador' pela ação do app funciona", msg == "" and procs[1].poll() is not None, msg)
    finally:
        for pr in procs:  # mata também o ping filho de cada cmd (senão ele segura a saída do teste por 5 min)
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pr.pid)], capture_output=True)
        time.sleep(0.5)
        shutil.rmtree(tmp, ignore_errors=True)
    fails = 0
    for n, ok, d in RESULTS:
        fails += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {n}  {d}")
    print(f"\n{len(RESULTS) - fails}/{len(RESULTS)} OK")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
