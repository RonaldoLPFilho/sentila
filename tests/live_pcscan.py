"""Teste VIVO da "Verificar computador" (modo Rápida) neste PC. Somente leitura (o Defender faz a varredura; nada é movido/apagado).
Uso: python tests\\live_pcscan.py [full]   (a Rápida leva alguns minutos; a Completa, horas)."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinela import pcscan as pc  # noqa: E402
from sentinela.config import Settings  # noqa: E402


def main() -> int:
    mode = "full" if "full" in sys.argv else "quick"
    s = Settings()
    s.data["proc_vt"] = False
    t0 = time.time()
    last = {"m": ""}

    def step(i, msg=""):
        if msg and msg != last["m"] and (not msg.startswith(("Defender", "ClamAV:")) or int(time.time() - t0) % 20 == 0):
            print(f"[{int(time.time() - t0):4d}s] ({i}) {msg}", flush=True)
            last["m"] = msg

    rep = pc.run_pc_scan(s, mode, None, allow_clam_update="--update" in sys.argv, step=step)
    print("\nVEREDITO:", rep.verdict.headline, rep.verdict.score, "|", rep.verdict.summary)
    print("motores:", rep.engines)
    print("stats:", rep.stats)
    print("achados em arquivos:", [(i.level, i.path[-60:], [f.title for f in i.findings]) for i in rep.items if i.level != "ok"][:8])
    print("persistência sinalizada:", [(p.level, p.kind, p.where[:40]) for p in rep.persist][:8])
    print("higiene:", [(f.points, f.title) for f in rep.hygiene])
    print("lacunas:", [(g.title, g.detail) for g in rep.gaps])
    print("duração:", round(rep.elapsed), "s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
