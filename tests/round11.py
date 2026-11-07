"""Verificação offline do Defender (sentinela/offscan.py): WinRE, erros, marcador e leitura após o reinício. Nada é elevado nem agendado."""
from __future__ import annotations

import json
import shutil
import tempfile
import time
from pathlib import Path


def run_round11(ctx) -> None:
    check = ctx.check
    from sentinela import offscan as off
    from sentinela import scanengines as se

    tmp = Path(tempfile.mkdtemp(prefix="sent_off_"))
    old_dir, old_ev, old_hist = off.DATA_DIR, off.se.defender_events, off._history_detections
    off.DATA_DIR = tmp
    try:
        x = tmp / "ReAgent.xml"
        for st, want in (("1", True), ("0", False), ("7", None)):
            x.write_text(f"<?xml version='1.0' encoding='utf-8'?><WindowsRE version='2.0'><InstallState state='{st}'/></WindowsRE>", encoding="utf-8")
            check(f"O1 WinRE InstallState={st} => {want}", off.winre_enabled(x) is want)
        x.write_text("<lixo", encoding="utf-8")
        check("O2 ReAgent.xml corrompido => None (não sabe), sem exceção", off.winre_enabled(x) is None)
        check("O2 ReAgent.xml ausente => None", off.winre_enabled(tmp / "nao_existe.xml") is None)

        msg = off.explain_error("HRESULT 0x80070032,Start-MpWDOScan", "Erros encontrados")
        check("O3 0x80070032 explica o WinRE e como reativar", "0x80070032" in msg and "reagentc" in msg, msg)
        check("O3 código desconhecido mostra a mensagem limpa", "boom" in off.explain_error("x", "boom\u202e"), off.explain_error("x", "boom\u202e"))

        check("O4 sem pedido => nada a coletar", off.collect(boot_time=time.time()) is None)

        now = time.time()
        (tmp / off.MARKER).write_text(json.dumps({"requested": now - 600, "since": "2026-01-01T00:00:00Z"}), encoding="utf-8")
        check("O5 pedido sem reinício => ainda pendente", off.collect(boot_time=now - 3600, now=now) is None and off.pending() is not None)
        check("O5 pedido velho sem reinício => descartado", off.collect(boot_time=now - 10 * 86400, now=now + 4 * 86400) is None and off.pending() is None)

        def arm():
            (tmp / off.MARKER).write_text(json.dumps({"requested": now - 600, "since": "2026-01-01T00:00:00Z"}), encoding="utf-8")

        off.se.defender_events = lambda since, cancelled=lambda: False: []
        off._history_detections = lambda since: []
        arm()
        r = off.collect(boot_time=now - 60, now=now)
        check("O6 reiniciou e sem detecções => Sem detecções e marcador limpo", r is not None and r.level == "safe" and off.pending() is None, getattr(r, "level", None))
        check("O6 relatório diz que o reinício é o sinal usado", r is not None and "reinício" in off.report_text(r))

        fam = se.Detection("defender", "Trojan:Win64/Lumma.ABC", r"C:\x\a.exe", 5)
        gen = se.Detection("defender", "Trojan:Win32/Wacatac.B!ml", r"C:\x\b.exe", 5)
        off.se.defender_events = lambda since, cancelled=lambda: False: [fam, gen]
        off._history_detections = lambda since: [se.Detection("defender", "trojan:win64/lumma.abc", r"c:\x\A.exe", 5)]
        arm()
        r = off.collect(boot_time=now - 60, now=now)
        check("O7 nome de família => Perigoso", r is not None and r.level == "danger", getattr(r, "level", None))
        check("O7 mesma detecção nas duas fontes conta uma vez", r is not None and len(r.detections) == 2, str(getattr(r, "detections", None)))

        off.se.defender_events = lambda since, cancelled=lambda: False: [gen]
        off._history_detections = lambda since: []
        arm()
        r = off.collect(boot_time=now - 60, now=now)
        check("O8 só genérica => Atenção", r is not None and r.level == "caution", getattr(r, "level", None))

        off.se.defender_events = lambda since, cancelled=lambda: False: None
        off._history_detections = lambda since: None
        arm()
        r = off.collect(boot_time=now - 60, now=now)
        check("O9 log ilegível nas duas fontes => Inconclusivo, nunca 'sem detecções'", r is not None and r.level == "unknown", getattr(r, "level", None))

        (tmp / off.MARKER).write_text('{"requested": "x"}', encoding="utf-8")
        check("O10 marcador malformado => ignorado e apagado", off.pending() is None and not (tmp / off.MARKER).exists())
    finally:
        off.DATA_DIR, off.se.defender_events, off._history_detections = old_dir, old_ev, old_hist
        shutil.rmtree(tmp, ignore_errors=True)
