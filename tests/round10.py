"""Histórico das últimas 10 análises (sentinela/history.py)."""
from __future__ import annotations

import os
import shutil
import tempfile
import time
from pathlib import Path


def run_round10(ctx) -> None:
    check = ctx.check
    from sentinela import history as h

    tmp = Path(tempfile.mkdtemp(prefix="sent_hist_"))
    old = h.DATA_DIR
    h.DATA_DIR = tmp
    try:
        check("H1 sem arquivo => histórico vazio", h.entries() == [])
        for i in range(12):
            h.record("files" if i % 2 else "net", f"item {i}", "safe", "Seguro", i, "resumo", f"relatório {i}", duration=i)
            time.sleep(0.01)
        es = h.entries()
        check("H2 guarda só as 10 últimas, da mais recente para a mais antiga", len(es) == 10 and es[0]["title"] == "item 11" and es[-1]["title"] == "item 2", f"{len(es)} {es[0]['title']} {es[-1]['title']}")
        check("H3 todos os tipos são aceitos (files/procs/net/pc) e tipo inválido é ignorado",
              all(h.record(k, "x", "safe", "Seguro", 0, "", "r") for k in ("files", "procs", "net", "pc")) and h.record("outro", "x", "safe", "Seguro", 0, "", "r") is None)
        user = os.environ.get("USERNAME", "usuario")
        h.clear()
        h.record("pc", "t", "caution", "Atenção", 20, "s", "arquivo C:" + chr(92) + "Users" + chr(92) + user + chr(92) + "x.exe --password hunter2 https://u:pw@h/p?key=ABC")
        rep = h.entries()[0]["report"]
        check("H4 o relatório é guardado REDIGIDO (usuário do Windows e segredos escondidos)", user not in rep.replace("<usuario>", "") or len(user) < 2, rep)
        check("H4 senha/token/chave escondidos", "hunter2" not in rep and "pw@" not in rep and "key=ABC" not in rep, rep)
        h.record("net", "evil" + chr(0x202E) + chr(0x3164) + chr(10) + "x", "safe", "Seguro" + chr(0x202E), 0, "s" + chr(0), "r")
        e = h.entries()[0]
        check("H5 título/veredito hostis (bidi, invisíveis, quebra de linha) são limpos", chr(0x202E) not in e["title"] + e["headline"] and chr(0x3164) not in e["title"] and chr(10) not in e["title"])
        h.record("procs", "grande", "safe", "Seguro", 0, "", "x" * (h.MAX_REPORT + 5000))
        check("H6 relatório gigante é truncado", len(h.entries()[0]["report"]) <= h.MAX_REPORT)
        eid = h.entries()[0]["id"]
        n = len(h.entries())
        h.remove(eid)
        check("H7 remover um item", len(h.entries()) == n - 1 and all(x["id"] != eid for x in h.entries()))
        (tmp / "historico.json").write_text("{lixo", encoding="utf-8")
        check("H8 arquivo corrompido => vazio, sem exceção", h.entries() == [])
        (tmp / "historico.json").write_text('[{"kind": "net"}, 5, {"kind": "xx", "report": "r"}]', encoding="utf-8")
        check("H8 entradas malformadas são ignoradas", h.entries() == [])
        h.record("pc", "a", "safe", "Seguro", 0, "", "r")
        h.clear()
        check("H9 limpar apaga tudo", h.entries() == [])
        h.DATA_DIR = tmp / "arquivo_no_lugar_de_pasta"
        (tmp / "arquivo_no_lugar_de_pasta").write_text("x")
        check("H10 falha de disco NÃO derruba a análise (record devolve None)", h.record("net", "a", "safe", "Seguro", 0, "", "r") is None)
    finally:
        h.DATA_DIR = old
        shutil.rmtree(tmp, ignore_errors=True)
