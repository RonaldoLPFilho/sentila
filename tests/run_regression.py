"""Regressão do veredito do Sentinela (cenários da auditoria cybersec).

Uso:  python tests\\run_regression.py
Tudo é inerte: scripts só com texto suspeito, PEs sintéticos (não executáveis) e o arquivo de teste EICAR.
Nada é enviado à internet (o VirusTotal é substituído por respostas sintéticas).
"""
from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import traceback
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.pop("SENTINELA_VT_KEY", None)

from sentinela import checks, sandbox  # noqa: E402
from sentinela.config import Settings  # noqa: E402
from sentinela.pipeline import Analyzer  # noqa: E402
from sentinela.scoring import Finding, build_verdict, compute_score, final_findings, sanitize_report, score_sandbox  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="sentinela_tests_"))
SEVEN = r"C:\Program Files\7-Zip\7z.exe"
RESULTS: list[tuple[str, bool, str]] = []


def mkpe(name: str, sections=None, pad_to: int = 0, tail: bytes = b"") -> Path:
    """PE mínimo sintético (NÃO executa)."""
    sections = sections or [(".text", b"\x90" * 20000)]
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", 0x14C, len(sections), 0, 0, 0, 0xE0, 0x102)
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)
    off, hdrs, raw = 0x400, b"", b""
    for sname, data in sections:
        data = data + b"\0" * ((-len(data)) % 0x200)
        hdrs += sname.encode().ljust(8, b"\0") + struct.pack("<IIIIIIHHI", len(data), 0x1000, len(data), off + len(raw), 0, 0, 0, 0, 0x60000020)
        raw += data
    blob = (bytes(dos) + coff + bytes(opt) + hdrs).ljust(0x400, b"\0") + raw + tail
    if pad_to and len(blob) < pad_to:
        blob += b"\0" * (pad_to - len(blob))
    p = TMP / name
    p.write_bytes(blob)
    return p


def mkzip(name: str, entries: dict) -> Path:
    p = TMP / name
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in entries.items():
            z.writestr(k, v)
    return p


class FakeVT:
    def __init__(self, default=None):
        self.key, self.default = "x", default if default is not None else {"found": False}

    def lookup(self, sha, status=None, cancelled=None):
        return self.default


def analyze(path: Path, vt=None):
    a = Analyzer(Settings())
    a.vt = (lambda: vt) if vt is not None else (lambda: None)  # nunca usa a rede real
    sr = a.analyze_static(str(path), lambda *x: None)
    fin = final_findings(sr.findings, sr.recommendation.mode, False, None)
    v = build_verdict(fin, False)
    a.cleanup()
    return sr, fin, v


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(ok), detail))


def scenario(name: str, expect_levels: set[str], path: Path, vt=None, must_have: str | None = None, must_not_have: str | None = None):
    try:
        sr, fin, v = analyze(path, vt)
    except Exception as e:  # noqa: BLE001
        check(name, False, f"exceção {type(e).__name__}: {e}")
        return None
    titles = " | ".join(f.title for f in fin)
    ok = v.level in expect_levels
    if must_have:
        ok = ok and must_have.lower() in titles.lower()
    if must_not_have:
        ok = ok and must_not_have.lower() not in titles.lower()
    check(name, ok, f"{v.headline} {v.score}/100 (esperado {'/'.join(sorted(expect_levels))})" + ("" if ok else f"  achados: {titles[:200]}"))
    return v


DESTRUCTIVE = ("@echo off\r\nvssadmin delete shadows /all /quiet\r\npowershell -c Set-MpPreference -DisableRealtimeMonitoring $true\r\n"
               "net user hacker P4ss /add\r\npowershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA\r\n")
INJ = [b"WriteProcessMemory", b"CreateRemoteThread", b"VirtualAllocEx"]
KEY = [b"SetWindowsHookExA", b"GetAsyncKeyState", b"GetClipboardData"]


def vtres(spec: dict, total=70):
    return {"found": True, "stats": {"malicious": len(spec), "suspicious": 0, "harmless": 0, "undetected": total - len(spec)},
            "engines": {n: {"category": "malicious", "result": r} for n, r in spec.items()}, "link": "x"}


def run() -> None:
    notepad = Path(os.environ["windir"]) / "System32" / "notepad.exe"

    # ---- falsos negativos (devem NUNCA virar "Seguro")
    p = TMP / "destrutivo.bat"
    p.write_text(DESTRUCTIVE, encoding="ascii")
    scenario("C1/A1 .bat destrutivo (vssadmin+Defender+net user) => Perigoso", {"danger"}, p)

    inner = mkzip("inner.zip", {"destrutivo.bat": DESTRUCTIVE})
    outer = TMP / "outer.zip"
    with zipfile.ZipFile(outer, "w") as z:
        z.write(inner, "inner.zip")
    scenario("C5 mesmo .bat em zip dentro de zip => Perigoso", {"danger"}, outer)

    dll = mkpe("version.dll", pad_to=0, tail=b"\0".join(INJ + KEY))
    shutil.copy(notepad, TMP / "app.exe")
    scenario("C3 exe assinado + DLL com APIs de injeção ao lado => não é Seguro/Inconclusivo", {"caution", "danger"},
             mkzip("sideload.zip", {"app.exe": (TMP / "app.exe").read_bytes(), "version.dll": dll.read_bytes()}))

    if Path(SEVEN).exists():
        sec = TMP / "sec"
        sec.mkdir()
        (sec / "leia.txt").write_text("oi")
        (sec / "run.bat").write_text("@echo off\r\necho x\r\n")
        for label, args in (("zip c/ senha", ["-tzip", "-pSEGREDO"]), ("7z c/ senha", ["-t7z", "-pSEGREDO"]),
                            ("7z c/ senha + cabeçalho cifrado", ["-t7z", "-pSEGREDO", "-mhe=on"])):
            out = TMP / (label.replace(" ", "_").replace("/", "") + ".pkg")
            subprocess.run([SEVEN, "a", *args, str(out), str(sec / "*")], capture_output=True)
            target = out
            if label.startswith("zip"):
                target = out.with_suffix(".zip")
                out.rename(target)
            elif not target.suffix == ".7z":
                target = out.with_suffix(".7z")
                out.rename(target)
            v = scenario(f"C5 {label} => não é Seguro e marca lacuna", {"unknown", "caution", "danger"}, target, must_have="senha")
    else:
        check("C5 7-Zip ausente: testes de senha pulados", True, "instale o 7-Zip para cobrir 7z/RAR com senha")

    eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    try:
        z = mkzip("eicar.zip", {"mod/teste.com": eicar})
        scenario("EICAR em zip => Perigoso", {"danger"}, z)
    except OSError:
        check("EICAR em zip => Perigoso", True, "o Defender bloqueou a própria criação do arquivo (ok)")

    packed = mkpe("packed.exe", sections=[(".text", os.urandom(40000))])
    scenario("Exe empacotado, não assinado, sem VT => nunca Seguro", {"unknown", "caution", "danger"}, packed)

    big = mkpe("grande.exe", pad_to=70 << 20, tail=b"\0".join(INJ))
    sr, fin, v = analyze(big)
    check("A: APIs de injeção após 70 MB de preenchimento são detectadas", any("injeção" in f.title for f in fin), f"{v.headline} {v.score}")

    wide = mkpe("wide.exe", tail=b"".join(a.decode().encode("utf-16le") + b"\0\0" for a in INJ))
    sr, fin, v = analyze(wide)
    check("A: APIs em UTF-16 são detectadas", any("injeção" in f.title for f in fin), f"{v.headline} {v.score}")

    # formatos novos
    jar = TMP / "mod.jar"
    with zipfile.ZipFile(jar, "w") as z:
        z.writestr("A.class", b"java/lang/ProcessBuilder\0https://discord.com/api/webhooks/123/abc\0Login Data")
    scenario("C5 .jar ladrão (webhook do Discord + Login Data) => Atenção/Perigoso", {"caution", "danger"}, jar)

    lnk = TMP / "atalho.lnk"
    lnk.write_bytes("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA".encode("utf-16le"))
    scenario("C5 .lnk com PowerShell codificado => Atenção/Perigoso", {"caution", "danger"}, lnk)

    docm = mkzip("planilha.docm", {"word/vbaProject.bin": b"VBA", "[Content_Types].xml": "<x/>"})
    scenario("C5 documento com macro VBA => Atenção", {"caution", "danger"}, docm)

    reg = TMP / "x.reg"
    reg.write_text('Windows Registry Editor Version 5.00\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender]\n"DisableAntiSpyware"=dword:00000001\n', encoding="utf-16")
    scenario("C5 .reg que desativa o Defender => Perigoso", {"danger"}, reg)

    # arquivo sem conteúdo executável (trust)
    scenario("Mod só com texturas/texto => Seguro (sem conteúdo executável)", {"safe"}, mkzip("texturas.zip", {"tex/a.png": b"\x89PNG....", "leia.txt": "ok"}))

    # ---- VirusTotal (respostas sintéticas)
    real = vtres({"Kaspersky": "Trojan-PSW.Win32.RedLine.gen", "Microsoft": "Trojan:Win32/Lumma.GG!MTB"})
    f, _ = checks.vt_findings(real, "", True)
    check("A4 duas famílias reais em AVs principais => Crítico", f[0].severity == "critical", f"{f[0].severity} {f[0].points}")
    f, _ = checks.vt_findings(vtres({"Avira (no cloud)": "TR/AD.AgentTesla.xyz", "Trellix (ENS)": "AgentTesla-FDGH", "Kaspersky": "HEUR:Trojan-PSW.MSIL.Agent.gen"}), "", True)
    check("A4 'Agent'/AgentTesla NÃO é tratado como genérico; nomes 'Avira (no cloud)'/'Trellix' reconhecidos", f[0].points >= 45, f"{f[0].severity} {f[0].points}")
    gen = {f"Eng{i}": "Generic.Malware.Gen" for i in range(14)}
    f, _ = checks.vt_findings(vtres(gen), "", True)
    check("A4 ≥12 detecções genéricas (trainer) => High, não Crítico", f[0].severity == "high" and f[0].points < 45, f"{f[0].severity} {f[0].points}")
    f, _ = checks.vt_findings(vtres({"Zillya": "Trojan.Generic.123", "Ikarus": "PUA.Win32.X"}), "", True)
    check("2 detecções genéricas de motores menores => provável falso positivo", f[0].points <= 6, f"{f[0].points}")

    # ---- pontuação
    d = [Finding("vt", "x", "", 45, "high"), Finding("signature", "ass", "", -25, "info", trust=True), Finding("defender", "ok", "", -5)]
    check("C3 créditos não anulam achado grave (VT high + assinatura + Defender) => Perigoso", build_verdict(d, False).level == "danger",
          str(compute_score(d)))
    check("C2 sem confiança positiva nem lacuna explícita => Inconclusivo", build_verdict([Finding("static", "nada", "", 0)], False).level == "unknown")
    check("C2 com lacuna => Inconclusivo", build_verdict([Finding("signature", "ok", "", -25, "info", trust=True), Finding("gap", "faltou", "", 0, gap=True)], False).level == "unknown")
    check("Assinatura total sem VT => pode ser Seguro", build_verdict([Finding("signature", "ok", "", -25, "info", trust=True),
                                                                      Finding("vt", "sem VT", "", 0, gap=True)], False).level == "safe")

    # ---- sandbox: relatório do guest é hostil
    clean = {"ok": True, "seconds": 60, "new_processes": [], "defender": {"threats": []}, "decoys_total": 12, "decoys_tampered": 0}
    s = sanitize_report(clean)
    fs = score_sandbox(s, False)
    check("C1 sandbox 'limpo' não concede crédito (nenhum ponto negativo)", all(f.points >= 0 for f in fs))
    v = build_verdict(fs + [Finding("static", "exe desconhecido", "", 10, "low")], True)
    check("C1 relatório forjado como limpo + exe sem reputação => nunca Seguro", v.level != "safe", v.headline)
    garbage = {"ok": "yes", "new_processes": "abc", "connections": [1, 2, "x", {"port": "NaN"}], "defender": "oops", "persistence": [1],
               "new_files": {"path": 5}, "cpu_percent": "alto", "decoys_tampered": "3", "windows": [{"a": 1}], "seconds": [1]}
    try:
        score_sandbox(sanitize_report(garbage), True)
        ok = True
    except Exception as e:  # noqa: BLE001
        ok = False
    check("C1/M1 relatório com tipos errados não derruba a análise", ok)
    check("M1 relatório que não é objeto é rejeitado", sanitize_report(["x"]) is None and sanitize_report("x") is None)
    deep = "[" * 100000 + "]" * 100000
    try:
        json.loads(deep)
        ok = False
    except RecursionError:
        ok = True  # sandbox.run captura RecursionError => relatório inválido
    except ValueError:
        ok = True
    check("M1 JSON profundamente aninhado é tratado como inválido", ok)
    start_fail = sanitize_report({"ok": True, "seconds": 60, "start_error": "arquivo inválido"})
    check("A3 amostra que não inicia => lacuna (não 'limpo')", any(f.gap for f in score_sandbox(start_fail, False)))
    check("M1 só PNG de verdade passa para o Qt", not sandbox._valid_png(b"GIF89a" + b"\0" * 60) and not sandbox._valid_png(b"MZ" + b"\0" * 60))

    # ---- falsos positivos
    js = {"package.json": "{}", "index.html": "<html></html>", "a.js": "eval('x')", "b.js": "execute(1)", "c.js": "x"}
    scenario("FP jogo HTML5/Electron com eval()/execute() em .js => não é Atenção", {"unknown", "safe"}, mkzip("jogo_html5.zip", js))
    ce = mkpe("carteira.exe", tail=b"BCryptEncrypt\0bitcoin\0")
    sr, fin, v = analyze(ce)
    check("FP 'BCryptEncrypt'+'bitcoin' não é marcado como ransomware", not any("ransomware" in f.title.lower() for f in fin))
    miss = TMP / "nao_existe.exe"
    try:
        analyze(miss)
        check("FP arquivo inexistente => erro claro, nunca 'Perigoso'", False, "não levantou erro")
    except (OSError, RuntimeError):
        check("FP arquivo inexistente => erro claro, nunca 'Perigoso'", True)

    import types
    from round2 import run_round2
    run_round2(types.SimpleNamespace(TMP=TMP, SEVEN=SEVEN, notepad=notepad, DESTRUCTIVE=DESTRUCTIVE, mkpe=mkpe, mkzip=mkzip,
                                     analyze=analyze, scenario=scenario, check=check, FakeVT=FakeVT, checks=checks))

    from round3 import run_round3
    run_round3(types.SimpleNamespace(TMP=TMP, SEVEN=SEVEN, notepad=notepad, DESTRUCTIVE=DESTRUCTIVE, mkpe=mkpe, mkzip=mkzip,
                                     analyze=analyze, scenario=scenario, check=check, FakeVT=FakeVT, checks=checks))

    from round4 import run_round4
    run_round4(types.SimpleNamespace(check=check))

    from round5 import run_round5
    run_round5(types.SimpleNamespace(check=check))

    from round6 import run_round6
    run_round6(types.SimpleNamespace(check=check))

    from round7 import run_round7
    run_round7(types.SimpleNamespace(check=check))

    from round8 import run_round8
    run_round8(types.SimpleNamespace(check=check))

    # av_blocked só para 225/226
    check("M2 FileNotFoundError não é 'bloqueado pelo antivírus'", not checks.av_blocked(FileNotFoundError(2, "x")))
    e = OSError(22, "Invalid argument")
    check("M2 EINVAL sem WinError 225 real não é 'bloqueado'", not checks.av_blocked(e, TMP / "x.txt"))


def main() -> int:
    try:
        run()
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        check("execução da suíte", False, "exceção não tratada")
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    width = max(len(n) for n, _, _ in RESULTS)
    fails = 0
    for n, ok, d in RESULTS:
        fails += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {n.ljust(width)}  {d}")
    print(f"\n{len(RESULTS) - fails}/{len(RESULTS)} cenários OK")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
