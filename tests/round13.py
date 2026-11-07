"""Drivers de kernel (sentinela/kerneldrv.py): lista LOLDrivers, drivers em pasta de usuário, veredito."""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path


def run_round13(ctx) -> None:
    check = ctx.check
    from sentinela import kerneldrv as k
    from sentinela import pcscan as pc

    root = os.environ.get("SystemRoot", r"C:\Windows")
    check("K1 \\SystemRoot\\ vira caminho Win32", k.norm_driver_path(r"\SystemRoot\System32\drivers\x.sys").lower() == (root + r"\System32\drivers\x.sys").lower())
    check("K1 system32\\ relativo vira caminho Win32", k.norm_driver_path(r"system32\drivers\y.sys").lower() == os.path.join(root, r"system32\drivers\y.sys").lower())
    check("K1 \\??\\C:\\ vira C:\\", k.norm_driver_path(r"\??\C:\Users\a\Downloads\g\SimpleSvm.sys") == r"C:\Users\a\Downloads\g\SimpleSvm.sys")
    check("K2 pasta de usuário detectada", k.in_user_folder(r"C:\Users\a\Downloads\g\SimpleSvm.sys") and k.in_user_folder(r"D:\Temp\x.sys"))
    check("K2 C:\\Windows não é pasta de usuário", not k.in_user_folder(root + r"\System32\drivers\x.sys"))

    real = k.load_list()
    check("K3 lista empacotada carrega e tem hashes", len(real) > 1000 and all(len(h) == 64 for h in list(real)[:50]), str(len(real)))
    tmp = Path(tempfile.mkdtemp(prefix="sent_drv_"))
    try:
        (tmp / "bad.json").write_text("{lixo", encoding="utf-8")
        check("K4 lista corrompida => {} sem exceção", k.load_list(tmp / "bad.json") == {} and k.load_list(tmp / "nao.json") == {})
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    V, M = "a" * 64, "b" * 64
    vuln = {V: ["WinRing0x64.sys", "v"], M: ["evil.sys", "m"]}
    sysd = root + r"\System32\drivers"
    D = k.Driver
    fs = k.judge([D("WinRing0", sysd + r"\WinRing0x64.sys", True, V)], vuln, {}, {})
    check("K5 vulnerável carregado => Atenção (médio)", len(fs) == 1 and fs[0].severity == "medium" and "vulnerável" in fs[0].title, str([f.title for f in fs]))
    fs2 = k.judge([D("WinRing0", sysd + r"\WinRing0x64.sys", False, V)], vuln, {}, {})
    check("K5 vulnerável só registrado => leve", fs2 and fs2[0].severity == "low")
    fs = k.judge([D("evil", sysd + r"\evil.sys", True, M)], vuln, {}, {})
    check("K6 malicioso conhecido => crítico", fs and fs[0].severity == "critical")
    crack = r"C:\Users\a\Downloads\game\driver_amd\SimpleSvm.sys"
    fs = k.judge([D("denuvo", crack, True, "c" * 64)], vuln, {crack: {"status": "HashMismatch"}}, {crack: "Denuvo GmbH"})
    check("K7 driver de pasta de usuário com assinatura inválida => alto", fs and fs[0].severity == "high" and "NÃO é válida" in fs[0].detail, str([(f.severity, f.title) for f in fs]))
    hw = r"C:\Users\a\AppData\Local\Temp\HWiNFO_x64_216.sys"
    fs = k.judge([D("HWiNFO_216", hw, True, "d" * 64)], vuln, {hw: {"status": "Valid", "subject": "CN=REALiX s.r.o., O=REALiX"}}, {})
    check("K8 driver de pasta de usuário assinado (HWiNFO) => só nota leve", fs and fs[0].severity == "low" and "REALiX" in fs[0].detail, str([(f.severity, f.detail[-80:]) for f in fs]))
    fs = k.judge([D("x", crack, True, "c" * 64)], vuln, {crack: {"status": "CheckFailed"}}, {})
    check("K9 checagem de assinatura que não terminou não condena", fs and fs[0].severity == "medium")
    check("K10 driver do sistema fora da lista => nada", k.judge([D("disk", sysd + r"\disk.sys", True, "e" * 64)], vuln, {}, {}) == [])

    two = k.judge([D("a", sysd + r"\a.sys", True, V), D("b", sysd + r"\b.sys", True, V)], vuln, {}, {})
    check("K11 dois drivers vulneráveis legítimos não somam Perigoso", pc.pc_verdict([], [], [], None, [], two).level == "caution")
    mal = k.judge([D("evil", sysd + r"\evil.sys", True, M)], vuln, {}, {})
    check("K11 driver malicioso conhecido => Perigoso", pc.pc_verdict([], [], [], None, [], mal).level == "danger")
    crk = k.judge([D("denuvo", crack, True, "c" * 64)], vuln, {crack: {"status": "NotSigned"}}, {})
    check("K11 driver de crack sem assinatura válida em Downloads => Perigoso", pc.pc_verdict([], [], [], None, [], crk).level == "danger")
