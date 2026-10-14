"""Verificar computador: triagem, persistência, zonas, quarentena, execução limitada e ClamAV real (base de teste por hash)."""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BS = chr(92)
SYS32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"


def run_round8(ctx) -> None:
    check = ctx.check
    from sentinela import components as comp
    from sentinela import pcscan as pc
    from sentinela import procscan as ps
    from sentinela import quarantine as q
    from sentinela import scanengines as se

    tmp = Path(tempfile.mkdtemp(prefix="sent_pc_"))
    old_q = q.Q_DIR
    q.Q_DIR = tmp / "quarentena"
    try:
        UNS = {"status": "NotSigned", "verified": True, "subject": "", "issuer": "", "thumb": ""}
        SIG = {"status": "Valid", "verified": True, "subject": 'CN="Foo", O=Foo Inc, L=X, C=NO', "issuer": "CN=DigiCert", "thumb": "a"}
        MS = {"status": "Valid", "verified": True, "subject": "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
              "issuer": "CN=Microsoft Windows Production PCA 2011", "thumb": "b"}

        # ---------------- classificação de nomes de detecção
        cn = se.classify_name
        check("C1 EICAR é 'test'", cn("defender", "Virus:DOS/EICAR_Test_File") == "test" and cn("clamav", "Win.Test.EICAR_HDB-1") == "test")
        check("C2 Wacatac/PUA/HackTool/Heuristics/Agent-NNN são 'generic'", all(cn("defender", n) == "generic" for n in ("Trojan:Win32/Wacatac.B!ml", "PUA:Win32/Presenoker", "HackTool:Win32/Keygen"))
              and all(cn("clamav", n) == "generic" for n in ("Heuristics.Encrypted.PDF", "Win.Trojan.Agent-1234567", "PUA.Win.Tool.X")))
        check("C3 nomes de família são 'family'", cn("defender", "Trojan:Win32/Lumma.GG!MTB") == "family" and cn("clamav", "Win.Ransomware.Lockbit-9876543-0") == "family")

        # ---------------- triagem (sem arquivos reais: caminhos inexistentes)
        def triage(dets, trusted=None):
            return pc.triage_detections(dets, trusted or {})

        D = se.Detection
        fake = str(tmp / "mod" / "trainer.exe")
        r = triage([D("defender", "Trojan:Win32/Wacatac.B!ml", fake)])[0]
        check("T1 Defender GENÉRICO sozinho => Atenção, nunca Perigoso", r.level == "caution" and r.score <= 30, f"{r.level} {r.score}")
        r = triage([D("clamav", "Win.Trojan.Agent-1234567", fake)])[0]
        check("T2 ClamAV genérico sozinho => só informação (não gera Atenção)", r.level == "ok", f"{r.level} {r.score}")
        r = triage([D("defender", "Trojan:Win32/Lumma.GG!MTB", fake)])[0]
        check("T3 Defender com nome de FAMÍLIA => Perigoso", r.level == "danger", f"{r.level} {r.score}")
        r = triage([D("clamav", "Win.Ransomware.Lockbit-9876543-0", fake)])[0]
        check("T4 ClamAV família SOZINHO => Atenção (não Perigoso)", r.level == "caution" and r.score == 30, f"{r.level} {r.score}")
        r = triage([D("clamav", "Win.Ransomware.Lockbit-9876543-0", fake), D("defender", "Trojan:Win32/Wacatac.B!ml", fake)])[0]
        check("T5 ClamAV família + Defender no MESMO arquivo => Perigoso (critical)", r.level == "danger" and any(f.severity == "critical" for f in r.findings), f"{r.level} {r.score}")
        r = triage([D("defender", "Virus:DOS/EICAR_Test_File", fake)])[0]
        check("T6 arquivo de teste EICAR => Atenção explicando que é teste", r.level == "caution" and any("TESTE" in f.detail for f in r.findings))
        r = triage([D("defender", "Trojan:Win32/Lumma.GG!MTB", fake)], {})[0]
        trusted_hash = hashlib.sha256(b"x").hexdigest()
        f2 = tmp / "t.exe"
        f2.write_bytes(b"x")
        r2 = triage([D("defender", "Trojan:Win32/Lumma.GG!MTB", str(f2))], {trusted_hash: {}})[0]
        check("T7 'Confiar' por SHA-256 silencia a detecção", r2.level == "ok" and r2.status == "user", f"{r2.level} {r2.status}")
        r = triage([D("defender", "Bloqueado pelo antivírus em tempo real", fake)])[0]
        check("T8 arquivo bloqueado em tempo real (nome desconhecido) => Perigoso (high 45)", r.level == "danger", f"{r.level} {r.score}")
        dets = [D("defender", "Trojan:Win32/Wacatac.B!ml", fake), D("defender", "Trojan:Win32/Wacatac.B!ml", fake.upper())]
        check("T9 mesmo arquivo com caminho em maiúsculas é agrupado", len(triage(dets)) == 1)
        notepad = str(SYS32 / "notepad.exe")
        r = triage([D("clamav", "Win.Trojan.Lumma-123", notepad)])[0]
        check("T10 detecção em arquivo assinado pela Microsoft => provável falso positivo (sem pontos)", r.score == 0 and r.level == "ok", f"{r.level} {r.score} {[f.title for f in r.findings]}")

        # ---------------- veredito geral
        v = pc.pc_verdict([], [], [], None, [])
        check("V1 tudo vazio sem lacunas => 'Sem indícios (parcial)', nunca 'limpo'", v.level == "safe" and "parcial" in v.headline)
        v = pc.pc_verdict([], [], [], None, [ps.gap("ClamAV ausente")])
        check("V2 com lacuna (ClamAV ausente) => Inconclusivo", v.level == "unknown")
        v = pc.pc_verdict(triage([D("defender", "Trojan:Win32/Lumma.GG!MTB", fake)]), [], [], None, [])
        check("V3 achado perigoso => Perigoso mesmo com 0 lacunas", v.level == "danger")

        # ---------------- persistência (sintética)
        def pitem(kind, cmd, flags=(), where="x"):
            it = pc.PItem(kind, where, cmd, pc.targets_of(cmd), set(flags))
            return it

        user_exe = tmp / "AppData" / "Local" / "Temp" / "evil.exe"
        user_exe.parent.mkdir(parents=True)
        user_exe.write_bytes(b"MZ")
        NU = ps.norm_path(user_exe)
        it = pitem("Run", f'"{user_exe}" -x')
        pc.triage_persistence([it], {NU: UNS})
        check("P1 Run -> exe sem assinatura em pasta de usuário, sozinho => só nota (sem Atenção)", it.level == "ok", f"{it.level} {it.score}")
        it = pitem("Tarefa agendada", f'"{user_exe}"', {"hidden"})
        pc.triage_persistence([it], {NU: UNS})
        check("P2 tarefa OCULTA -> exe sem assinatura em pasta de usuário => Atenção", it.level == "caution", f"{it.level} {it.score}")
        it = pitem("Tarefa agendada", f'rundll32.exe "{user_exe}",Entry', {"hidden"})
        pc.triage_persistence([it], {NU: UNS})
        check("P3 tarefa oculta + LOLBin carregando payload de usuário => pontua mais", it.score >= 35, f"{it.level} {it.score}")
        it = pitem("Run", f'"{user_exe}"')
        pc.triage_persistence([it], {NU: SIG})
        check("P4 mesmo caminho, mas ASSINADO por publicador válido => sem alerta", it.score == 0 and it.level == "ok", f"{it.level} {it.score}")
        it = pitem("IFEO", r"C:\Windows\System32\vsjitdebugger.exe", {"ifeo"}, "notepad.exe")
        it.targets = [str(user_exe)]
        pc.triage_persistence([it], {NU: UNS})
        check("P5 IFEO redirecionando um programa para exe sem assinatura => Perigoso", it.level == "danger", f"{it.level} {it.score}")
        it = pitem("Winlogon", r"C:\Users\x\evil.exe", {"winlogon"}, "Shell")
        pc.triage_persistence([it], {})
        check("P6 Winlogon Shell alterado => Perigoso", it.level == "danger")
        it = pitem("WMI", "powershell -enc " + "QQBCAEMA" * 8, {"wmi"})
        pc.triage_persistence([it], {})
        check("P7 assinatura WMI executando PowerShell codificado => Perigoso", it.level == "danger", f"{it.level} {it.score}")
        it = pitem("Serviço", r"C:\Windows\System32\svchost.exe -k netsvcs")
        pc.triage_persistence([it], {str(SYS32 / "svchost.exe"): MS})
        check("P8 serviço do Windows (svchost assinado) => sem alerta", it.score == 0, f"{it.level} {it.score}")
        it = pitem("BITS", "http://evil.example/a.exe -> C:" + BS + "x" + BS + "a.exe", {"bits"})
        pc.triage_persistence([it], {})
        check("P9 BITS para destino desconhecido => Atenção", it.level == "caution", f"{it.level} {it.score}")
        tg = pc.targets_of('rundll32.exe C:' + BS + 'Users' + BS + 'u' + BS + 'a.dll,Entry')
        check("P10 targets_of acha a DLL carregada por rundll32", ps.norm_path("C:" + BS + "Users" + BS + "u" + BS + "a.dll") in tg, str(tg))

        # ---------------- zonas
        z = tmp / "zona"
        (z / "sub").mkdir(parents=True)
        (z / "a.exe").write_bytes(b"MZ")
        (z / "sub" / "b.dll").write_bytes(b"MZ")
        (z / "sub" / "texto.txt").write_text("x")
        (z / "big.exe").write_bytes(b"MZ")
        outside = tmp / "fora"
        outside.mkdir()
        (outside / "segredo.exe").write_bytes(b"MZ")
        subprocess.run(["cmd", "/c", "mklink", "/J", str(z / "atalho"), str(outside)], capture_output=True)
        zr = se.enumerate_zone([z])
        names = sorted(os.path.basename(f) for f in zr.files)
        check("Z1 lista só executáveis/scripts e NÃO segue junction para fora da zona", names == ["a.exe", "b.dll", "big.exe"] and zr.skipped_reparse >= 1, f"{names} reparse={zr.skipped_reparse}")
        zr = se.enumerate_zone([z], max_files=2)
        check("Z2 respeita o limite de arquivos e avisa que truncou", len(zr.files) == 2 and zr.truncated)
        zr = se.enumerate_zone([z], modified_within_days=1)
        check("Z3 filtro por data (Rápida) inclui arquivos recentes", len(zr.files) == 3)
        if (z / "atalho").exists():
            subprocess.run(["cmd", "/c", "rmdir", str(z / "atalho")], capture_output=True)

        # ---------------- execução limitada
        t0 = time.time()
        r = se.run_limited(["cmd", "/c", "ping -n 40 127.0.0.1 >nul"], 60, lambda: time.time() - t0 > 1.5)
        check("E1 cancelamento mata o processo em ~2 s", r.cancelled and time.time() - t0 < 5, f"{time.time() - t0:.1f}s")
        r = se.run_limited(["cmd", "/c", "for /l %i in (1,1,300000) do @echo linha %i"], 30, max_bytes=50000)
        check("E2 saída enorme é truncada (não enche a memória)", r.truncated and len(r.out) < 60000)
        r = se.run_limited(["cmd", "/c", "ping -n 30 127.0.0.1 >nul"], 1.0)
        check("E3 tempo limite estoura e encerra", r.timed_out)
        det = se.parse_clam_output("a.exe: Win.Test.X FOUND" + chr(10) + "lixo sem found" + chr(10) + "C:" + BS + "p q" + BS + "b.dll: Heuristics.Y.UNOFFICIAL FOUND" + chr(10))
        check("E4 parse da saída do ClamAV (inclui caminho com espaço)", [(d.name, os.path.basename(d.path)) for d in det] == [("Win.Test.X", "a.exe"), ("Heuristics.Y.UNOFFICIAL", "b.dll")], str(det))
        hostile = ("evil" + chr(0x202E) + chr(0x3164) + ": Win.X FOUND" + chr(10)) * 3
        check("E5 saída hostil do scanner: nome limpo de bidi/invisíveis", all(chr(0x202E) not in ps.clean_text(d.path) for d in se.parse_clam_output(hostile)))

        # ---------------- quarentena
        f = tmp / "dl" / "tool.exe"
        f.parent.mkdir()
        f.write_bytes(b"MZ-quarentena-" + os.urandom(32))
        h = hashlib.sha256(f.read_bytes()).hexdigest()
        ent = q.quarantine(str(f), "teste", UNS)
        check("Q1 quarentena move o arquivo para o cofre (GUID .bin) e guarda o hash", (not f.exists()) and (q.Q_DIR / (ent["id"] + ".bin")).is_file() and ent["sha256"] == h)
        back = q.restore(ent["id"])
        check("Q2 restaurar devolve o arquivo ao lugar original com o mesmo hash", back == str(f) and hashlib.sha256(f.read_bytes()).hexdigest() == h and not q.entries())
        ent = q.quarantine(str(f), "teste", UNS)
        f.write_bytes(b"outro conteudo")
        back = q.restore(ent["id"])
        check("Q3 restaurar NUNCA sobrescreve: cria nome novo", back != str(f) and "(restaurado" in back and f.read_bytes() == b"outro conteudo", back)
        for victim, why in ((notepad, "arquivo do Windows"), (str(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "x.exe"), "Program Files")):
            ok, msg = q.can_quarantine(victim, UNS)
            check(f"Q4 recusa mover {why}", not ok, msg)
        ok, msg = q.can_quarantine(str(tmp / "nao_existe.exe"), UNS)
        check("Q5 arquivo inexistente é recusado", not ok)
        run_copy = tmp / "dl" / "em_uso.exe"
        shutil.copy2(SYS32 / "ping.exe", run_copy)
        pr = subprocess.Popen([str(run_copy), "-n", "20", "127.0.0.1"], stdout=subprocess.DEVNULL)
        time.sleep(0.5)
        ok, msg = q.can_quarantine(str(run_copy), UNS)
        pr.kill()
        check("Q6 programa em execução não pode ser movido", not ok and "execução" in msg, msg)
        jt = tmp / "jdir"
        real = tmp / "real_dir"
        real.mkdir()
        (real / "x.exe").write_bytes(b"MZ")
        subprocess.run(["cmd", "/c", "mklink", "/J", str(jt), str(real)], capture_output=True)
        if jt.exists():
            ok, msg = q.can_quarantine(str(jt / "x.exe"), UNS)
            check("Q7 caminho que passa por junction é recusado", not ok and "junction" in msg, msg)
            subprocess.run(["cmd", "/c", "rmdir", str(jt)], capture_output=True)
        msf = tmp / "dl" / "assinado.exe"
        msf.write_bytes(b"MZ")
        ok, msg = q.can_quarantine(str(msf), MS)
        check("Q8 arquivo com assinatura Microsoft válida é recusado", not ok and "Microsoft" in msg, msg)
        ent = q.quarantine(str(tmp / "dl" / "tool (restaurado).exe") if (tmp / "dl" / "tool (restaurado).exe").exists() else str(f), "t", UNS)
        (q.Q_DIR / (ent["id"] + ".bin")).write_bytes(b"adulterado")
        try:
            q.restore(ent["id"])
            ok = False
        except q.QuarantineError:
            ok = True
        check("Q9 item do cofre adulterado não é restaurado", ok)

        # ---------------- ClamAV real com base de teste (opcional: precisa do ClamAV instalado e verificado)
        man = comp.load_bundled_manifest(save=False)
        cc = man["components"]["clamav"]
        st = comp.detect("clamav", cc, man)
        if st.state == comp.OK:
            db = tmp / "db"
            db.mkdir()
            sample = tmp / "amostra_teste.exe"
            sample.write_bytes(b"MZ-SENTINELA-TESTE-INERTE-" + os.urandom(64))
            (db / "teste.hdb").write_text(hashlib.md5(sample.read_bytes()).hexdigest() + ":" + str(sample.stat().st_size) + ":Win.Test.Sentinela_HDB-1" + chr(10))
            clean = tmp / "limpo.exe"
            clean.write_bytes(b"MZ" + b"\0" * 100)
            with comp.PinnedRun(st, cc) as run:
                dets, n, errs = se.clam_scan(run, [str(sample), str(clean)], db)
            check("A1 ClamAV real (cópia privada verificada) detecta a amostra de teste e não o arquivo limpo",
                  n == 2 and not errs and len(dets) == 1 and os.path.basename(dets[0].path) == "amostra_teste.exe", f"{n} {errs} {[(d.name) for d in dets]}")
            tr = pc.triage_detections(dets, {})
            check("A2 detecção de teste do ClamAV (nome 'Win.Test…' ) vira só atenção/informação, nunca Perigoso", tr[0].level != "danger", f"{tr[0].level} {tr[0].score}")
        else:
            check("A1-A2 ClamAV real (pulado: componente não instalado)", True, "pulado")
    finally:
        q.Q_DIR = old_q
        shutil.rmtree(tmp, ignore_errors=True)
