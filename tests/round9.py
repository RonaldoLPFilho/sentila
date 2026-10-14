"""Reauditoria da "Verificar computador": base do ClamAV, contagem de varridos, base plantada, alvos remotos, quarentena (diário, hash esperado, limite, índice)."""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

BS = chr(92)


class FakeRun:
    def __init__(self, d: Path) -> None:
        self.dir = d
        self.calls: list = []

    def exe(self, rel: str) -> str:
        return str(self.dir / rel)

    def verify_names(self):
        return True, ""


def run_round9(ctx) -> None:
    check = ctx.check
    from sentinela import pcscan as pc
    from sentinela import procscan as ps
    from sentinela import quarantine as q
    from sentinela import scanengines as se

    tmp = Path(tempfile.mkdtemp(prefix="sent_r9_"))
    old = (se.CLAM_DB, q.Q_DIR, q.MAX_PER_ACTION, se.run_limited)
    try:
        # ---------------- B1: base completa
        db = tmp / "clamdb"
        se.CLAM_DB = db
        db.mkdir()
        (db / "daily.cvd").write_bytes(b"x")
        ok, age, why = se.clam_db_state()
        check("B1 só daily => base INCOMPLETA (faltam main e bytecode)", not ok and "main" in why and "bytecode" in why, why)
        (db / "main.cvd").write_bytes(b"x")
        (db / "bytecode.cvd").write_bytes(b"x")
        ok, age, why = se.clam_db_state()
        check("B1 main + daily + bytecode => base íntegra", ok, why)
        (db / "tmp.abc").mkdir()
        ok, age, why = se.clam_db_state()
        check("B1 pasta tmp.* pendente (atualização interrompida) => base NÃO íntegra", not ok and "interrompida" in why, why)
        shutil.rmtree(db / "tmp.abc")
        (db / "allow.fp").write_text("44d88612fea8a8f36de82e1278abb02f:68:Eicar" + chr(10))
        ok, age, why = se.clam_db_state()
        check("B3 arquivo estranho plantado na pasta da base (.fp de allowlist) => base NÃO íntegra", not ok and "allow.fp" in why, why)
        (db / "allow.fp").unlink()

        # ---------------- B2/B3: contagem de varridos e argumentos
        calls = []
        scripted = {"r": None}

        def fake_run(cmd, timeout, cancelled=lambda: False, **kw):
            calls.append(cmd)
            return scripted["r"]

        se.run_limited = fake_run
        run = FakeRun(tmp)
        files = [str(tmp / f"a{i}.exe") for i in range(3)]
        scripted["r"] = se.RunResult(0, "", timed_out=True)
        dets, n, errs = se.clam_scan(run, files)
        check("B2 lote com TEMPO EXCEDIDO não conta como varrido", n == 0 and any("tempo excedido" in e for e in errs), f"{n} {errs}")
        scripted["r"] = se.RunResult(0, "x", truncated=True)
        dets, n, errs = se.clam_scan(run, files)
        check("B2 saída TRUNCADA não conta como varrido", n == 0 and any("grande demais" in e for e in errs), f"{n} {errs}")
        out = "WARNING: Can't open file " + files[0] + ": Permission denied" + chr(10) + "LibClamAV Warning: Can't open file " + files[1] + ": 225" + chr(10)
        scripted["r"] = se.RunResult(2, out)
        dets, n, errs = se.clam_scan(run, files)
        check("B2 'Can't open' comum vira lacuna; 225 vira detecção do antivírus em tempo real; só o restante é 'varrido'",
              n == 1 and any(d.name.startswith("Bloqueado") and d.path == files[1] for d in dets) and any("não puderam ser abertos" in e for e in errs), f"{n} {errs} {[d.name for d in dets]}")
        scripted["r"] = se.RunResult(2, "ERROR: Can't allocate memory")
        dets, n, errs = se.clam_scan(run, files)
        check("B2 erro real do clamscan (código 2 com ERROR) => lote não contado", n == 0 and errs, f"{n} {errs}")
        scripted["r"] = se.RunResult(0, "")
        calls.clear()
        dets, n, errs = se.clam_scan(run, files)
        check("B3 clamscan roda com --official-db-only=yes (só .cvd/.cld assinados)", n == 3 and calls and "--official-db-only=yes" in calls[0], str(calls[0] if calls else ""))
        (db / "evil.ldb").write_text("x")
        calls.clear()
        dets, n, errs = se.clam_scan(run, files)
        check("B3 base com arquivo plantado => NÃO executa o clamscan e avisa", n == 0 and not calls and errs and "íntegra" in errs[0], str(errs))
        (db / "evil.ldb").unlink()
        se.run_limited = old[3]

        # ---------------- B6: alvo de persistência na rede nunca é aberto
        real_isfile = os.path.isfile

        def guarded(p):
            if str(p).startswith(BS * 2):
                raise AssertionError("tentou abrir caminho de rede: " + str(p))
            return real_isfile(p)

        os.path.isfile = guarded
        try:
            it = pc.PItem("Run", "x", BS * 2 + "10.255.255.1" + BS + "s" + BS + "a.exe")
            it.targets = pc.targets_of(it.command)
            pc.triage_persistence([it], {})
            check("B6 Run apontando para \\\\servidor\\... => achado 'rede', SEM abrir o arquivo", it.level == "caution" and any("rede" in f.title for f in it.findings), f"{it.level} {[f.title for f in it.findings]}")
        finally:
            os.path.isfile = real_isfile
        docs = tmp / "Documents"
        docs.mkdir()
        ex = docs / "evil.exe"
        ex.write_bytes(b"MZ")
        nk = ps.norm_path(ex)
        it = pc.PItem("Run", "x", f'"{ex}"')
        it.targets = pc.targets_of(it.command)
        pc.triage_persistence([it], {nk: {"status": "NotSigned", "verified": True, "subject": "", "issuer": "", "thumb": ""}})
        check("R1 programa sem assinatura em Documents/fora de Program Files inicia com o Windows => nota (não ignora)", it.score == 8, f"{it.level} {it.score}")

        # ---------------- B4: higiene não vira Perigoso
        from sentinela.scoring import Finding
        hyg = [Finding("hygiene", "Firewall desligado", "", 20, "medium"), Finding("hygiene", "UAC desligado", "", 25, "medium")]
        v = pc.pc_verdict([], [], hyg, None, [])
        check("B4 firewall + UAC desligados (45) => no máximo Atenção (configuração insegura não é malware)", v.level == "caution", v.headline)
        hyg = [Finding("hygiene", "Tempo real desligado", "", 40, "high"), Finding("hygiene", "Assinaturas velhas", "", 15, "medium")]
        check("B4 Defender desligado + assinaturas velhas (55) => no máximo Atenção", pc.pc_verdict([], [], hyg, None, []).level == "caution")

        # ---------------- componentes: pasta travada não aceita arquivo novo
        from sentinela import components as comp
        dirx = tmp / "privada"
        (dirx / ".work").mkdir(parents=True)
        (dirx / "clamscan.exe").write_bytes(b"x")
        (dirx / ".work" / "lista.txt").write_text("x")
        pr = comp.PinnedRun.__new__(comp.PinnedRun)
        pr.dir, pr.comp = dirx, {"tree": {"clamscan.exe": "00"}}
        check("C1 arquivos de trabalho (.work) não contam como arquivo estranho", pr.verify_names()[0])
        (dirx / "version.dll").write_bytes(b"plantada")
        ok, msg = pr.verify_names()
        check("C1 DLL nova plantada ao lado do exe durante a varredura => detectada", not ok and "version.dll" in msg, msg)
        check("C2 piso de serial no código existe (não depende só do registro)", comp.MIN_SERIAL >= 1)

        # ---------------- B7: quarentena
        q.Q_DIR = tmp / "q"
        q.MAX_PER_ACTION = 2
        UNS = {"status": "NotSigned", "verified": True, "subject": "", "issuer": "", "thumb": ""}
        d = tmp / "dl"
        d.mkdir()

        def mk(name):
            f = d / name
            f.write_bytes(b"MZ-" + name.encode() + os.urandom(16))
            return f

        f1 = mk("a.exe")
        import hashlib
        h = hashlib.sha256(f1.read_bytes()).hexdigest()
        try:
            q.quarantine(str(f1), "t", UNS, expected_sha256="0" * 64)
            ok = False
        except q.QuarantineError as e:
            ok = "diferente" in str(e) and f1.exists()
        check("B7 hash esperado diferente (arquivo trocado desde a varredura) => NÃO move", ok)
        e1 = q.quarantine(str(f1), "t", UNS, expected_sha256=h)
        check("B7 hash esperado correto => move e marca state=ok", not f1.exists() and q.entries()[0]["state"] == "ok")
        # falha no meio do movimento: o arquivo fica no cofre COM entrada (restaurável)
        f2 = mk("b.exe")
        real_move = shutil.move

        def bad_move(src, dst):
            shutil.copy2(src, dst)
            os.unlink(src)
            raise OSError("falha simulada depois de copiar")

        shutil.move = bad_move
        try:
            try:
                q.quarantine(str(f2), "t", UNS)
                ok = False
            except q.QuarantineError as e:
                ok = "cofre" in str(e)
        finally:
            shutil.move = real_move
        ents = q.entries()
        check("B7 falha DEPOIS de mover => o arquivo está no cofre e há entrada (restaurável)", ok and len(ents) == 2 and any(x["original"] == str(f2) for x in ents))
        back = q.restore(next(x["id"] for x in ents if x["original"] == str(f2)))
        check("B7 ...e a restauração funciona", back == str(f2) and f2.exists())
        q.quarantine(str(mk("d.exe")), "t", UNS)
        f3 = mk("c.exe")
        try:
            q.quarantine(str(f3), "t", UNS)
            ok = False
        except q.QuarantineError as e:
            ok = "Limite" in str(e)
        check("B7 limite por ação (MAX_PER_ACTION) é aplicado", ok and f3.exists())
        # índice adulterado
        idxp = q.Q_DIR / "index.json"
        txt = idxp.read_text(encoding="utf-8").replace('"state": "ok"', '"state": "ok", "extra": 1')
        idxp.write_text(txt, encoding="utf-8")
        check("B7 índice editado à mão (MAC não confere) => nada é restaurado a partir dele", q.entries() == [])
    finally:
        se.CLAM_DB, q.Q_DIR, q.MAX_PER_ACTION, se.run_limited = old
        shutil.rmtree(tmp, ignore_errors=True)
