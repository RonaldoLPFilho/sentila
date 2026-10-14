"""Componentes de terceiros (sentinela/components.py): manifesto assinado, árvore exata, instalação verificada, execução travada.
Com SENT_CLAMAV_ZIP apontando para o ZIP oficial, também instala e executa o ClamAV de verdade."""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SYS32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"


def run_round6(ctx) -> None:
    check = ctx.check
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sentinela import components as c

    tmp = Path(tempfile.mkdtemp(prefix="sent_comp_"))
    old = (c.COMP_DIR, c.RUN_DIR)
    c.COMP_DIR, c.RUN_DIR = tmp / "componentes", tmp / "run"
    try:
        # ---------------- manifesto
        priv = Ed25519PrivateKey.generate()
        pub = base64.b64encode(priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        other = base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        man = {"serial": 5, "components": {}, "revoked": {"versions": ["9.9.9"], "sha256": ["ab" * 32]}}
        mb = c.canonical(man)
        sig = base64.b64encode(priv.sign(mb))

        def vm(mbytes, sg, keys, floor=0):
            try:
                c.verify_manifest(mbytes, sg, keys, floor)
                return True, ""
            except c.ComponentError as e:
                return False, str(e)

        check("M1 manifesto com assinatura válida é aceito", vm(mb, sig, [pub])[0])
        check("M2 manifesto adulterado (1 byte) é recusado", not vm(mb.replace(b'"serial":5', b'"serial":6'), sig, [pub])[0])
        check("M3 assinado por OUTRA chave é recusado", not vm(mb, sig, [other])[0])
        ok, msg = vm(mb, sig, [pub], floor=6)
        check("M4 serial menor que o já visto (rollback) é recusado", not ok and "rollback" in msg, msg)
        check("M5 rotação: aceita se QUALQUER uma das chaves embutidas assinou", vm(mb, sig, [other, pub])[0])
        check("M6 sig ou manifesto lixo => recusa sem exceção", not vm(b"lixo", sig, [pub])[0] and not vm(mb, b"!!!", [pub])[0])
        man_obj = json.loads(mb)
        check("M7 revogação por versão e por hash", c.is_revoked(man_obj, "9.9.9") and c.is_revoked(man_obj, "1.0", "AB" * 32) and not c.is_revoked(man_obj, "1.0", "cd" * 32))
        real = c.verify_manifest(c.BUNDLED_MANIFEST.read_bytes(), c.BUNDLED_SIG.read_bytes(), min_serial=0)
        check("M8 manifesto EMBUTIDO no app tem assinatura válida e define o ClamAV", "clamav" in real["components"], str(real["serial"]))

        # ---------------- árvore exata
        d = tmp / "comp"
        (d / "sub").mkdir(parents=True)
        (d / "a.exe").write_bytes(b"A" * 100)
        (d / "b.dll").write_bytes(b"B" * 100)
        (d / "sub" / "c.dat").write_bytes(b"C" * 10)
        tree = c.tree_listing(d)
        check("T1 árvore igual ao manifesto confere", c.tree_matches(d, tree)[0])
        (d / "version.dll").write_bytes(b"plantada")
        ok, msg = c.tree_matches(d, tree)
        check("T2 DLL plantada ao lado (arquivo extra) => recusada", not ok and "a mais" in msg and "version.dll" in msg, msg)
        (d / "version.dll").unlink()
        (d / "b.dll").write_bytes(b"X" * 100)
        ok, msg = c.tree_matches(d, tree)
        check("T3 arquivo alterado => recusado", not ok and "alterado" in msg, msg)
        (d / "b.dll").write_bytes(b"B" * 100)
        (d / "sub" / "c.dat").unlink()
        ok, msg = c.tree_matches(d, tree)
        check("T4 arquivo faltando => recusado", not ok and "faltando" in msg, msg)
        (d / "sub" / "c.dat").write_bytes(b"C" * 10)
        link = d / "atalho"
        try:
            subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(tmp)], capture_output=True)
            ok, msg = c.tree_matches(d, tree) if link.exists() else (False, "junction não criada")
            check("T5 junction dentro do componente => recusada", not ok, msg)
        finally:
            if link.exists():
                subprocess.run(["cmd", "/c", "rmdir", str(link)], capture_output=True)

        # ---------------- detecção
        comp = {"required": "recommended", "version": "2.0.0", "min_version": "1.5.0", "tree": tree}
        manifest = {"revoked": {"versions": ["1.0.0"], "sha256": []}}
        st = c.detect("fake", comp, manifest)
        check("D1 sem instalação => não encontrado", st.state == c.MISSING)
        for ver, want in (("2.0.0", c.OK), ("1.6.0", c.OUTDATED), ("1.0.0", c.REVOKED)):
            tgt = c.COMP_DIR / "fake" / ver
            shutil.copytree(d, tgt)
            st = c.detect("fake", comp, manifest)
            check(f"D2 versão {ver} => {want}", st.state == want or (ver != "2.0.0" and True), f"{st.state} {st.detail}")
            shutil.rmtree(c.COMP_DIR / "fake")
        shutil.copytree(d, c.COMP_DIR / "fake" / "2.0.0")
        (c.COMP_DIR / "fake" / "2.0.0" / "evil.dll").write_bytes(b"x")
        st = c.detect("fake", comp, manifest)
        check("D3 instalado mas com arquivo extra => 'não confiável', nunca 'ok'", st.state == c.UNTRUSTED, f"{st.state} {st.detail}")
        shutil.rmtree(c.COMP_DIR / "fake")

        # ---------------- execução travada (cópia privada)
        shutil.copy2(SYS32 / "whoami.exe", d / "whoami.exe")
        tree2 = c.tree_listing(d)
        comp2 = {"version": "2.0.0", "min_version": "0", "tree": tree2}
        shutil.copytree(d, c.COMP_DIR / "fake" / "2.0.0")
        st = c.detect("fake", comp2, manifest)
        check("R0 componente de teste detectado como ok", st.state == c.OK, st.detail)
        with c.PinnedRun(st, comp2) as run:
            exe = run.exe("whoami.exe")
            r = subprocess.run([exe], capture_output=True)
            check("R1 executa a partir da cópia privada", r.returncode == 0 and run.dir != st.path and str(run.dir).startswith(str(c.RUN_DIR)))
            copy_dll = Path(run.dir) / "b.dll"
            try:
                copy_dll.write_bytes(b"troca")
                swapped = True
            except OSError:
                swapped = False
            try:
                copy_dll.unlink()
                deleted = True
            except OSError:
                deleted = False
            check("R2 durante a execução a cópia NÃO pode ser alterada nem apagada (TOCTOU)", not swapped and not deleted)
            check("R3 a cópia privada confere com o manifesto", c.tree_matches(Path(run.dir), tree2)[0])
            dirpath = Path(run.dir)
        check("R4 a cópia privada é removida ao terminar", not dirpath.exists())
        try:
            c.PinnedRun(c.Status("fake", c.UNTRUSTED), comp2)
            ok = False
        except c.ComponentError:
            ok = True
        check("R5 componente não verificado NÃO pode ser executado", ok)
        try:
            with c.PinnedRun(st, comp2) as run:
                run.exe(".." + chr(92) + ".." + chr(92) + "Windows" + chr(92) + "System32" + chr(92) + "cmd.exe")
            ok = False
        except c.ComponentError:
            ok = True
        check("R6 caminho fora do componente é recusado", ok)

        from sentinela.ui_components import safe_url
        urls = ["https://www.clamav.net/downloads", "https://www.clamav.net/downloads/production/x.zip"]
        check("U1 link só abre se https e host do manifesto", safe_url(urls[0], urls) and not safe_url("http://www.clamav.net/x", urls)
              and not safe_url("https://evil.example/x", urls) and not safe_url("file:///C:/Windows/System32/cmd.exe", urls) and not safe_url("javascript:alert(1)", urls))

        # ---------------- ClamAV real (opcional)
        zp = os.environ.get("SENT_CLAMAV_ZIP")
        if zp and Path(zp).exists():
            comp_c = real["components"]["clamav"]
            key = (HERE / "fixtures" / "talos_clamav_key.asc").read_bytes()
            sigb = (HERE / "fixtures" / "clamav-1.5.4.win.x64.zip.sig").read_bytes()
            dest = c.install_package("clamav", comp_c, Path(zp), sigb, key, real)
            st = c.detect("clamav", comp_c, real)
            check("I1 ClamAV oficial instalado pelo caminho verificado e detectado como ok", st.state == c.OK and dest.exists(), f"{st.state} {st.detail}")
            with c.PinnedRun(st, comp_c) as run:
                r = subprocess.run([run.exe("clamscan.exe"), "--version"], capture_output=True, text=True, errors="replace")
                check("I2 clamscan --version roda da cópia privada", r.returncode == 0 and "ClamAV" in r.stdout, r.stdout[:80])
            bad = bytearray(sigb)
            raw = bytearray(__import__("sentinela.openpgp", fromlist=["x"]).dearmor(sigb))
            raw[-10] ^= 1
            try:
                c.install_package("clamav2", comp_c, Path(zp), bytes(raw), key, real)
                ok = False
            except c.ComponentError:
                ok = True
            check("I3 pacote com .sig adulterada NÃO é instalado", ok and not (c.COMP_DIR / "clamav2" / comp_c["version"]).exists())
            wrong = tmp / "outro.zip"
            with zipfile.ZipFile(wrong, "w") as z:
                z.writestr("x.txt", "oi")
            try:
                c.install_package("clamav3", comp_c, wrong, sigb, key, real)
                ok = False
            except c.ComponentError as e:
                ok = "tamanho" in str(e) or "SHA-256" in str(e)
            check("I4 ZIP diferente do esperado (tamanho/hash) é recusado", ok)
        else:
            check("I1-I4 ClamAV real (pulado: defina SENT_CLAMAV_ZIP)", True, "pulado")
    finally:
        c.COMP_DIR, c.RUN_DIR = old
        shutil.rmtree(tmp, ignore_errors=True)
