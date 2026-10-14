"""Verificador OpenPGP mínimo (sentinela/openpgp.py): usa o GnuPG (se existir) como oráculo para gerar assinaturas reais e testa adulterações.
Se a variável SENT_CLAMAV_ZIP apontar para o clamav-1.5.4.win.x64.zip oficial, também confere a assinatura REAL da Talos."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
TALOS_FPR = "5BADCA2665EF59DCF8A23D8B707F0DB480836771"


def _gpg() -> str | None:
    exe = shutil.which("gpg")
    if exe:
        return exe
    cand = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "usr" / "bin" / "gpg.exe"
    return str(cand) if cand.exists() else None


def _home(p: Path) -> str:
    """GNUPGHOME no formato que o gpg do Git (msys) entende (caminho Windows vira /c/pasta/...)."""
    s = str(p).replace(chr(92), "/")
    return "/" + s[0].lower() + s[2:] if len(s) > 2 and s[1] == ":" else s


def run_round5(ctx) -> None:
    check = ctx.check
    from sentinela import openpgp as o

    key = (HERE / "fixtures" / "talos_clamav_key.asc").read_bytes()
    sig = (HERE / "fixtures" / "clamav-1.5.4.win.x64.zip.sig").read_bytes()

    pk = o.load_primary_key(key, TALOS_FPR)
    check("S1 chave real da Talos: fingerprint pinado confere e a chave expira em 2027-03-13",
          pk.keyid.hex() == "707f0db480836771" and pk.expires and time.strftime("%Y-%m-%d", time.gmtime(pk.expires)) == "2027-03-13")
    try:
        o.load_primary_key(key, "0" * 40)
        ok = False
    except o.PgpError:
        ok = True
    check("S2 fingerprint DIFERENTE do pinado => chave recusada", ok)
    check("S3 .sig real: 1 assinatura RSA/SHA-1 (hash legado) que só passa com allow_sha1",
          o.parse_signature([b for t, b in o.packets(o.dearmor(sig)) if t == 2][0]).hashalgo == 2)

    zp = os.environ.get("SENT_CLAMAV_ZIP")
    if zp and Path(zp).exists():
        ok1, m1 = o.verify_detached(zp, sig, key, TALOS_FPR, allow_sha1=False)
        ok2, m2 = o.verify_detached(zp, sig, key, TALOS_FPR, allow_sha1=True)
        check("S4 ZIP oficial do ClamAV: SHA-1 recusado por padrão e VÁLIDO com allow_sha1", (not ok1) and ok2, f"{m1} | {m2}")
        raw = bytearray(o.dearmor(sig))
        raw[-10] ^= 1
        ok3, m3 = o.verify_detached(zp, bytes(raw), key, TALOS_FPR, allow_sha1=True)
        check("S5 assinatura REAL adulterada (1 bit) => recusada", not ok3, m3)
        ok4, m4 = o.verify_detached(zp, sig, key, TALOS_FPR, allow_sha1=True, now=time.mktime((2028, 1, 1, 0, 0, 0, 0, 0, 0)))
        check("S6 chave expirada (2028) => recusada", not ok4 and "expirou" in m4, m4)
    else:
        check("S4-S6 assinatura real da Talos (pulado: defina SENT_CLAMAV_ZIP com o zip oficial)", True, "pulado")

    gpg = _gpg()
    if not gpg:
        check("S7-S14 oráculo GnuPG (pulado: gpg não encontrado)", True, "pulado")
        return
    tmp = Path(tempfile.mkdtemp(prefix="sent_pgp_"))
    env = dict(os.environ, GNUPGHOME=_home(tmp / "home"))
    (tmp / "home").mkdir()
    try:
        def g(*args, **kw):
            return subprocess.run([gpg, "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "", *args], env=env,
                                  capture_output=True, **kw)

        r = g("--quick-generate-key", "Teste Sentinela <t@example.test>", "rsa3072", "sign", "1y")
        fpr = next((ln.split(":")[9] for ln in g("--list-keys", "--with-colons").stdout.decode().splitlines() if ln.startswith("fpr")), "")
        if r.returncode != 0 or len(fpr) != 40:
            check("S7-S14 oráculo GnuPG (pulado: não conseguiu gerar chave de teste)", True, "pulado")
            return
        pub = g("--armor", "--export", fpr).stdout
        data = tmp / "dados.bin"
        data.write_bytes(os.urandom(300_000))

        def sign(digest: str, path=data) -> bytes:
            out = tmp / ("s_" + digest + ".sig")
            if out.exists():
                out.unlink()
            g("--digest-algo", digest, "--detach-sign", "--output", str(out), str(path))
            return out.read_bytes()

        s256, s1 = sign("SHA256"), sign("SHA1")
        ok, m = o.verify_detached(data, s256, pub, fpr)
        check("S7 assinatura RSA/SHA-256 gerada pelo GnuPG é aceita", ok, m)
        ok, m = o.verify_detached(data, s256, pub, fpr.lower())
        check("S7 fingerprint pinado aceita minúsculas", ok, m)
        ok, m = o.verify_detached(data, s1, pub, fpr)
        check("S8 SHA-1 é recusado por padrão", (not ok) and "SHA-1" in m, m)
        ok, m = o.verify_detached(data, s1, pub, fpr, allow_sha1=True)
        check("S8 ...e aceito só com allow_sha1", ok, m)
        bad = tmp / "dados_adulterado.bin"
        b = bytearray(data.read_bytes())
        b[1000] ^= 1
        bad.write_bytes(bytes(b))
        ok, m = o.verify_detached(bad, s256, pub, fpr)
        check("S9 arquivo adulterado (1 bit) => recusado", not ok and "NÃO confere" in m, m)
        raw = bytearray(o.dearmor(s256) if s256.startswith(b"-----") else s256)
        raw[-7] ^= 1
        ok, m = o.verify_detached(data, bytes(raw), pub, fpr)
        check("S10 assinatura adulterada (1 bit) => recusada", not ok, m)
        ok, m = o.verify_detached(data, s256, pub, "1" * 40)
        check("S11 chave com outro fingerprint => recusada", not ok, m)
        # chave do atacante: assinatura válida, mas de OUTRA chave
        env2 = dict(env, GNUPGHOME=_home(tmp / "home2"))
        (tmp / "home2").mkdir()
        subprocess.run([gpg, "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key", "Atacante <a@example.test>", "rsa3072", "sign", "1y"],
                       env=env2, capture_output=True)
        fpr2 = next((ln.split(":")[9] for ln in subprocess.run([gpg, "--list-keys", "--with-colons"], env=env2, capture_output=True).stdout.decode().splitlines() if ln.startswith("fpr")), "")
        out2 = tmp / "atacante.sig"
        subprocess.run([gpg, "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "", "--digest-algo", "SHA256", "--detach-sign", "--output", str(out2), str(data)], env=env2, capture_output=True)
        pub2 = subprocess.run([gpg, "--armor", "--export", fpr2], env=env2, capture_output=True).stdout
        ok, m = o.verify_detached(data, out2.read_bytes(), pub, fpr)
        check("S12 assinatura válida de OUTRA chave (atacante) contra a chave pinada => recusada", not ok, m)
        ok, m = o.verify_detached(data, out2.read_bytes(), pub2, fpr2)
        check("S12 ...(controle) a mesma assinatura é válida com a chave do atacante, então o pino é o que protege", ok, m)
        ok, m = o.verify_detached(data, s256, pub, fpr, now=time.time() + 3 * 365 * 86400)
        check("S13 chave expirada (hoje + 3 anos) => recusada", not ok and "expirou" in m, m)
        ok, m = o.verify_detached(data, s256, pub, fpr, now=time.time() - 400 * 86400)
        check("S13 assinatura datada do futuro (relógio no passado) => recusada", not ok, m)
        # entrada hostil
        for name, s_, k_ in (("lixo aleatório", os.urandom(900), pub), ("vazio", b"", pub), ("sig truncada", s256[:60], pub),
                             ("chave lixo", s256, os.urandom(500)), ("armor sem corpo", b"-----BEGIN PGP SIGNATURE-----\n\n-----END PGP SIGNATURE-----\n", pub)):
            try:
                ok, m = o.verify_detached(data, s_, k_, fpr)
            except Exception as e:  # noqa: BLE001
                ok, m = True, f"EXCEÇÃO {e!r}"
            check(f"S14 entrada hostil ({name}) => recusa sem exceção", not ok and "EXCEÇÃO" not in m, m)
        ok, m = o.verify_detached(tmp / "nao_existe.bin", s256, pub, fpr)
        check("S14 arquivo inexistente => recusa", not ok, m)
    finally:
        pass
        shutil.rmtree(tmp, ignore_errors=True)
