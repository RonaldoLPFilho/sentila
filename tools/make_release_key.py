"""Cria a chave de RELEASE que assina o manifesto de componentes (Ed25519, PEM cifrado com senha). Uso (do mantenedor, uma vez):

    python tools\\make_release_key.py [--out <arquivo.pem>]

A senha é pedida no terminal (nunca por variável de ambiente nem argumento). Depois:
  1. coloque a chave pública impressa em MANIFEST_PUBKEYS (sentinela/components.py), no lugar da chave de desenvolvimento;
  2. assine de novo o manifesto: python tools\\make_manifest.py --resign --key-file <arquivo.pem> --serial <N>;
  3. guarde o .pem fora deste PC (pendrive/cofre) e apague a cópia local. Sem o arquivo E a senha, ninguém assina um manifesto aceito.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import os
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MIN_PASS = 12


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(Path.home() / ".sentinela-keys" / "release_ed25519.pem"))
    a = ap.parse_args()
    out = Path(a.out)
    if out.exists():
        sys.exit(f"{out} já existe: não sobrescrevo uma chave de release.")
    pw = getpass.getpass(f"Senha da chave de release (mínimo {MIN_PASS} caracteres): ")
    if len(pw) < MIN_PASS:
        sys.exit("Senha curta demais.")
    if getpass.getpass("Repita a senha: ") != pw:
        sys.exit("As senhas não conferem.")
    k = Ed25519PrivateKey.generate()
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["icacls", str(out.parent), "/inheritance:r", "/grant:r", f"{os.environ.get('USERNAME', '')}:(OI)(CI)F"], capture_output=True)
    out.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(pw.encode())))
    pub = base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    print(f"\nChave de release criada (cifrada): {out}")
    print(f"CHAVE PÚBLICA para MANIFEST_PUBKEYS: {pub}")
    print("Próximo passo: python tools\\make_manifest.py --resign --key-file \"" + str(out) + "\" --serial 2")


if __name__ == "__main__":
    main()
