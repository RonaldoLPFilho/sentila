"""Gera e assina sentinela/manifest.json (lista de componentes de terceiros). Uso (do mantenedor, NUNCA em máquina de usuário):

    python tools\\make_manifest.py --zip <clamav-x.y.z.win.x64.zip> --sig <.sig> --serial 3 --key-file <release.pem>
    python tools\\make_manifest.py --resign --serial 3 --key-file <release.pem>      (só assina de novo o manifesto atual, p.ex. troca de chave)

A chave privada é a de RELEASE (tools\\make_release_key.py): PEM cifrado, guardado fora deste PC; a senha é pedida no terminal.
Chave sem senha só com --dev (testes). Nenhuma chave é criada aqui. A chave pública tem de estar em MANIFEST_PUBKEYS (sentinela/components.py).
O arquivo .sig GPG do pacote só é conferido aqui com o verificador do próprio Sentinela (fingerprint pinado abaixo)."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import time
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from sentinela import openpgp  # noqa: E402
from sentinela.components import canonical  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TALOS_FPR = "5BADCA2665EF59DCF8A23D8B707F0DB480836771"   # conferido em 3 fontes: clamav.net, keys.openpgp.org e GitHub Cisco-Talos/clamav-documentation
DEFAULT_KEY = Path.home() / ".sentinela-keys" / "release_ed25519.pem"


def load_key(path: Path, dev: bool) -> Ed25519PrivateKey:
    """Carrega a chave de assinatura. Exige PEM cifrado (senha pedida no terminal), salvo --dev."""
    if not path.exists():
        sys.exit(f"Chave não encontrada: {path}. Crie a de release com tools\\make_release_key.py (nada é criado aqui).")
    pem = path.read_bytes()
    if b"ENCRYPTED" not in pem:
        if not dev:
            sys.exit("Chave SEM senha: recusada para release. Use a chave de release cifrada, ou --dev só para testes.")
        k = serialization.load_pem_private_key(pem, None)
    else:
        import getpass
        try:
            k = serialization.load_pem_private_key(pem, getpass.getpass(f"Senha de {path.name}: ").encode())
        except (ValueError, TypeError):
            sys.exit("Senha incorreta.")
    if not isinstance(k, Ed25519PrivateKey):
        sys.exit("A chave não é Ed25519.")
    return k


def clamav_allowlist(names: list[str], prefix: str) -> list[str]:
    keep = []
    for n in names:
        if not n.startswith(prefix) or n.endswith("/"):
            continue
        rel = n[len(prefix):]
        low = rel.lower()
        if "/" not in rel and (low.endswith(".dll") or low in ("clamscan.exe", "freshclam.exe", "sigtool.exe")):
            keep.append(rel)
        elif low == "certs/clamav.crt":
            keep.append(rel)
    return sorted(keep)


def sign_and_write(manifest: dict, k: Ed25519PrivateKey) -> None:
    from sentinela.components import MANIFEST_PUBKEYS
    mb = canonical(manifest)
    (ROOT / "sentinela" / "manifest.json").write_bytes(mb)
    (ROOT / "sentinela" / "manifest.sig").write_bytes(base64.b64encode(k.sign(mb)))
    pub = base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    print("serial", manifest["serial"], "| issued", manifest["issued"])
    print("CHAVE PÚBLICA:", pub, "(já está em MANIFEST_PUBKEYS)" if pub in MANIFEST_PUBKEYS else "<- coloque em MANIFEST_PUBKEYS e suba MIN_SERIAL")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip")
    ap.add_argument("--sig")
    ap.add_argument("--key", default=str(ROOT / "tests" / "fixtures" / "talos_clamav_key.asc"))
    ap.add_argument("--serial", type=int, required=True)
    ap.add_argument("--key-file", default=str(DEFAULT_KEY))
    ap.add_argument("--resign", action="store_true", help="assina de novo o manifesto atual (conferido antes) com outro serial/chave")
    ap.add_argument("--dev", action="store_true", help="aceita chave sem senha (só testes)")
    a = ap.parse_args()
    if a.resign:
        from sentinela.components import ComponentError, verify_manifest
        mb = (ROOT / "sentinela" / "manifest.json").read_bytes()
        try:
            cur = verify_manifest(mb, (ROOT / "sentinela" / "manifest.sig").read_bytes(), min_serial=0)
        except ComponentError as e:
            sys.exit(f"O manifesto atual não confere com as chaves do app ({e}): não reassino conteúdo não verificado.")
        if a.serial <= cur["serial"]:
            sys.exit(f"--serial precisa ser maior que o atual ({cur['serial']}).")
        cur["serial"], cur["issued"] = a.serial, time.strftime("%Y-%m-%d")
        sign_and_write(cur, load_key(Path(a.key_file), a.dev))
        return
    if not (a.zip and a.sig):
        sys.exit("--zip e --sig são obrigatórios (ou use --resign).")
    zp = Path(a.zip)
    m = re.match(r"clamav-(\d+\.\d+\.\d+)\.win\.x64\.zip$", zp.name)
    if not m:
        sys.exit("nome do zip inesperado")
    ver = m.group(1)
    sig, key = Path(a.sig).read_bytes(), Path(a.key).read_bytes()
    ok, msg = openpgp.verify_detached(zp, sig, key, TALOS_FPR, allow_sha1=True)
    if not ok:
        sys.exit("ASSINATURA GPG INVÁLIDA: " + msg)
    print("GPG:", msg)
    prefix = f"clamav-{ver}.win.x64/"
    tree = {}
    with zipfile.ZipFile(zp) as z:
        for rel in clamav_allowlist(z.namelist(), prefix):
            tree[rel.lower()] = hashlib.sha256(z.read(prefix + rel)).hexdigest()
    h = hashlib.sha256()
    with open(zp, "rb") as f:
        while c := f.read(4 << 20):
            h.update(c)
    manifest = {
        "serial": a.serial, "issued": time.strftime("%Y-%m-%d"),
        "revoked": {"versions": [], "sha256": []},
        "components": {
            "clamav": {
                "title": "ClamAV (2ª opinião de antivírus)", "required": "recommended", "version": ver, "min_version": "1.4.6",
                "purpose": "Antivírus de código aberto (Cisco Talos) com assinaturas INDEPENDENTES das do Defender. Dá uma 2ª opinião sobre arquivos nas pastas de risco.",
                "download_page": "https://www.clamav.net/downloads",
                "instructions": [
                    "Abra a página oficial de downloads do ClamAV (botão abaixo).",
                    f"Baixe o ZIP \"clamav-{ver}.win.x64.zip\" (Windows, 64 bits, ~215 MB) e o arquivo de assinatura ao lado dele, \"clamav-{ver}.win.x64.zip.sig\".",
                    "Salve os DOIS na mesma pasta (por exemplo, Downloads). Não precisa extrair nem instalar nada.",
                    "Volte ao Sentinela, clique em \"Importar pacote…\" e escolha o ZIP. O Sentinela confere a assinatura, o hash e cada arquivo antes de usar.",
                ],
                "archive": {
                    "name": zp.name, "size": zp.stat().st_size, "sha256": h.hexdigest(), "zip_prefix": prefix,
                    "url": f"https://www.clamav.net/downloads/production/{zp.name}",
                    "sig_url": f"https://www.clamav.net/downloads/production/{zp.name}.sig",
                    "gpg_fingerprint": TALOS_FPR, "allow_sha1": True,   # a Talos ainda assina com SHA-1; por isso o SHA-256 acima também é pinado
                },
                "tree": tree,
                "exes": {"scan": "clamscan.exe", "update": "freshclam.exe", "sigtool": "sigtool.exe"},
            }
        },
    }
    print("arquivos na árvore:", len(tree))
    sign_and_write(manifest, load_key(Path(a.key_file), a.dev))


if __name__ == "__main__":
    main()
