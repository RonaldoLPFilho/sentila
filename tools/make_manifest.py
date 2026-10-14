"""Gera e assina sentinela/manifest.json (lista de componentes de terceiros). Uso (do mantenedor, NUNCA em máquina de usuário):

    python tools\\make_manifest.py --zip <clamav-x.y.z.win.x64.zip> --sig <.sig> --serial 2

A chave privada Ed25519 fica FORA do repositório (padrão: %USERPROFILE%\\.sentinela-keys\\manifest_ed25519.pem; em produção, chave offline
guardada em hardware/cofre). A chave pública impressa deve ser colocada em MANIFEST_PUBKEYS (sentinela/components.py).
O arquivo .sig GPG do pacote só é conferido aqui com o verificador do próprio Sentinela (fingerprint pinado abaixo)."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from sentinela import openpgp  # noqa: E402
from sentinela.components import canonical  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TALOS_FPR = "5BADCA2665EF59DCF8A23D8B707F0DB480836771"   # conferido em 3 fontes: clamav.net, keys.openpgp.org e GitHub Cisco-Talos/clamav-documentation
KEY_PATH = Path(os.environ.get("SENT_MANIFEST_KEY", Path.home() / ".sentinela-keys" / "manifest_ed25519.pem"))


def load_or_create_key() -> Ed25519PrivateKey:
    if KEY_PATH.exists():
        return serialization.load_pem_private_key(KEY_PATH.read_bytes(), None)
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    k = Ed25519PrivateKey.generate()
    KEY_PATH.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    print(f"[!] chave NOVA criada em {KEY_PATH} (guarde; em produção use uma chave offline)")
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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip", required=True)
    ap.add_argument("--sig", required=True)
    ap.add_argument("--key", default=str(ROOT / "tests" / "fixtures" / "talos_clamav_key.asc"))
    ap.add_argument("--serial", type=int, required=True)
    a = ap.parse_args()
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
        "serial": a.serial, "issued": "2026-10-13",
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
    mb = canonical(manifest)
    k = load_or_create_key()
    (ROOT / "sentinela" / "manifest.json").write_bytes(mb)
    (ROOT / "sentinela" / "manifest.sig").write_bytes(base64.b64encode(k.sign(mb)))
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    print("arquivos na árvore:", len(tree), "| serial", a.serial)
    print("CHAVE PÚBLICA para MANIFEST_PUBKEYS:", base64.b64encode(pub).decode())


if __name__ == "__main__":
    main()
