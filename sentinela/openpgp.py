"""Verificador MÍNIMO de assinatura destacada OpenPGP (RFC 4880, assinaturas v4 de RSA), só para conferir componentes de terceiros.

Escopo deliberadamente pequeno (superfície de ataque pequena e auditável):
  * a chave pública é aceita SOMENTE se o fingerprint (SHA-1 do pacote, v4) for igual ao fingerprint PINADO pelo Sentinela;
  * só RSA com PKCS#1 v1.5 (o que a Talos/ClamAV usa); outros algoritmos são recusados, nunca ignorados;
  * SHA-256/384/512 sempre aceitos; SHA-1 só quando o chamador permite explicitamente (e o manifesto deve pinar também o SHA-256 do arquivo);
  * chave expirada, assinatura datada do futuro, assinatura feita fora da validade da chave, ou "issuer" diferente => falha.
Nunca lança exceção para entrada malformada: devolve (False, motivo). O motivo é texto fixo (não repete bytes do arquivo).
"""
from __future__ import annotations

import base64
import hashlib
import re
import struct
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

HASHES = {8: ("SHA256", hashes.SHA256, hashlib.sha256), 9: ("SHA384", hashes.SHA384, hashlib.sha384),
          10: ("SHA512", hashes.SHA512, hashlib.sha512), 2: ("SHA1", hashes.SHA1, hashlib.sha1)}
MAX_PACKET = 1 << 20
CLOCK_SKEW = 24 * 3600


class PgpError(Exception):
    pass


def dearmor(data: bytes) -> bytes:
    """Aceita blocos ASCII-armored ou binários. Confere o CRC24 quando presente."""
    if not data.lstrip().startswith(b"-----BEGIN PGP"):
        return data
    lines = data.decode("ascii", "ignore").splitlines()
    try:
        start = next(k for k, l in enumerate(lines) if l.startswith("-----BEGIN PGP "))
        end = next(k for k in range(start + 1, len(lines)) if lines[k].startswith("-----END PGP "))
    except StopIteration:
        raise PgpError("bloco ASCII-armored inválido")
    body_lines = lines[start + 1:end]
    if "" in body_lines:  # cabeçalhos (Version:, Comment:) terminam na primeira linha em branco
        body_lines = body_lines[body_lines.index("") + 1:]
    crc_line = None
    if body_lines and body_lines[-1].startswith("="):
        crc_line = body_lines.pop()
    body = "".join(l.strip() for l in body_lines)
    try:
        raw = base64.b64decode(body, validate=True)
    except ValueError:
        raise PgpError("base64 inválido")
    if crc_line:
        crc = 0xB704CE
        for byte in raw:
            crc ^= byte << 16
            for _ in range(8):
                crc <<= 1
                if crc & 0x1000000:
                    crc ^= 0x1864CFB
        try:
            want = base64.b64decode(crc_line[1:], validate=True)
        except ValueError:
            raise PgpError("CRC inválido")
        if (crc & 0xFFFFFF).to_bytes(3, "big") != want:
            raise PgpError("CRC do bloco não confere")
    return raw


def packets(data: bytes):
    """Gera (tag, corpo) de cada pacote. Só formatos de comprimento definido (os usados em chaves e assinaturas)."""
    i, n = 0, len(data)
    while i < n:
        ctb = data[i]
        if not ctb & 0x80:
            raise PgpError("pacote inválido")
        i += 1
        if ctb & 0x40:  # novo formato
            tag = ctb & 0x3F
            if i >= n:
                raise PgpError("pacote truncado")
            l0 = data[i]
            i += 1
            if l0 < 192:
                ln = l0
            elif l0 < 224:
                if i >= n:
                    raise PgpError("pacote truncado")
                ln = ((l0 - 192) << 8) + data[i] + 192
                i += 1
            elif l0 == 255:
                if i + 4 > n:
                    raise PgpError("pacote truncado")
                ln = struct.unpack(">I", data[i:i + 4])[0]
                i += 4
            else:
                raise PgpError("comprimento parcial não suportado")
        else:  # formato antigo
            tag = (ctb >> 2) & 0x0F
            lt = ctb & 3
            size = {0: 1, 1: 2, 2: 4}.get(lt)
            if size is None or i + size > n:
                raise PgpError("comprimento indefinido não suportado")
            ln = int.from_bytes(data[i:i + size], "big")
            i += size
        if ln > MAX_PACKET or i + ln > n:
            raise PgpError("pacote grande demais ou truncado")
        yield tag, data[i:i + ln]
        i += ln


def _mpi(buf: bytes, i: int) -> tuple[int, int]:
    if i + 2 > len(buf):
        raise PgpError("MPI truncado")
    bits = struct.unpack(">H", buf[i:i + 2])[0]
    ln = (bits + 7) // 8
    if i + 2 + ln > len(buf) or ln == 0 or ln > 1024:
        raise PgpError("MPI inválido")
    return int.from_bytes(buf[i + 2:i + 2 + ln], "big"), i + 2 + ln


def subpackets(area: bytes):
    i = 0
    while i < len(area):
        l0 = area[i]
        i += 1
        if l0 < 192:
            ln = l0
        elif l0 < 255:
            if i >= len(area):
                raise PgpError("subpacote truncado")
            ln = ((l0 - 192) << 8) + area[i] + 192
            i += 1
        else:
            if i + 4 > len(area):
                raise PgpError("subpacote truncado")
            ln = struct.unpack(">I", area[i:i + 4])[0]
            i += 4
        if ln < 1 or i + ln > len(area):
            raise PgpError("subpacote inválido")
        yield area[i] & 0x7F, area[i + 1:i + ln]
        i += ln


@dataclass
class Signature:
    sigtype: int
    pubalgo: int
    hashalgo: int
    hashed: bytes          # área hasheada de subpacotes
    header: bytes          # versão..área hasheada (entra no hash)
    created: int
    key_expires: int | None
    issuer_keyid: bytes | None
    issuer_fpr: bytes | None
    digest_prefix: bytes
    value: int


def parse_signature(body: bytes) -> Signature:
    if len(body) < 10 or body[0] != 4:
        raise PgpError("só assinaturas v4 são suportadas")
    sigtype, pubalgo, hashalgo = body[1], body[2], body[3]
    hl = struct.unpack(">H", body[4:6])[0]
    if 6 + hl + 2 > len(body):
        raise PgpError("assinatura truncada")
    hashed = body[6:6 + hl]
    ul = struct.unpack(">H", body[6 + hl:8 + hl])[0]
    unhashed = body[8 + hl:8 + hl + ul]
    j = 8 + hl + ul
    if j + 2 > len(body):
        raise PgpError("assinatura truncada")
    prefix = body[j:j + 2]
    value, end = _mpi(body, j + 2)
    created = key_exp = None
    keyid = fpr = None
    for area, is_hashed in ((hashed, True), (unhashed, False)):
        for typ, data in subpackets(area):
            if typ == 2 and is_hashed and len(data) == 4:
                created = struct.unpack(">I", data)[0]
            elif typ == 9 and is_hashed and len(data) == 4:
                key_exp = struct.unpack(">I", data)[0]
            elif typ == 16 and len(data) == 8:
                keyid = data
            elif typ == 33 and is_hashed and len(data) == 21 and data[0] == 4:
                fpr = data[1:]
    if created is None:
        raise PgpError("assinatura sem data")
    return Signature(sigtype, pubalgo, hashalgo, hashed, body[:6 + hl], created, key_exp, keyid, fpr, prefix, value)


@dataclass
class PublicKey:
    fingerprint: bytes
    keyid: bytes
    n: int
    e: int
    created: int
    expires: int | None   # epoch absoluto, ou None se a chave não expira


def load_primary_key(armored_or_binary: bytes, pinned_fingerprint: str) -> PublicKey:
    """Lê a chave PRIMÁRIA e só a aceita se o fingerprint for exatamente o pinado."""
    want = re.sub(r"\s+", "", pinned_fingerprint).upper()
    if not re.fullmatch(r"[0-9A-F]{40}", want):
        raise PgpError("fingerprint pinado inválido")
    raw = dearmor(armored_or_binary)
    pk = None
    selfsig_exp = None
    it = list(packets(raw))
    for idx, (tag, body) in enumerate(it):
        if tag == 6 and pk is None:
            if len(body) < 6 or body[0] != 4:
                raise PgpError("só chaves v4 são suportadas")
            created = struct.unpack(">I", body[1:5])[0]
            if body[5] != 1:
                raise PgpError("só chaves RSA são suportadas")
            n, i = _mpi(body, 6)
            e, i = _mpi(body, i)
            if n.bit_length() < 2048 or e < 3 or e % 2 == 0:
                raise PgpError("chave RSA fraca ou inválida")
            fpr = hashlib.sha1(b"\x99" + struct.pack(">H", len(body)) + body).digest()
            if fpr.hex().upper() != want:
                raise PgpError("o fingerprint da chave NÃO é o pinado pelo Sentinela")
            pk = PublicKey(fpr, fpr[-8:], n, e, created, None)
        elif tag == 2 and pk is not None and selfsig_exp is None:
            try:
                sg = parse_signature(body)
            except PgpError:
                continue
            if sg.sigtype in (0x10, 0x11, 0x12, 0x13, 0x1F) and sg.issuer_keyid in (None, pk.keyid) and sg.key_expires is not None:
                selfsig_exp = sg.key_expires
    if pk is None:
        raise PgpError("nenhuma chave pública encontrada")
    if selfsig_exp:
        pk.expires = pk.created + selfsig_exp
    return pk


def _verify_rsa(pk: PublicKey, sig: Signature, digest: bytes, hashcls) -> bool:
    key = RSAPublicNumbers(pk.e, pk.n).public_key()
    k = (pk.n.bit_length() + 7) // 8
    try:
        key.verify(sig.value.to_bytes(k, "big"), digest, padding.PKCS1v15(), utils.Prehashed(hashcls()))
        return True
    except (InvalidSignature, ValueError, OverflowError):
        return False


def verify_detached(data_path: str | Path, sig_bytes: bytes, key_bytes: bytes, pinned_fingerprint: str,
                    allow_sha1: bool = False, now: float | None = None) -> tuple[bool, str]:
    """Confere a assinatura destacada de `data_path`. Devolve (ok, motivo). Nunca lança por entrada malformada."""
    now = time.time() if now is None else now
    try:
        pk = load_primary_key(key_bytes, pinned_fingerprint)
        pk_list = [b for t, b in packets(dearmor(sig_bytes)) if t == 2]
        if len(pk_list) != 1:
            return False, "o arquivo .sig deve ter exatamente uma assinatura"
        sig = parse_signature(pk_list[0])
        if sig.pubalgo != 1:
            return False, "algoritmo de assinatura não suportado (só RSA)"
        if sig.sigtype not in (0x00, 0x01):
            return False, "tipo de assinatura inesperado"
        h = HASHES.get(sig.hashalgo)
        if not h:
            return False, "algoritmo de hash não suportado"
        if h[0] == "SHA1" and not allow_sha1:
            return False, "assinatura com SHA-1 recusada pela política"
        if sig.issuer_fpr is not None and sig.issuer_fpr != pk.fingerprint:
            return False, "a assinatura declara outra chave"
        if sig.issuer_keyid is not None and sig.issuer_keyid != pk.keyid:
            return False, "a assinatura foi feita por outra chave"
        if sig.issuer_keyid is None and sig.issuer_fpr is None:
            return False, "a assinatura não identifica o signatário"
        if sig.created > now + CLOCK_SKEW:
            return False, "assinatura datada do futuro"
        if sig.created < pk.created:
            return False, "assinatura anterior à criação da chave"
        if pk.expires is not None and (now > pk.expires or sig.created > pk.expires):
            return False, "a chave de assinatura expirou (chave pode ter sido rotacionada: atualize o manifesto do Sentinela)"
        hasher = h[2]()
        with open(data_path, "rb") as f:
            while chunk := f.read(4 << 20):
                hasher.update(chunk)
        hasher.update(sig.header)
        hasher.update(b"\x04\xff" + struct.pack(">I", len(sig.header)))
        digest = hasher.digest()
        if digest[:2] != sig.digest_prefix:
            return False, "assinatura NÃO confere com o arquivo"
        if not _verify_rsa(pk, sig, digest, h[1]):
            return False, "assinatura NÃO confere com o arquivo"
        return True, "assinatura válida (" + h[0] + ")"
    except PgpError as e:
        return False, "assinatura/chave malformada: " + str(e)
    except OSError:
        return False, "não foi possível ler o arquivo"
    except Exception:  # noqa: BLE001  entrada hostil nunca derruba o app
        return False, "falha inesperada ao verificar a assinatura"
