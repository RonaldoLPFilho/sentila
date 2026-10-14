"""Componentes de terceiros (ClamAV…): manifesto assinado, instalação verificada, detecção e execução a partir de uma cópia privada.

Nada de terceiros vai no instalador do Sentinela. O app só EXECUTA um componente depois de:
  1. o manifesto (lista de componentes, versões mínimas, hashes, revogações) ter assinatura Ed25519 válida de uma chave embutida no app
     e `serial` >= o maior já visto neste PC (impede voltar a um manifesto antigo);
  2. o pacote baixado ter assinatura GPG com fingerprint PINADO no manifesto (quando a fonte publica GPG) E o SHA-256 igual ao do manifesto;
  3. a árvore de arquivos ser EXATAMENTE a do manifesto (todo arquivo com o SHA-256 certo e nenhum arquivo a mais, p.ex. uma DLL plantada);
  4. a versão não estar revogada nem abaixo do piso;
  5. a execução ocorrer numa CÓPIA PRIVADA (pasta nova com ACL só do usuário), re-verificada, com os arquivos mantidos abertos sem
     permissão de escrita/exclusão enquanto o processo roda (fecha a troca entre a verificação e a execução).
Limite assumido (documentado): malware que já roda como o MESMO usuário pode alterar o próprio Sentinela; o modelo de ameaça é o malware
que chega depois e ainda não persistiu.
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import time
import winreg
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import openpgp
from .checks import CREATE_NO_WINDOW
from .config import DATA_DIR

COMP_DIR = DATA_DIR / "componentes"
RUN_DIR = DATA_DIR / "run"
BUNDLED_MANIFEST = Path(__file__).with_name("manifest.json")
BUNDLED_SIG = Path(__file__).with_name("manifest.sig")
# Chaves de assinatura do manifesto (Ed25519, base64 da chave pública crua). Duas posições: a atual e a próxima (rotação).
MANIFEST_PUBKEYS = [
    "Eh/2pS4TeOWDWwXux2sUhoF5826174RxuEUoIkTMi3M=",   # chave de DESENVOLVIMENTO (a de release deve ser offline e substituir esta)
]
SERIAL_KEY = r"Software\Sentinela"
MIN_SERIAL = 1   # piso NO CÓDIGO: apagar/baixar o serial do registro não reabre manifestos mais antigos que este (suba a cada release)
MAX_MANIFEST = 1 << 20

# estados mostrados na tela Componentes
OK, OUTDATED, UNTRUSTED, MISSING, UNREADABLE, REVOKED = "ok", "outdated", "untrusted", "missing", "unreadable", "revoked"


class ComponentError(Exception):
    pass


# ---------------------------------------------------------------- manifesto

def _ver(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", str(v)))


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load_serial() -> int:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, SERIAL_KEY) as k:
            return int(winreg.QueryValueEx(k, "manifest_serial")[0])
    except (OSError, ValueError, TypeError):
        return 0


def save_serial(n: int) -> None:
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, SERIAL_KEY) as k:
            winreg.SetValueEx(k, "manifest_serial", 0, winreg.REG_DWORD, int(n))
    except OSError:
        pass


def verify_manifest(manifest_bytes: bytes, sig_b64: bytes, pubkeys: list[str] | None = None, min_serial: int | None = None) -> dict:
    """Devolve o manifesto (dict) se a assinatura for válida e o serial não regredir; senão lança ComponentError."""
    if len(manifest_bytes) > MAX_MANIFEST:
        raise ComponentError("manifesto grande demais")
    keys = MANIFEST_PUBKEYS if pubkeys is None else pubkeys
    try:
        sig = base64.b64decode(sig_b64.strip(), validate=True)
        obj = json.loads(manifest_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ComponentError("manifesto ilegível")
    if not isinstance(obj, dict) or not isinstance(obj.get("serial"), int) or not isinstance(obj.get("components"), dict):
        raise ComponentError("manifesto malformado")
    good = False
    for pk in keys:
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(pk, validate=True)).verify(sig, manifest_bytes)
            good = True
            break
        except (InvalidSignature, ValueError):
            continue
    if not good:
        raise ComponentError("assinatura do manifesto inválida")
    floor = max(load_serial(), MIN_SERIAL) if min_serial is None else min_serial
    if obj["serial"] < floor:
        raise ComponentError("manifesto mais antigo que o já visto neste PC (possível rollback)")
    return obj


def load_bundled_manifest(save: bool = True) -> dict:
    mb = BUNDLED_MANIFEST.read_bytes()
    obj = verify_manifest(mb, BUNDLED_SIG.read_bytes())
    if save and obj["serial"] > load_serial():
        save_serial(obj["serial"])
    return obj


def is_revoked(manifest: dict, version: str, sha256: str = "") -> bool:
    rev = manifest.get("revoked") or {}
    return (sha256 and sha256.lower() in {str(x).lower() for x in rev.get("sha256", [])}) or version in {str(x) for x in rev.get("versions", [])}


# ---------------------------------------------------------------- hash e árvore

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(4 << 20):
            h.update(chunk)
    return h.hexdigest()


def tree_listing(root: Path) -> dict[str, str]:
    """relpath(posix, minúsculo) -> sha256 de TODOS os arquivos sob root. Recusa reparse points/links."""
    out: dict[str, str] = {}
    for dirpath, dirs, files in os.walk(root, followlinks=False):
        for name in list(dirs) + files:
            full = Path(dirpath) / name
            if full.is_symlink() or _is_reparse(full):
                raise ComponentError("o componente contém link/junction: recusado")
        for f in files:
            full = Path(dirpath) / f
            out[full.relative_to(root).as_posix().lower()] = sha256_file(full)
    return out


def _is_reparse(p: Path) -> bool:
    try:
        return bool(os.lstat(p).st_file_attributes & 0x400)
    except (OSError, AttributeError):
        return False


def tree_matches(root: Path, expected: dict[str, str]) -> tuple[bool, str]:
    exp = {k.lower(): v.lower() for k, v in expected.items()}
    try:
        got = tree_listing(root)
    except (ComponentError, OSError) as e:
        return False, str(e) or "não foi possível ler o componente"
    extra = sorted(set(got) - set(exp))
    missing = sorted(set(exp) - set(got))
    bad = sorted(k for k in exp if k in got and got[k] != exp[k])
    if extra:
        return False, f"arquivo(s) a mais no componente (ex.: {extra[0]})"
    if missing:
        return False, f"arquivo(s) faltando (ex.: {missing[0]})"
    if bad:
        return False, f"arquivo alterado (ex.: {bad[0]})"
    return True, "árvore confere com o manifesto"


# ---------------------------------------------------------------- instalação a partir de um pacote baixado pelo usuário

def verify_package(spec: dict, archive: Path, sig: bytes, key_bytes: bytes, manifest: dict) -> tuple[bool, str]:
    """spec = manifest['components'][nome]['archive']. Confere tamanho, SHA-256 do manifesto, GPG com fingerprint pinado e revogação."""
    try:
        if archive.stat().st_size != int(spec["size"]):
            return False, "o tamanho do arquivo não é o esperado"
        digest = sha256_file(archive)
        if digest != str(spec["sha256"]).lower():
            return False, "o SHA-256 do arquivo não é o do manifesto (arquivo errado, corrompido ou adulterado)"
        if is_revoked(manifest, "", digest):
            return False, "este arquivo foi revogado"
        ok, msg = openpgp.verify_detached(archive, sig, key_bytes, spec["gpg_fingerprint"], allow_sha1=bool(spec.get("allow_sha1")))
        return ok, msg
    except (KeyError, ValueError, OSError):
        return False, "não foi possível verificar o pacote"


def _safe_member(name: str, prefix: str, allow: set[str]) -> str | None:
    n = name.replace(chr(92), "/")
    if n.startswith("/") or ".." in n.split("/") or ":" in n:
        return None
    if prefix and n.startswith(prefix):
        n = n[len(prefix):]
    return n if n.lower() in allow else None


def install_package(name: str, comp: dict, archive: Path, sig: bytes, key_bytes: bytes, manifest: dict, status=lambda m: None) -> Path:
    """Verifica o pacote e extrai SÓ os arquivos da lista do manifesto para COMP_DIR/<nome>/<versão>. Lança ComponentError se algo falhar."""
    import zipfile
    spec = comp["archive"]
    version = str(comp["version"])
    if is_revoked(manifest, version):
        raise ComponentError("esta versão do componente foi revogada")
    if _ver(version) < _ver(str(comp.get("min_version", "0"))):
        raise ComponentError("versão abaixo do mínimo exigido")
    status("Verificando a assinatura GPG e o hash do pacote…")
    ok, msg = verify_package(spec, archive, sig, key_bytes, manifest)
    if not ok:
        raise ComponentError(msg)
    tree = {k.lower(): v.lower() for k, v in comp["tree"].items()}
    dest = COMP_DIR / name / version
    tmp = COMP_DIR / name / f".novo-{secrets.token_hex(6)}"
    prefix = str(spec.get("zip_prefix", ""))
    tmp.mkdir(parents=True, exist_ok=False)
    try:
        status("Extraindo somente os arquivos esperados…")
        done = set()
        with zipfile.ZipFile(archive) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                rel = _safe_member(info.filename, prefix, set(tree))
                if rel is None:
                    continue
                if info.file_size > (1 << 30):
                    raise ComponentError("arquivo interno grande demais")
                target = tmp / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                with z.open(info) as src, open(target, "xb") as out:
                    shutil.copyfileobj(src, out, 1 << 20)
                done.add(rel.lower())
        if done != set(tree):
            raise ComponentError("o pacote não contém todos os arquivos esperados")
        status("Conferindo cada arquivo extraído…")
        ok, msg = tree_matches(tmp, tree)
        if not ok:
            raise ComponentError(msg)
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp.rename(dest)
        return dest
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


# ---------------------------------------------------------------- detecção (checkbox automático)

@dataclass
class Status:
    name: str
    state: str                    # ok | outdated | untrusted | missing | unreadable | revoked
    version: str = ""
    path: Path | None = None
    detail: str = ""
    required: str = "optional"


def detect(name: str, comp: dict, manifest: dict, extra_dirs: list[str] | None = None) -> Status:
    """Procura o componente na pasta do app (e em pastas que o usuário apontou) e valida a árvore inteira contra o manifesto."""
    required = str(comp.get("required", "optional"))
    tree = comp.get("tree") or {}
    cands: list[Path] = []
    base = COMP_DIR / name
    if base.is_dir():
        cands += sorted([p for p in base.iterdir() if p.is_dir() and not p.name.startswith(".")], key=lambda p: _ver(p.name), reverse=True)
    for d in extra_dirs or []:
        p = Path(d)
        if p.is_dir():
            cands.append(p)
    if not cands:
        return Status(name, MISSING, detail="Não instalado.", required=required)
    last = ""
    for p in cands:
        ok, msg = tree_matches(p, tree)
        if not ok:
            last = msg
            continue
        ver = p.name if re.match(r"^\d", p.name) else str(comp.get("version", ""))
        if is_revoked(manifest, ver):
            return Status(name, REVOKED, ver, p, "Esta versão foi revogada: instale uma versão atual.", required)
        if _ver(ver) < _ver(str(comp.get("min_version", "0"))):
            return Status(name, OUTDATED, ver, p, f"Versão {ver} abaixo da mínima ({comp.get('min_version')}).", required)
        if _ver(ver) < _ver(str(comp.get("version", "0"))):
            return Status(name, OUTDATED, ver, p, f"Há versão mais nova ({comp.get('version')}).", required)
        return Status(name, OK, ver, p, "Instalado e verificado.", required)
    return Status(name, UNTRUSTED, detail="Encontrado, mas NÃO confiável: " + last, required=required)


# ---------------------------------------------------------------- execução a partir de cópia privada com arquivos travados

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.CreateFileW.restype = ctypes.c_void_p
_k32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
_k32.CloseHandle.argtypes = [ctypes.c_void_p]
GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL = 0x80000000, 1, 3, 0x80
INVALID = ctypes.c_void_p(-1).value


def _private_dir() -> Path:
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    d = RUN_DIR / secrets.token_hex(8)
    d.mkdir()
    user = os.environ.get("USERNAME", "")
    # remove a herança e deixa só o usuário atual com controle total
    subprocess.run(["icacls", str(d), "/inheritance:r", "/grant:r", f"{user}:(OI)(CI)F"], capture_output=True, creationflags=CREATE_NO_WINDOW)
    return d


class PinnedRun:
    """Cópia privada de um componente já verificado, com cada arquivo aberto SEM FILE_SHARE_WRITE/DELETE até o fim (with ... as run)."""

    def __init__(self, status: Status, comp: dict) -> None:
        if status.state != OK or status.path is None:
            raise ComponentError("o componente não está instalado e verificado")
        self.src, self.comp, self.dir = status.path, comp, None
        self._handles: list[int] = []

    def __enter__(self) -> "PinnedRun":
        self.dir = _private_dir()
        try:
            shutil.copytree(self.src, self.dir, dirs_exist_ok=True)
            for f in self.dir.rglob("*"):
                if f.is_file():
                    h = _k32.CreateFileW(str(f), GENERIC_READ, FILE_SHARE_READ, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
                    if h in (None, INVALID):
                        raise ComponentError("não foi possível travar um arquivo do componente")
                    self._handles.append(h)
            ok, msg = tree_matches(self.dir, self.comp["tree"])   # re-verifica a cópia JÁ travada
            if not ok:
                raise ComponentError("a cópia privada não confere: " + msg)
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def verify_names(self) -> tuple[bool, str]:
        """Barato (sem hash): a lista de nomes da pasta privada continua igual à do manifesto (nenhum arquivo novo plantado)."""
        try:
            got = {f.relative_to(self.dir).as_posix().lower() for f in Path(self.dir).rglob("*") if f.is_file()}
            got = {g for g in got if not g.startswith(".work/")}   # arquivos de trabalho do próprio app (listas, configuração)
        except OSError:
            return False, "pasta ilegível"
        exp = {k.lower() for k in self.comp["tree"]}
        extra = sorted(got - exp)
        if extra:
            return False, "arquivo novo: " + extra[0]
        return True, ""

    def exe(self, rel: str) -> str:
        p = (self.dir / rel).resolve()
        if self.dir.resolve() not in p.parents:
            raise ComponentError("caminho fora do componente")
        return str(p)

    def __exit__(self, *a) -> None:
        for h in self._handles:
            _k32.CloseHandle(ctypes.c_void_p(h))
        self._handles.clear()
        if self.dir:
            for _ in range(8):          # o processo recém-encerrado pode levar um instante para soltar os arquivos
                shutil.rmtree(self.dir, ignore_errors=True)
                if not Path(self.dir).exists():
                    break
                time.sleep(0.5)


def purge_stale_runs(max_age: float = 3600) -> None:
    try:
        for d in RUN_DIR.iterdir():
            if d.is_dir() and time.time() - d.stat().st_mtime > max_age:
                shutil.rmtree(d, ignore_errors=True)
    except OSError:
        pass
