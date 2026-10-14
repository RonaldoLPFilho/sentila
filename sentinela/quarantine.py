"""Quarentena REVERSÍVEL. Nunca exclui permanentemente. Regras (da revisão de segurança):
  * proibido: Windows, Program Files, ProgramData\\Microsoft, pastas do próprio Sentinela, arquivo com assinatura Microsoft válida,
    unidade de rede, placeholder de nuvem, qualquer caminho que atravesse junction/symlink, arquivo em uso por um processo;
  * identidade conferida (ID do arquivo + tamanho + SHA-256 antes e depois); o cofre usa ACL só do usuário, nome = GUID e extensão neutra;
  * restaurar NUNCA sobrescreve (cria nome novo) e recusa destino que atravessa link."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import shutil
import subprocess
import time
from pathlib import Path

import psutil

from . import procscan as ps
from .checks import CREATE_NO_WINDOW, dn_fields, hash_file, verify_signatures
from .config import DATA_DIR, _dpapi

Q_DIR = DATA_DIR / "quarentena"
MAX_PER_ACTION = 20          # no máximo N arquivos movidos em 10 minutos (um falso positivo não esvazia o PC)
RATE_WINDOW = 600
ATTR_REPARSE, ATTR_OFFLINE, ATTR_RECALL_OPEN, ATTR_RECALL_DATA = 0x400, 0x1000, 0x40000, 0x400000


class QuarantineError(Exception):
    pass


def _index_path() -> Path:
    return Q_DIR / "index.json"


def _mac_key() -> bytes:
    kf = Q_DIR / "index.key"
    try:
        return _dpapi(kf.read_bytes(), protect=False)
    except (OSError, ValueError):
        pass
    Q_DIR.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    kf.write_bytes(_dpapi(key, protect=True))
    return key


def _mac(entries: dict) -> str:
    return hmac.new(_mac_key(), json.dumps(entries, sort_keys=True, ensure_ascii=False).encode("utf-8"), hashlib.sha256).hexdigest()


def _load() -> dict:
    """Entradas do índice. Se o arquivo foi editado (MAC não confere), devolve {}: nada é restaurado a partir de um índice adulterado."""
    try:
        d = json.loads(_index_path().read_text(encoding="utf-8"))
        ents = d.get("entries") if isinstance(d, dict) else None
        if not isinstance(ents, dict) or not hmac.compare_digest(str(d.get("mac", "")), _mac(ents)):
            return {}
        return ents
    except (OSError, ValueError):
        return {}


def _save(ents: dict) -> None:
    Q_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _index_path().with_suffix(".tmp")
    tmp.write_text(json.dumps({"entries": ents, "mac": _mac(ents)}, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, _index_path())


def _vault() -> Path:
    first = not Q_DIR.exists()
    Q_DIR.mkdir(parents=True, exist_ok=True)
    if first:
        user = os.environ.get("USERNAME", "")
        subprocess.run(["icacls", str(Q_DIR), "/inheritance:r", "/grant:r", f"{user}:(OI)(CI)F"], capture_output=True, creationflags=CREATE_NO_WINDOW)
    return Q_DIR


def _attrs(p: str) -> int:
    return getattr(os.lstat(p), "st_file_attributes", 0)


def path_has_reparse(path: str) -> bool:
    """True se o arquivo ou QUALQUER pasta acima dele é junction/symlink."""
    p = Path(path)
    for part in [p, *p.parents]:
        try:
            if part.is_symlink() or (_attrs(str(part)) & ATTR_REPARSE):
                return True
        except OSError:
            continue
    return False


_FORBIDDEN = [os.environ.get("SystemRoot", r"C:\Windows"), os.environ.get("ProgramFiles", r"C:\Program Files"), os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
              os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Microsoft"), str(DATA_DIR)]


def can_quarantine(path: str, sig: dict | None = None) -> tuple[bool, str]:
    """(ok, motivo da recusa). Não modifica nada."""
    try:
        p = os.path.abspath(path)
        if not os.path.isfile(p):
            return False, "O arquivo não existe mais."
        n = ps.norm_path(p)
        for f in _FORBIDDEN:
            if f and (n == ps.norm_path(f) or n.startswith(ps.norm_path(f) + chr(92))):
                return False, "Arquivos do Windows, de Program Files e do próprio Sentinela não podem ser movidos."
        if ps.path_kind(p) != "local":
            return False, "Só arquivos em discos fixos locais podem ser movidos (não rede nem mídia removível)."
        if path_has_reparse(p):
            return False, "O caminho passa por um atalho de pasta (junction/link): recusado por segurança."
        if _attrs(p) & (ATTR_OFFLINE | ATTR_RECALL_OPEN | ATTR_RECALL_DATA):
            return False, "O arquivo está só na nuvem (OneDrive): não será baixado."
        for pr in psutil.process_iter(["exe"]):
            try:
                if pr.info.get("exe") and ps.norm_path(pr.info["exe"]) == n:
                    return False, "O programa está em execução. Encerre o processo antes (aba Processos)."
            except psutil.Error:
                continue
        s = sig if sig is not None else verify_signatures([p]).get(p)
        pr_ = ps.Proc(pid=0, name=os.path.basename(p), exe=p)
        pr_.sig = s
        if ps.sig_state(pr_) == "ms" or (s and s.get("status") == "Valid" and dn_fields(s.get("subject", "")).get("O") == "Microsoft Corporation"):
            return False, "O arquivo tem assinatura válida da Microsoft."
        return True, ""
    except OSError as e:
        return False, f"Não foi possível verificar o arquivo ({e.__class__.__name__})."


def _lock_acl(path: Path) -> None:
    user = os.environ.get("USERNAME", "")
    subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"], capture_output=True, creationflags=CREATE_NO_WINDOW)


def quarantine(path: str, reason: str = "", sig: dict | None = None, expected_sha256: str = "") -> dict:
    """Move para o cofre. `expected_sha256` (o hash visto na varredura) impede mover um arquivo que foi trocado depois."""
    ok, why = can_quarantine(path, sig)
    if not ok:
        raise QuarantineError(why)
    recent = [e for e in entries() if time.time() - e.get("when", 0) < RATE_WINDOW]
    if len(recent) >= MAX_PER_ACTION:
        raise QuarantineError(f"Limite de {MAX_PER_ACTION} arquivos em 10 minutos atingido. Revise os achados antes de mover mais (um falso positivo não deve esvaziar o PC).")
    p = os.path.abspath(path)
    st0 = os.stat(p)
    h0 = hash_file(Path(p))["sha256"]
    st1 = os.stat(p)
    if (st0.st_ino, st0.st_size, st0.st_mtime_ns) != (st1.st_ino, st1.st_size, st1.st_mtime_ns):
        raise QuarantineError("O arquivo mudou enquanto era conferido. Tente de novo.")
    if expected_sha256 and h0.lower() != expected_sha256.lower():
        raise QuarantineError("O arquivo é diferente do que foi analisado (o conteúdo mudou desde a verificação). Verifique de novo.")
    vault = _vault()
    qid = secrets.token_hex(16)
    dest = vault / (qid + ".bin")
    # diário: a entrada existe ANTES de mover (se algo falhar depois, o arquivo no cofre continua restaurável)
    idx = _load()
    idx[qid] = {"original": p, "sha256": h0, "size": st0.st_size, "mtime": st0.st_mtime, "when": time.time(), "reason": ps.clean_text(reason, 300), "state": "pending"}
    _save(idx)
    try:
        shutil.move(p, dest)
    except OSError as e:
        idx = _load()
        if not dest.exists():
            idx.pop(qid, None)
            _save(idx)
            raise QuarantineError(f"Não foi possível mover o arquivo ({e.__class__.__name__}).")
        raise QuarantineError("O movimento foi interrompido; o arquivo está no cofre e pode ser restaurado em Quarentena.")
    _lock_acl(dest)
    if hash_file(dest)["sha256"] != h0:
        raise QuarantineError("O arquivo movido não confere com o original: ele está no cofre e pode ser restaurado em Quarentena.")
    idx = _load()
    if qid in idx:
        idx[qid]["state"] = "ok"
        _save(idx)
    return {"id": qid, **idx.get(qid, {})}


def entries() -> list[dict]:
    idx = _load()
    return sorted(({"id": k, **v} for k, v in idx.items() if isinstance(v, dict)), key=lambda e: -e.get("when", 0))


def restore(qid: str) -> str:
    """Devolve o arquivo; nunca sobrescreve. Retorna o caminho em que ficou."""
    idx = _load()
    e = idx.get(qid)
    if not e:
        raise QuarantineError("Item não encontrado na quarentena.")
    src = _vault() / (qid + ".bin")
    if not src.is_file():
        raise QuarantineError("O arquivo da quarentena não existe mais.")
    if hash_file(src)["sha256"] != e["sha256"]:
        raise QuarantineError("O arquivo da quarentena foi alterado: não será restaurado.")
    target = Path(e["original"])
    if not target.parent.is_dir() or path_has_reparse(str(target.parent)) or ps.path_kind(str(target.parent)) != "local":
        target = Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Downloads" / "Sentinela-restaurados" / target.name
        target.parent.mkdir(parents=True, exist_ok=True)
    n = 1
    final = target
    while True:
        try:
            if os.path.lexists(final):
                raise FileExistsError
            os.rename(src, final)          # mesmo volume: atômico e NUNCA sobrescreve
            break
        except FileExistsError:
            final = target.with_name(f"{target.stem} (restaurado{'' if n == 1 else ' ' + str(n)}){target.suffix}")
            n += 1
            if n > 50:
                raise QuarantineError("Não foi possível escolher um nome livre.")
        except OSError:                     # volumes diferentes: copia sem sobrescrever (modo exclusivo) e só então apaga o cofre
            try:
                with open(src, "rb") as fi, open(final, "xb") as fo:
                    shutil.copyfileobj(fi, fo, 1 << 20)
                os.unlink(src)
                break
            except FileExistsError:
                final = target.with_name(f"{target.stem} (restaurado{'' if n == 1 else ' ' + str(n)}){target.suffix}")
                n += 1
                if n > 50:
                    raise QuarantineError("Não foi possível escolher um nome livre.")
            except OSError:
                raise QuarantineError("Não foi possível restaurar o arquivo.")
    try:
        os.utime(final, (e["mtime"], e["mtime"]))
    except OSError:
        pass
    del idx[qid]
    _save(idx)
    return str(final)
