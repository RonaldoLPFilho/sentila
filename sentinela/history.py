"""Histórico das últimas análises (todos os tipos) com o relatório de cada uma.

Privacidade: o relatório é guardado JÁ REDIGIDO (nome de usuário do Windows e segredos de linhas de comando escondidos), só neste computador
(%APPDATA%\\Sentinela\\historico.json) e limitado às últimas MAX_ENTRIES análises. O usuário pode remover itens ou limpar tudo."""
from __future__ import annotations

import json
import os
import secrets
import time

from . import procscan as ps
from .config import DATA_DIR

MAX_ENTRIES = 10
MAX_REPORT = 200_000          # caracteres por relatório
KINDS = {"files": "Arquivo", "procs": "Processos", "net": "Rede", "pc": "Computador"}


def _path():
    return DATA_DIR / "historico.json"


def _load() -> list[dict]:
    try:
        d = json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(d, list):
        return []
    out = []
    for e in d:
        if isinstance(e, dict) and e.get("kind") in KINDS and isinstance(e.get("report"), str):
            out.append({"id": str(e.get("id", "")), "kind": e["kind"], "title": ps.clean_text(e.get("title", ""), 160), "when": float(e.get("when", 0) or 0),
                        "duration": float(e.get("duration", 0) or 0), "level": str(e.get("level", "unknown")), "headline": ps.clean_text(e.get("headline", ""), 60),
                        "score": int(e.get("score", 0) or 0), "summary": ps.clean_text(e.get("summary", ""), 400), "detail": ps.clean_text(e.get("detail", ""), 120),
                        "report": e["report"][:MAX_REPORT]})
    return out


def _save(entries: list[dict]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _path().with_suffix(".tmp")
    tmp.write_text(json.dumps(entries, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, _path())


def record(kind: str, title: str, level: str, headline: str, score: int, summary: str, report_text: str, duration: float = 0.0, detail: str = "") -> dict | None:
    """Acrescenta uma análise ao histórico (mantém só as MAX_ENTRIES mais recentes). Nunca lança: falha de disco não pode derrubar a análise."""
    if kind not in KINDS:
        return None
    try:
        e = {"id": secrets.token_hex(6), "kind": kind, "title": ps.clean_text(title, 160), "when": time.time(), "duration": float(duration), "level": level,
             "headline": ps.clean_text(headline, 60), "score": int(score), "summary": ps.clean_text(summary, 400), "detail": ps.clean_text(detail, 120),
             "report": ps.redact(report_text)[:MAX_REPORT]}
        entries = [e] + _load()
        _save(entries[:MAX_ENTRIES])
        return e
    except (OSError, ValueError, TypeError):
        return None


def entries() -> list[dict]:
    return sorted(_load(), key=lambda e: -e["when"])[:MAX_ENTRIES]


def remove(entry_id: str) -> None:
    try:
        _save([e for e in _load() if e["id"] != entry_id])
    except OSError:
        pass


def clear() -> None:
    try:
        _save([])
    except OSError:
        pass
