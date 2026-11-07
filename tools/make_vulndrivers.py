"""Gera sentinela/vulndrivers.json (hashes de drivers vulneráveis/maliciosos conhecidos) a partir do LOLDrivers. Uso (do mantenedor):

    curl -L -o drivers.json https://www.loldrivers.io/api/drivers.json
    python -I tools\\make_vulndrivers.py drivers.json

O JSON baixado é dado não confiável: só SHA-256 de 64 hex, nomes curtos e a categoria entram no arquivo gerado (que vai junto do app)."""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HEX64 = re.compile(r"^[0-9a-f]{64}$")
NAME = re.compile(r"^[\w.\- ]{1,64}$")


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("uso: make_vulndrivers.py drivers.json")
    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    out: dict[str, list] = {}
    for e in data if isinstance(data, list) else []:
        if not isinstance(e, dict):
            continue
        cat = "m" if str(e.get("Category", "")).lower() == "malicious" else "v"
        tags = [t for t in (e.get("Tags") or []) if isinstance(t, str) and NAME.match(t)]
        name = tags[0] if tags else ""
        for s in e.get("KnownVulnerableSamples") or []:
            h = str((s or {}).get("SHA256") or "").strip().lower()
            if HEX64.match(h):
                prev = out.get(h)
                out[h] = [name or (prev[0] if prev else ""), "m" if cat == "m" or (prev and prev[1] == "m") else "v"]
    doc = {"source": "https://www.loldrivers.io/api/drivers.json", "generated": time.strftime("%Y-%m-%d"), "count": len(out),
           "sha256": dict(sorted(out.items()))}
    dest = ROOT / "sentinela" / "vulndrivers.json"
    dest.write_text(json.dumps(doc, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"{len(out)} hashes ({sum(1 for v in out.values() if v[1] == 'm')} maliciosos) -> {dest} ({dest.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
