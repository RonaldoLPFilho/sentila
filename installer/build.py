"""Gera Sentinela-Setup-<versão>.exe.   Uso:  python installer\\build.py

1. cria o ícone  2. empacota o app (PyInstaller)  3. compacta o payload  4. empacota o instalador com o payload dentro.
"""
from __future__ import annotations

import re
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BUILD = HERE / "build"
VERSION = re.search(r'__version__ = "([^"]+)"', (ROOT / "sentinela" / "__init__.py").read_text(encoding="utf-8")).group(1)


def make_icon(path: Path) -> None:
    from PySide6.QtCore import QBuffer, QByteArray, QIODevice, Qt
    from PySide6.QtGui import QGuiApplication, QImage, QPainter

    sys.path.insert(0, str(ROOT))
    from sentinela.ui import draw_shield

    app = QGuiApplication.instance() or QGuiApplication([])
    sizes = (16, 24, 32, 48, 64, 128, 256)
    blobs = []
    for s in sizes:
        img = QImage(s, s, QImage.Format_ARGB32)
        img.fill(Qt.transparent)
        p = QPainter(img)
        p.setRenderHint(QPainter.Antialiasing)
        draw_shield(p, s / 2, s / 2, s * 0.9)
        p.end()
        ba = QByteArray()
        buf = QBuffer(ba)
        buf.open(QIODevice.WriteOnly)
        img.save(buf, "PNG")
        blobs.append(bytes(ba))
    head = struct.pack("<HHH", 0, 1, len(sizes))
    offset = 6 + 16 * len(sizes)
    entries = b""
    for s, b in zip(sizes, blobs):
        entries += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(b), offset)
        offset += len(b)
    path.write_bytes(head + entries + b"".join(blobs))
    del app


def pyinstaller(*args: str) -> None:
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", *args], check=True)


def main() -> None:
    if BUILD.exists():
        shutil.rmtree(BUILD)
    BUILD.mkdir()
    ico = BUILD / "sentinela.ico"
    make_icon(ico)
    print("• ícone criado")

    print("• empacotando o aplicativo…")
    pyinstaller("--windowed", "--name", "Sentinela", "--icon", str(ico), "--paths", str(ROOT),
                "--add-data", f"{ROOT / 'sentinela' / 'agent.ps1'};sentinela",
                "--exclude-module", "tkinter",
                "--distpath", str(BUILD / "dist"), "--workpath", str(BUILD / "work_app"), "--specpath", str(BUILD),
                str(HERE / "run_sentinela.py"))
    app_dir = BUILD / "dist" / "Sentinela"
    shutil.copy2(HERE / "uninstall.ps1", app_dir / "uninstall.ps1")
    shutil.copy2(ROOT / "LEIA-ME.md", app_dir / "LEIA-ME.md")

    print("• compactando o payload…")
    payload = BUILD / "payload.zip"
    with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for f in sorted(app_dir.rglob("*")):
            if f.is_file():
                z.write(f, f.relative_to(app_dir).as_posix())
    print(f"  payload: {payload.stat().st_size / 1e6:.1f} MB")

    print("• empacotando o instalador…")
    name = f"Sentinela-Setup-{VERSION}"
    (BUILD / "version.txt").write_text(VERSION, encoding="utf-8")
    pyinstaller("--onefile", "--windowed", "--name", name, "--icon", str(ico),
                "--add-data", f"{payload};.", "--add-data", f"{BUILD / 'version.txt'};.", "--exclude-module", "tkinter",
                "--distpath", str(HERE), "--workpath", str(BUILD / "work_setup"), "--specpath", str(BUILD),
                str(HERE / "setup_app.py"))
    out = HERE / f"{name}.exe"
    print(f"\n✔ Instalador pronto: {out}  ({out.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
