"""Instalador do Sentinela (por usuário, sem precisar de administrador).

Uso:  Sentinela-Setup.exe                 -> assistente gráfico
      Sentinela-Setup.exe /S [/D=pasta]   -> instalação silenciosa
                          [/NODESKTOP] [/NOSTART] [/NOCONTEXT]
"""
from __future__ import annotations

import os
import subprocess
import sys
import traceback
import winreg
import zipfile
from pathlib import Path

APP = "Sentinela"


def _read_version() -> str:
    """A versão vem de sentinela/__init__.py (via version.txt gravado pelo build): um único lugar para mudar."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).parent / "build"))
    try:
        return (base / "version.txt").read_text(encoding="utf-8").strip() or "dev"
    except OSError:
        return "dev"


VERSION = _read_version()
UNINSTALL_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentinela"
CONTEXT_KEY = r"Software\Classes\*\shell\Sentinela"
DEFAULT_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Programs" / APP
CREATE_NO_WINDOW = 0x08000000


def payload_path() -> Path:
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).parent / "build"))
    return base / "payload.zip"


def normalize_dir(text: str) -> Path:
    """A instalação sempre fica numa subpasta chamada 'Sentinela' (evita apagar/misturar com outra pasta do usuário)."""
    p = Path(os.path.expandvars(text.strip().strip('"'))).expanduser().resolve()
    return p if p.name.lower() == APP.lower() else p / APP


# ---------------------------------------------------------------- instalação

_PS_SHORTCUTS = r"""
$ErrorActionPreference = 'Stop'
$ws = New-Object -ComObject WScript.Shell
function Mk($path, $target, $arguments, $icon, $desc) {
    New-Item -ItemType Directory -Force -Path (Split-Path $path) | Out-Null
    $s = $ws.CreateShortcut($path)
    $s.TargetPath = $target; $s.Arguments = $arguments
    $s.WorkingDirectory = $env:S_DIR; $s.IconLocation = $icon; $s.Description = $desc
    $s.Save()
}
$exe = Join-Path $env:S_DIR 'Sentinela.exe'
if ($env:S_DESKTOP -eq '1') { Mk (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Sentinela.lnk') $exe '' "$exe,0" 'Analise arquivos antes de abrir' }
if ($env:S_START -eq '1') {
    $prog = Join-Path ([Environment]::GetFolderPath('Programs')) 'Sentinela'
    Mk (Join-Path $prog 'Sentinela.lnk') $exe '' "$exe,0" 'Analise arquivos antes de abrir'
    $un = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$(Join-Path $env:S_DIR 'uninstall.ps1')`""
    Mk (Join-Path $prog 'Desinstalar Sentinela.lnk') "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" $un "$exe,0" 'Remove o Sentinela'
}
"""


def stop_running() -> None:
    subprocess.run(["taskkill", "/F", "/IM", "Sentinela.exe"], capture_output=True, creationflags=CREATE_NO_WINDOW)


def install(target: Path, desktop: bool, start: bool, context: bool, progress=lambda pct, msg: None) -> None:
    zpath = payload_path()
    if not zpath.exists():
        raise FileNotFoundError(f"Pacote de instalação não encontrado: {zpath}")
    progress(2, "Preparando…")
    stop_running()
    if target.exists():  # atualização: limpa a versão anterior (a pasta é sempre ...\Sentinela)
        import shutil
        shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True, exist_ok=True)

    root = target.resolve()
    with zipfile.ZipFile(zpath) as z:
        infos = z.infolist()
        total = sum(i.file_size for i in infos) or 1
        done = 0
        for info in infos:
            dest = (target / info.filename).resolve()
            if root != dest and root not in dest.parents:
                raise ValueError(f"Entrada inválida no pacote: {info.filename}")
            if info.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as s, open(dest, "wb") as d:
                while chunk := s.read(1 << 20):
                    d.write(chunk)
            done += info.file_size
            progress(5 + int(80 * done / total), f"Copiando {info.filename.split('/')[-1]}…")

    exe = target / "Sentinela.exe"
    if not exe.exists():
        raise FileNotFoundError("Sentinela.exe não foi instalado corretamente.")

    progress(88, "Criando atalhos…")
    env = dict(os.environ, S_DIR=str(target), S_DESKTOP="1" if desktop else "0", S_START="1" if start else "0")
    r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", _PS_SHORTCUTS],
                       env=env, capture_output=True, text=True, errors="replace", creationflags=CREATE_NO_WINDOW)
    if r.returncode != 0:
        raise RuntimeError("Falha ao criar atalhos: " + (r.stderr or r.stdout)[-300:])

    progress(94, "Registrando no Windows…")
    size_kb = sum(f.stat().st_size for f in target.rglob("*") if f.is_file()) // 1024
    un_cmd = f'powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{target / "uninstall.ps1"}"'
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, UNINSTALL_KEY) as k:
        for name, val in (("DisplayName", APP), ("DisplayVersion", VERSION), ("Publisher", APP), ("InstallLocation", str(target)),
                          ("DisplayIcon", str(exe)), ("UninstallString", un_cmd), ("QuietUninstallString", un_cmd + " -Silent")):
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, val)
        for name, val in (("EstimatedSize", size_kb), ("NoModify", 1), ("NoRepair", 1)):
            winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, val)
    if context:  # clique direito em qualquer arquivo -> "Analisar com Sentinela"
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, CONTEXT_KEY) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, "Analisar com Sentinela")
            winreg.SetValueEx(k, "Icon", 0, winreg.REG_SZ, str(exe))
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, CONTEXT_KEY + r"\command") as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, f'"{exe}" "%1"')
    progress(100, "Concluído")


# ---------------------------------------------------------------- linha de comando

def run_silent(argv: list[str]) -> int:
    flags = {a.upper() for a in argv}
    target = DEFAULT_DIR
    for a in argv:
        if a.upper().startswith("/D="):
            target = normalize_dir(a[3:])
    try:
        install(target, "/NODESKTOP" not in flags, "/NOSTART" not in flags, "/NOCONTEXT" not in flags)
    except Exception:
        return 1
    return 0


# ---------------------------------------------------------------- interface

def run_gui() -> int:
    from PySide6.QtCore import QPointF, QRectF, Qt, QThread, Signal
    from PySide6.QtGui import QBrush, QColor, QIcon, QLinearGradient, QPainter, QPainterPath, QPen, QPixmap
    from PySide6.QtWidgets import (QApplication, QCheckBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QProgressBar,
                                   QPushButton, QStackedWidget, QVBoxLayout, QWidget)

    BG, SURFACE, BORDER, TEXT, MUTED = "#0B0F17", "#121826", "#27324B", "#E8ECF4", "#8B96AD"
    ACCENT, ACCENT2, GREEN, RED = "#6C8CFF", "#9B6CFF", "#34D399", "#F87171"
    qss = f"""
    * {{ font-family: "Segoe UI Variable Text", "Segoe UI"; font-size: 14px; color: {TEXT}; }}
    QWidget#root, QStackedWidget {{ background: {BG}; }}
    QLabel {{ background: transparent; }}
    QLineEdit {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 8px; padding: 9px 10px; }}
    QLineEdit:focus {{ border-color: {ACCENT}; }}
    QPushButton {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 10px; padding: 10px 20px; }}
    QPushButton:hover {{ border-color: {ACCENT}; }}
    QPushButton#primary {{ border: none; color: white; font-weight: 600;
        background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 {ACCENT}, stop:1 {ACCENT2}); }}
    QPushButton#primary:disabled {{ background: {BORDER}; color: {MUTED}; }}
    QCheckBox {{ spacing: 10px; }}
    QProgressBar {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 8px; height: 14px; text-align: center; color: transparent; }}
    QProgressBar::chunk {{ border-radius: 7px; background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 {ACCENT}, stop:1 {ACCENT2}); }}
    """

    def shield_pixmap(size: int) -> QPixmap:
        pm = QPixmap(size, size)
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.Antialiasing)
        s, cx, cy = size * 0.88, size / 2, size / 2
        path = QPainterPath()
        path.moveTo(cx, cy - 0.5 * s)
        path.lineTo(cx + 0.42 * s, cy - 0.34 * s)
        path.lineTo(cx + 0.42 * s, cy + 0.05 * s)
        path.cubicTo(cx + 0.42 * s, cy + 0.30 * s, cx + 0.18 * s, cy + 0.44 * s, cx, cy + 0.5 * s)
        path.cubicTo(cx - 0.18 * s, cy + 0.44 * s, cx - 0.42 * s, cy + 0.30 * s, cx - 0.42 * s, cy + 0.05 * s)
        path.lineTo(cx - 0.42 * s, cy - 0.34 * s)
        path.closeSubpath()
        g = QLinearGradient(0, 0, size, size)
        g.setColorAt(0, QColor(ACCENT))
        g.setColorAt(1, QColor(ACCENT2))
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(g))
        p.drawPath(path)
        p.setPen(QPen(QColor("white"), max(2.0, s * 0.07), Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        p.setBrush(Qt.NoBrush)
        p.drawPolyline([QPointF(cx - 0.17 * s, cy + 0.02 * s), QPointF(cx - 0.04 * s, cy + 0.15 * s), QPointF(cx + 0.19 * s, cy - 0.12 * s)])
        p.end()
        return pm

    def label(text, size=14, weight=400, color=TEXT, wrap=True):
        w = QLabel(text)
        w.setWordWrap(wrap)
        w.setStyleSheet(f"color:{color}; font-size:{size}px; font-weight:{weight};")
        return w

    class Worker(QThread):
        progress = Signal(int, str)
        ok = Signal()
        failed = Signal(str)

        def __init__(self, target, desktop, start, context):
            super().__init__()
            self.args = (target, desktop, start, context)

        def run(self):
            try:
                install(*self.args, progress=lambda p, m: self.progress.emit(p, m))
            except Exception:
                self.failed.emit(traceback.format_exc())
            else:
                self.ok.emit()

    class Wizard(QWidget):
        def __init__(self):
            super().__init__()
            self.setObjectName("root")
            self.setWindowTitle(f"Instalar o {APP}")
            self.setWindowIcon(QIcon(shield_pixmap(128)))
            self.setFixedSize(620, 520)
            self.worker = None
            self.target = DEFAULT_DIR
            lay = QVBoxLayout(self)
            lay.setContentsMargins(0, 0, 0, 0)
            self.stack = QStackedWidget()
            lay.addWidget(self.stack)
            self.stack.addWidget(self._welcome())
            self.stack.addWidget(self._installing())
            self.stack.addWidget(self._done())

        def _header(self, title, sub):
            row = QHBoxLayout()
            logo = QLabel()
            logo.setPixmap(shield_pixmap(56))
            col = QVBoxLayout()
            col.setSpacing(2)
            col.addWidget(label(title, 22, 700, wrap=False))
            col.addWidget(label(sub, 13, 400, MUTED))
            row.addWidget(logo)
            row.addSpacing(12)
            row.addLayout(col, 1)
            return row

        def _welcome(self):
            w = QWidget()
            v = QVBoxLayout(w)
            v.setContentsMargins(36, 32, 36, 28)
            v.setSpacing(10)
            v.addLayout(self._header(f"Instalar o {APP}", f"Versão {VERSION} · analise arquivos antes de abrir"))
            v.addSpacing(14)
            v.addWidget(label("Pasta de instalação", 13, 600))
            row = QHBoxLayout()
            self.dir_edit = QLineEdit(str(DEFAULT_DIR))
            browse = QPushButton("Procurar…")
            browse.clicked.connect(self._browse)
            row.addWidget(self.dir_edit, 1)
            row.addWidget(browse)
            v.addLayout(row)
            v.addWidget(label("Instalação só para o seu usuário: não precisa de administrador.", 12, 400, MUTED))
            v.addSpacing(8)
            self.c_desktop = QCheckBox("Criar atalho na Área de Trabalho")
            self.c_start = QCheckBox("Criar atalho no Menu Iniciar")
            self.c_ctx = QCheckBox("Adicionar “Analisar com Sentinela” ao clique direito dos arquivos")
            for c in (self.c_desktop, self.c_start, self.c_ctx):
                c.setChecked(True)
                v.addWidget(c)
            v.addStretch()
            v.addWidget(label("O Windows Sandbox (opcional) e a chave do VirusTotal (gratuita) são configurados depois, dentro do aplicativo.", 12, 400, MUTED))
            row2 = QHBoxLayout()
            cancel = QPushButton("Cancelar")
            cancel.clicked.connect(self.close)
            self.btn_install = QPushButton("Instalar")
            self.btn_install.setObjectName("primary")
            self.btn_install.clicked.connect(self._start)
            row2.addStretch()
            row2.addWidget(cancel)
            row2.addWidget(self.btn_install)
            v.addLayout(row2)
            return w

        def _installing(self):
            w = QWidget()
            v = QVBoxLayout(w)
            v.setContentsMargins(36, 32, 36, 36)
            v.addLayout(self._header("Instalando…", "Isso leva alguns segundos"))
            v.addStretch()
            self.bar = QProgressBar()
            self.bar.setRange(0, 100)
            v.addWidget(self.bar)
            self.status = label("", 13, 400, MUTED)
            v.addWidget(self.status)
            v.addStretch()
            return w

        def _done(self):
            w = QWidget()
            v = QVBoxLayout(w)
            v.setContentsMargins(36, 32, 36, 28)
            self.done_header = QVBoxLayout()
            v.addLayout(self._header("Instalação concluída", "O Sentinela está pronto para uso"))
            v.addSpacing(16)
            self.done_text = label("", 13, 400, MUTED)
            v.addWidget(self.done_text)
            v.addSpacing(8)
            self.c_run = QCheckBox("Abrir o Sentinela agora")
            self.c_run.setChecked(True)
            v.addWidget(self.c_run)
            v.addStretch()
            row = QHBoxLayout()
            row.addStretch()
            fin = QPushButton("Concluir")
            fin.setObjectName("primary")
            fin.clicked.connect(self._finish)
            row.addWidget(fin)
            v.addLayout(row)
            return w

        def _browse(self):
            d = QFileDialog.getExistingDirectory(self, "Escolha a pasta de instalação", str(Path(self.dir_edit.text()).parent))
            if d:
                self.dir_edit.setText(str(normalize_dir(d)))

        def _start(self):
            try:
                self.target = normalize_dir(self.dir_edit.text())
            except (OSError, ValueError):
                QMessageBox.warning(self, APP, "Pasta de instalação inválida.")
                return
            self.stack.setCurrentIndex(1)
            self.worker = Worker(self.target, self.c_desktop.isChecked(), self.c_start.isChecked(), self.c_ctx.isChecked())
            self.worker.progress.connect(lambda p, m: (self.bar.setValue(p), self.status.setText(m)))
            self.worker.ok.connect(self._ok)
            self.worker.failed.connect(self._fail)
            self.worker.start()

        def _ok(self):
            self.done_text.setText(f"Instalado em:\n{self.target}\n\nPara desinstalar: Configurações do Windows › Aplicativos, "
                                   "ou o atalho “Desinstalar Sentinela” no Menu Iniciar.")
            self.stack.setCurrentIndex(2)

        def _fail(self, tb):
            QMessageBox.critical(self, APP, "A instalação falhou:\n\n" + tb[-700:])
            self.stack.setCurrentIndex(0)

        def _finish(self):
            if self.c_run.isChecked():
                subprocess.Popen([str(self.target / "Sentinela.exe")], cwd=str(self.target))
            self.close()

        def closeEvent(self, e):
            if self.worker and self.worker.isRunning():
                e.ignore()
            else:
                e.accept()

    app = QApplication(sys.argv)
    import tempfile
    chk = Path(tempfile.gettempdir()) / "sentinela_setup_check.png"  # marca de "ok" para os checkboxes
    pm = QPixmap(18, 18)
    pm.fill(Qt.transparent)
    cp = QPainter(pm)
    cp.setRenderHint(QPainter.Antialiasing)
    cp.setPen(QPen(QColor("white"), 2.2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    cp.drawPolyline([QPointF(4.5, 9.5), QPointF(7.8, 12.8), QPointF(13.5, 5.5)])
    cp.end()
    pm.save(str(chk))
    qss += f"""
    QCheckBox::indicator {{ width: 18px; height: 18px; border-radius: 5px; border: 1px solid {BORDER}; background: {SURFACE}; }}
    QCheckBox::indicator:hover {{ border-color: {ACCENT}; }}
    QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; image: url({chk.as_posix()}); }}
    """
    app.setStyleSheet(qss)
    w = Wizard()
    w.btn_install.setFocus()
    w.dir_edit.setCursorPosition(0)
    w.show()
    try:
        import ctypes
        ctypes.windll.dwmapi.DwmSetWindowAttribute(int(w.winId()), 20, ctypes.byref(ctypes.c_int(1)), 4)
    except Exception:
        pass
    return app.exec()


if __name__ == "__main__":
    args = sys.argv[1:]
    sys.exit(run_silent(args) if any(a.upper() == "/S" for a in args) else run_gui())
