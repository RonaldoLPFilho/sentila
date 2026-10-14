"""Interface do Sentinela (PySide6): tema escuro, arrastar-e-soltar, progresso por etapas e veredito."""
from __future__ import annotations

import ctypes
import os
import subprocess
import traceback
from pathlib import Path

from PySide6.QtCore import QEasingCurve, QPointF, QRectF, QSize, Qt, QThread, QTimer, QUrl, QVariantAnimation, Signal
from PySide6.QtGui import (QBrush, QColor, QDesktopServices, QFont, QFontMetrics, QIcon, QLinearGradient, QPainter, QPainterPath,
                           QPen, QPixmap)
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QFileDialog, QFrame, QHBoxLayout, QLabel, QLineEdit,
                               QMainWindow, QMessageBox, QPushButton, QScrollArea, QSpinBox, QStackedWidget, QVBoxLayout, QWidget)

from . import __version__, sandbox
from .checks import CREATE_NO_WINDOW, KIND_LABEL, find_mpcmdrun, hash_file, human_size
from .config import Settings
from .pipeline import Analyzer, Candidate, SandboxResult, StaticResult
from .scoring import Finding, Verdict, build_verdict, final_findings

BG, SURFACE, SURFACE2, BORDER = "#0B0F17", "#121826", "#1A2336", "#27324B"
TEXT, MUTED = "#E8ECF4", "#8B96AD"
ACCENT, ACCENT2 = "#6C8CFF", "#9B6CFF"
GREEN, AMBER, RED, ORANGE, BLUE = "#34D399", "#FBBF24", "#F87171", "#FB923C", "#60A5FA"
LEVEL_COLOR = {"safe": GREEN, "caution": AMBER, "danger": RED, "unknown": "#94A3B8"}
SEV_COLOR = {"info": MUTED, "low": BLUE, "medium": AMBER, "high": ORANGE, "critical": RED}
FONT = '"Segoe UI Variable Text", "Segoe UI"'

STATIC_STEPS = [
    ("id", "Identificação e extração segura"),
    ("vt", "Reputação · VirusTotal"),
    ("def", "Antivírus local · Microsoft Defender"),
    ("sig", "Assinatura digital e análise estática"),
    ("dec", "Ponderação do risco"),
]
SANDBOX_STEPS = [
    ("sb_prep", "Preparar o Windows Sandbox"),
    ("sb_run", "Executar e observar o comportamento"),
    ("sb_collect", "Avaliar o comportamento observado"),
]
CLEAN_STEP = ("clean", "Limpeza dos arquivos gerados na análise")

QSS = f"""
* {{ font-family: {FONT}; color: {TEXT}; font-size: 14px; }}
QMainWindow, QStackedWidget, #page {{ background: {BG}; }}
QLabel {{ background: transparent; }}
QFrame#topbar {{ background: {SURFACE}; border: none; border-bottom: 1px solid {BORDER}; }}
QFrame#card {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 16px; }}
QFrame#cardAlt {{ background: {SURFACE2}; border: 1px solid {BORDER}; border-radius: 12px; }}
QPushButton {{ background: {SURFACE2}; border: 1px solid {BORDER}; border-radius: 10px; padding: 10px 18px; }}
QPushButton:hover {{ border-color: {ACCENT}; background: #1F2A42; }}
QPushButton:disabled {{ color: {MUTED}; border-color: {SURFACE2}; }}
QPushButton#primary {{ border: none; color: white; font-weight: 600;
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 {ACCENT}, stop:1 {ACCENT2}); }}
QPushButton#primary:hover {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #82A0FF, stop:1 #AE84FF); }}
QPushButton#danger {{ background: transparent; border: 1px solid {RED}; color: {RED}; }}
QPushButton#danger:hover {{ background: rgba(248,113,113,0.12); }}
QPushButton#ghost {{ background: transparent; border: none; color: {MUTED}; }}
QPushButton#ghost:hover {{ color: {TEXT}; }}
QPushButton#nav {{ background: transparent; border: none; border-radius: 8px; color: {MUTED}; padding: 7px 16px; font-weight: 600; }}
QPushButton#nav:hover {{ color: {TEXT}; background: {SURFACE2}; }}
QPushButton#nav:checked {{ color: {TEXT}; background: {SURFACE2}; border: 1px solid {BORDER}; }}
QPushButton#nav:disabled {{ color: {MUTED}; background: transparent; }}
QScrollArea {{ border: none; background: transparent; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {BORDER}; border-radius: 4px; min-height: 30px; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QLineEdit, QSpinBox, QComboBox {{ background: {BG}; border: 1px solid {BORDER}; border-radius: 8px; padding: 8px 10px; }}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{ border-color: {ACCENT}; }}
QComboBox QAbstractItemView {{ background: {SURFACE}; border: 1px solid {BORDER}; selection-background-color: {SURFACE2}; }}
QCheckBox {{ spacing: 10px; }}
QDialog {{ background: {SURFACE}; }}
QToolTip {{ background: {SURFACE2}; color: {TEXT}; border: 1px solid {BORDER}; }}
"""


# ------------------------------------------------------------------ helpers

def lbl(text: str = "", size: int = 14, weight: int = 400, color: str = TEXT, wrap: bool = False, rich: bool = False) -> QLabel:
    """Texto PURO por padrão: nomes de arquivo, linhas de comando e títulos de janela vêm de fonte não confiável
    e não podem ser interpretados como HTML (spoof de veredito)."""
    w = QLabel()
    w.setTextFormat(Qt.RichText if rich else Qt.PlainText)
    w.setText(text)
    w._size, w._weight = size, weight
    set_style(w, color)
    w.setWordWrap(wrap)
    return w


def set_style(w: QLabel, color: str) -> None:
    w.setStyleSheet(f"color: {color}; font-size: {w._size}px; font-weight: {w._weight};")


def card(name: str = "card") -> QFrame:
    f = QFrame()
    f.setObjectName(name)
    return f


def dark_titlebar(win: QWidget) -> None:
    try:
        val = ctypes.c_int(1)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(int(win.winId()), 20, ctypes.byref(val), ctypes.sizeof(val))
    except Exception:
        pass


def shield_path(cx: float, cy: float, s: float) -> QPainterPath:
    p = QPainterPath()
    p.moveTo(cx, cy - 0.5 * s)
    p.lineTo(cx + 0.42 * s, cy - 0.34 * s)
    p.lineTo(cx + 0.42 * s, cy + 0.05 * s)
    p.cubicTo(cx + 0.42 * s, cy + 0.30 * s, cx + 0.18 * s, cy + 0.44 * s, cx, cy + 0.5 * s)
    p.cubicTo(cx - 0.18 * s, cy + 0.44 * s, cx - 0.42 * s, cy + 0.30 * s, cx - 0.42 * s, cy + 0.05 * s)
    p.lineTo(cx - 0.42 * s, cy - 0.34 * s)
    p.closeSubpath()
    return p


def draw_shield(p: QPainter, cx: float, cy: float, s: float, c1: str = ACCENT, c2: str = ACCENT2, check: bool = True) -> None:
    g = QLinearGradient(cx - s / 2, cy - s / 2, cx + s / 2, cy + s / 2)
    g.setColorAt(0, QColor(c1))
    g.setColorAt(1, QColor(c2))
    p.setPen(Qt.NoPen)
    p.setBrush(QBrush(g))
    p.drawPath(shield_path(cx, cy, s))
    if check:
        pen = QPen(QColor("white"), max(2.0, s * 0.07), Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
        p.setPen(pen)
        p.setBrush(Qt.NoBrush)
        p.drawPolyline([QPointF(cx - 0.17 * s, cy + 0.02 * s), QPointF(cx - 0.04 * s, cy + 0.15 * s), QPointF(cx + 0.19 * s, cy - 0.12 * s)])


def app_icon() -> QIcon:
    pm = QPixmap(128, 128)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    draw_shield(p, 64, 64, 112)
    p.end()
    return QIcon(pm)


class Worker(QThread):
    step = Signal(str, str, str)
    done = Signal(object)
    failed = Signal(str)
    cancelled = Signal()

    def __init__(self, fn) -> None:
        super().__init__()
        self.fn = fn

    def run(self) -> None:
        try:
            res = self.fn(lambda sid, st, d="": self.step.emit(sid, st, d))
        except InterruptedError:
            self.cancelled.emit()
        except Exception:
            self.failed.emit(traceback.format_exc())
        else:
            self.done.emit(res)


# ------------------------------------------------------------------ widgets

class DropZone(QFrame):
    fileDropped = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self.setAcceptDrops(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumSize(560, 300)
        self._hover = self._drag = False
        self._glow = 0.0
        self._anim = QVariantAnimation(self, duration=220)
        self._anim.valueChanged.connect(lambda v: (setattr(self, "_glow", v), self.update()))

    def _set_glow(self, on: bool) -> None:
        self._anim.stop()
        self._anim.setStartValue(self._glow)
        self._anim.setEndValue(1.0 if on else 0.0)
        self._anim.start()

    def enterEvent(self, e) -> None:
        self._hover = True
        self._set_glow(True)

    def leaveEvent(self, e) -> None:
        self._hover = False
        self._set_glow(self._drag)

    def mouseReleaseEvent(self, e) -> None:
        if e.button() == Qt.LeftButton:
            self.choose()

    def choose(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Selecione o arquivo para analisar", str(Path.home() / "Downloads"), "Todos os arquivos (*.*)")
        if path:
            self.fileDropped.emit(path)

    def dragEnterEvent(self, e) -> None:
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
            self._drag = True
            self._set_glow(True)

    def dragLeaveEvent(self, e) -> None:
        self._drag = False
        self._set_glow(self._hover)

    def dropEvent(self, e) -> None:
        self._drag = False
        self._set_glow(False)
        urls = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
        files = [u for u in urls if Path(u).is_file()]
        if files:
            self.fileDropped.emit(files[0])
        elif urls:
            QMessageBox.information(self, "Sentinela", "Arraste um arquivo (não uma pasta). Para pastas, compacte em .zip primeiro.")

    def paintEvent(self, e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(self.rect()).adjusted(2, 2, -2, -2)
        bg = QColor(SURFACE)
        glow = QColor(ACCENT)
        glow.setAlphaF(0.10 * self._glow)
        p.setPen(Qt.NoPen)
        p.setBrush(bg)
        p.drawRoundedRect(r, 24, 24)
        p.setBrush(glow)
        p.drawRoundedRect(r, 24, 24)
        c = QColor(BORDER)
        a = QColor(ACCENT)
        mix = QColor(int(c.red() + (a.red() - c.red()) * self._glow), int(c.green() + (a.green() - c.green()) * self._glow),
                     int(c.blue() + (a.blue() - c.blue()) * self._glow))
        pen = QPen(mix, 2)
        pen.setStyle(Qt.CustomDashLine)
        pen.setDashPattern([5, 5])
        p.setPen(pen)
        p.setBrush(Qt.NoBrush)
        p.drawRoundedRect(r, 24, 24)
        cx, cy = r.center().x(), r.center().y()
        draw_shield(p, cx, cy - 52 - 4 * self._glow, 92)
        f = QFont(self.font())
        f.setPixelSize(22)
        f.setWeight(QFont.DemiBold)
        p.setFont(f)
        p.setPen(QColor(TEXT))
        title = "Solte o arquivo aqui" if self._drag else "Arraste o arquivo para analisar"
        p.drawText(QRectF(r.left(), cy + 20, r.width(), 34), Qt.AlignCenter, title)
        f.setPixelSize(14)
        f.setWeight(QFont.Normal)
        p.setFont(f)
        p.setPen(QColor(MUTED))
        p.drawText(QRectF(r.left(), cy + 56, r.width(), 24), Qt.AlignCenter, "ou clique para selecionar · jogos, mods, instaladores, .zip, .rar, .7z, scripts…")


class StateIcon(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setFixedSize(26, 26)
        self.state = "pending"
        self.angle = 0

    def set_state(self, s: str) -> None:
        self.state = s
        self.update()

    def paintEvent(self, e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(3, 3, 20, 20)
        col = {"pending": BORDER, "run": ACCENT, "ok": GREEN, "warn": AMBER, "bad": RED, "skip": MUTED}[self.state]
        if self.state == "run":
            p.setPen(QPen(QColor(BORDER), 3))
            p.drawEllipse(r)
            p.setPen(QPen(QColor(col), 3, Qt.SolidLine, Qt.RoundCap))
            p.drawArc(r, -self.angle * 16, 100 * 16)
            return
        if self.state in ("pending", "skip"):
            p.setPen(QPen(QColor(col), 2))
            p.drawEllipse(r)
            if self.state == "skip":
                p.drawLine(QPointF(8, 13), QPointF(18, 13))
            return
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(col))
        p.drawEllipse(r)
        pen = QPen(QColor(BG), 2.4, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
        p.setPen(pen)
        if self.state == "ok":
            p.drawPolyline([QPointF(8, 13.5), QPointF(11.5, 17), QPointF(18, 9.5)])
        elif self.state == "warn":
            p.drawLine(QPointF(13, 8), QPointF(13, 14.5))
            p.drawPoint(QPointF(13, 18))
        else:
            p.drawLine(QPointF(9, 9), QPointF(17, 17))
            p.drawLine(QPointF(17, 9), QPointF(9, 17))


class StepRow(QWidget):
    def __init__(self, title: str) -> None:
        super().__init__()
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 6, 0, 6)
        h.setSpacing(14)
        self.icon = StateIcon()
        v = QVBoxLayout()
        v.setSpacing(2)
        self.title = lbl(title, 15, 600)
        self.detail = lbl("Aguardando…", 13, 400, MUTED, True)
        v.addWidget(self.title)
        v.addWidget(self.detail)
        h.addWidget(self.icon, 0, Qt.AlignTop)
        h.addLayout(v, 1)

    def update_state(self, state: str, detail: str) -> None:
        self.icon.set_state(state)
        if detail or state in ("ok", "bad", "warn"):
            self.detail.setText(detail)
        elif state == "skip":
            self.detail.setText("Não executado")
        set_style(self.detail, {"bad": RED, "warn": AMBER}.get(state, MUTED))
        set_style(self.title, MUTED if state in ("pending", "skip") else TEXT)


class Gauge(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setFixedSize(230, 230)
        self._v = 0.0
        self._color = QColor(GREEN)
        self._anim = QVariantAnimation(self, duration=1100)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)
        self._anim.valueChanged.connect(lambda v: (setattr(self, "_v", v), self.update()))

    def show_score(self, score: int, color: str) -> None:
        self._color = QColor(color)
        self._anim.stop()
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(float(score))
        self._anim.start()

    def paintEvent(self, e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(18, 18, self.width() - 36, self.height() - 36)
        p.setPen(QPen(QColor(BORDER), 14, Qt.SolidLine, Qt.RoundCap))
        p.drawArc(r, 225 * 16, -270 * 16)
        if self._v > 0.5:
            p.setPen(QPen(self._color, 14, Qt.SolidLine, Qt.RoundCap))
            p.drawArc(r, 225 * 16, int(-270 * 16 * self._v / 100))
        f = QFont(self.font())
        f.setPixelSize(58)
        f.setWeight(QFont.Bold)
        p.setFont(f)
        p.setPen(QColor(TEXT))
        p.drawText(QRectF(0, 62, self.width(), 76), Qt.AlignCenter, str(int(round(self._v))))
        f.setPixelSize(13)
        f.setWeight(QFont.Normal)
        p.setFont(f)
        p.setPen(QColor(MUTED))
        p.drawText(QRectF(0, 136, self.width(), 22), Qt.AlignCenter, "pontuação de risco / 100")


class FindingCard(QFrame):
    def __init__(self, f: Finding) -> None:
        super().__init__()
        self.setObjectName("cardAlt")
        color = AMBER if f.gap else (GREEN if f.points < 0 else SEV_COLOR[f.severity])
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 0, 14, 0)
        h.setSpacing(12)
        bar = QFrame()
        bar.setFixedWidth(5)
        bar.setStyleSheet(f"background: {color}; border-top-left-radius: 12px; border-bottom-left-radius: 12px; border: none;")
        v = QVBoxLayout()
        v.setContentsMargins(0, 11, 0, 11)
        v.setSpacing(3)
        v.addWidget(lbl(f.title, 14, 600, TEXT, True))
        if f.detail:
            d = lbl(f.detail, 12, 400, MUTED, True)
            d.setTextInteractionFlags(Qt.TextSelectableByMouse)
            v.addWidget(d)
        h.addWidget(bar)
        h.addLayout(v, 1)
        if f.points:
            chip = lbl(f"{f.points:+d}".replace("-", "−"), 13, 700, color)
            chip.setAlignment(Qt.AlignCenter)
            chip.setFixedWidth(46)
            h.addWidget(chip, 0, Qt.AlignTop)


class Chip(QLabel):
    def __init__(self) -> None:
        super().__init__()
        self.setStyleSheet(f"background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 14px; padding: 6px 14px; color: {MUTED}; font-size: 12px;")

    def set(self, text: str, ok: bool | None) -> None:
        col = GREEN if ok else (AMBER if ok is None else RED)
        self.setText(f"<span style='color:{col}'>●</span>&nbsp; {text}")


# ------------------------------------------------------------------ settings

class SettingsDialog(QDialog):
    def __init__(self, settings: Settings, parent=None) -> None:
        super().__init__(parent)
        self.s = settings
        self.setWindowTitle("Configurações")
        self.setMinimumWidth(520)
        v = QVBoxLayout(self)
        v.setContentsMargins(26, 24, 26, 22)
        v.setSpacing(10)
        v.addWidget(lbl("Configurações", 20, 700))
        v.addSpacing(6)
        v.addWidget(lbl("Chave de API do VirusTotal", 14, 600))
        self.key = QLineEdit()
        self.key.setEchoMode(QLineEdit.Password)
        self.key.setPlaceholderText("•••••• chave salva (deixe em branco para manter)" if settings.vt_key else "Cole sua chave aqui")
        v.addWidget(self.key)
        link = lbl("<a href='https://www.virustotal.com/gui/my-apikey' style='color:#6C8CFF'>Obter chave gratuita</a> · "
                   "só o hash do arquivo é enviado, nunca o arquivo. Limite gratuito: 4 consultas/min.", 12, 400, MUTED, True, rich=True)
        link.setOpenExternalLinks(True)
        v.addWidget(link)
        v.addSpacing(10)
        self.auto = QCheckBox("Iniciar o sandbox automaticamente quando for recomendado")
        self.auto.setChecked(bool(settings["auto_sandbox"]))
        v.addWidget(self.auto)
        self.prot = QCheckBox("Modo protegido do sandbox (mais isolamento; pode não funcionar em todos os PCs)")
        self.prot.setChecked(bool(settings["sandbox_protected"]))
        v.addWidget(self.prot)
        self.net = QCheckBox("Permitir internet dentro do sandbox")
        self.net.setChecked(bool(settings["sandbox_network"]))
        v.addWidget(self.net)
        v.addWidget(lbl("Com internet, dá para ver conexões do programa, mas ele também poderia alcançar sua rede local. "
                        "Deixe desligado, a menos que precise.", 12, 400, AMBER, True))
        row = QHBoxLayout()
        row.addWidget(lbl("Tempo de observação no sandbox:"))
        self.secs = QSpinBox()
        self.secs.setRange(20, 300)
        self.secs.setSuffix(" s")
        self.secs.setValue(int(settings["sandbox_seconds"]))
        row.addWidget(self.secs)
        row.addStretch()
        v.addLayout(row)
        v.addSpacing(10)
        h = QHBoxLayout()
        h.addStretch()
        cancel = QPushButton("Cancelar")
        cancel.clicked.connect(self.reject)
        ok = QPushButton("Salvar")
        ok.setObjectName("primary")
        ok.clicked.connect(self.save)
        h.addWidget(cancel)
        h.addWidget(ok)
        v.addLayout(h)

    def save(self) -> None:
        if self.key.text().strip():
            self.s.vt_key = self.key.text()
        self.s["auto_sandbox"] = self.auto.isChecked()
        self.s["sandbox_network"] = self.net.isChecked()
        self.s["sandbox_protected"] = self.prot.isChecked()
        self.s["sandbox_seconds"] = self.secs.value()
        self.s.save()
        self.accept()


# ------------------------------------------------------------------ páginas

class TopBar(QFrame):
    """Barra fixa no topo de TODAS as telas: identidade do app, versão e configurações."""
    openSettings = Signal()
    navigate = Signal(str)  # "files" | "procs"

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("topbar")
        self.setFixedHeight(58)
        h = QHBoxLayout(self)
        h.setContentsMargins(24, 0, 24, 0)
        h.setSpacing(12)
        logo = QLabel()
        logo.setPixmap(app_icon().pixmap(QSize(30, 30)))
        h.addWidget(logo)
        h.addWidget(lbl("Sentinela", 17, 700))
        self.version = QLabel(f"v{__version__}")
        self.version.setToolTip(f"Sentinela versão {__version__}")
        self.version.setAlignment(Qt.AlignCenter)
        self.version.setFixedHeight(22)
        self.version.setStyleSheet(f"color: {ACCENT}; background: rgba(108,140,255,0.14); border: 1px solid rgba(108,140,255,0.35);"
                                   "border-radius: 11px; padding: 0 10px; font-size: 12px; font-weight: 600;")
        h.addWidget(self.version, 0, Qt.AlignVCenter)
        h.addSpacing(18)
        self.nav: dict[str, QPushButton] = {}
        for key, text in (("files", "Arquivos"), ("procs", "Processos")):
            b = QPushButton(text)
            b.setObjectName("nav")
            b.setCheckable(True)
            b.setCursor(Qt.PointingHandCursor)
            b.clicked.connect(lambda _=False, k=key: self.navigate.emit(k))
            self.nav[key] = b
            h.addWidget(b)
        self.set_section("files")
        h.addStretch()
        self.gear = QPushButton("Configurações")
        self.gear.setObjectName("ghost")
        self.gear.setCursor(Qt.PointingHandCursor)
        self.gear.clicked.connect(self.openSettings)
        h.addWidget(self.gear)

    def set_section(self, key: str) -> None:
        for k, b in self.nav.items():
            b.setChecked(k == key)

    def set_busy(self, busy: bool) -> None:
        """Durante uma análise não se troca de aba nem se abre Configurações."""
        self.gear.setEnabled(not busy)
        for b in self.nav.values():
            b.setEnabled(not busy)


class HomePage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("page")
        root = QVBoxLayout(self)
        root.setContentsMargins(48, 24, 48, 32)
        root.addStretch(1)
        self.drop = DropZone()
        root.addWidget(self.drop, 0, Qt.AlignCenter)
        root.addSpacing(18)
        hint = lbl("Nada é executado no seu computador. O arquivo é lido, verificado e, se preciso, testado dentro de um Windows descartável.",
                   13, 400, MUTED, True)
        hint.setAlignment(Qt.AlignCenter)
        root.addWidget(hint)
        root.addStretch(1)
        chips = QHBoxLayout()
        chips.addStretch()
        self.c_vt, self.c_def, self.c_sb = Chip(), Chip(), Chip()
        for c in (self.c_vt, self.c_def, self.c_sb):
            chips.addWidget(c)
        chips.addStretch()
        root.addLayout(chips)

    def refresh(self, settings: Settings) -> None:
        self.c_vt.set("VirusTotal ativo" if settings.vt_key else "VirusTotal sem chave", bool(settings.vt_key) or None)
        self.c_def.set("Microsoft Defender pronto" if find_mpcmdrun() else "Defender não encontrado", bool(find_mpcmdrun()))
        self.c_sb.set("Windows Sandbox disponível" if sandbox.available() else "Windows Sandbox não ativado", sandbox.available() or None)


class DecisionPanel(QFrame):
    start = Signal(int)
    skip = Signal()

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("card")
        v = QVBoxLayout(self)
        v.setContentsMargins(22, 18, 22, 18)
        v.setSpacing(8)
        self.title = lbl("", 16, 700)
        self.reason = lbl("", 13, 400, MUTED, True)
        self.combo = QComboBox()
        self.info = lbl("", 12, 400, MUTED, True)
        self.count = lbl("", 13, 600, ACCENT)
        v.addWidget(self.title)
        v.addWidget(self.reason)
        v.addWidget(self.combo)
        v.addWidget(self.info)
        row = QHBoxLayout()
        self.go = QPushButton("Executar no Sandbox agora")
        self.go.setObjectName("primary")
        self.go.clicked.connect(self._go)
        self.no = QPushButton("Pular")
        self.no.clicked.connect(self._skip)
        row.addWidget(self.go)
        row.addWidget(self.no)
        row.addStretch()
        row.addWidget(self.count)
        v.addLayout(row)
        self._timer = QTimer(self, interval=1000)
        self._timer.timeout.connect(self._tick)
        self._left = 0

    def open(self, sr: StaticResult, settings: Settings, auto: bool) -> None:
        pv = build_verdict(sr.findings, False)
        self.title.setText(f"Sandbox recomendado · pontuação preliminar {sr.score}/100 ({pv.headline.lower()})")
        self.reason.setText(sr.recommendation.reason + " Uma janela do Windows Sandbox vai abrir: não a feche nem interaja.")
        self.combo.clear()
        for c in sr.candidates:
            self.combo.addItem(c.label)
        self.combo.setVisible(len(sr.candidates) > 1)
        net = "ligada (menos seguro)" if settings["sandbox_network"] else "desligada"
        self.info.setText(f"Rede {net} · observação de {settings['sandbox_seconds']} s · a pasta da amostra fica somente leitura.")
        self.count.setText("")
        self.show()
        if auto:
            self._left = 6
            self.count.setText(f"Iniciando em {self._left} s…")
            self._timer.start()

    def _tick(self) -> None:
        self._left -= 1
        if self._left <= 0:
            self._go()
        else:
            self.count.setText(f"Iniciando em {self._left} s…")

    def _go(self) -> None:
        self._timer.stop()
        self.hide()
        self.start.emit(max(0, self.combo.currentIndex()))

    def _skip(self) -> None:
        self._timer.stop()
        self.hide()
        self.skip.emit()

    def stop(self) -> None:
        self._timer.stop()
        self.hide()


class ProgressPage(QWidget):
    cancel = Signal()

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("page")
        self.rows: dict[str, StepRow] = {}
        root = QVBoxLayout(self)
        root.setContentsMargins(48, 32, 48, 28)
        root.setSpacing(16)
        fc = card()
        fh = QHBoxLayout(fc)
        fh.setContentsMargins(20, 16, 20, 16)
        ic = QLabel()
        ic.setPixmap(app_icon().pixmap(QSize(38, 38)))
        fh.addWidget(ic)
        fv = QVBoxLayout()
        fv.setSpacing(2)
        self.name = lbl("", 17, 700)
        self.meta = lbl("", 12, 400, MUTED)
        fv.addWidget(self.name)
        fv.addWidget(self.meta)
        fh.addSpacing(8)
        fh.addLayout(fv, 1)
        root.addWidget(fc)

        self.steps_card = card()
        self.steps_layout = QVBoxLayout(self.steps_card)
        self.steps_layout.setContentsMargins(24, 14, 24, 14)
        self.steps_layout.setSpacing(0)
        sa = QScrollArea()
        sa.setWidgetResizable(True)
        sa.setWidget(self.steps_card)
        sa.setFrameShape(QFrame.NoFrame)
        root.addWidget(sa, 1)

        self.decision = DecisionPanel()
        self.decision.hide()
        root.addWidget(self.decision)

        bottom = QHBoxLayout()
        self.btn = QPushButton("Cancelar análise")
        self.btn.clicked.connect(self._cancel)
        bottom.addStretch()
        bottom.addWidget(self.btn)
        root.addLayout(bottom)

        self._spin = QTimer(self, interval=40)
        self._spin.timeout.connect(self._rotate)
        self._spin.start()

    def _rotate(self) -> None:
        for r in self.rows.values():
            if r.icon.state == "run":
                r.icon.angle = (r.icon.angle + 12) % 360
                r.icon.update()

    def _cancel(self) -> None:
        self.btn.setEnabled(False)
        self.btn.setText("Cancelando…")
        self.cancel.emit()

    def reset(self, path: Path, size: int) -> None:
        self.decision.stop()
        self.name.setText(path.name)
        self.meta.setText(f"{human_size(size)} · {path.parent}")
        self.btn.setEnabled(True)
        self.btn.setText("Cancelar análise")
        while self.steps_layout.count():
            it = self.steps_layout.takeAt(0)
            if it.widget():
                it.widget().deleteLater()
        self.rows.clear()
        self.add_steps(STATIC_STEPS)

    def add_steps(self, steps) -> None:
        if self.steps_layout.count() and self.steps_layout.itemAt(self.steps_layout.count() - 1).spacerItem():
            self.steps_layout.takeAt(self.steps_layout.count() - 1)
        for sid, title in steps:
            row = StepRow(title)
            self.rows[sid] = row
            self.steps_layout.addWidget(row)
        self.steps_layout.addStretch()

    def update_step(self, sid: str, state: str, detail: str) -> None:
        if sid in self.rows:
            self.rows[sid].update_state(state, detail)


class ResultPage(QWidget):
    openFile = Signal()
    revealFile = Signal()
    deleteFile = Signal()
    saveReport = Signal()
    again = Signal()
    forceSandbox = Signal()
    enableSandbox = Signal()

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("page")
        root = QVBoxLayout(self)
        root.setContentsMargins(40, 28, 40, 24)
        root.setSpacing(16)
        body = QHBoxLayout()
        body.setSpacing(20)

        left = card()
        left.setFixedWidth(330)
        lv = QVBoxLayout(left)
        lv.setContentsMargins(22, 24, 22, 22)
        lv.setSpacing(10)
        lv.setAlignment(Qt.AlignTop)
        self.gauge = Gauge()
        lv.addWidget(self.gauge, 0, Qt.AlignHCenter)
        self.headline = lbl("", 28, 700)
        self.headline.setAlignment(Qt.AlignCenter)
        lv.addWidget(self.headline)
        self.summary = lbl("", 13, 400, MUTED, True)
        self.summary.setAlignment(Qt.AlignCenter)
        lv.addWidget(self.summary)
        lv.addSpacing(8)
        self.fname = lbl("", 12, 600, TEXT, True)
        self.fname.setAlignment(Qt.AlignCenter)
        lv.addWidget(self.fname)
        self.hashes = lbl("", 11, 400, MUTED, True)
        self.hashes.setAlignment(Qt.AlignCenter)
        self.hashes.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lv.addWidget(self.hashes)
        lv.addStretch()
        self.cleaned = lbl("", 12, 400, GREEN, True)
        self.cleaned.setAlignment(Qt.AlignCenter)
        lv.addWidget(self.cleaned)
        body.addWidget(left)

        right = QVBoxLayout()
        right.setSpacing(10)
        self.banner = card("cardAlt")
        bv = QVBoxLayout(self.banner)
        bv.setContentsMargins(18, 14, 18, 14)
        self.banner_text = lbl("", 13, 400, TEXT, True)
        bv.addWidget(self.banner_text)
        self.banner_row = QHBoxLayout()
        self.banner_btn = QPushButton("")
        self.banner_btn.setObjectName("primary")
        self._banner_action = None
        self.banner_btn.clicked.connect(lambda: self._banner_action.emit() if self._banner_action else None)
        self.banner_row.addWidget(self.banner_btn)
        self.banner_row.addStretch()
        bv.addLayout(self.banner_row)
        right.addWidget(self.banner)
        self.shot = QLabel()
        self.shot.setAlignment(Qt.AlignCenter)
        self.shot.hide()
        sc = QScrollArea()
        sc.setWidgetResizable(True)
        self.list_host = QWidget()
        self.list_host.setObjectName("page")
        self.list = QVBoxLayout(self.list_host)
        self.list.setContentsMargins(0, 0, 8, 0)
        self.list.setSpacing(8)
        sc.setWidget(self.list_host)
        right.addWidget(sc, 1)
        body.addLayout(right, 1)
        root.addLayout(body, 1)

        bar = QHBoxLayout()
        bar.setSpacing(10)
        self.b_open = QPushButton("")
        self.b_open.clicked.connect(self.openFile)
        self.b_reveal = QPushButton("Mostrar na pasta")
        self.b_reveal.clicked.connect(self.revealFile)
        self.b_report = QPushButton("Salvar relatório")
        self.b_report.clicked.connect(self.saveReport)
        self.b_delete = QPushButton("Excluir arquivo")
        self.b_delete.setObjectName("danger")
        self.b_delete.clicked.connect(self.deleteFile)
        self.b_new = QPushButton("Analisar outro")
        self.b_new.setObjectName("primary")
        self.b_new.clicked.connect(self.again)
        for b in (self.b_open, self.b_reveal, self.b_report, self.b_delete):
            bar.addWidget(b)
        bar.addStretch()
        bar.addWidget(self.b_new)
        root.addLayout(bar)

    def _clear_list(self) -> None:
        while self.list.count():
            it = self.list.takeAt(0)
            if it.widget():
                it.widget().deleteLater()

    def _section(self, title: str, items: list[Finding]) -> None:
        if not items:
            return
        t = lbl(title.upper(), 11, 700, MUTED)
        t.setContentsMargins(2, 8, 0, 0)
        self.list.addWidget(t)
        for f in items:
            self.list.addWidget(FindingCard(f))

    def show_result(self, sr: StaticResult, sbr: SandboxResult | None, verdict: Verdict, freed: int, shot: QPixmap | None,
                    sandbox_ok: bool, can_force: bool, findings: list[Finding]) -> None:
        color = LEVEL_COLOR[verdict.level]
        self.headline.setText(verdict.headline)
        set_style(self.headline, color)
        self.summary.setText(verdict.summary)
        self.fname.setText(sr.path.name)
        h = sr.hashes.get("sha256", "-")
        self.hashes.setText(f"SHA-256\n{h[:32]}\n{h[32:]}")
        self.cleaned.setText(f"✓ Limpeza concluída: {human_size(freed)} de arquivos temporários removidos." if freed else "✓ Nenhum arquivo temporário restante.")
        self.gauge.show_score(verdict.score, color)

        # banner do sandbox
        ran = bool(sbr and sbr.ran)
        mode = sr.recommendation.mode if sr.recommendation else "unnecessary"
        self._banner_action = None
        self.banner.show()
        self.banner_btn.show()
        if ran:
            self.banner_text.setText("A amostra foi executada em um Windows Sandbox descartável. Atenção: o sandbox é só informativo e pode ser enganado "
                                     "por malware. Ele detecta comportamento ruidoso, mas “nada suspeito” NÃO prova que o arquivo é seguro.")
            self.banner_btn.hide()
        elif sbr and not sbr.ran:
            self.banner_text.setText(f"O teste em sandbox não foi conclusivo: {sbr.error or 'sem detalhes'}. O resultado não vale como evidência de segurança.")
            self.banner_btn.setText("Tentar novamente")
            self._banner_action = self.forceSandbox
        elif mode == "recommended" and not sandbox_ok:
            self.banner_text.setText("O sandbox era recomendado para este arquivo, mas o Windows Sandbox não está ativado. É preciso permissão de administrador e reiniciar o PC.")
            self.banner_btn.setText("Ativar o Windows Sandbox")
            self._banner_action = self.enableSandbox
        elif mode == "recommended":
            self.banner_text.setText("Você pulou o teste em sandbox, que era recomendado.")
            self.banner_btn.setText("Testar no Sandbox agora")
            self._banner_action = self.forceSandbox
        elif can_force and sandbox_ok and mode in ("optional", "blocked"):
            self.banner_text.setText("Sandbox dispensado: " + sr.recommendation.reason)
            self.banner_btn.setText("Testar no Sandbox mesmo assim")
            self._banner_action = self.forceSandbox
        else:
            self.banner_text.setText("Sandbox dispensado: " + (sr.recommendation.reason if sr.recommendation else ""))
            self.banner_btn.hide()

        self._clear_list()
        if shot:
            self.shot.setPixmap(shot.scaledToWidth(420, Qt.SmoothTransformation))
            self.shot.setStyleSheet(f"border: 1px solid {BORDER}; border-radius: 8px;")
            t = lbl("CAPTURA DA TELA DO SANDBOX", 11, 700, MUTED)
            self.list.addWidget(t)
            self.list.addWidget(self.shot, 0, Qt.AlignLeft)
            self.shot.show()
        risk = sorted([f for f in findings if f.points > 0], key=lambda f: -f.points)
        gaps = [f for f in findings if f.gap]
        good = [f for f in findings if f.points < 0]
        info = [f for f in findings if f.points == 0 and not f.gap]
        self._section("Pontos de atenção", risk)
        self._section("Não verificado (por isso o veredito é cauteloso)", [f for f in gaps if f.points <= 0])
        self._section("A favor do arquivo", good)
        self._section("Informações", info)
        self.list.addStretch()

        kind = sr.kind
        label = {"exe": "Instalar / executar agora", "msi": "Instalar agora", "archive": "Abrir arquivo compactado"}.get(kind, "Abrir arquivo")
        self.b_open.setText(label)
        self.b_open.setObjectName("danger" if verdict.level == "danger" else "")
        self.b_open.setStyleSheet("")
        self.b_open.style().unpolish(self.b_open)
        self.b_open.style().polish(self.b_open)


# ------------------------------------------------------------------ janela principal

def build_report(sr: StaticResult, sbr: SandboxResult | None, v: Verdict, findings: list[Finding]) -> str:
    lines = ["RELATÓRIO SENTINELA", "=" * 60, f"Arquivo : {sr.path}", f"Tipo    : {KIND_LABEL.get(sr.kind, sr.kind)} · {human_size(sr.size)}",
             f"SHA-256 : {sr.hashes.get('sha256')}", f"MD5     : {sr.hashes.get('md5')}", "",
             f"VEREDITO: {v.headline.upper()} ({v.score}/100)", v.summary, ""]
    for title, sel in (("PONTOS DE ATENÇÃO", lambda f: f.points > 0), ("NÃO VERIFICADO", lambda f: f.gap and f.points <= 0),
                       ("A FAVOR", lambda f: f.points < 0), ("INFORMAÇÕES", lambda f: f.points == 0 and not f.gap)):
        items = [f for f in findings if sel(f)]
        if items:
            lines += [title, "-" * 60]
            for f in items:
                lines.append(f"[{f.points:+d}] ({f.stage}) {f.title}")
                if f.detail:
                    lines += ["      " + d for d in f.detail.splitlines()]
            lines.append("")
    lines.append("Nenhuma análise garante 100% de segurança.")
    return "\n".join(lines)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"Sentinela v{__version__}")
        self.setWindowIcon(app_icon())
        self.resize(1080, 800)
        self.setMinimumSize(940, 720)
        self.settings = Settings()
        self.analyzer = Analyzer(self.settings)
        self.worker: Worker | None = None
        self.sr: StaticResult | None = None
        self.sbr: SandboxResult | None = None
        self.path: Path | None = None
        self._force = False
        self._stage = "idle"

        self.stack = QStackedWidget()
        from .ui_procs import ProcessPage  # import tardio: ui_procs usa widgets deste módulo
        self.home, self.progress, self.result = HomePage(), ProgressPage(), ResultPage()
        self.procs = ProcessPage(self.settings)
        self._procs_busy = False
        self._files_widget: QWidget = self.home
        for w in (self.home, self.progress, self.result, self.procs):
            self.stack.addWidget(w)
        self.topbar = TopBar()
        central = QWidget()
        central.setObjectName("page")
        col = QVBoxLayout(central)
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(0)
        col.addWidget(self.topbar)
        col.addWidget(self.stack, 1)
        self.setCentralWidget(central)
        # configurações e troca de aba só quando não há análise em andamento
        self.stack.currentChanged.connect(self._sync_chrome)
        self.procs.busyChanged.connect(self._on_procs_busy)
        self.topbar.navigate.connect(self.navigate)
        self.procs.analyzeFile.connect(self._analyze_from_procs)

        self.home.drop.fileDropped.connect(self.start_analysis)
        self.topbar.openSettings.connect(self.open_settings)
        self.progress.cancel.connect(self.cancel_analysis)
        self.progress.decision.start.connect(self.start_sandbox)
        self.progress.decision.skip.connect(lambda: self.finalize(None))
        self.result.again.connect(self.go_home)
        self.result.openFile.connect(self.open_file)
        self.result.revealFile.connect(self.reveal_file)
        self.result.deleteFile.connect(self.delete_file)
        self.result.saveReport.connect(self.save_report)
        self.result.forceSandbox.connect(lambda: self.start_analysis(str(self.path), force=True))
        self.result.enableSandbox.connect(self.enable_sandbox)
        self.go_home()

    # ---- navegação
    def go_home(self) -> None:
        self.home.refresh(self.settings)
        self.stack.setCurrentWidget(self.home)

    def open_settings(self) -> None:
        if SettingsDialog(self.settings, self).exec():
            self.home.refresh(self.settings)
            self.procs.refresh()

    def _sync_chrome(self, *_a) -> None:
        cur = self.stack.currentWidget()
        if cur is not self.procs:
            self._files_widget = cur
        self.topbar.set_busy(cur is self.progress or self._procs_busy)
        self.topbar.set_section("procs" if cur is self.procs else "files")

    def _on_procs_busy(self, busy: bool) -> None:
        self._procs_busy = busy
        self._sync_chrome()

    def navigate(self, key: str) -> None:
        if key == "procs":
            self.procs.refresh()
            self.stack.setCurrentWidget(self.procs)
        else:
            self.stack.setCurrentWidget(self._files_widget if self._files_widget is not self.progress else self.home)
        self._sync_chrome()

    def _analyze_from_procs(self, path: str) -> None:
        self.stack.setCurrentWidget(self.home)
        self.start_analysis(path)

    def _run(self, fn, on_done) -> None:
        w = Worker(fn)
        w.step.connect(self.progress.update_step)
        w.done.connect(on_done)
        w.failed.connect(self._failed)
        w.cancelled.connect(self._cancelled)
        self._workers = [x for x in getattr(self, "_workers", []) if x.isRunning()] + [w]  # evita destruir QThread ativa
        self.worker = w
        w.start()

    def _failed(self, tb: str) -> None:
        self.progress.decision.stop()
        self.analyzer.cleanup()
        if "FileNotFoundError" in tb or "No such file" in tb:
            QMessageBox.warning(self, "Sentinela", "O arquivo não foi encontrado. Ele pode ter sido movido, renomeado ou removido pelo antivírus.")
        else:
            QMessageBox.critical(self, "Sentinela", "A análise falhou por um erro inesperado.\n\n" + tb[-900:])
        self.go_home()

    def _cancelled(self) -> None:
        self.progress.decision.stop()
        self.analyzer.cleanup()
        self.go_home()

    def cancel_analysis(self) -> None:
        self.analyzer.cancel()
        if self._stage == "decision" or not (self.worker and self.worker.isRunning()):
            self._cancelled()

    # ---- fluxo
    def start_analysis(self, path_str: str, force: bool = False) -> None:
        if (self.worker and self.worker.isRunning()) or self._procs_busy:
            return
        self.path = Path(path_str)
        self._force = force
        self.sr = self.sbr = None
        try:
            size = self.path.stat().st_size
        except OSError:
            size = 0
        self._stage = "static"
        self.progress.reset(self.path, size)
        self.stack.setCurrentWidget(self.progress)
        self._run(lambda emit: self.analyzer.analyze_static(path_str, emit), self.on_static_done)

    def on_static_done(self, sr: StaticResult) -> None:
        self.sr = sr
        rec = sr.recommendation
        avail = sandbox.available()
        wants = rec.mode == "recommended" or (self._force and rec.mode in ("optional", "blocked", "recommended"))
        if wants and avail and sr.candidates:
            self._stage = "decision"
            manual = self._force and len(sr.candidates) == 1
            if manual:
                self.start_sandbox(0)
            else:
                self.progress.decision.open(sr, self.settings, auto=bool(self.settings["auto_sandbox"]) and not self._force)
        else:
            self.finalize(None)

    def start_sandbox(self, idx: int) -> None:
        sr = self.sr
        cand: Candidate = sr.candidates[idx]
        self._stage = "sandbox"
        self.progress.add_steps(SANDBOX_STEPS)
        self._run(lambda emit: self.analyzer.run_sandbox(sr, cand, emit), self.finalize)

    def finalize(self, sbr: SandboxResult | None) -> None:
        self.sbr = sbr
        self._stage = "clean"
        steps = [CLEAN_STEP]
        if sbr is None and not any(k in self.progress.rows for k in ("sb_prep",)):
            pass
        self.progress.add_steps(steps)
        self.progress.btn.setEnabled(False)
        shot = None
        if sbr and sbr.outcome and sbr.outcome.screenshot:
            pm = QPixmap()
            if pm.loadFromData(sbr.outcome.screenshot):
                shot = pm
        self._shot = shot
        self.progress.update_step("clean", "run", "Removendo extrações, cópias e a configuração do sandbox…")

        def work(emit):
            freed = self.analyzer.cleanup()
            return freed

        self._run(work, self.show_result)

    def show_result(self, freed: int) -> None:
        sr, sbr = self.sr, self.sbr
        self.progress.update_step("clean", "ok", f"{human_size(freed)} removidos")
        findings = self._all_findings()
        verdict = build_verdict(findings, bool(sbr and sbr.ran))
        QTimer.singleShot(450, lambda: self._display(sr, sbr, verdict, freed, findings))

    def _all_findings(self) -> list[Finding]:
        """Achados estáticos + sandbox + lacuna de 'sandbox recomendado e não concluído'."""
        sr, sbr = self.sr, self.sbr
        mode = sr.recommendation.mode if sr.recommendation else "unnecessary"
        return final_findings(sr.findings, mode, bool(sbr and sbr.ran), sbr.findings if sbr else None)

    def _display(self, sr, sbr, verdict, freed, findings) -> None:
        can_force = bool(sr.candidates) and not (sbr and sbr.ran)
        self.result.show_result(sr, sbr, verdict, freed, getattr(self, "_shot", None), sandbox.available(), can_force, findings)
        self.stack.setCurrentWidget(self.result)
        self._stage = "idle"

    # ---- ações finais
    def open_file(self) -> None:
        if not (self.sr and self.path):
            return
        # o arquivo analisado precisa ser exatamente o que será aberto
        try:
            now = hash_file(self.path)["sha256"]
        except OSError as e:
            QMessageBox.warning(self, "Sentinela", f"Não foi possível ler o arquivo para conferir o hash:\n{e}")
            return
        if self.sr.hashes.get("sha256") not in (now, "-"):
            QMessageBox.critical(self, "Sentinela", "O arquivo foi MODIFICADO depois da análise (o hash mudou). "
                                 "Por segurança ele não será aberto. Analise-o de novo.")
            return
        v = build_verdict(self._all_findings(), bool(self.sbr and self.sbr.ran))
        if v.level != "safe":
            m = QMessageBox(QMessageBox.Warning, "Sentinela", f"Veredito: {v.headline} ({v.score}/100).\n\n{v.summary}\n\n"
                            "Tem certeza de que quer abrir/instalar este arquivo no seu computador?", parent=self)
            m.setTextFormat(Qt.PlainText)
            yes = m.addButton("Abrir mesmo assim", QMessageBox.DestructiveRole)
            m.addButton("Cancelar", QMessageBox.RejectRole)
            m.setDefaultButton(m.buttons()[-1])
            m.exec()
            if m.clickedButton() is not yes:
                return
        try:
            os.startfile(str(self.path))
        except OSError as e:
            QMessageBox.warning(self, "Sentinela", f"Não foi possível abrir o arquivo:\n{e}")

    def reveal_file(self) -> None:
        if self.path:
            subprocess.Popen(["explorer.exe", f"/select,{self.path}"])

    def delete_file(self) -> None:
        if not self.path or not self.path.exists():
            return
        if QMessageBox.question(self, "Sentinela", f"Enviar para a Lixeira?\n\n{self.path}") != QMessageBox.Yes:
            return
        ps = ("Add-Type -AssemblyName Microsoft.VisualBasic; "
              "[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($env:SENT_PATH,'OnlyErrorDialogs','SendToRecycleBin')")
        r = subprocess.run(["powershell.exe", "-NoProfile", "-Command", ps], env=dict(os.environ, SENT_PATH=str(self.path)),
                           capture_output=True, creationflags=CREATE_NO_WINDOW)
        if r.returncode == 0 and not self.path.exists():
            QMessageBox.information(self, "Sentinela", "Arquivo enviado para a Lixeira.")
            self.go_home()
        else:
            QMessageBox.warning(self, "Sentinela", "Não foi possível excluir o arquivo.")

    def save_report(self) -> None:
        if not self.sr:
            return
        findings = self._all_findings()
        v = build_verdict(findings, bool(self.sbr and self.sbr.ran))
        dest, _ = QFileDialog.getSaveFileName(self, "Salvar relatório", str(Path.home() / "Documents" / f"Sentinela_{self.sr.path.stem}.txt"), "Texto (*.txt)")
        if dest:
            Path(dest).write_text(build_report(self.sr, self.sbr, v, findings), encoding="utf-8")

    def enable_sandbox(self) -> None:
        QMessageBox.information(self, "Sentinela", "O Windows vai pedir permissão de administrador para ativar o recurso. "
                                "Depois, REINICIE o computador e analise o arquivo novamente.")
        sandbox.enable_feature_elevated()

    def closeEvent(self, e) -> None:
        self.analyzer.cancel()
        self.procs._cancel = True
        if self.procs.worker and self.procs.worker.isRunning():
            self.procs.worker.wait(8000)
        if self.worker and self.worker.isRunning():
            self.worker.wait(8000)
        self.analyzer.cleanup()
        super().closeEvent(e)


def main(argv: list[str]) -> int:
    Analyzer.purge_stale()
    app = QApplication(argv)
    app.setStyleSheet(QSS)
    app.setApplicationName("Sentinela")
    win = MainWindow()
    win.show()
    dark_titlebar(win)
    if len(argv) > 1 and Path(argv[1]).is_file():
        QTimer.singleShot(200, lambda: win.start_analysis(argv[1]))
    return app.exec()
