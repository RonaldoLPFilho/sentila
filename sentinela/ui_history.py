"""Aba "Histórico": as últimas análises de todos os tipos, com o relatório de cada uma."""
from __future__ import annotations

import time
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (QDialog, QFileDialog, QFrame, QHBoxLayout, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QVBoxLayout, QWidget)

from . import history as hist
from . import procscan as ps
from .ui import AMBER, GREEN, LEVEL_COLOR, MUTED, RED, TEXT, card, lbl
from .ui_procs import wrapable

KIND_ICON = {"files": "Arquivo", "procs": "Processos", "net": "Rede", "pc": "Computador"}


def fmt_dur(sec: float) -> str:
    s = int(max(0, sec))
    return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"


class ReportDialog(QDialog):
    """Mostra o relatório como TEXTO PURO (nada é interpretado como HTML)."""

    def __init__(self, entry: dict, parent=None) -> None:
        super().__init__(parent)
        self.entry = entry
        self.setWindowTitle(f"Relatório · {KIND_ICON.get(entry['kind'], '')} · {ps.clean_text(entry['title'], 60)}")
        self.resize(860, 620)
        v = QVBoxLayout(self)
        v.setContentsMargins(20, 18, 20, 16)
        v.setSpacing(10)
        v.addWidget(lbl(wrapable(entry["title"]), 17, 700, TEXT, True))
        v.addWidget(lbl(f"{time.strftime('%d/%m/%Y %H:%M', time.localtime(entry['when']))} · duração {fmt_dur(entry['duration'])} · {entry['headline']} (pontuação {entry['score']})",
                        12, 400, MUTED, True))
        box = QPlainTextEdit()
        box.setReadOnly(True)
        f = QFont("Consolas")
        f.setPixelSize(12)
        box.setFont(f)
        box.setLineWrapMode(QPlainTextEdit.NoWrap)
        box.setPlainText(entry["report"])
        v.addWidget(box, 1)
        row = QHBoxLayout()
        b_save = QPushButton("Salvar como .txt")
        b_save.clicked.connect(self._save)
        b_close = QPushButton("Fechar")
        b_close.setObjectName("primary")
        b_close.clicked.connect(self.accept)
        row.addWidget(b_save)
        row.addStretch()
        row.addWidget(b_close)
        v.addLayout(row)

    def _save(self) -> None:
        name = f"Sentinela_{self.entry['kind']}_{time.strftime('%Y%m%d_%H%M', time.localtime(self.entry['when']))}.txt"
        dest, _ = QFileDialog.getSaveFileName(self, "Salvar relatório", str(Path.home() / "Documents" / name), "Texto (*.txt)")
        if dest:
            Path(dest).write_text(self.entry["report"], encoding="utf-8")


class EntryCard(QFrame):
    view = Signal(object)
    remove = Signal(object)

    def __init__(self, e: dict) -> None:
        super().__init__()
        self.e = e
        self.setObjectName("cardAlt")
        color = LEVEL_COLOR.get(e["level"], MUTED)
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 0, 14, 0)
        h.setSpacing(12)
        bar = QFrame()
        bar.setFixedWidth(5)
        bar.setStyleSheet(f"background: {color}; border-top-left-radius: 12px; border-bottom-left-radius: 12px; border: none;")
        h.addWidget(bar)
        v = QVBoxLayout()
        v.setContentsMargins(0, 11, 0, 11)
        v.setSpacing(3)
        v.addWidget(lbl(wrapable(f"{KIND_ICON.get(e['kind'], '')} · {e['title']}"), 14, 700, TEXT, True))
        v.addWidget(lbl(f"{time.strftime('%d/%m/%Y %H:%M', time.localtime(e['when']))} · duração {fmt_dur(e['duration'])}" + (f" · {e['detail']}" if e["detail"] else ""), 12, 400, MUTED, True))
        v.addWidget(lbl(f"{e['headline']} · pontuação {e['score']}", 13, 700, color, True))
        if e["summary"]:
            v.addWidget(lbl(wrapable(e["summary"]), 12, 400, MUTED, True))
        h.addLayout(v, 1)
        col = QVBoxLayout()
        col.setSpacing(6)
        col.setContentsMargins(0, 10, 0, 10)
        b1 = QPushButton("Ver relatório")
        b1.setObjectName("primary")
        b1.setStyleSheet("padding: 6px 14px; font-size: 12px;")
        b1.clicked.connect(lambda: self.view.emit(self.e))
        b2 = QPushButton("Remover")
        b2.setStyleSheet("padding: 6px 14px; font-size: 12px;")
        b2.clicked.connect(lambda: self.remove.emit(self.e))
        col.addWidget(b1)
        col.addWidget(b2)
        col.addStretch()
        h.addLayout(col)


class HistoryPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("page")
        root = QVBoxLayout(self)
        root.setContentsMargins(40, 26, 40, 22)
        root.setSpacing(12)
        top = QHBoxLayout()
        v = QVBoxLayout()
        v.setSpacing(4)
        v.addWidget(lbl("Histórico", 24, 700))
        self.sub = lbl("", 13, 400, MUTED, True)
        v.addWidget(self.sub)
        top.addLayout(v, 1)
        self.b_clear = QPushButton("Limpar histórico")
        self.b_clear.setObjectName("danger")
        self.b_clear.clicked.connect(self._clear)
        top.addWidget(self.b_clear, 0, Qt.AlignTop)
        root.addLayout(top)
        root.addWidget(lbl("Guarda as últimas 10 análises de todos os tipos (arquivo, processos, rede e computador), com o relatório de cada uma. Fica só neste "
                           "computador e os relatórios já são salvos com seu nome de usuário e possíveis segredos escondidos.", 12, 400, MUTED, True))
        sc = QScrollArea()
        sc.setWidgetResizable(True)
        sc.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        host = QWidget()
        host.setObjectName("page")
        self.list = QVBoxLayout(host)
        self.list.setContentsMargins(0, 0, 8, 0)
        self.list.setSpacing(8)
        sc.setWidget(host)
        root.addWidget(sc, 1)

    def showEvent(self, e) -> None:
        super().showEvent(e)
        self.refresh()

    def refresh(self) -> None:
        while self.list.count():
            it = self.list.takeAt(0)
            if it.widget():
                it.widget().deleteLater()
        es = hist.entries()
        self.sub.setText(f"{len(es)} de {hist.MAX_ENTRIES} análises guardadas" if es else "Nenhuma análise ainda.")
        self.b_clear.setEnabled(bool(es))
        if not es:
            self.list.addWidget(lbl("Quando você terminar uma análise (arquivo, processos, rede ou computador), ela aparece aqui.", 13, 400, MUTED, True))
        for e in es:
            c = EntryCard(e)
            c.view.connect(lambda ent: ReportDialog(ent, self).exec())
            c.remove.connect(self._remove)
            self.list.addWidget(c)
        self.list.addStretch()

    def _remove(self, e: dict) -> None:
        hist.remove(e["id"])
        self.refresh()

    def _clear(self) -> None:
        m = QMessageBox(QMessageBox.Question, "Sentinela", "Apagar todo o histórico de análises deste computador? (Isto não afeta nenhum arquivo analisado.)", parent=self)
        yes = m.addButton("Limpar", QMessageBox.DestructiveRole)
        m.addButton("Cancelar", QMessageBox.RejectRole)
        m.exec()
        if m.clickedButton() is yes:
            hist.clear()
            self.refresh()
