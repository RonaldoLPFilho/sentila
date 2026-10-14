"""Tela "Componentes": guia o usuário a instalar as ferramentas de terceiros e valida SOZINHA (checkbox automático) se estão presentes e íntegras.
Os textos, links e instruções vêm do manifesto ASSINADO; o app só abre links https de domínios do próprio manifesto."""
from __future__ import annotations

import shutil
from pathlib import Path
from urllib.parse import urlparse

from PySide6.QtCore import QEvent, QObject, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QApplication, QFileDialog, QFrame, QHBoxLayout, QMessageBox, QPushButton, QScrollArea, QVBoxLayout, QWidget)

from . import components as comp
from .config import Settings
from .ui import ACCENT, AMBER, GREEN, MUTED, RED, TEXT, Worker, card, lbl, set_style
from .procscan import clean_text

STATE_TEXT = {
    comp.OK: ("Instalado e verificado", GREEN), comp.OUTDATED: ("Instalado, mas desatualizado", AMBER),
    comp.UNTRUSTED: ("Encontrado, mas NÃO confiável", RED), comp.MISSING: ("Não encontrado", MUTED),
    comp.UNREADABLE: ("Não foi possível verificar", AMBER), comp.REVOKED: ("Versão revogada", RED),
}
REQ_TEXT = {"required": "OBRIGATÓRIO", "recommended": "RECOMENDADO", "optional": "OPCIONAL"}


def safe_url(url: str, manifest_urls: list[str]) -> bool:
    """Só https e só hosts que aparecem no manifesto assinado."""
    u = urlparse(str(url))
    hosts = {urlparse(x).hostname for x in manifest_urls if isinstance(x, str)}
    return u.scheme == "https" and bool(u.hostname) and u.hostname in hosts


class Check(QFrame):
    """Checkbox somente-leitura: quem marca e desmarca é a detecção automática."""

    def __init__(self) -> None:
        super().__init__()
        self.setFixedSize(26, 26)
        self.on = False
        self.warn = False
        self._paint()

    def set(self, on: bool, warn: bool = False) -> None:
        self.on, self.warn = on, warn
        self._paint()

    def _paint(self) -> None:
        color = GREEN if self.on else (RED if self.warn else "#27324B")
        self.setStyleSheet(f"background: {color if (self.on or self.warn) else 'transparent'}; border: 2px solid {color}; border-radius: 7px;")
        self.setToolTip("Marcado automaticamente quando o componente é encontrado e verificado")


class ComponentCard(QFrame):
    importPkg = Signal(str)
    recheck = Signal()
    remove = Signal(str)
    openPage = Signal(str)

    def __init__(self, name: str, c: dict) -> None:
        super().__init__()
        self.name = name
        self.setObjectName("card")
        v = QVBoxLayout(self)
        v.setContentsMargins(22, 18, 22, 18)
        v.setSpacing(8)
        head = QHBoxLayout()
        self.check = Check()
        head.addWidget(self.check, 0, Qt.AlignTop)
        tv = QVBoxLayout()
        tv.setSpacing(2)
        tv.addWidget(lbl(clean_text(c.get("title", name), 120), 16, 700, TEXT, True))
        self.state = lbl("Verificando…", 13, 600, MUTED, True)
        tv.addWidget(self.state)
        head.addLayout(tv, 1)
        req = lbl(REQ_TEXT.get(c.get("required", "optional"), "OPCIONAL"), 11, 700, ACCENT)
        head.addWidget(req, 0, Qt.AlignTop)
        v.addLayout(head)
        v.addWidget(lbl(clean_text(c.get("purpose", ""), 400), 13, 400, MUTED, True))
        self.detail = lbl("", 12, 400, MUTED, True)
        v.addWidget(self.detail)
        self.steps = QWidget()
        sv = QVBoxLayout(self.steps)
        sv.setContentsMargins(0, 4, 0, 0)
        sv.setSpacing(4)
        sv.addWidget(lbl("COMO INSTALAR", 11, 700, MUTED))
        for i, step in enumerate(c.get("instructions", []), 1):
            sv.addWidget(lbl(f"{i}.  {clean_text(step, 300)}", 13, 400, TEXT, True))
        v.addWidget(self.steps)
        self.progress = lbl("", 12, 600, ACCENT, True)
        self.progress.hide()
        v.addWidget(self.progress)
        row = QHBoxLayout()
        row.setSpacing(8)
        self.b_page = QPushButton("Abrir página oficial")
        self.b_page.clicked.connect(lambda: self.openPage.emit(self.name))
        self.b_import = QPushButton("Importar pacote…")
        self.b_import.setObjectName("primary")
        self.b_import.clicked.connect(self._pick)
        self.b_re = QPushButton("Verificar de novo")
        self.b_re.clicked.connect(self.recheck)
        self.b_rm = QPushButton("Remover")
        self.b_rm.clicked.connect(lambda: self.remove.emit(self.name))
        for b in (self.b_page, self.b_import, self.b_re, self.b_rm):
            row.addWidget(b)
        row.addStretch()
        v.addLayout(row)

    def _pick(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Escolha o pacote baixado (.zip)", str(Path.home() / "Downloads"), "Pacotes (*.zip)")
        if path:
            self.importPkg.emit(path)

    def show_status(self, st: comp.Status) -> None:
        text, color = STATE_TEXT.get(st.state, ("?", MUTED))
        self.check.set(st.state == comp.OK, warn=st.state in (comp.UNTRUSTED, comp.REVOKED))
        self.state.setText(text + (f"  ·  versão {clean_text(st.version, 20)}" if st.version else ""))
        set_style(self.state, color)
        self.detail.setText(clean_text(st.detail, 300))
        self.steps.setVisible(st.state != comp.OK)
        self.b_rm.setEnabled(st.state != comp.MISSING)
        self.b_import.setText("Importar pacote…" if st.state in (comp.MISSING, comp.UNTRUSTED, comp.UNREADABLE) else "Importar versão nova…")

    def busy(self, on: bool, text: str = "") -> None:
        for b in (self.b_page, self.b_import, self.b_re, self.b_rm):
            b.setEnabled(not on)
        self.progress.setVisible(on)
        self.progress.setText(clean_text(text, 200))


class FocusWatcher(QObject):
    """Dispara a re-verificação quando a janela volta ao foco (o usuário instalou e voltou)."""
    activated = Signal()

    def __init__(self) -> None:
        super().__init__()
        QApplication.instance().applicationStateChanged.connect(lambda s: self.activated.emit() if s == Qt.ApplicationActive else None)


class ComponentsPage(QWidget):
    busyChanged = Signal(bool)
    changed = Signal()

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.setObjectName("page")
        self.settings = settings
        self.manifest: dict | None = None
        self.error = ""
        self.cards: dict[str, ComponentCard] = {}
        self.worker: Worker | None = None
        self._keep: list[Worker] = []
        self._pending = False
        self._busy = False
        root = QVBoxLayout(self)
        root.setContentsMargins(40, 26, 40, 22)
        root.setSpacing(12)
        root.addWidget(lbl("Componentes", 24, 700))
        root.addWidget(lbl("Ferramentas de terceiros que o Sentinela usa na verificação do computador. Nada vem junto com o instalador: você baixa "
                           "da fonte oficial e o Sentinela confere a assinatura, o hash e cada arquivo antes de usar. O marcador ao lado de cada "
                           "item é automático.", 13, 400, MUTED, True))
        self.summary = lbl("", 13, 600, TEXT, True)
        root.addWidget(self.summary)
        sc = QScrollArea()
        sc.setWidgetResizable(True)
        sc.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        host = QWidget()
        host.setObjectName("page")
        self.list = QVBoxLayout(host)
        self.list.setContentsMargins(0, 0, 8, 0)
        self.list.setSpacing(12)
        sc.setWidget(host)
        root.addWidget(sc, 1)
        self.watch = FocusWatcher()
        self.watch.activated.connect(self._on_focus)
        self._load_manifest()

    # ---------------------------------------------------------------- manifesto
    def _load_manifest(self) -> None:
        try:
            self.manifest = comp.load_bundled_manifest()
            self.error = ""
        except (comp.ComponentError, OSError) as e:
            self.manifest, self.error = None, str(e) or "manifesto ausente"
        while self.list.count():
            it = self.list.takeAt(0)
            if it.widget():
                it.widget().deleteLater()
        self.cards.clear()
        if not self.manifest:
            self.summary.setText("A lista de componentes não passou na verificação de integridade. Reinstale o Sentinela. Motivo: " + clean_text(self.error, 200))
            set_style(self.summary, RED)
            return
        for name, c in self.manifest["components"].items():
            card_ = ComponentCard(name, c)
            card_.importPkg.connect(lambda p, n=name: self._import(n, p))
            card_.recheck.connect(self.refresh)
            card_.remove.connect(self._remove)
            card_.openPage.connect(self._open_page)
            self.cards[name] = card_
            self.list.addWidget(card_)
        self.list.addStretch()

    def showEvent(self, e) -> None:
        super().showEvent(e)
        self.refresh()

    def _on_focus(self) -> None:
        if self.isVisible() and not self._busy:
            self.refresh()

    # ---------------------------------------------------------------- detecção automática (em segundo plano)
    def refresh(self) -> None:
        if not self.manifest or self._busy:
            return
        if self.worker and self.worker.isRunning():
            self._pending = True
            return
        man = self.manifest

        def work(emit):
            return {n: comp.detect(n, c, man) for n, c in man["components"].items()}

        w = Worker(work)
        w.done.connect(self._on_detected)
        w.failed.connect(lambda tb: self.summary.setText("Falha ao verificar os componentes."))
        self.worker = w
        self._keep = [x for x in self._keep if x.isRunning()] + [w]
        w.start()

    def _on_detected(self, res: dict) -> None:
        for n, st in res.items():
            if n in self.cards:
                self.cards[n].show_status(st)
        self.status = res
        missing = [self.manifest["components"][n].get("title", n) for n, s in res.items() if s.state != comp.OK and s.required in ("required", "recommended")]
        if not missing:
            self.summary.setText("Tudo o que é necessário ou recomendado está instalado e verificado.")
            set_style(self.summary, GREEN)
        else:
            self.summary.setText("Falta instalar ou corrigir: " + ", ".join(clean_text(m, 60) for m in missing) + ". Sem isso, a varredura roda com lacunas e o resultado fica Inconclusivo.")
            set_style(self.summary, AMBER)
        self.changed.emit()
        if self._pending:
            self._pending = False
            self.refresh()

    # ---------------------------------------------------------------- ações
    def _open_page(self, name: str) -> None:
        c = self.manifest["components"][name]
        urls = [c.get("download_page", "")] + [c.get("archive", {}).get(k, "") for k in ("url", "sig_url")]
        if safe_url(c.get("download_page", ""), urls):
            QDesktopServices.openUrl(QUrl(c["download_page"]))

    def _import(self, name: str, zip_path: str) -> None:
        c = self.manifest["components"][name]
        zp = Path(zip_path)
        sigp = zp.with_name(zp.name + ".sig")
        if not sigp.exists():
            sg, _ = QFileDialog.getOpenFileName(self, "Escolha o arquivo de assinatura (.sig) deste pacote", str(zp.parent), "Assinatura (*.sig *.asc)")
            if not sg:
                return
            sigp = Path(sg)
        key_bytes = self._key_bytes(c)
        if key_bytes is None:
            QMessageBox.warning(self, "Sentinela", "A chave pública do fornecedor não está disponível neste app. Reinstale o Sentinela.")
            return
        card_ = self.cards[name]
        card_.busy(True, "Verificando…")
        self._busy = True
        self.busyChanged.emit(True)
        man = self.manifest

        def work(emit):
            return comp.install_package(name, c, zp, sigp.read_bytes(), key_bytes, man, lambda m: emit("x", "run", m))

        w = Worker(work)
        w.step.connect(lambda sid, st, d: card_.busy(True, d))
        w.done.connect(lambda dest: self._import_done(name, ""))
        w.cancelled.connect(lambda: self._import_done(name, "cancelado"))

        def failed(tb: str) -> None:
            # ComponentError vem como texto do traceback: mostra só a última linha (mensagem em português, sem dados do arquivo)
            last = [ln for ln in tb.strip().splitlines() if ln.strip()][-1] if tb.strip() else ""
            msg = last.split("ComponentError:", 1)[1].strip() if "ComponentError:" in last else "falha inesperada ao instalar"
            self._import_done(name, msg)

        w.failed.connect(failed)
        self._keep = [x for x in self._keep if x.isRunning()] + [w]
        w.start()

    def _import_done(self, name: str, err: str) -> None:
        self._busy = False
        self.busyChanged.emit(False)
        self.cards[name].busy(False)
        if err:
            m = QMessageBox(QMessageBox.Critical, "Sentinela", "O pacote NÃO foi instalado.\n\n" + clean_text(err, 300) +
                            "\n\nBaixe de novo pela página oficial e importe o ZIP e o .sig originais.", parent=self)
            m.setTextFormat(Qt.PlainText)
            m.exec()
        self.refresh()

    @staticmethod
    def _key_bytes(c: dict) -> bytes | None:
        # chave pública do fornecedor distribuída com o app; o que vale é o fingerprint pinado no manifesto assinado
        try:
            return (Path(__file__).with_name("keys") / "talos_clamav_key.asc").read_bytes()
        except OSError:
            return None

    def _remove(self, name: str) -> None:
        m = QMessageBox(QMessageBox.Question, "Sentinela", "Remover este componente do Sentinela? (Não afeta outros programas.)", parent=self)
        yes = m.addButton("Remover", QMessageBox.DestructiveRole)
        m.addButton("Cancelar", QMessageBox.RejectRole)
        m.exec()
        if m.clickedButton() is yes:
            shutil.rmtree(comp.COMP_DIR / name, ignore_errors=True)
            self.refresh()
