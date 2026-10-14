"""Aba "Computador": verificação do PC (Defender + ClamAV + persistência + higiene + processos) e quarentena reversível."""
from __future__ import annotations

import os
import subprocess
import time
from datetime import date
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QFileDialog, QFrame, QHBoxLayout, QMessageBox, QPushButton, QScrollArea, QStackedWidget,
                               QVBoxLayout, QWidget)

from . import components as comp
from . import pcscan as pc
from . import procscan as ps
from . import quarantine as quar
from . import scanengines as se
from .checks import VirusTotal
from .config import Settings
from .scoring import Finding
from .ui import AMBER, GREEN, LEVEL_COLOR, MUTED, RED, TEXT, FindingCard, Gauge, StepRow, Worker, card, lbl, set_style
from .ui_procs import wrapable

STEPS = [("upd", "Atualizar o Defender"), ("def", "Defender: varredura"), ("proc", "Processos em execução"), ("per", "O que inicia com o Windows"),
         ("hyg", "Higiene do Windows"), ("clam", "ClamAV: segunda opinião"), ("tri", "Triagem dos achados")]
MODE_TEXT = (("quick", "Rápida (10 a 15 min): Defender rápido, processos, inicialização, higiene e ClamAV só nos arquivos modificados nos últimos 30 dias nas pastas de risco"),
             ("full", "Completa (1 a 3 h): tudo da Rápida + Defender completo + ClamAV em todas as pastas de risco e de jogos/mods"))
LEVEL_NAME = {"danger": "Perigoso", "caution": "Atenção", "ok": "Sem alerta"}


class FileCard(QFrame):
    openFolder = Signal(object)
    analyze = Signal(object)
    quarantine = Signal(object)
    trust = Signal(object)

    def __init__(self, it: pc.FileItem) -> None:
        super().__init__()
        self.it = it
        self.setObjectName("cardAlt")
        color = {"danger": RED, "caution": AMBER}.get(it.level, MUTED)
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 0, 14, 0)
        h.setSpacing(12)
        bar = QFrame()
        bar.setFixedWidth(5)
        bar.setStyleSheet(f"background: {color}; border-top-left-radius: 12px; border-bottom-left-radius: 12px; border: none;")
        h.addWidget(bar)
        v = QVBoxLayout()
        v.setContentsMargins(0, 11, 0, 11)
        v.setSpacing(4)
        v.addWidget(lbl(wrapable(os.path.basename(it.path) or it.path), 14, 700, TEXT, True))
        meta = lbl(wrapable(f"{LEVEL_NAME.get(it.level, '')} · {ps.clean_text(it.path, 240)}"), 12, 400, MUTED, True)
        meta.setTextInteractionFlags(Qt.TextSelectableByMouse)
        v.addWidget(meta)
        for f in sorted(it.findings, key=lambda f: -f.points):
            if f.points <= 0 and f.severity == "info" and not f.trust:
                continue
            col = {"info": MUTED, "low": MUTED}.get(f.severity, color)
            v.addWidget(lbl(wrapable((f"{f.points:+d}".replace("-", "−") + "  " + f.title) if f.points else f.title), 13, 600, col, True))
            if f.detail:
                v.addWidget(lbl(wrapable(f.detail), 12, 400, MUTED, True))
        self.note = lbl("", 12, 600, GREEN, True)
        self.note.hide()
        v.addWidget(self.note)
        row = QHBoxLayout()
        row.setSpacing(8)
        self.buttons = []
        ok_q, why = quar.can_quarantine(it.path, it.sig) if it.exists else (False, "O arquivo não existe mais.")
        for text, sig, enabled, tip in (("Mostrar pasta", self.openFolder, it.exists, "Abre o Explorer no arquivo"),
                                        ("Analisar no Sentinela", self.analyze, it.exists, "Análise completa de arquivo (VirusTotal, estática e sandbox)"),
                                        ("Mover para a quarentena", self.quarantine, ok_q, "Move o arquivo para um cofre reversível" if ok_q else why),
                                        ("Confiar", self.trust, bool(it.sha256), "Marca este arquivo (pelo hash) como seu conhecido")):
            b = QPushButton(text)
            b.setToolTip(tip)
            b.setEnabled(enabled)
            b.setStyleSheet("padding: 6px 12px; font-size: 12px;")
            if "quarentena" in text:
                b.setObjectName("danger")
            b.clicked.connect(lambda _=False, s=sig: s.emit(self.it))
            self.buttons.append(b)
            row.addWidget(b)
        row.addStretch()
        v.addLayout(row)
        h.addLayout(v, 1)

    def set_note(self, text: str, ok: bool = True) -> None:
        self.note.setText(text)
        set_style(self.note, GREEN if ok else AMBER)
        self.note.show()


class QuarantineDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Quarentena")
        self.setMinimumWidth(640)
        self.v = QVBoxLayout(self)
        self.v.setContentsMargins(24, 22, 24, 20)
        self.v.setSpacing(8)
        self._fill()

    def _fill(self) -> None:
        while self.v.count():
            it = self.v.takeAt(0)
            if it.widget():
                it.widget().deleteLater()
            elif it.layout():
                while it.layout().count():
                    s = it.layout().takeAt(0)
                    if s.widget():
                        s.widget().deleteLater()
        self.v.addWidget(lbl("Quarentena", 18, 700))
        self.v.addWidget(lbl("Os arquivos ficam num cofre protegido, sem extensão executável. Nada é apagado: você pode restaurar. Restaurar nunca sobrescreve outro arquivo.", 12, 400, MUTED, True))
        es = quar.entries()
        if not es:
            self.v.addWidget(lbl("Nenhum arquivo na quarentena.", 13, 400, MUTED))
        for e in es:
            row = QHBoxLayout()
            when = time.strftime("%d/%m/%Y %H:%M", time.localtime(e.get("when", 0)))
            row.addWidget(lbl(wrapable(f"{ps.clean_text(e.get('original', ''), 200)}\n{when} · SHA-256 {str(e.get('sha256', ''))[:16]}…  {ps.clean_text(e.get('reason', ''), 80)}"), 12, 400, TEXT, True), 1)
            b = QPushButton("Restaurar")
            b.clicked.connect(lambda _=False, qid=e["id"]: self._restore(qid))
            row.addWidget(b)
            host = QWidget()
            host.setLayout(row)
            self.v.addWidget(host)
        close = QPushButton("Fechar")
        close.clicked.connect(self.accept)
        self.v.addWidget(close, 0, Qt.AlignRight)

    def _restore(self, qid: str) -> None:
        try:
            dest = quar.restore(qid)
            QMessageBox.information(self, "Sentinela", "Arquivo restaurado em:\n" + dest)
        except quar.QuarantineError as e:
            QMessageBox.warning(self, "Sentinela", str(e))
        self._fill()


class ScanPage(QWidget):
    busyChanged = Signal(bool)
    analyzeFile = Signal(str)
    openComponents = Signal()

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.setObjectName("page")
        self.settings = settings
        self.worker: Worker | None = None
        self.rep: pc.PcReport | None = None
        self._cancel = False
        self._keep: list = []
        self.rows: dict[str, StepRow] = {}
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.stack = QStackedWidget()
        lay.addWidget(self.stack)
        self.idle, self.prog, self.res = self._build_idle(), self._build_progress(), self._build_result()
        for w in (self.idle, self.prog, self.res):
            self.stack.addWidget(w)
        self._spin = QTimer(self, interval=40)
        self._spin.timeout.connect(self._rotate)
        self._spin.start()

    # ---------------------------------------------------------------- construção
    def _build_idle(self) -> QWidget:
        w = QWidget()
        w.setObjectName("page")
        root = QVBoxLayout(w)
        root.setContentsMargins(48, 24, 48, 28)
        root.addStretch(1)
        c = card()
        c.setFixedWidth(820)
        v = QVBoxLayout(c)
        v.setContentsMargins(30, 26, 30, 24)
        v.setSpacing(10)
        v.addWidget(lbl("Verificar o computador", 22, 700))
        v.addWidget(lbl("Combina o Microsoft Defender com uma segunda opinião (ClamAV, com assinaturas independentes) e olha o que os antivírus costumam deixar "
                        "de fora: o que inicia sozinho com o Windows, programas sem assinatura em pastas de risco, a higiene do Windows e os processos em execução.", 13, 400, MUTED, True))
        self.comp_line = lbl("", 12, 600, AMBER, True)
        v.addWidget(self.comp_line)
        self.mode = QComboBox()
        for k, t in MODE_TEXT:
            self.mode.addItem(t, k)
        v.addWidget(self.mode)
        self.upd = QCheckBox("Baixar/atualizar as assinaturas do ClamAV antes (cerca de 300 MB, direto do servidor oficial do ClamAV)")
        v.addWidget(self.upd)
        self.use_vt = QCheckBox("Consultar o VirusTotal para arquivos suspeitos sem assinatura (envia só o hash)")
        v.addWidget(self.use_vt)
        v.addWidget(lbl("Nada é apagado ou movido sozinho. Os achados aparecem com botões para você decidir (quarentena reversível, analisar, confiar).", 12, 400, TEXT, True))
        v.addWidget(lbl("Limites: não vê rootkits de kernel nem malware que só vive na memória; sem administrador as exclusões do Defender não são lidas; o ClamAV tem "
                        "muitos falsos positivos em mods e trainers (por isso uma detecção genérica de um único motor só gera atenção). Resultado limpo significa "
                        "\"sem indícios nos testes feitos\", nunca \"PC limpo\". Um antivírus residente continua sendo necessário.", 12, 400, AMBER, True))
        btns = QHBoxLayout()
        self.go = QPushButton("Verificar agora")
        self.go.setObjectName("primary")
        self.go.clicked.connect(self.start)
        self.b_comp = QPushButton("Componentes")
        self.b_comp.setObjectName("ghost")
        self.b_comp.clicked.connect(self.openComponents)
        self.b_q = QPushButton("Quarentena")
        self.b_q.setObjectName("ghost")
        self.b_q.clicked.connect(lambda: QuarantineDialog(self).exec())
        for b in (self.go, self.b_comp, self.b_q):
            btns.addWidget(b)
        btns.addStretch()
        v.addSpacing(4)
        v.addLayout(btns)
        root.addWidget(c, 0, Qt.AlignHCenter)
        root.addStretch(1)
        return w

    def _build_progress(self) -> QWidget:
        w = QWidget()
        w.setObjectName("page")
        root = QVBoxLayout(w)
        root.setContentsMargins(48, 32, 48, 28)
        root.setSpacing(16)
        c = card()
        h = QVBoxLayout(c)
        h.setContentsMargins(22, 16, 22, 16)
        self.prog_title = lbl("Verificando o computador…", 17, 700)
        h.addWidget(self.prog_title)
        self.prog_meta = lbl("Você pode usar o PC; a verificação usa prioridade baixa. Cancelar encerra todos os scanners.", 12, 400, MUTED, True)
        h.addWidget(self.prog_meta)
        root.addWidget(c)
        sc = card()
        sl = QVBoxLayout(sc)
        sl.setContentsMargins(24, 14, 24, 14)
        sl.setSpacing(0)
        for sid, title in STEPS:
            r = StepRow(title)
            self.rows[sid] = r
            sl.addWidget(r)
        sl.addStretch()
        root.addWidget(sc, 1)
        bottom = QHBoxLayout()
        bottom.addStretch()
        self.cancel_btn = QPushButton("Cancelar")
        self.cancel_btn.clicked.connect(self._on_cancel)
        bottom.addWidget(self.cancel_btn)
        root.addLayout(bottom)
        return w

    def _build_result(self) -> QWidget:
        w = QWidget()
        w.setObjectName("page")
        root = QVBoxLayout(w)
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
        self.headline = lbl("", 26, 700)
        self.headline.setAlignment(Qt.AlignCenter)
        lv.addWidget(self.headline)
        self.summary = lbl("", 13, 400, MUTED, True)
        self.summary.setAlignment(Qt.AlignCenter)
        lv.addWidget(self.summary)
        lv.addSpacing(6)
        self.stats = lbl("", 12, 400, MUTED, True)
        self.stats.setAlignment(Qt.AlignCenter)
        lv.addWidget(self.stats)
        lv.addStretch()
        body.addWidget(left)
        sc = QScrollArea()
        sc.setWidgetResizable(True)
        sc.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        host = QWidget()
        host.setObjectName("page")
        self.list = QVBoxLayout(host)
        self.list.setContentsMargins(0, 0, 8, 0)
        self.list.setSpacing(8)
        sc.setWidget(host)
        body.addWidget(sc, 1)
        root.addLayout(body, 1)
        bar = QHBoxLayout()
        b_rep = QPushButton("Salvar relatório")
        b_rep.clicked.connect(self._save_report)
        b_q = QPushButton("Quarentena")
        b_q.clicked.connect(lambda: QuarantineDialog(self).exec())
        b_new = QPushButton("Verificar de novo")
        b_new.setObjectName("primary")
        b_new.clicked.connect(self.show_idle)
        bar.addWidget(b_rep)
        bar.addWidget(b_q)
        bar.addStretch()
        bar.addWidget(b_new)
        root.addLayout(bar)
        return w

    # ---------------------------------------------------------------- estado
    def show_idle(self) -> None:
        self.refresh()
        self.stack.setCurrentWidget(self.idle)

    def refresh(self) -> None:
        try:
            man = comp.load_bundled_manifest(save=False)
            st = comp.detect("clamav", man["components"]["clamav"], man)
            has_db, age, why_db = se.clam_db_state()
            if st.state != comp.OK:
                self.comp_line.setText("ClamAV não está instalado e verificado: a verificação roda sem a 2ª opinião e o resultado fica Inconclusivo. Instale pela aba Componentes.")
                set_style(self.comp_line, AMBER)
                self.upd.setEnabled(False)
                self.upd.setChecked(False)
            else:
                msg = "ClamAV instalado e verificado." + ("" if has_db else f" Assinaturas: {why_db}. Marque a opção abaixo para baixar/refazer.") + (f" Assinaturas com {int(age)} dias." if has_db and age > 7 else "")
                self.comp_line.setText(msg)
                set_style(self.comp_line, GREEN if has_db and age <= 7 else AMBER)
                self.upd.setEnabled(True)
                self.upd.setChecked(not has_db or age > 7)
        except (comp.ComponentError, OSError):
            self.comp_line.setText("Lista de componentes inválida: reinstale o Sentinela.")
            set_style(self.comp_line, RED)
        has_key = bool(self.settings.vt_key)
        self.use_vt.setEnabled(has_key)
        self.use_vt.setChecked(has_key and bool(self.settings.data.get("proc_vt", True)))

    def _rotate(self) -> None:
        for r in self.rows.values():
            if r.icon.state == "run":
                r.icon.angle = (r.icon.angle + 12) % 360
                r.icon.update()

    # ---------------------------------------------------------------- execução
    def start(self) -> None:
        if self.worker and self.worker.isRunning():
            return
        mode = self.mode.currentData() or "quick"
        if mode == "full":
            m = QMessageBox(QMessageBox.Question, "Sentinela", "A verificação Completa pode levar de 1 a 3 horas e usa disco e CPU (em prioridade baixa). Continuar?", parent=self)
            yes = m.addButton("Continuar", QMessageBox.AcceptRole)
            m.addButton("Cancelar", QMessageBox.RejectRole)
            m.exec()
            if m.clickedButton() is not yes:
                return
        key = self.settings.vt_key
        vt = VirusTotal(key) if (key and self.use_vt.isChecked()) else None
        allow = self.upd.isChecked() and self.upd.isEnabled()
        self._cancel = False
        self.cancel_btn.setEnabled(True)
        self.cancel_btn.setText("Cancelar")
        for sid, _t in STEPS:
            self.rows[sid].update_state("pending", "Aguardando…")
            self.rows[sid].detail.setText("Aguardando…")
        self.prog_title.setText(f"Verificando o computador ({pc.MODES[mode].lower()})…")
        self.stack.setCurrentWidget(self.prog)
        self.busyChanged.emit(True)
        ids = [s for s, _ in STEPS]

        def work(emit):
            cur = {"i": -1}

            def step(i, msg=""):
                if i != cur["i"]:
                    if cur["i"] >= 0:
                        emit(ids[cur["i"]], "ok", "")
                    cur["i"] = i
                emit(ids[i], "run", msg)

            rep = pc.run_pc_scan(self.settings, mode, vt, allow, None, step, lambda: self._cancel)
            emit(ids[cur["i"]], "ok", "")
            return rep

        w = Worker(work)
        w.step.connect(lambda sid, st, d: self.rows[sid].update_state(st, ps.clean_text(d, 200)) if sid in self.rows else None)
        w.done.connect(self._on_done)
        w.failed.connect(self._on_failed)
        w.cancelled.connect(self._on_cancelled)
        self.worker = w
        self._keep = [x for x in self._keep if x.isRunning()] + [w]
        w.start()

    def _on_cancel(self) -> None:
        self._cancel = True
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.setText("Cancelando…")

    def _on_cancelled(self) -> None:
        self.busyChanged.emit(False)
        self.show_idle()

    def _on_failed(self, tb: str) -> None:
        self.busyChanged.emit(False)
        m = QMessageBox(QMessageBox.Critical, "Sentinela", "A verificação falhou por um erro inesperado.\n\n" + tb[-900:], parent=self)
        m.setTextFormat(Qt.PlainText)
        m.exec()
        self.show_idle()

    def _on_done(self, rep: pc.PcReport) -> None:
        self.rep = rep
        self.busyChanged.emit(False)
        QTimer.singleShot(300, lambda: self.show_result(rep))

    # ---------------------------------------------------------------- resultado
    def _section(self, title: str) -> None:
        t = lbl(title.upper(), 11, 700, MUTED)
        t.setContentsMargins(2, 8, 0, 0)
        self.list.addWidget(t)

    def show_result(self, rep: pc.PcReport) -> None:
        v = rep.verdict
        color = LEVEL_COLOR[v.level]
        self.headline.setText(v.headline)
        set_style(self.headline, color)
        self.summary.setText(ps.clean_text(v.summary, 600))
        self.gauge.show_score(v.score, color)
        s = rep.stats
        eng = " · ".join(f"{k}: {ps.clean_text(str(x), 40)}" for k, x in rep.engines.items())
        self.stats.setText(f"Verificação {pc.MODES.get(rep.mode, rep.mode).lower()} em {int(rep.elapsed // 60)} min {int(rep.elapsed % 60)} s\n{eng}\n"
                           f"{s['persist_total']} itens de inicialização · {s['zone_files']} arquivos nas zonas de risco")
        while self.list.count():
            it = self.list.takeAt(0)
            if it.widget():
                it.widget().deleteLater()
        flagged = [i for i in rep.items if i.level != "ok" or any(f.points > 0 for f in i.findings)]
        if flagged:
            self._section("Arquivos com detecção")
            for it in flagged:
                self.list.addWidget(self._file_card(it))
        if rep.persist:
            self._section("O que inicia com o Windows (pontos de atenção)")
            for p in rep.persist:
                for f in p.findings:
                    if f.points > 0 or f.severity != "info":
                        self.list.addWidget(FindingCard(Finding(f.stage, f"{f.title}", f"{p.kind} · {ps.clean_text(p.where, 80)}: {ps.clean_text(p.command, 200)}\n{f.detail}", f.points, f.severity)))
        hyg = [f for f in rep.hygiene if f.points > 0 or f.severity != "info"]
        if hyg:
            self._section("Higiene do Windows")
            for f in hyg:
                self.list.addWidget(FindingCard(f))
        if rep.procs is not None and rep.procs.verdict.level in ("danger", "caution"):
            self._section("Processos em execução")
            self.list.addWidget(lbl(f"A verificação de processos deu: {rep.procs.verdict.headline}. Abra a aba Processos e verifique de novo para ver os detalhes e agir.", 13, 600, AMBER, True))
        if rep.gaps:
            self._section("Não verificado (por isso o resultado é cauteloso)")
            for g in rep.gaps:
                self.list.addWidget(FindingCard(Finding("gap", g.title, g.detail, 0, "info", gap=True)))
        if rep.notes:
            self._section("Observações")
            for n in rep.notes:
                self.list.addWidget(lbl("•  " + wrapable(n), 12, 400, MUTED, True))
        self._section("Limites desta análise")
        for x in rep.limits:
            self.list.addWidget(lbl("•  " + wrapable(x), 12, 400, MUTED, True))
        self.list.addStretch()
        self.stack.setCurrentWidget(self.res)

    def _file_card(self, it: pc.FileItem) -> FileCard:
        c = FileCard(it)
        c.openFolder.connect(lambda i: subprocess.Popen(["explorer.exe", f"/select,{i.path}"]) if os.path.exists(i.path) else None)
        c.analyze.connect(lambda i: self.analyzeFile.emit(i.path))
        c.quarantine.connect(lambda i, card_=c: self._quarantine(i, card_))
        c.trust.connect(lambda i, card_=c: self._trust(i, card_))
        return c

    def _ask(self, text: str, yes: str, danger: bool = False) -> bool:
        m = QMessageBox(QMessageBox.Warning if danger else QMessageBox.Question, "Sentinela", text, parent=self)
        m.setTextFormat(Qt.PlainText)
        y = m.addButton(yes, QMessageBox.DestructiveRole if danger else QMessageBox.AcceptRole)
        m.addButton("Cancelar", QMessageBox.RejectRole)
        m.setDefaultButton(m.buttons()[-1])
        m.exec()
        return m.clickedButton() is y

    def _quarantine(self, it: pc.FileItem, c: FileCard) -> None:
        if not self._ask(f"Mover este arquivo para a quarentena?\n\n{ps.clean_text(it.path, 240)}\n\nEle fica num cofre protegido e você pode restaurá-lo depois. "
                         "Nada é apagado.", "Mover para a quarentena", danger=True):
            return
        try:
            e = quar.quarantine(it.path, "; ".join(f.title for f in it.findings if f.points > 0)[:200], it.sig, it.sha256)
        except quar.QuarantineError as ex:
            QMessageBox.warning(self, "Sentinela", str(ex))
            return
        for b in c.buttons:
            b.setEnabled(False)
        c.set_note("Movido para a quarentena. Você pode restaurar em \"Quarentena\".")

    def _trust(self, it: pc.FileItem, c: FileCard) -> None:
        if not it.sha256:
            return
        if not self._ask(f"Confiar neste arquivo?\n\n{ps.clean_text(it.path, 240)}\nSHA-256: {it.sha256[:32]}…\n\nEle deixa de gerar alertas enquanto não mudar.", "Confiar", danger=it.level == "danger"):
            return
        lst = [e for e in self.settings.data.get("proc_ignore", []) if isinstance(e, dict) and e.get("sha256") != it.sha256]
        lst.append({"sha256": it.sha256, "name": ps.clean_text(os.path.basename(it.path), 80), "motivo": f"confiado em {date.today().isoformat()}"})
        self.settings.data["proc_ignore"] = lst
        self.settings.save()
        c.set_note("Marcado como confiável.")
        for b in c.buttons:
            b.setEnabled(False)

    def _save_report(self) -> None:
        if not self.rep:
            return
        m = QMessageBox(QMessageBox.Question, "Sentinela", "Esconder seu nome de usuário e possíveis segredos nos caminhos do relatório? (recomendado)", parent=self)
        yes = m.addButton("Esconder (recomendado)", QMessageBox.AcceptRole)
        no = m.addButton("Manter tudo", QMessageBox.DestructiveRole)
        m.addButton("Cancelar", QMessageBox.RejectRole)
        m.exec()
        if m.clickedButton() not in (yes, no):
            return
        dest, _ = QFileDialog.getSaveFileName(self, "Salvar relatório", str(Path.home() / "Documents" / f"Sentinela_computador_{time.strftime('%Y%m%d_%H%M')}.txt"), "Texto (*.txt)")
        if dest:
            Path(dest).write_text(pc.report_text(self.rep, m.clickedButton() is yes), encoding="utf-8")
