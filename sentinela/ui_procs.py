"""Tela "Processos": verifica o que está rodando agora (assinatura, comportamento, mineração, rede) e mostra o resultado.
Todo texto vindo do sistema passa por clean_text() e é exibido como texto puro; tooltips usam apenas frases fixas."""
from __future__ import annotations

import os
import re
import subprocess
import time
from datetime import date
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QDialog, QFileDialog, QFrame, QHBoxLayout, QMessageBox,
                               QPushButton, QScrollArea, QStackedWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from . import procscan as ps
from .checks import VirusTotal
from .config import Settings
from .scoring import Finding
from .ui import ACCENT, AMBER, BORDER, GREEN, LEVEL_COLOR, MUTED, RED, TEXT, FindingCard, Gauge, StepRow, Worker, card, lbl, set_style

PROC_STEPS = [
    ("inv", "Lista de processos em execução"),
    ("sig", "Assinatura digital dos programas"),
    ("vt", "Reputação · VirusTotal (só o hash)"),
    ("obs", "Comportamento · CPU, GPU e rede"),
    ("ana", "Ponderação do risco"),
]
STATUS_LABEL = {
    "verified": "Verificado", "reputation": "Reputação limpa", "user": "Confiável (você)", "unverified": "Sem verificação",
    "unreadable": "Ilegível", "failed": "Falha na verificação", "remote": "Executa da rede", "system": "Sistema",
}
LEVEL_NAME = {"danger": "Perigoso", "caution": "Atenção", "ok": "Sem alerta"}
_LONG = re.compile(r"(\S{36})(?=\S)")


def wrapable(text: str) -> str:
    """Texto hostil pode ser uma palavra gigante sem espaços, que o QLabel não quebra e que alargaria a tela. Só para EXIBIR."""
    return _LONG.sub(lambda m: m.group(1) + chr(0x200B), ps.clean_text(text, 2000))


class ProcCard(QFrame):
    """Um processo com os motivos do alerta e as ações possíveis (nenhuma automática)."""
    openFolder = Signal(object)
    analyze = Signal(object)
    trust = Signal(object)
    suspend = Signal(object)
    terminate = Signal(object)

    def __init__(self, p: ps.Proc) -> None:
        super().__init__()
        self.p = p
        self.setObjectName("cardAlt")
        color = {"danger": RED, "caution": AMBER}.get(p.level, MUTED)
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
        head = lbl(wrapable(f"{p.name}  ·  PID {p.pid}"), 14, 700, TEXT, True)
        v.addWidget(head)
        who = p.publisher or STATUS_LABEL.get(p.status, "")
        meta = lbl(wrapable(f"{LEVEL_NAME.get(p.level, '')} · {who}" + (f" · {ps.clean_text(p.exe, 200)}" if p.exe else "")), 12, 400, MUTED, True)
        meta.setTextInteractionFlags(Qt.TextSelectableByMouse)
        v.addWidget(meta)
        for f in sorted(p.findings, key=lambda f: -f.points):
            if f.points <= 0 and f.severity == "info" and not f.trust:
                continue
            fc = {"info": MUTED, "low": MUTED}.get(f.severity, color)
            v.addWidget(lbl(wrapable((f"{f.points:+d}".replace("-", "−") + "  " + f.title) if f.points else f.title), 13, 600, fc, True))
            if f.detail:
                d = lbl(wrapable(f.detail), 12, 400, MUTED, True)
                d.setTextInteractionFlags(Qt.TextSelectableByMouse)
                v.addWidget(d)
        self.note = lbl("", 12, 600, GREEN, True)
        self.note.hide()
        v.addWidget(self.note)
        row = QHBoxLayout()
        row.setSpacing(8)
        self.buttons: list[QPushButton] = []
        exists = bool(p.exe) and p.kind in ("local", "removable") and p.exists
        for text, sig, enabled, tip in (
            ("Mostrar pasta", self.openFolder, exists, "Abre o Explorer no arquivo do programa"),
            ("Analisar arquivo", self.analyze, exists, "Envia o arquivo para a análise completa do Sentinela"),
            ("Confiar", self.trust, bool(p.sha256), "Marca este arquivo (pelo hash) como seu conhecido"),
            ("Suspender", self.suspend, not ps.action_block_reason(p), "Pausa o processo sem encerrá-lo; dá para retomar"),
            ("Encerrar", self.terminate, not ps.action_block_reason(p), "Encerra o processo (não remove o que ele instalou)"),
        ):
            b = QPushButton(text)
            b.setToolTip(tip)
            b.setEnabled(enabled)
            b.setStyleSheet("padding: 6px 12px; font-size: 12px;")
            if text == "Encerrar":
                b.setObjectName("danger")
            b.clicked.connect(lambda _=False, s=sig: s.emit(self.p))
            self.buttons.append(b)
            row.addWidget(b)
        row.addStretch()
        v.addLayout(row)
        h.addLayout(v, 1)

    def set_note(self, text: str, ok: bool = True) -> None:
        self.note.setText(text)
        set_style(self.note, GREEN if ok else AMBER)
        self.note.show()


class AllProcsDialog(QDialog):
    def __init__(self, rep: ps.ScanReport, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Todos os processos")
        self.resize(1000, 560)
        v = QVBoxLayout(self)
        t = QTableWidget(len(rep.procs), 6)
        t.setHorizontalHeaderLabels(["Nome", "PID", "Situação", "CPU média %", "Destinos externos", "Caminho"])
        t.setEditTriggers(QAbstractItemView.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectRows)
        t.verticalHeader().hide()
        ncores = rep.stats.get("ncores", 1)
        for r, p in enumerate(rep.procs):
            st = ps.cpu_stats(p.cpu, ncores)
            vals = [p.name, p.pid, STATUS_LABEL.get(p.status, p.status) + (f" · {p.publisher}" if p.publisher else ""),
                    round(st["avg"], 1) if st else 0.0, len(p.remote_ips), ps.clean_text(p.exe, 260)]
            for c, val in enumerate(vals):
                it = QTableWidgetItem()
                it.setData(Qt.DisplayRole, val)
                t.setItem(r, c, it)
        t.setSortingEnabled(True)
        t.sortByColumn(3, Qt.DescendingOrder)
        t.horizontalHeader().setStretchLastSection(True)
        t.setColumnWidth(0, 200)
        t.setColumnWidth(2, 260)
        v.addWidget(t)


class TrustDialog(QDialog):
    """Lista de programas em que o usuário confia (por SHA-256), com opção de revogar."""

    def __init__(self, settings: Settings, parent=None) -> None:
        super().__init__(parent)
        self.s = settings
        self.setWindowTitle("Programas confiáveis")
        self.setMinimumWidth(560)
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
                    sub = it.layout().takeAt(0)
                    if sub.widget():
                        sub.widget().deleteLater()
        self.v.addWidget(lbl("Programas confiáveis", 18, 700))
        self.v.addWidget(lbl("Estes arquivos não geram alertas (exceto os críticos de linha de comando). Se o arquivo mudar, a confiança deixa de valer.",
                             12, 400, MUTED, True))
        entries = [e for e in self.s.data.get("proc_ignore", []) if isinstance(e, dict)]
        if not entries:
            self.v.addWidget(lbl("Nenhum programa marcado.", 13, 400, MUTED))
        for e in entries:
            row = QHBoxLayout()
            row.addWidget(lbl(f"{ps.clean_text(e.get('name', '?'), 60)}  ·  {str(e.get('sha256', ''))[:16]}…  ·  {ps.clean_text(e.get('motivo', ''), 60)}", 12, 400, TEXT, True), 1)
            b = QPushButton("Revogar")
            b.clicked.connect(lambda _=False, sha=e.get("sha256"): self._remove(sha))
            row.addWidget(b)
            host = QWidget()
            host.setLayout(row)
            self.v.addWidget(host)
        close = QPushButton("Fechar")
        close.clicked.connect(self.accept)
        self.v.addWidget(close, 0, Qt.AlignRight)

    def _remove(self, sha) -> None:
        self.s.data["proc_ignore"] = [e for e in self.s.data.get("proc_ignore", []) if not (isinstance(e, dict) and e.get("sha256") == sha)]
        self.s.save()
        self._fill()


class ProcessPage(QWidget):
    busyChanged = Signal(bool)
    analyzeFile = Signal(str)

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.setObjectName("page")
        self.settings = settings
        self.worker: Worker | None = None
        self.rep: ps.ScanReport | None = None
        self._cancel = False
        self.rows: dict[str, StepRow] = {}
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.stack = QStackedWidget()
        lay.addWidget(self.stack)
        self.idle, self.prog, self.res = self._build_idle(), self._build_progress(), self._build_result()
        for w in (self.idle, self.prog, self.res):
            self.stack.addWidget(w)
        self.stack.setCurrentWidget(self.idle)
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
        c.setMaximumWidth(760)
        v = QVBoxLayout(c)
        v.setContentsMargins(30, 26, 30, 24)
        v.setSpacing(10)
        v.addWidget(lbl("Verificar processos em execução", 22, 700))
        v.addWidget(lbl("Olha tudo o que está rodando agora no seu PC e procura sinais de programa malicioso, mineração de criptomoeda, "
                        "consumo estranho de CPU/GPU e comportamento de rede típico de botnet. Nada é encerrado sem a sua confirmação.",
                        13, 400, MUTED, True))
        v.addWidget(lbl("O que é verificado", 12, 700, TEXT))
        for line in ("Assinatura digital de cada programa e reputação (VirusTotal, só o hash) dos que não têm assinatura",
                     "Programas que fingem ser do Windows, executáveis apagados, comandos suspeitos (PowerShell codificado…)",
                     "Mineradores: nome, parâmetros, conexão com pools e uso contínuo de CPU/GPU",
                     "Rede: varredura de outros PCs, portas de IRC/Tor, programas escutando conexões",
                     "Programas que se registram para iniciar com o Windows, e o estado do Defender"):
            v.addWidget(lbl("•  " + line, 12, 400, TEXT, True))
        v.addWidget(lbl("O que NÃO dá para ver: rootkits, malware que só vive na memória, mineração dentro do navegador ou que se esconde "
                        "reduzindo o uso. Um resultado limpo significa “sem indícios nos testes feitos”, nunca “PC limpo”.", 12, 400, AMBER, True))
        row = QHBoxLayout()
        row.addWidget(lbl("Tempo de observação:", 13))
        self.secs = QComboBox()
        for s, t in ((30, "30 s (rápido; não avalia consumo contínuo)"), (60, "60 s (recomendado)"), (120, "120 s (mais sensível)")):
            self.secs.addItem(t, s)
        row.addWidget(self.secs)
        row.addStretch()
        v.addLayout(row)
        self.use_vt = QCheckBox("Consultar o VirusTotal para programas sem assinatura (envia só o hash, nunca o arquivo)")
        v.addWidget(self.use_vt)
        self.susp_host = QWidget()
        self.susp_lay = QVBoxLayout(self.susp_host)
        self.susp_lay.setContentsMargins(0, 6, 0, 0)
        v.addWidget(self.susp_host)
        btns = QHBoxLayout()
        self.go = QPushButton("Verificar agora")
        self.go.setObjectName("primary")
        self.go.clicked.connect(self.start)
        self.trust_btn = QPushButton("Programas confiáveis")
        self.trust_btn.setObjectName("ghost")
        self.trust_btn.clicked.connect(self._manage_trust)
        btns.addWidget(self.go)
        btns.addWidget(self.trust_btn)
        btns.addStretch()
        v.addSpacing(6)
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
        h.addWidget(lbl("Verificando processos…", 17, 700))
        self.prog_meta = lbl("", 12, 400, MUTED, True)
        h.addWidget(self.prog_meta)
        root.addWidget(c)
        self.steps_card = card()
        sl = QVBoxLayout(self.steps_card)
        sl.setContentsMargins(24, 14, 24, 14)
        sl.setSpacing(0)
        for sid, title in PROC_STEPS:
            r = StepRow(title)
            self.rows[sid] = r
            sl.addWidget(r)
        sl.addStretch()
        root.addWidget(self.steps_card, 1)
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
        bar.setSpacing(10)
        b_all = QPushButton("Ver todos os processos")
        b_all.clicked.connect(self._show_all)
        b_rep = QPushButton("Salvar relatório")
        b_rep.clicked.connect(self._save_report)
        b_new = QPushButton("Verificar de novo")
        b_new.setObjectName("primary")
        b_new.clicked.connect(self.show_idle)
        bar.addWidget(b_all)
        bar.addWidget(b_rep)
        bar.addStretch()
        bar.addWidget(b_new)
        root.addLayout(bar)
        return w

    # ---------------------------------------------------------------- estado
    def show_idle(self) -> None:
        self.refresh()
        self.stack.setCurrentWidget(self.idle)

    def refresh(self) -> None:
        sec = int(self.settings.data.get("proc_seconds", 60))
        self.secs.setCurrentIndex(max(0, self.secs.findData(sec)))
        has_key = bool(self.settings.vt_key)
        self.use_vt.setEnabled(has_key)
        self.use_vt.setChecked(has_key and bool(self.settings.data.get("proc_vt", True)))
        self.use_vt.setText("Consultar o VirusTotal para programas sem assinatura (envia só o hash, nunca o arquivo)" if has_key
                            else "VirusTotal sem chave: configure em Configurações para checar a reputação dos programas sem assinatura")
        n = len([e for e in self.settings.data.get("proc_ignore", []) if isinstance(e, dict)])
        self.trust_btn.setText(f"Programas confiáveis ({n})" if n else "Programas confiáveis")
        while self.susp_lay.count():
            it = self.susp_lay.takeAt(0)
            if it.widget():
                it.widget().deleteLater()
        for e in [x for x in self.settings.data.get("proc_suspended", []) if isinstance(x, dict)]:
            row = QHBoxLayout()
            row.addWidget(lbl(f"Suspenso por você: {ps.clean_text(e.get('name', '?'), 50)} (PID {e.get('pid')})", 12, 600, AMBER, True), 1)
            b = QPushButton("Retomar")
            b.clicked.connect(lambda _=False, ent=e: self._resume(ent))
            row.addWidget(b)
            host = QWidget()
            host.setLayout(row)
            self.susp_lay.addWidget(host)

    def _resume(self, e: dict) -> None:
        p = ps.Proc(pid=int(e.get("pid", 0) or 0), name=str(e.get("name", "")), exe=str(e.get("exe", "")), create_time=float(e.get("create_time", 0) or 0))
        import psutil
        if not psutil.pid_exists(p.pid):
            msg = ""  # o processo já terminou: só limpa a entrada
        else:
            msg = ps.act_on_process(p, "resume")
        if msg and "mudou" not in msg:
            QMessageBox.warning(self, "Sentinela", msg)
            return
        self.settings.data["proc_suspended"] = [x for x in self.settings.data.get("proc_suspended", []) if x != e]
        self.settings.save()
        self.refresh()

    def _manage_trust(self) -> None:
        TrustDialog(self.settings, self).exec()
        self.refresh()

    def _rotate(self) -> None:
        for r in self.rows.values():
            if r.icon.state == "run":
                r.icon.angle = (r.icon.angle + 12) % 360
                r.icon.update()

    # ---------------------------------------------------------------- execução
    def start(self) -> None:
        if self.worker and self.worker.isRunning():
            return
        secs = int(self.secs.currentData() or 60)
        self.settings.data["proc_seconds"] = secs
        self.settings.data["proc_vt"] = self.use_vt.isChecked()
        self.settings.save()
        key = self.settings.vt_key
        vt = VirusTotal(key) if (key and self.use_vt.isChecked()) else None
        self._cancel = False
        self.cancel_btn.setEnabled(True)
        self.cancel_btn.setText("Cancelar")
        for sid, _t in PROC_STEPS:
            self.rows[sid].update_state("pending", "Aguardando…")
            self.rows[sid].detail.setText("Aguardando…")
        self.prog_meta.setText(f"Observação de {secs} s. Pode usar o PC normalmente; abrir e fechar programas durante a leitura é normal.")
        self.stack.setCurrentWidget(self.prog)
        self.busyChanged.emit(True)
        ids = [s for s, _ in PROC_STEPS]

        def work(emit):
            cur = {"i": -1}

            def step(i, msg=""):
                if i != cur["i"]:
                    if cur["i"] >= 0:
                        emit(ids[cur["i"]], "ok", "")
                    cur["i"] = i
                emit(ids[i], "run", msg)

            rep = ps.run_scan(self.settings, vt, secs, step, lambda: self._cancel)
            emit(ids[cur["i"]], "ok", "")
            return rep

        w = Worker(work)
        w.step.connect(self._on_step)
        w.done.connect(self._on_done)
        w.failed.connect(self._on_failed)
        w.cancelled.connect(self._on_cancelled)
        self.worker = w
        self._keep = [x for x in getattr(self, "_keep", []) if x.isRunning()] + [w]
        w.start()

    def _on_step(self, sid: str, state: str, detail: str) -> None:
        if sid in self.rows:
            self.rows[sid].update_state(state, ps.clean_text(detail, 200))

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

    def _on_done(self, rep: ps.ScanReport) -> None:
        self.rep = rep
        self.busyChanged.emit(False)
        QTimer.singleShot(350, lambda: self.show_result(rep))

    # ---------------------------------------------------------------- resultado
    def _section(self, title: str) -> None:
        t = lbl(title.upper(), 11, 700, MUTED)
        t.setContentsMargins(2, 8, 0, 0)
        self.list.addWidget(t)

    def show_result(self, rep: ps.ScanReport) -> None:
        v = rep.verdict
        color = LEVEL_COLOR[v.level]
        self.headline.setText(v.headline)
        set_style(self.headline, color)
        self.summary.setText(ps.clean_text(v.summary, 600))
        self.gauge.show_score(v.score, color)
        s = rep.stats
        self.stats.setText(f"{s['total']} processos · {s['verified']} com assinatura/pacote verificado · {s['unverified']} sem verificação\n"
                           f"{rep.seconds} s observados em {rep.elapsed:.0f} s"
                           + (f"{chr(10)}{len(s['trusted'])} ignorado(s) por Confiar" if s.get("trusted") else ""))
        while self.list.count():
            it = self.list.takeAt(0)
            if it.widget():
                it.widget().deleteLater()
        flagged = sorted([p for p in rep.procs if p.level in ("danger", "caution")], key=lambda p: -p.score)
        light = sorted([p for p in rep.procs if p.level == "ok" and any(f.points > 0 for f in p.findings)], key=lambda p: -p.score)
        m_risk = [f for f in rep.machine if f.points > 0]
        if flagged or m_risk:
            self._section("Pontos de atenção")
            for f in m_risk:
                self.list.addWidget(FindingCard(f))
            for p in flagged:
                self.list.addWidget(self._card(p))
        if light:
            self._section("Sinais leves (não bastam para alertar)")
            for p in light:
                self.list.addWidget(self._card(p))
        unknown = [Finding("gap", g.title, g.detail, 0, "info", gap=True) for g in rep.gaps] + \
                  [Finding("gap", x, "", 0, "info", gap=True) for x in rep.limits]
        if unknown:
            self._section("Não verificado (por isso o resultado é cauteloso)")
            for f in unknown:
                self.list.addWidget(FindingCard(f))
        if rep.top:
            self._section("Maiores consumidores durante a observação")
            for p, cpu, gpu in rep.top:
                who = p.publisher or STATUS_LABEL.get(p.status, "")
                self.list.addWidget(lbl(wrapable(f"{p.name} (PID {p.pid})  ·  CPU {cpu:.0f}%  ·  GPU {gpu:.0f}%  ·  {who}"), 12, 400, TEXT, True))
        self._section("Informações")
        self.list.addWidget(lbl(f"{s['verified']} processos têm assinatura digital válida ou são apps empacotados do Windows. Isso confirma o "
                                "arquivo no disco, não o que está na memória.", 12, 400, MUTED, True))
        self.list.addStretch()
        self.stack.setCurrentWidget(self.res)

    def _card(self, p: ps.Proc) -> ProcCard:
        c = ProcCard(p)
        c.openFolder.connect(self._open_folder)
        c.analyze.connect(lambda pr: self.analyzeFile.emit(pr.exe))
        c.trust.connect(lambda pr, card_=c: self._trust(pr, card_))
        c.suspend.connect(lambda pr, card_=c: self._act(pr, "suspend", card_))
        c.terminate.connect(lambda pr, card_=c: self._act(pr, "terminate", card_))
        return c

    # ---------------------------------------------------------------- ações
    def _open_folder(self, p: ps.Proc) -> None:
        if p.exe and os.path.exists(p.exe):
            subprocess.Popen(["explorer.exe", f"/select,{p.exe}"])

    def _ask(self, text: str, yes: str, danger: bool = False) -> bool:
        m = QMessageBox(QMessageBox.Warning if danger else QMessageBox.Question, "Sentinela", text, parent=self)
        m.setTextFormat(Qt.PlainText)
        y = m.addButton(yes, QMessageBox.DestructiveRole if danger else QMessageBox.AcceptRole)
        m.addButton("Cancelar", QMessageBox.RejectRole)
        m.setDefaultButton(m.buttons()[-1])
        m.exec()
        return m.clickedButton() is y

    def _trust(self, p: ps.Proc, c: ProcCard) -> None:
        if not p.sha256:
            return
        if p.stem in ps.TRUST_BLOCKED:
            QMessageBox.information(self, "Sentinela", "Não é possível confiar em interpretadores (python, node, java, PowerShell, cmd…): "
                                    "confiar neles silenciaria qualquer script malicioso que rodasse por meio deles.")
            return
        extra = "\n\nATENÇÃO: este programa tem alertas graves. Só confie se você mesmo o instalou e sabe o que ele faz." if p.level == "danger" else ""
        if not self._ask(f"Confiar neste arquivo?\n\n{ps.clean_text(p.name, 80)}\n{ps.clean_text(p.exe, 200)}\nSHA-256: {p.sha256[:32]}…\n\n"
                         "Ele deixará de gerar alertas enquanto o arquivo não mudar (você pode revogar depois)." + extra, "Confiar", p.level == "danger"):
            return
        lst = [e for e in self.settings.data.get("proc_ignore", []) if isinstance(e, dict) and e.get("sha256") != p.sha256]
        lst.append({"sha256": p.sha256, "name": ps.clean_text(p.name, 80), "motivo": f"confiado em {date.today().isoformat()}"})
        self.settings.data["proc_ignore"] = lst
        self.settings.save()
        c.set_note("Marcado como confiável. Rode a verificação de novo para atualizar o resultado.")
        for b in c.buttons:
            b.setEnabled(False)

    def _act(self, p: ps.Proc, action: str, c: ProcCard) -> None:
        why = ps.action_block_reason(p)
        if why:
            QMessageBox.information(self, "Sentinela", why)
            return
        verb = "Encerrar" if action == "terminate" else "Suspender"
        warn = ps.action_warning(p)
        text = (f"{verb} este processo?\n\n{ps.clean_text(p.name, 80)} (PID {p.pid})\n{ps.clean_text(p.exe, 200)}\n\n"
                + ("Isto encerra o programa, mas NÃO remove o que ele instalou nem como ele inicia com o Windows." if action == "terminate"
                   else "O programa fica pausado até você retomá-lo (volte à tela inicial desta aba)."))
        if warn:
            text += "\n\n" + warn
        if not self._ask(text, verb, danger=True):
            return
        msg = ps.act_on_process(p, action)
        if msg:
            QMessageBox.warning(self, "Sentinela", msg)
            return
        for b in c.buttons:
            b.setEnabled(False)
        if action == "terminate":
            c.set_note("Processo encerrado. Isto não remove o arquivo nem a inicialização automática.")
        else:
            c.set_note("Processo suspenso. Retome pela tela inicial desta aba quando quiser.", ok=False)
            lst = list(self.settings.data.get("proc_suspended", []))
            lst.append({"pid": p.pid, "create_time": p.create_time, "name": ps.clean_text(p.name, 80), "exe": p.exe})
            self.settings.data["proc_suspended"] = lst
            self.settings.save()

    def _show_all(self) -> None:
        if self.rep:
            AllProcsDialog(self.rep, self).exec()

    def _save_report(self) -> None:
        if not self.rep:
            return
        m = QMessageBox(QMessageBox.Question, "Sentinela", "Esconder seu nome de usuário e possíveis senhas/tokens das linhas de comando no relatório?\n"
                        "(recomendado, principalmente se for compartilhar o arquivo)", parent=self)
        m.setTextFormat(Qt.PlainText)
        yes = m.addButton("Esconder (recomendado)", QMessageBox.AcceptRole)
        no = m.addButton("Manter tudo", QMessageBox.DestructiveRole)
        m.addButton("Cancelar", QMessageBox.RejectRole)
        m.exec()
        if m.clickedButton() not in (yes, no):
            return
        dest, _ = QFileDialog.getSaveFileName(self, "Salvar relatório", str(Path.home() / "Documents" / f"Sentinela_processos_{time.strftime('%Y%m%d_%H%M')}.txt"),
                                              "Texto (*.txt)")
        if dest:
            Path(dest).write_text(ps.report_text(self.rep, m.clickedButton() is yes), encoding="utf-8")
