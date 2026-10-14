"""Aba "Rede": monitora as conexões deste computador por um tempo e mostra envio/comunicação suspeita (v1, sem administrador)."""
from __future__ import annotations

import time
from pathlib import Path

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QMessageBox, QPushButton, QScrollArea, QStackedWidget,
                               QVBoxLayout, QWidget)

from . import netmon as nm
from . import procscan as ps
from .config import Settings
from .scoring import Finding
from .ui import ACCENT, AMBER, BG, BORDER, GREEN, LEVEL_COLOR, MUTED, SURFACE, TEXT, FindingCard, Gauge, StepRow, Worker, card, lbl, set_style
from .ui_procs import ProcActionsMixin, wrapable

STEPS = [("inv", "Lista de processos"), ("mon", "Monitoramento das conexões e do tráfego por adaptador"),
         ("sig", "Assinatura dos programas que usaram a rede"), ("ana", "Análise")]
DURATIONS = ((60, "1 minuto (teste rápido)"), (300, "5 minutos"), (900, "15 minutos (recomendado)"), (3600, "60 minutos"), (0, "Até eu parar"))


def human_rate(bps: float) -> str:
    for unit, div in (("MB/s", 1 << 20), ("KB/s", 1 << 10)):
        if bps >= div:
            return f"{bps / div:.1f} {unit}"
    return f"{bps:.0f} B/s"


class Timeline(QWidget):
    """Linha do tempo de envio (↑) e recebimento (↓) por adaptador. Só desenha; os dados vêm de Live.timeline."""

    def __init__(self) -> None:
        super().__init__()
        self.setMinimumHeight(150)
        self.data: list = []

    def set_data(self, data: list) -> None:
        self.data = data[-180:]
        self.update()

    def paintEvent(self, e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(8, 8, self.width() - 16, self.height() - 28)
        p.setPen(QPen(QColor(BORDER), 1))
        p.drawRoundedRect(r, 8, 8)
        if len(self.data) < 2:
            p.setPen(QColor(MUTED))
            p.drawText(r, Qt.AlignCenter, "Coletando…")
            return
        top = max(max(d[1], d[2]) for d in self.data) or 1.0
        n = len(self.data)
        for idx, col in ((1, "#FB923C"), (2, "#60A5FA")):
            pts = [QPointF(r.left() + r.width() * i / (n - 1), r.bottom() - 4 - (r.height() - 10) * d[idx] / top) for i, d in enumerate(self.data)]
            p.setPen(QPen(QColor(col), 2))
            p.drawPolyline(pts)
        p.setPen(QColor(MUTED))
        f = QFont(self.font())
        f.setPixelSize(11)
        p.setFont(f)
        p.drawText(QRectF(r.left() + 6, r.top() + 2, 200, 16), Qt.AlignLeft, f"pico {human_rate(top)}")
        p.drawText(QRectF(8, self.height() - 18, self.width() - 16, 16), Qt.AlignLeft, "laranja = enviado (↑)   azul = recebido (↓)   (soma de todos os adaptadores)")


class NetPage(ProcActionsMixin, QWidget):
    busyChanged = Signal(bool)
    analyzeFile = Signal(str)

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.setObjectName("page")
        self.settings = settings
        self.worker: Worker | None = None
        self.rep: nm.NetReport | None = None
        self.live = nm.Live()
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
        self.tick = QTimer(self, interval=500)
        self.tick.timeout.connect(self._update_live)
        self._spin = QTimer(self, interval=40)
        self._spin.timeout.connect(self._rotate)
        self._spin.start()

    # ------------------------------------------------------------------ construção
    def _build_idle(self) -> QWidget:
        w = QWidget()
        w.setObjectName("page")
        root = QVBoxLayout(w)
        root.setContentsMargins(48, 24, 48, 28)
        root.addStretch(1)
        c = card()
        c.setMaximumWidth(780)
        v = QVBoxLayout(c)
        v.setContentsMargins(30, 26, 30, 24)
        v.setSpacing(10)
        v.addWidget(lbl("Monitorar a rede", 22, 700))
        v.addWidget(lbl("Fica um tempo observando as conexões que saem e entram neste computador e procura sinais de envio ou comunicação suspeita: "
                        "programas sem assinatura \"ligando para casa\" em intervalos regulares, varredura de outros PCs, portas de IRC/Tor, "
                        "pools de mineração e destinos de listas de servidores de comando e controle.", 13, 400, MUTED, True))
        v.addWidget(lbl("O que é registrado", 12, 700, TEXT))
        for line in ("Qual programa falou com qual endereço e porta, e quantas conexões novas abriu (nada do conteúdo dos pacotes)",
                     "O total enviado e recebido por cada adaptador de rede, ao longo do tempo",
                     "Tudo fica só em memória neste computador e é apagado ao fechar o Sentinela, a menos que você salve um relatório"):
            v.addWidget(lbl("•  " + line, 12, 400, TEXT, True))
        v.addWidget(lbl("Limites importantes: isto NÃO é captura de pacotes. Sem administrador não há bytes por programa (só o total por adaptador), "
                        "conexões que duram menos de meio segundo e todo o conteúdo cifrado não são vistos, e sites legítimos (Discord, GitHub, nuvem) "
                        "usados por malware parecem tráfego normal. Resultado limpo significa \"sem indícios nos testes feitos\", nunca \"rede segura\".",
                        12, 400, AMBER, True))
        v.addWidget(lbl("Só o tráfego DESTE computador é observado. Em computador de empresa ou rede compartilhada, confirme que a política da sua organização "
                        "permite esse monitoramento.", 12, 400, MUTED, True))
        row = QHBoxLayout()
        row.addWidget(lbl("Tempo de observação:", 13))
        self.secs = QComboBox()
        for s, t in DURATIONS:
            self.secs.addItem(t, s)
        row.addWidget(self.secs)
        row.addStretch()
        v.addLayout(row)
        self.ok = QCheckBox("Entendi o que é registrado e os limites, e estou monitorando o meu próprio computador")
        v.addWidget(self.ok)
        self.go = QPushButton("Iniciar monitoramento")
        self.go.setObjectName("primary")
        self.go.setEnabled(False)
        self.ok.toggled.connect(self.go.setEnabled)
        self.go.clicked.connect(self.start)
        v.addSpacing(4)
        v.addWidget(self.go, 0, Qt.AlignLeft)
        root.addWidget(c, 0, Qt.AlignHCenter)
        root.addStretch(1)
        return w

    def _build_progress(self) -> QWidget:
        w = QWidget()
        w.setObjectName("page")
        root = QVBoxLayout(w)
        root.setContentsMargins(48, 28, 48, 24)
        root.setSpacing(12)
        c = card()
        h = QVBoxLayout(c)
        h.setContentsMargins(22, 16, 22, 16)
        h.addWidget(lbl("Monitorando a rede…", 17, 700))
        self.live_text = lbl("", 13, 400, MUTED, True)
        h.addWidget(self.live_text)
        self.timeline = Timeline()
        h.addWidget(self.timeline)
        root.addWidget(c)
        sc = card()
        sl = QVBoxLayout(sc)
        sl.setContentsMargins(24, 10, 24, 10)
        sl.setSpacing(0)
        for sid, title in STEPS:
            r = StepRow(title)
            self.rows[sid] = r
            sl.addWidget(r)
        root.addWidget(sc, 1)
        bottom = QHBoxLayout()
        self.stop_btn = QPushButton("Parar e analisar")
        self.stop_btn.setObjectName("primary")
        self.stop_btn.clicked.connect(self._on_stop)
        self.cancel_btn = QPushButton("Cancelar")
        self.cancel_btn.clicked.connect(self._on_cancel)
        bottom.addStretch()
        bottom.addWidget(self.stop_btn)
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
        b_new = QPushButton("Monitorar de novo")
        b_new.setObjectName("primary")
        b_new.clicked.connect(self.show_idle)
        bar.addWidget(b_rep)
        bar.addStretch()
        bar.addWidget(b_new)
        root.addLayout(bar)
        return w

    # ------------------------------------------------------------------ estados
    def show_idle(self) -> None:
        self.refresh()
        self.stack.setCurrentWidget(self.idle)

    def refresh(self) -> None:
        sec = int(self.settings.data.get("net_seconds", 900))
        self.secs.setCurrentIndex(max(0, self.secs.findData(sec)))

    def _rotate(self) -> None:
        for r in self.rows.values():
            if r.icon.state == "run":
                r.icon.angle = (r.icon.angle + 12) % 360
                r.icon.update()

    def start(self) -> None:
        if self.worker and self.worker.isRunning():
            return
        secs = int(self.secs.currentData() if self.secs.currentData() is not None else 900)
        self.settings.data["net_seconds"] = secs
        self.settings.save()
        self.live = nm.Live()
        self._cancel = False
        self.stop_btn.setEnabled(True)
        self.cancel_btn.setEnabled(True)
        self.cancel_btn.setText("Cancelar")
        for sid, _t in STEPS:
            self.rows[sid].update_state("pending", "Aguardando…")
            self.rows[sid].detail.setText("Aguardando…")
        self.timeline.set_data([])
        self.stack.setCurrentWidget(self.prog)
        self.busyChanged.emit(True)
        live = self.live
        ids = [s for s, _ in STEPS]

        def work(emit):
            cur = {"i": -1}

            def step(i, msg=""):
                if i != cur["i"]:
                    if cur["i"] >= 0:
                        emit(ids[cur["i"]], "ok", "")
                    cur["i"] = i
                emit(ids[i], "run", msg)

            rep = nm.run_net(self.settings, secs, live, step, lambda: self._cancel)
            emit(ids[cur["i"]], "ok", "")
            return rep

        w = Worker(work)
        w.step.connect(lambda sid, st, d: self.rows[sid].update_state(st, ps.clean_text(d, 200)) if sid in self.rows else None)
        w.done.connect(self._on_done)
        w.failed.connect(self._on_failed)
        w.cancelled.connect(self._on_cancelled)
        self.worker = w
        self._keep = [x for x in self._keep if x.isRunning()] + [w]
        self.tick.start()
        w.start()

    def _update_live(self) -> None:
        lv = self.live
        left = ""
        if lv.seconds:
            rest = max(0, int(lv.seconds - lv.elapsed))
            left = f" · faltam {rest // 60} min {rest % 60:02d} s"
        self.live_text.setText(f"{int(lv.elapsed // 60)} min {int(lv.elapsed % 60):02d} s{left}  ·  {lv.active_conns} conexões agora  ·  {lv.procs_active} programas ativos  ·  "
                               f"↑ {human_rate(lv.up_bps)}  ↓ {human_rate(lv.down_bps)}  ·  {lv.arrivals} conexões novas vistas")
        self.timeline.set_data(lv.timeline)

    def _on_stop(self) -> None:
        self.live.stop = True
        self.stop_btn.setEnabled(False)

    def _on_cancel(self) -> None:
        self._cancel = True
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.setText("Cancelando…")

    def _on_cancelled(self) -> None:
        self.tick.stop()
        self.busyChanged.emit(False)
        self.show_idle()

    def _on_failed(self, tb: str) -> None:
        self.tick.stop()
        self.busyChanged.emit(False)
        m = QMessageBox(QMessageBox.Critical, "Sentinela", "O monitoramento falhou por um erro inesperado.\n\n" + tb[-900:], parent=self)
        m.setTextFormat(Qt.PlainText)
        m.exec()
        self.show_idle()

    def _on_done(self, rep: nm.NetReport) -> None:
        self.tick.stop()
        self.rep = rep
        self.busyChanged.emit(False)
        QTimer.singleShot(300, lambda: self.show_result(rep))

    def _section(self, title: str) -> None:
        t = lbl(title.upper(), 11, 700, MUTED)
        t.setContentsMargins(2, 8, 0, 0)
        self.list.addWidget(t)

    def show_result(self, rep: nm.NetReport) -> None:
        v = rep.verdict
        color = LEVEL_COLOR[v.level]
        self.headline.setText(v.headline)
        set_style(self.headline, color)
        self.summary.setText(ps.clean_text(v.summary, 600))
        self.gauge.show_score(v.score, color)
        s = rep.stats
        self.stats.setText(f"{int(rep.window // 60)} min {int(rep.window % 60)} s observados\n{s['processes']} programas com conexões · {s['external']} falaram com a internet\n"
                           f"{s['destinations']} destinos · ↑ {s['up'] / 1048576:.0f} MB  ↓ {s['down'] / 1048576:.0f} MB (todos os adaptadores)")
        while self.list.count():
            it = self.list.takeAt(0)
            if it.widget():
                it.widget().deleteLater()
        flagged = sorted([p for p in rep.procs if p.level in ("danger", "caution")], key=lambda p: -p.score)
        if flagged or rep.findings:
            self._section("Pontos de atenção")
            for f in rep.findings:
                self.list.addWidget(FindingCard(f))
            for p in flagged:
                self.list.addWidget(self._card(p))
        light = sorted([p for p in rep.procs if p.level == "ok" and any(f.points > 0 for f in p.findings)], key=lambda p: -p.score)
        if light:
            self._section("Sinais leves (não bastam para alertar)")
            for p in light:
                self.list.addWidget(self._card(p))
        if rep.gaps:
            self._section("Não verificado (por isso o resultado é cauteloso)")
            for g in rep.gaps:
                self.list.addWidget(FindingCard(Finding("gap", g.title, g.detail, 0, "info", gap=True)))
        if rep.top_dests:
            self._section("Destinos mais contatados (nº de conexões abertas)")
            for ip, host, n, names, internal, ports in rep.top_dests[:12]:
                who = ", ".join(names)
                self.list.addWidget(lbl(wrapable(f"{ip}{' (' + host + ')' if host else ''}{'  [rede local]' if internal else ''}  ·  {n}  ·  portas {ports}  ·  {who}"),
                                        12, 400, TEXT, True))
        if rep.nics:
            self._section("Adaptadores (total desde que o Windows iniciou)")
            for name, up, down, kind, isup in rep.nics:
                if up or down:
                    self.list.addWidget(lbl(wrapable(f"{name} [{kind}]{'' if isup else ' (desconectado)'}  ·  ↑ {up / 1048576:.0f} MB  ↓ {down / 1048576:.0f} MB"), 12, 400, MUTED, True))
        self._section("Limites desta análise")
        for x in rep.limits:
            self.list.addWidget(lbl("•  " + wrapable(x), 12, 400, MUTED, True))
        self.list.addStretch()
        self.stack.setCurrentWidget(self.res)

    def _save_report(self) -> None:
        if not self.rep:
            return
        m = QMessageBox(QMessageBox.Question, "Sentinela", "Esconder seu nome de usuário e possíveis segredos nos caminhos e linhas de comando do relatório?\n(recomendado)", parent=self)
        m.setTextFormat(Qt.PlainText)
        yes = m.addButton("Esconder (recomendado)", QMessageBox.AcceptRole)
        no = m.addButton("Manter tudo", QMessageBox.DestructiveRole)
        m.addButton("Cancelar", QMessageBox.RejectRole)
        m.exec()
        if m.clickedButton() not in (yes, no):
            return
        dest, _ = QFileDialog.getSaveFileName(self, "Salvar relatório", str(Path.home() / "Documents" / f"Sentinela_rede_{time.strftime('%Y%m%d_%H%M')}.txt"), "Texto (*.txt)")
        if dest:
            Path(dest).write_text(nm.report_text(self.rep, m.clickedButton() is yes), encoding="utf-8")
