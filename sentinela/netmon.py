"""Aba "Rede" (v1, SEM administrador): observa as conexões do computador por um tempo e procura sinais de envio/comunicação suspeita.

O que é (e o que NÃO é):
  * NÃO é captura de pacotes (sem driver, sem payload, sem MITM de TLS). Amostra a tabela de conexões a cada 0,5 s e os contadores
    de bytes por ADAPTADOR. Não vê bytes por processo (isso exige administrador/ETW: v2), conexões que duram < 0,5 s, nem conteúdo cifrado.
  * Só vê o tráfego DESTE computador. Nada é gravado em disco; os dados ficam em memória.
  * "Sem indícios" nunca significa "rede segura": canais legítimos (Discord, GitHub, CDN, DoH…) usados como C2 não são distinguíveis.
Reaproveita procscan (identidade, assinatura, mineração, varredura, IRC/Tor, escuta) e acrescenta beaconing e listas de C2.
"""
from __future__ import annotations

import ipaddress
import os
import statistics
import time
from dataclasses import dataclass, field

import psutil

from . import procscan as ps
from .checks import verify_signatures
from .scoring import Finding, Verdict, gap

SAMPLE_INTERVAL = 0.5
NIC_INTERVAL = 1.0
VPN_HINTS = ("vpn", "radmin", "tap-", "wireguard", "tailscale", "zerotier", "hamachi", "openvpn", "nord", "proton")
VIRT_HINTS = ("vethernet", "vmware", "virtualbox", "hyper-v", "loopback", "wsl", "docker")


@dataclass
class Thresholds:
    beacon_min_arrivals: int = 8
    beacon_min_interval: float = 5.0
    beacon_rel_jitter: float = 0.15
    beacon_abs_jitter: float = 1.0
    beacon_min_window: int = 600
    scan_syn: int = 100
    scan_nets: int = 20
    high_upload_bytes: int = 100 << 20
    high_upload_ratio: float = 5.0
    include_internal: bool = False   # só para testes: considera destinos locais


@dataclass
class Live:
    """Estado que a UI lê enquanto a coleta roda (somente leitura para a UI)."""
    started: float = 0.0
    elapsed: float = 0.0
    seconds: int = 0
    active_conns: int = 0
    procs_active: int = 0
    up_bps: float = 0.0
    down_bps: float = 0.0
    timeline: list = field(default_factory=list)   # (t, up_bps, down_bps)
    stop: bool = False                              # "Parar": encerra a coleta e analisa o que existe
    total_up: int = 0
    total_down: int = 0
    arrivals: int = 0


@dataclass
class NetReport:
    procs: list
    findings: list          # achados de máquina/adaptador
    gaps: list
    limits: list
    verdict: Verdict
    window: float
    top_dests: list         # (ip, nome, nº conexões, [processos], privado?)
    nics: list              # (nome, bytes enviados, recebidos, tipo)
    timeline: list
    stats: dict


def _split(ip: str) -> str:
    return ".".join(ip.split(".")[:3]) if "." in ip else ip.rsplit(":", 1)[0]


def is_internal(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified or a.is_reserved


def beacon_check(times: list, window: float, th: Thresholds) -> tuple[bool, float, int]:
    """(é beacon?, intervalo médio, nº de chegadas). Regular = desvio-padrão ≤ max(rel × média, abs)."""
    ts = sorted(times)
    if window < th.beacon_min_window or len(ts) < th.beacon_min_arrivals:
        return False, 0.0, len(ts)
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    mean = sum(gaps) / len(gaps)
    if mean < th.beacon_min_interval:
        return False, mean, len(ts)
    sd = statistics.pstdev(gaps)
    return sd <= max(th.beacon_rel_jitter * mean, th.beacon_abs_jitter), mean, len(ts)


# ---------------------------------------------------------------- coleta

def _adopt(pid: int, index: dict, procs: list) -> ps.Proc | None:
    """Processo que nasceu durante a janela: cria o registro com (pid, create_time) estável."""
    try:
        pr = psutil.Process(pid)
        ct = round(pr.create_time(), 2)
        key = (pid, ct)
        if key in index:
            return index[key]
        try:
            exe = pr.exe()
        except (psutil.Error, OSError):
            exe = ""
        try:
            cmd = " ".join(pr.cmdline())[: ps.CMD_LIMIT]
        except (psutil.Error, OSError):
            cmd = ""
        p = ps.Proc(pid=pid, name=ps.clean_text(pr.name(), 120), exe=exe, cmdline=cmd, ppid=pr.ppid(), create_time=ct)
        if exe:
            p.kind = ps.path_kind(exe)
            if p.kind == "unknown":
                p.kind = "none"
            st = ps._safe_stat(exe)
            p.exists = st is not None or not ps._file_gone(exe)
            p.stat0 = ps._ft(st)
        index[key] = p
        procs.append(p)
        return p
    except (psutil.Error, OSError):
        return None


def sample_network(procs: list, seconds: int, live: Live, status=lambda m: None, cancelled=lambda: False,
                   bad_ips: dict | None = None) -> float:
    """Coleta por `seconds` (ou até live.stop). Devolve a duração real. Atribuição por (pid, create_time)."""
    index = {p.key: p for p in procs}
    cts = {p.pid: p.key for p in procs}
    seen: dict[tuple, bool] = {}              # conexão já vista (para detectar chegadas novas)
    t0 = time.time()
    live.started, live.seconds = t0, seconds
    last_nic = psutil.net_io_counters()
    last_nic_t = t0
    next_nic = t0 + NIC_INTERVAL
    first_nic = psutil.net_io_counters()
    next_tick = t0
    while True:
        now = time.time()
        live.elapsed = now - t0
        if cancelled():
            raise InterruptedError
        if live.stop or (seconds and now - t0 >= seconds):
            break
        if now < next_tick:
            time.sleep(min(0.05, next_tick - now))
            continue
        next_tick = now + SAMPLE_INTERVAL
        try:
            conns = psutil.net_connections("inet")
        except (psutil.Error, OSError):
            conns = []
        syn_now: dict[int, int] = {}
        active = set()
        nconn = 0
        for c in conns:
            if not c.pid:
                continue
            key = cts.get(c.pid)
            p = index.get(key) if key else None
            if p is None:
                p = _adopt(c.pid, index, procs)
                if p is None:
                    continue
                cts[c.pid] = p.key
            elif p.pid != c.pid:
                continue
            if c.status == "LISTEN":
                if c.laddr and c.laddr.ip in ("0.0.0.0", "::"):
                    p.listen_public.add(c.laddr.port)
                continue
            if not c.raddr:
                continue
            rip, rport = c.raddr.ip, c.raddr.port
            nconn += 1
            active.add(p.key)
            ckey = (p.key, c.laddr.ip if c.laddr else "", c.laddr.port if c.laddr else 0, rip, rport, c.type)
            dest = (rip, rport)
            if ckey not in seen:
                seen[ckey] = True
                p.dests[dest] = p.dests.get(dest, 0) + 1
                p.arrivals.setdefault(dest, []).append(now - t0)
                live.arrivals += 1
            internal = is_internal(rip)
            if not internal:
                p.remote_ips.add(rip)
                p.remote_ports.add(rport)
                if rport in ps.SCAN_PORTS:
                    p.scan_ips.add(rip)
                if bad_ips and rip in bad_ips:
                    p.c2_hits.add(rip)
            if c.status == "SYN_SENT":
                syn_now[p.pid] = syn_now.get(p.pid, 0) + 1
                p.syn_nets.add(_split(rip))
        for p in procs:
            if p.pid in syn_now:
                p.syn.append(syn_now[p.pid])
        live.active_conns, live.procs_active = nconn, len(active)
        if now >= next_nic:
            cur = psutil.net_io_counters()
            dt = max(1e-3, now - last_nic_t)
            up, down = (cur.bytes_sent - last_nic.bytes_sent) / dt, (cur.bytes_recv - last_nic.bytes_recv) / dt
            live.up_bps, live.down_bps = max(0.0, up), max(0.0, down)
            live.timeline.append((now - t0, live.up_bps, live.down_bps))
            live.total_up, live.total_down = cur.bytes_sent - first_nic.bytes_sent, cur.bytes_recv - first_nic.bytes_recv
            last_nic, last_nic_t, next_nic = cur, now, now + NIC_INTERVAL
            status(f"Monitorando… {int(now - t0)} s · {nconn} conexões · ↑ {live.up_bps / 1024:.0f} KB/s ↓ {live.down_bps / 1024:.0f} KB/s")
    wins = ps.visible_window_pids()
    fg = ps.foreground_pid()
    for p in procs:
        p.has_window = p.pid in wins
        p.foreground = p.pid == fg
    return time.time() - t0


# ---------------------------------------------------------------- análise

def net_findings(p: ps.Proc, window: float, th: Thresholds, unsigned: bool) -> list[Finding]:
    out: list[Finding] = []
    label = ps.clean_text(p.name, 80)
    for ip in sorted(p.c2_hits):
        out.append(Finding("net", f"Conexão com endereço de lista de C2 ({ip})", f"{label} contatou um endereço que consta numa lista de servidores de comando e controle.", 55, "high"))
    for dest, times in p.arrivals.items():
        if is_internal(dest[0]) and not th.include_internal:
            continue
        ok, mean, n = beacon_check(times, window, th)
        if not ok:
            continue
        if unsigned:
            out.append(Finding("net", f"Comunicação periódica regular com {dest[0]}:{dest[1]}",
                               f"{label}: {n} conexões novas, uma a cada ~{mean:.0f} s com variação mínima, durante {int(window // 60)} min. "
                               "Programas de botnet/RAT costumam \"ligar para casa\" assim; atualizadores e sincronizadores também. "
                               "Confira o publicador e o destino.", 20, "medium"))
        else:
            out.append(Finding("net", f"Comunicação periódica de {label} com {dest[0]}:{dest[1]}",
                               f"{n} conexões a cada ~{mean:.0f} s. Programa assinado: comum em sincronização/telemetria.", 0, "info"))
        break
    return out


def nic_summary() -> list:
    first = psutil.net_io_counters(pernic=True)
    stats = psutil.net_if_stats()
    out = []
    for name, io in first.items():
        low = name.lower()
        kind = "vpn" if any(h in low for h in VPN_HINTS) else "virtual" if any(h in low for h in VIRT_HINTS) else "físico"
        up = stats.get(name).isup if stats.get(name) else False
        out.append((ps.clean_text(name, 60), io.bytes_sent, io.bytes_recv, kind, up))
    return out


def analyze_net(procs: list, window: float, live: Live, th: Thresholds, ctx_dns: dict, nic_before: list, nic_after: list) -> NetReport:
    ctx = ps.Ctx()
    ctx.window = int(window)
    ctx.dns = ctx_dns
    active = [p for p in procs if p.dests or p.remote_ips or p.listen_public or p.syn]
    ps.analyze_all(active, ctx)
    for p in active:
        unsigned = ps.sig_state(p) in ("unsigned", "invalid", "failed", "remote")
        extra = net_findings(p, window, th, unsigned)
        if extra:
            p.findings = list(p.findings) + extra
            p.score, p.level = ps.level_of(p.findings)

    machine: list[Finding] = []
    up, down = max(0, live.total_up), max(0, live.total_down)
    if up >= th.high_upload_bytes and up > th.high_upload_ratio * max(1, down):
        machine.append(Finding("net", f"Envio alto de dados: {up / 1048576:.0f} MB enviados contra {down / 1048576:.0f} MB recebidos",
                               "O Sentinela não consegue dizer QUAL programa enviou (isso exige administrador). Backups, uploads e transmissões que "
                               "você fez explicam isso; se você não estava enviando nada, investigue.", 10, "low"))
    gaps: list = []
    limits = [
        "Sem administrador não há bytes por programa: só o total por adaptador. Não dá para saber quanto CADA processo enviou (modo avançado futuro).",
        "Isto NÃO é captura de pacotes: conexões que duram menos de 0,5 s e o conteúdo (cifrado) não são vistos.",
        "Canais legítimos usados como C2 (Discord, GitHub, Telegram, nuvem, DNS sobre HTTPS) parecem tráfego normal.",
        "O nome do destino vem do cache DNS do Windows, que é do sistema inteiro: serve de pista, nunca de prova.",
    ]
    if window < th.beacon_min_window:
        limits.append(f"Janela de {int(window // 60)} min {int(window % 60)} s: curta demais para detectar comunicação periódica (use 10 min ou mais).")
    if any(k == "vpn" for _n, _u, _d, k, _up in nic_after):
        limits.append("Há adaptador de VPN: o tráfego que passa por ele aparece sob o processo da VPN, não do programa de origem.")
    unverified = [p for p in active if p.status == "unverified" and p.remote_ips]
    failed = [p for p in active if p.status == "failed" and p.remote_ips]
    if failed:
        gaps.append(gap(f"A verificação de assinatura falhou para {len(failed)} programa(s) com conexão externa",
                        ", ".join(ps.clean_text(p.name, 40) for p in failed[:8])))
    if unverified:
        gaps.append(gap(f"{len(unverified)} programa(s) sem assinatura se comunicaram com a internet e não têm reputação conhecida",
                        ", ".join(ps.clean_text(p.name, 40) for p in unverified[:10])))
    verdict = ps.scan_verdict(active, machine, gaps)
    if verdict.level == "safe":
        verdict = Verdict(verdict.score, "safe", "Sem indícios (parcial)",
                          "Nenhum sinal de comunicação suspeita nos testes feitos. Isto não é um atestado de rede segura: veja os limites abaixo.")

    # destinos mais contatados (sem bytes: por nº de conexões distintas)
    agg: dict[str, list] = {}
    for p in active:
        for (ip, port), n in p.dests.items():
            a = agg.setdefault(ip, [0, set(), set()])
            a[0] += n
            a[1].add(ps.clean_text(p.name, 40))
            a[2].add(port)
    top = []
    for ip, (n, names, ports) in sorted(agg.items(), key=lambda kv: -kv[1][0])[:25]:
        host = ", ".join(sorted(ctx_dns.get(ip, ()))[:2])
        top.append((ip, ps.clean_text(host, 80), n, sorted(names)[:4], is_internal(ip), sorted(ports)[:4]))
    stats = {"processes": len(active), "external": sum(1 for p in active if p.remote_ips), "destinations": len(agg),
             "arrivals": live.arrivals, "up": up, "down": down}
    return NetReport(active, machine, gaps, limits, verdict, window, top, nic_after, list(live.timeline), stats)


def run_net(settings, seconds: int, live: Live, step=lambda i, msg="": None, cancelled=lambda: False,
            th: Thresholds | None = None, bad_ips: dict | None = None) -> NetReport:
    th = th or Thresholds()
    step(0, "Lendo a lista de processos…")
    procs, _g = ps.collect_inventory(cancelled)
    nic_before = nic_summary()
    step(1, "Monitorando as conexões…")
    window = sample_network(procs, seconds, live, lambda m: step(1, m), cancelled, bad_ips)
    step(2, "Verificando as assinaturas dos programas que usaram a rede…")
    ext = [p for p in procs if (p.dests or p.remote_ips or p.listen_public) and p.exe and p.kind in ("local", "removable") and p.exists]
    sigs = verify_signatures(sorted({p.exe for p in ext}), cancelled) if ext else {}
    for p in procs:
        p.sig = sigs.get(p.exe)
    step(3, "Analisando…")
    dns = ps.read_dns_cache(cancelled)
    return analyze_net(procs, window, live, th, dns, nic_before, nic_summary())


def report_text(rep: NetReport, redact_on: bool = True) -> str:
    fix = ps.redact if redact_on else (lambda s: s)
    v = rep.verdict
    lines = ["Sentinela – monitoramento de rede", f"Veredito: {v.headline} (pontuação {v.score})", ps.clean_text(v.summary, 600),
             f"Janela observada: {int(rep.window)} s · {rep.stats['processes']} programas com conexões · {rep.stats['destinations']} destinos", ""]
    for p in sorted(rep.procs, key=lambda p: -p.score):
        if p.level == "ok" and not any(f.points > 0 for f in p.findings):
            continue
        lines.append(f"[{p.level}] {ps.clean_text(p.name, 80)} (PID {p.pid}) {fix(ps.clean_text(p.exe, 240))}")
        for f in p.findings:
            if f.points > 0 or f.severity != "info":
                lines.append(f"    - {ps.clean_text(f.title, 160)} ({f.points:+d}): {fix(ps.clean_text(f.detail, 300))}")
    for f in rep.findings:
        lines.append(f"[rede] {ps.clean_text(f.title, 160)} ({f.points:+d}): {ps.clean_text(f.detail, 300)}")
    lines += ["", "Principais destinos (nº de conexões):"]
    for ip, host, n, names, internal, ports in rep.top_dests[:15]:
        lines.append(f"  {ip}{' (' + host + ')' if host else ''}{' [rede local]' if internal else ''} · {n} · {', '.join(names)}")
    lines += ["", "Não verificado / limites:"] + [f"  - {ps.clean_text(g.title, 200)}" for g in rep.gaps] + [f"  - {x}" for x in rep.limits]
    return "\n".join(lines)
