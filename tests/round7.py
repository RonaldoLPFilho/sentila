"""Aba Rede (sentinela/netmon.py): regras sintéticas + teste vivo em loopback (servidor/cliente inertes, sem rede externa)."""
from __future__ import annotations

import random
import subprocess
import sys
import time

BS = chr(92)


def run_round7(ctx) -> None:
    check = ctx.check
    from sentinela import netmon as nm
    from sentinela import procscan as ps

    th = nm.Thresholds()
    UNSIGNED = {"status": "NotSigned", "verified": True, "subject": "", "issuer": "", "thumb": ""}
    SIGNED = {"status": "Valid", "verified": True, "subject": 'CN="Foo", O=Foo Inc, L=X, C=NO', "issuer": "CN=DigiCert", "thumb": "a"}

    def times(n, step, jitter=0.0):
        rnd = random.Random(7)
        return [i * step + rnd.uniform(-jitter, jitter) for i in range(n)]

    ok, mean, n = nm.beacon_check(times(20, 30, 1.0), 900, th)
    check("N1 beaconing regular (30 s, jitter 1 s, 20 chegadas, 15 min) é detectado", ok and 29 < mean < 31 and n == 20, f"{ok} {mean:.1f}")
    check("N2 jitter alto (±15 s em 30 s) NÃO é beaconing", not nm.beacon_check(times(20, 30, 15.0), 900, th)[0])
    check("N3 janela curta (5 min) não conclui beaconing", not nm.beacon_check(times(20, 15, 0.5), 300, th)[0])
    check("N4 poucas chegadas (5) não é beaconing", not nm.beacon_check(times(5, 30, 0.5), 900, th)[0])
    check("N5 intervalo curto (2 s) não é beaconing (navegação/streaming)", not nm.beacon_check(times(40, 2, 0.1), 900, th)[0])
    check("N6 is_internal: privados/loopback/link-local sim, públicos não",
          nm.is_internal("127.0.0.1") and nm.is_internal("192.168.0.5") and nm.is_internal("169.254.1.1") and not nm.is_internal("8.8.8.8") and nm.is_internal("lixo"))

    def proc(name, exe, sig, **kw):
        p = ps.Proc(pid=kw.pop("pid", 900), name=name, exe=exe, create_time=kw.pop("ct", 1_700_000_100.0))
        p.sig = sig
        for k, v in kw.items():
            setattr(p, k, v)
        return p

    def analyze(p, window=900, dns=None, th_=None):
        return nm.analyze_net([p], window, nm.Live(), th_ or th, dns or {}, [], [])

    TEMP = "C:" + BS + "Users" + BS + "u" + BS + "AppData" + BS + "Local" + BS + "Temp" + BS
    dest = ("93.184.216.34", 443)
    rep = analyze(proc("upd.exe", TEMP + "upd.exe", UNSIGNED, arrivals={dest: times(20, 30, 1.0)}, dests={dest: 20}, remote_ips={dest[0]}, remote_ports={443}))
    p = rep.procs[0]
    check("N7 programa SEM assinatura com beaconing => Atenção (medium 20)",
          p.level == "caution" and any("periódica regular" in f.title and f.points == 20 for f in p.findings), f"{p.level} {[f.title for f in p.findings]}")
    rep = analyze(proc("sync.exe", "C:" + BS + "Program Files" + BS + "Foo" + BS + "sync.exe", SIGNED, arrivals={dest: times(20, 30, 1.0)}, dests={dest: 20}, remote_ips={dest[0]}))
    p = rep.procs[0]
    check("N8 programa ASSINADO com a mesma periodicidade => só informação",
          p.level == "ok" and sum(f.points for f in p.findings if f.points > 0) == 0, f"{p.level} {[f.title for f in p.findings]}")
    rep = analyze(proc("x.exe", TEMP + "x.exe", UNSIGNED, arrivals={dest: times(20, 30, 1.0)}, dests={dest: 20}, remote_ips={dest[0]}), window=300)
    check("N9 janela de 5 min: sem alerta de beaconing e com aviso de limite",
          not any("periódica" in f.title and f.points > 0 for f in rep.procs[0].findings) and any("curta demais" in x for x in rep.limits))
    rep = analyze(proc("bot.exe", TEMP + "bot.exe", UNSIGNED, dests={dest: 1}, remote_ips={dest[0]}, remote_ports={443}, c2_hits={dest[0]}))
    check("N10 destino em lista de C2 => Perigoso (high 55)", rep.verdict.level == "danger" and rep.procs[0].score >= 55, f"{rep.verdict.headline} {rep.procs[0].score}")
    rep = analyze(proc("w.exe", TEMP + "w.exe", UNSIGNED, dests={("10.0.0.5", 445): 3}, syn=[0, 130, 120], syn_nets={f"192.168.{i}" for i in range(30)}))
    check("N11 varredura LAN (SYN_SENT em 30 redes /24 privadas) por programa sem assinatura => Perigoso",
          rep.verdict.level == "danger" and any("varredura" in f.title.lower() for f in rep.procs[0].findings), rep.verdict.headline)
    rep = analyze(proc("bot.exe", TEMP + "bot.exe", UNSIGNED, dests={("93.184.216.35", 6667): 2}, remote_ips={"93.184.216.35"}, remote_ports={6667}))
    check("N12 porta IRC por programa sem assinatura => Atenção", rep.procs[0].level == "caution", rep.verdict.headline)
    ips = {f"5.5.{i % 250}.{i // 250}" for i in range(300)}
    rep = analyze(proc("qbit.exe", "C:" + BS + "Program Files" + BS + "qBit" + BS + "q.exe", SIGNED, dests={(ip, 51413): 1 for ip in ips}, remote_ips=ips, has_window=True))
    check("N13 torrent assinado com 300 destinos => sem alerta", rep.procs[0].level == "ok" and rep.verdict.level in ("safe", "unknown"), rep.verdict.headline)
    rep = analyze(proc("t.exe", TEMP + "t.exe", UNSIGNED, dests={("127.0.0.1", 5000): 50}, arrivals={("127.0.0.1", 5000): times(30, 30, 0.5)}))
    check("N14 tráfego local (loopback) não gera beaconing", not any("periódica" in f.title for f in rep.procs[0].findings))
    live = nm.Live()
    live.total_up, live.total_down = 400 << 20, 20 << 20
    rep = nm.analyze_net([], 900, live, th, {}, [], [])
    check("N15 envio alto no adaptador => só nota leve (low, 10), nunca Perigoso e sem culpar processo",
          rep.verdict.level != "danger" and any(f.points == 10 and f.severity == "low" for f in rep.findings))
    check("N16 'sem bytes por programa' é limite declarado (não bloqueia o resultado)",
          any("Sem administrador" in x for x in rep.limits) and rep.verdict.level in ("safe", "caution"), rep.verdict.headline)
    nasty = "evil" + chr(0x202E) + "x" + chr(0x3164)
    rep = analyze(proc(nasty + ".exe", TEMP + "x.exe", UNSIGNED, dests={dest: 1}, remote_ips={dest[0]}))
    txt = nm.report_text(rep, True)
    check("N17 relatório com nome hostil não carrega bidi/invisíveis", chr(0x202E) not in txt and chr(0x3164) not in txt)

    # ---------------- vivo, inerte: servidor e cliente em loopback (processos filhos)
    srv_code = ("import socket,time\ns=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',0));s.listen(50)\n"
                "print(s.getsockname()[1],flush=True)\nt=time.time()\nconns=[]\n"
                "while time.time()-t<30:\n s.settimeout(0.5)\n try:\n  c,_=s.accept();conns.append(c)\n except OSError:\n  pass\n")
    srv = subprocess.Popen([sys.executable, "-c", srv_code], stdout=subprocess.PIPE, text=True)
    port = int(srv.stdout.readline().strip())
    cli_code = f"import socket,time\nt=time.time()\nk=[]\nwhile time.time()-t<12:\n s=socket.socket();s.connect(('127.0.0.1',{port}));k.append(s);time.sleep(1.5)\n"
    cli = subprocess.Popen([sys.executable, "-c", cli_code])
    try:
        time.sleep(0.8)
        procs, _g = ps.collect_inventory()
        live = nm.Live()
        window = nm.sample_network(procs, 11, live)
        me = next((p for p in procs if p.pid == cli.pid), None)
        check("L1 o sampler vê o processo cliente pelo (pid, create_time) certo", me is not None and ("127.0.0.1", port) in me.dests, str(me.dests if me else None))
        arr = me.arrivals.get(("127.0.0.1", port), []) if me else []
        check("L2 registra as chegadas de conexão nova (~1 a cada 1,5 s)", 5 <= len(arr) <= 9, str(len(arr)))
        th2 = nm.Thresholds(beacon_min_arrivals=5, beacon_min_interval=1.0, beacon_min_window=8, beacon_abs_jitter=0.8, include_internal=True)
        if me is not None:
            me.sig = UNSIGNED
        for p in procs:
            if p is not me:
                p.sig = None
        rep = nm.analyze_net(procs, window, live, th2, {}, [], [])
        mine = next((p for p in rep.procs if p.pid == cli.pid), None)
        check("L3 beaconing REAL em loopback (cliente sem assinatura) é detectado como Atenção",
              mine is not None and any("periódica regular" in f.title and f.points == 20 for f in mine.findings), str([f.title for f in mine.findings]) if mine else "?")
        srvp = next((p for p in rep.procs if p.pid == srv.pid), None)
        check("L4 o servidor local (só escuta/aceita) não gera alerta de rede", srvp is None or not any(f.points > 0 and f.stage == "net" for f in srvp.findings))
        check("L5 a linha do tempo de bytes por adaptador foi coletada", len(live.timeline) >= 8, str(len(live.timeline)))
    finally:
        for pr in (cli, srv):
            if pr.poll() is None:
                pr.kill()
