"""Achados, pontuação de risco e decisão sobre o sandbox.

Pontos positivos = risco, negativos = indício de confiança. Princípios (revisão pós-auditoria):
  * Só "Perigoso" é confiável por si. "Seguro" exige evidência POSITIVA (reputação/assinatura/ausência de conteúdo executável)
    e nenhuma lacuna de verificação; faltou sinal => "Inconclusivo", nunca "Seguro".
  * Créditos (pontos negativos) são limitados e nunca anulam um achado grave.
  * O sandbox só pode AUMENTAR o risco. O guest é controlado pelo malware, então "limpo" vindo dele não vale crédito.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

SEVERITIES = ("info", "low", "medium", "high", "critical")
MAX_CREDIT = 20  # soma máxima de pontos a favor


@dataclass
class Finding:
    stage: str  # origin | vt | defender | signature | static | archive | sandbox | gap
    title: str
    detail: str = ""
    points: int = 0
    severity: str = "info"
    gap: bool = False    # uma verificação esperada não foi feita / ficou incompleta
    trust: bool = False  # evidência positiva que sustenta "Seguro"


@dataclass
class Verdict:
    score: int
    level: str  # safe | caution | danger | unknown
    headline: str
    summary: str


@dataclass
class Recommendation:
    mode: str  # recommended | optional | unnecessary | blocked
    reason: str


def gap(title: str, detail: str = "", stage: str = "gap") -> Finding:
    return Finding(stage, title, detail, 0, "info", gap=True)


def compute_score(findings: list[Finding]) -> int:
    risk = sum(f.points for f in findings if f.points > 0)
    credit = max(-MAX_CREDIT, sum(f.points for f in findings if f.points < 0))
    score = risk + credit
    # piso: créditos nunca reduzem a pontuação abaixo do maior achado grave
    floor = max((f.points for f in findings if f.points > 0 and f.severity in ("high", "critical")), default=0)
    score = max(score, floor)
    if any(f.severity == "critical" for f in findings):
        score = max(score, 85)
    return max(0, min(100, score))


def build_verdict(findings: list[Finding], sandbox_ran: bool) -> Verdict:
    score = compute_score(findings)
    critical = any(f.severity == "critical" for f in findings)
    trust = [f for f in findings if f.trust]
    # Se há evidência positiva independente do VirusTotal (todos os executáveis assinados, ou nada executável no pacote),
    # a falta de reputação no VirusTotal é redundante e não bloqueia o "Seguro".
    independent = any(f.trust and f.stage in ("signature", "static") for f in findings)
    gaps = [f for f in findings if f.gap and not (independent and f.stage == "vt")]
    medium_up = any(f.points > 0 and f.severity in ("medium", "high", "critical") for f in findings)
    missing = "; ".join(g.title for g in gaps[:3]) + (f" (+{len(gaps) - 3})" if len(gaps) > 3 else "")

    if critical or score >= 45:
        return Verdict(score, "danger", "Perigoso",
                       "Foram encontrados sinais fortes de comportamento malicioso. Não recomendamos abrir ou instalar este arquivo.")
    if score >= 20 or medium_up:
        extra = f" Verificações que faltaram: {missing}." if gaps else ""
        return Verdict(score, "caution", "Atenção",
                       "Há pontos de atenção que não bastam para condenar o arquivo. Confira a origem antes de instalar." + extra)
    if gaps or not trust:
        why = f"Faltaram verificações: {missing}." if gaps else "Não há evidência positiva (reputação conhecida ou assinatura válida)."
        return Verdict(score, "unknown", "Inconclusivo",
                       "Nenhum alerta encontrado, mas isso NÃO significa que o arquivo é seguro. " + why +
                       " Só instale se confiar na origem.")
    basis = "; ".join(t.title for t in trust[:2])
    return Verdict(score, "safe", "Seguro",
                   f"Nenhum alerta encontrado e há evidência positiva ({basis}). Isto reduz o risco, mas nenhuma análise "
                   "garante 100%: baixe sempre de fontes confiáveis.")


def final_findings(static: list[Finding], rec_mode: str, sandbox_ran: bool, sandbox: list[Finding] | None) -> list[Finding]:
    """Junta os achados e registra a lacuna quando o sandbox era recomendado e não concluiu."""
    out = list(static) + list(sandbox or [])
    if rec_mode == "recommended" and not sandbox_ran:
        out.append(gap("Teste em sandbox recomendado e não concluído",
                       "Sem observar o programa executando, o comportamento real é desconhecido."))
    return out


def recommend(findings: list[Finding], has_exec: bool, static_only: bool = False) -> Recommendation:
    score = compute_score(findings)
    if any(f.severity == "critical" for f in findings) or score >= 70:
        return Recommendation("blocked", "Já há sinais fortes de malware. Executar, mesmo isolado, não acrescenta nada.")
    if not has_exec:
        if static_only:
            return Recommendation("unnecessary", "Este conteúdo (.jar, script Python, macro, .reg…) não roda no sandbox: só pôde ser inspecionado estaticamente.")
        return Recommendation("unnecessary", "Não há nada executável aqui (só dados, texturas ou documentos). A análise estática basta.")
    # Assinatura válida ou "só dados" sustentam sozinhas a confiança. Reputação limpa no VirusTotal SEM assinatura pode ser
    # fabricada (basta enviar o arquivo ao VT e esperar), então ainda vale confirmar o comportamento no sandbox.
    strong_trust = any(f.trust and f.stage in ("signature", "static") for f in findings)
    if score <= 10 and strong_trust:
        return Recommendation("optional", "Assinatura válida em todos os executáveis. O sandbox é opcional.")
    if score <= 10 and any(f.trust for f in findings):
        return Recommendation("recommended", "Reputação limpa no VirusTotal, mas sem assinatura digital: a reputação pode ser forjada. "
                                              "Confirmar no sandbox fecha essa brecha.")
    if score <= 10:
        return Recommendation("recommended", "Nenhum alerta, mas o arquivo é executável e sem reputação conhecida. Vale observar em sandbox.")
    return Recommendation("recommended", "Há sinais ambíguos. O sandbox mostra o que o programa realmente faz ao rodar.")


# ---------------------------------------------------------------- relatório do sandbox (entrada NÃO confiável)

def _s(x, n: int = 400) -> str:
    return str(x)[:n] if isinstance(x, (str, int, float)) and not isinstance(x, bool) else ""


def _i(x, default: int = 0) -> int:
    try:
        return int(x) if not isinstance(x, bool) else default
    except (TypeError, ValueError, OverflowError):
        return default


def _f(x) -> float:
    try:
        v = float(x)
        return v if v == v and abs(v) < 1e9 else 0.0
    except (TypeError, ValueError, OverflowError):
        return 0.0


def _lst(x, n: int) -> list:
    if x is None:
        return []
    if not isinstance(x, list):
        x = [x]
    return x[:n]


def _dicts(x, n: int) -> list[dict]:
    return [d for d in _lst(x, n) if isinstance(d, dict)]


def sanitize_report(r) -> dict | None:
    """Normaliza o JSON vindo do guest: só chaves esperadas, tipos coagidos e tamanhos limitados."""
    if not isinstance(r, dict):
        return None
    d = r.get("defender") if isinstance(r.get("defender"), dict) else {}
    p = r.get("persistence") if isinstance(r.get("persistence"), dict) else {}
    ec = r.get("exit_code")
    return {
        "ok": r.get("ok") is not False,
        "error": _s(r.get("error")),
        "seconds": _i(r.get("seconds")),
        "start_error": _s(r.get("start_error")),
        "sample_exited": r.get("sample_exited") is True,
        "exit_code": _i(ec) if ec is not None and not isinstance(ec, bool) else None,
        "new_processes": [{"pid": _i(x.get("pid")), "ppid": _i(x.get("ppid")), "name": _s(x.get("name"), 120), "path": _s(x.get("path"), 300),
                           "cmd": _s(x.get("cmd"), 400), "descends": x.get("descends") is True, "t": _i(x.get("t"))}
                          for x in _dicts(r.get("new_processes"), 400)],
        "connections": [{"pid": _i(x.get("pid")), "proc": _s(x.get("proc"), 80), "remote": _s(x.get("remote"), 80), "port": _i(x.get("port"))}
                        for x in _dicts(r.get("connections"), 200)],
        "dns": [_s(x, 120) for x in _lst(r.get("dns"), 40) if isinstance(x, str)],
        "new_files": [{"path": _s(x.get("path"), 400), "size": _i(x.get("size"))} for x in _dicts(r.get("new_files"), 300)],
        "new_files_total": _i(r.get("new_files_total")),
        "persistence": {k: [_s(v, 300) for v in _lst(p.get(k), 50) if isinstance(v, str)] for k in ("run_keys", "services", "tasks", "ifeo")},
        "installed": [_s(x, 120) for x in _lst(r.get("installed"), 30) if isinstance(x, str)],
        "defender": {
            "threats": [{"name": _s(x.get("name"), 120), "resources": _s(x.get("resources"), 300)} for x in _dicts(d.get("threats"), 30)],
            "realtime_disabled": d.get("realtime_disabled") is True,
            "active": d.get("active") is True,
            "exclusions_added": [_s(x, 200) for x in _lst(d.get("exclusions_added"), 30) if isinstance(x, str)],
        },
        "hosts_changed": r.get("hosts_changed") is True,
        "decoys_total": _i(r.get("decoys_total")),
        "decoys_tampered": _i(r.get("decoys_tampered")),
        "cpu_percent": _f(r.get("cpu_percent")),
        "windows": [_s(x, 150) for x in _lst(r.get("windows"), 10) if isinstance(x, str)],
    }


# ---------------------------------------------------------------- pontuação do sandbox

_CMD_RULES: list[tuple[str, str, int, str]] = [
    (r"vssadmin(\.exe)?\"?\s+delete\s+shadows|wmic(\.exe)?\"?\s+shadowcopy\s+delete|bcdedit.*(recoveryenabled\s+no|ignoreallfailures)",
     "Apagou cópias de segurança / desativou recuperação do Windows", 90, "critical"),
    (r"set-mppreference|add-mppreference|disablerealtimemonitoring|taskkill.*msmpeng",
     "Tentou desativar ou contornar o Defender", 60, "critical"),
    (r"net\s+user\s+\S+\s+\S+\s+/add", "Criou uma conta de usuário", 45, "high"),
    (r"certutil.*(-urlcache|-decode)|bitsadmin.*/transfer|downloadstring|downloadfile|invoke-webrequest|\biwr\b|mshta\s+http|regsvr32.*(/i:http|scrobj)",
     "Baixou ou executou conteúdo remoto por ferramenta do Windows", 35, "high"),
    (r"-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|frombase64string|\biex\b|invoke-expression",
     "Executou comando ofuscado/codificado", 30, "high"),
    (r"reg(\.exe)?\"?\s+add\s+.*\\run", "Registrou-se para iniciar com o Windows (linha de comando)", 25, "medium"),
    (r"schtasks(\.exe)?\"?\s+/create", "Criou tarefa agendada", 20, "medium"),
    (r"netsh.*(advfirewall|firewall).*(off|add\s+rule)", "Alterou o firewall", 20, "medium"),
]

_SUSPICIOUS_PORTS = {4444, 1337, 6667, 31337, 5555, 9001, 8333}
_NOISE = {"wmiprvse.exe", "conhost.exe", "backgroundtaskhost.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
          "smartscreen.exe", "taskhostw.exe", "runtimebroker.exe", "audiodg.exe", "dllhost.exe", "sppsvc.exe",
          "mpcmdrun.exe", "msmpeng.exe", "tiworker.exe", "trustedinstaller.exe", "svchost.exe", "werfault.exe"}
_RISKY_DROP = re.compile(r"\\(Startup|Temp|AppData\\Roaming|AppData\\Local\\Temp|ProgramData)\\", re.I)
_STARTUP = re.compile(r"\\Start Menu\\Programs\\Startup\\", re.I)
_EXEC_EXT = (".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr", ".lnk", ".hta", ".msi")


def score_sandbox(report: dict, network: bool) -> list[Finding]:
    """Recebe o relatório JÁ saneado (sanitize_report). Nunca concede crédito: o guest é controlado pela amostra."""
    out: list[Finding] = []
    secs = report["seconds"]
    procs = [p for p in report["new_processes"] if p["name"].lower() not in _NOISE]

    d = report["defender"]
    if not d["active"]:
        out.append(Finding("sandbox", "O Defender do sandbox está desativado",
                           "Dentro do Windows Sandbox o antivírus costuma vir desligado: o sandbox só observa comportamento, "
                           "não verifica assinaturas. O Defender do seu PC continua sendo a única camada de assinaturas.", 0, "info"))
    if d["threats"]:
        names = ", ".join(sorted({t["name"] or "?" for t in d["threats"]}))[:200]
        out.append(Finding("sandbox", "Defender detectou ameaça durante a execução", names, 90, "critical"))
    if d["realtime_disabled"] or d["exclusions_added"]:
        out.append(Finding("sandbox", "Desativou ou criou exclusões no Defender",
                           "O programa mexeu na proteção do Windows dentro do sandbox.", 70, "critical"))

    tampered, total = report["decoys_tampered"], report["decoys_total"]
    if tampered >= 3:
        out.append(Finding("sandbox", "Comportamento de ransomware",
                           f"{tampered} de {total} arquivos-isca foram alterados ou apagados.", 90, "critical"))
    elif tampered > 0:
        out.append(Finding("sandbox", "Arquivos-isca alterados", f"{tampered} de {total} foram modificados.", 30, "high"))

    if report["hosts_changed"]:
        out.append(Finding("sandbox", "Alterou o arquivo hosts", "Pode redirecionar sites (ex.: bancos, antivírus).", 40, "high"))

    hit_titles: set[str] = set()
    for p in procs:
        cmd = f"{p['name']} {p['cmd']}"
        for pattern, title, pts, sev in _CMD_RULES:
            if title not in hit_titles and re.search(pattern, cmd, re.I):
                hit_titles.add(title)
                out.append(Finding("sandbox", title, p["cmd"][:220], pts, sev))

    per = report["persistence"]
    if per["ifeo"]:
        out.append(Finding("sandbox", "Sequestro de programas (IFEO)", "; ".join(per["ifeo"])[:220], 45, "high"))
    added = [f"{label}: {v}" for label, vs in (("chave Run/Winlogon", per["run_keys"]), ("serviço", per["services"]),
                                               ("tarefa agendada", per["tasks"])) for v in vs]
    if added:
        out.append(Finding("sandbox", "Criou itens de inicialização automática", "; ".join(added)[:260] +
                           "\nÉ comum em instaladores legítimos: confira se o publicador é confiável.", 22, "medium"))

    new_files = report["new_files"]
    startup = [f["path"] for f in new_files if _STARTUP.search(f["path"])]
    if startup:
        out.append(Finding("sandbox", "Colocou arquivos na pasta Inicializar", "; ".join(startup)[:220], 30, "high"))
    risky = [f["path"] for f in new_files if _RISKY_DROP.search(f["path"]) and f["path"].lower().endswith(_EXEC_EXT)
             and f["path"] not in startup]
    if risky:
        out.append(Finding("sandbox", "Criou executáveis em pastas de risco", f"{len(risky)} arquivo(s), ex.: {risky[0]}", 12, "medium"))
    if report["new_files_total"]:
        out.append(Finding("sandbox", f"{report['new_files_total']} arquivo(s) criados/alterados durante a execução",
                           "Lista completa disponível no relatório.", 0, "info"))

    conns = report["connections"]
    if network:
        remotes = {(c["remote"], c["port"]) for c in conns}
        bad = [r for r in remotes if r[1] in _SUSPICIOUS_PORTS]
        if bad:
            out.append(Finding("sandbox", "Conexão em porta típica de malware", ", ".join(f"{a}:{b}" for a, b in bad)[:200], 25, "high"))
        if remotes:
            uniq = {r[0] for r in remotes}
            out.append(Finding("sandbox", f"Contatou {len(uniq)} endereço(s) externo(s)",
                               ", ".join(f"{a}:{b}" for a, b in sorted(remotes, key=str)[:6]), min(20, 4 * len(uniq)), "low"))
        if report["dns"]:
            out.append(Finding("sandbox", "Domínios consultados", ", ".join(report["dns"][:8]), 0, "info"))
    else:
        out.append(Finding("sandbox", "Rede desativada no sandbox",
                           "Mais seguro, mas conexões do programa (C2, exfiltração) não puderam ser observadas.", 0, "info"))

    if report["cpu_percent"] > 70:
        out.append(Finding("sandbox", "Uso intenso e contínuo de CPU",
                           f"{report['cpu_percent']:.0f}% durante a execução (possível mineração).", 12, "medium"))
    if report["windows"]:
        out.append(Finding("sandbox", "Janelas exibidas", "; ".join(report["windows"][:5]), 0, "info"))

    started = not report["start_error"]
    exited_bad = report["sample_exited"] and report["exit_code"] not in (0, None) and not procs
    if report["start_error"] or exited_bad:
        out.append(gap("O programa não executou normalmente no sandbox",
                       (report["start_error"] or f"Encerrou com código {report['exit_code']}") +
                       ". Pode faltar componente ou exigir interação: o comportamento é desconhecido."))
    elif started and not any(f.points > 0 for f in out):
        out.append(Finding("sandbox", f"Nada suspeito observado em {secs} s",
                           "Isto NÃO prova segurança: malware pode esperar, detectar o sandbox ou agir sem deixar rastro de arquivo.", 0, "info"))
    return out
