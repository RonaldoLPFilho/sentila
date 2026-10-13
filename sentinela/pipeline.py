"""Orquestra a análise: estática (etapas 1–3 + decisão) → sandbox opcional → limpeza."""
from __future__ import annotations

import os
import shutil
import stat
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from . import sandbox
from .checks import (EXEC_KINDS, INSPECT_EXT, KIND_LABEL, MAX_EXTRACT_BYTES, MAX_FILES, SOFT_CODE_EXT, VirusTotal, analyze_content, analyze_pe, analyze_soft,
                     av_blocked, check_signatures, classify, defender_scan, dir_size, extract_archive, hash_file, human_size,
                     is_active_content, is_inert, list_7z, name_tricks, origin_check, publisher, sniff_magic, vt_findings)
from .config import WORK_ROOT, Settings
from .scoring import Finding, Recommendation, compute_score, gap, recommend, score_sandbox

_PRIORITY = {"exe": 0, "msi": 1, "bat": 2, "ps1": 3, "wsh": 4, "hta": 5, "lnk": 6, "dll": 7}
_DEPRIORITIZE = ("unins", "uninstall", "crash", "vc_redist", "vcredist", "dxsetup", "dotnet", "report", "helper")
MAX_DEPTH = 4          # níveis de arquivos dentro de arquivos
MAX_VT_LOOKUPS = 12    # consultas por análise (cota gratuita: 4/min)
MAX_SIG_FILES = 150
MAX_PE_ANALYSIS = 40
_PE_KINDS = ("exe", "msi", "lib")


@dataclass
class Candidate:
    rel: str
    kind: str
    size: int

    @property
    def label(self) -> str:
        return f"{self.rel}  ·  {KIND_LABEL.get(self.kind, self.kind)}  ·  {human_size(self.size)}"


@dataclass
class StaticResult:
    path: Path
    size: int
    kind: str
    hashes: dict
    findings: list[Finding] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    recommendation: Recommendation | None = None
    is_archive: bool = False
    files_inside: int = 0

    @property
    def score(self) -> int:
        return compute_score(self.findings)


@dataclass
class SandboxResult:
    ran: bool
    findings: list[Finding]
    outcome: sandbox.Outcome | None = None
    error: str = ""


class Analyzer:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.workdir: Path | None = None
        self._cancel = False
        self._vt: VirusTotal | None = None
        self._sandbox_started = False

    # -------------------------------------------------------------- utilidades
    def cancel(self) -> None:
        self._cancel = True

    def cancelled(self) -> bool:
        return self._cancel

    def _check_cancel(self) -> None:
        if self._cancel:
            raise InterruptedError

    def _new_workdir(self) -> None:
        self.cleanup()
        WORK_ROOT.mkdir(parents=True, exist_ok=True)
        self.workdir = WORK_ROOT / uuid.uuid4().hex[:12]
        self.workdir.mkdir()

    def vt(self) -> VirusTotal | None:
        key = self.settings.vt_key
        if not key:
            return None
        if self._vt is None or self._vt.key != key:
            self._vt = VirusTotal(key)
        return self._vt

    # -------------------------------------------------------------- extração recursiva
    def _extract_all(self, path: Path, magic: str, ext_dir: Path, findings: list[Finding]) -> int:
        """Extrai o arquivo e os arquivos dentro dele (até MAX_DEPTH). Retorna a contagem de arquivos extraídos."""
        enc: list[str] = []
        errs: list[str] = []
        blocked: list[str] = []
        slip = bomb_msg = nested_left = amb = 0
        bomb_msg = ""
        files = nbytes = 0
        tool = ""
        queue = [(path, magic, ext_dir, 0)]
        while queue:
            self._check_cancel()
            src, mg, dest, depth = queue.pop(0)
            ex = extract_archive(src, dest, mg, self.cancelled)
            tool = tool or ex.tool
            files += ex.files
            nbytes += ex.bytes
            slip += ex.slip
            blocked += ex.blocked
            if ex.encrypted:
                enc.append(src.name)
            if ex.bomb:
                bomb_msg = ex.error
                break
            if ex.error and not ex.encrypted:
                errs.append(f"{src.name}: {ex.error}")
            if mg == "zip":  # dois leitores com visões diferentes do mesmo zip = estrutura ambígua (zip concatenado/adulterado)
                info = list_7z(src)
                # compara CONTEÚDO (tamanho+CRC) e os nomes ASCII: nomes com acento podem ser lidos diferente sem ser ataque
                if info and not info["unreadable"] and ((ex.entries is not None and info["entries"] != ex.entries) or info["names"] != ex.names):
                    amb += 1
                    # analisa também o que o 7-Zip enxerga (o outro leitor pode ser o que o usuário usa depois)
                    try:
                        extract_archive(src, dest / "__vista_7zip", "7z", self.cancelled)
                    except OSError:
                        pass
            if files > MAX_FILES or dir_size(ext_dir) > MAX_EXTRACT_BYTES:
                bomb_msg = "Total de arquivos/bytes extraídos excede o limite de segurança."
                break
            for p in dest.rglob("*"):
                if p.is_symlink() or not p.is_file():
                    continue
                m2 = sniff_magic(p)
                if classify(p, m2) == "archive":
                    if depth < MAX_DEPTH:
                        queue.append((p, m2, p.parent / (p.name + "__x"), depth + 1))
                    else:
                        nested_left += 1
        if blocked:
            findings.append(Finding("defender", "Defender bloqueou arquivos ao extrair", f"{len(blocked)} item(ns), ex.: {blocked[0]}", 90, "critical"))
        if bomb_msg:
            findings.append(Finding("archive", "Possível bomba de descompressão", bomb_msg, 30, "high"))
            findings.append(gap("Arquivo não extraído por inteiro", "Excedeu o limite de segurança."))
        if slip:
            findings.append(Finding("archive", "Caminhos maliciosos dentro do arquivo",
                                    f"{slip} item(ns) tentavam escrever fora da pasta (zip slip). Foram ignorados.", 40, "high"))
        if amb:
            findings.append(Finding("archive", "Estrutura de zip ambígua (zip concatenado/adulterado)",
                                    "Dois leitores de zip enxergam listas de arquivos diferentes: técnica usada para esconder conteúdo de antivírus.", 35, "high"))
        if enc:
            findings.append(Finding("archive", "Arquivo protegido por senha",
                                    "O conteúdo não pode ser inspecionado. Senha em arquivo de mods é um truque comum para escapar de antivírus. "
                                    f"({', '.join(enc[:3])})", 25, "medium"))
            findings.append(gap("Conteúdo protegido por senha não inspecionado", f"{len(enc)} arquivo(s)."))
        if errs:
            findings.append(Finding("archive", "Extração incompleta", "; ".join(errs[:3]), 10, "medium"))
            findings.append(gap("Extração incompleta", "Parte do conteúdo não pôde ser lida."))
        if nested_left:
            findings.append(gap(f"Arquivos aninhados além de {MAX_DEPTH} níveis", f"{nested_left} arquivo(s) não foram abertos."))
        if files:
            findings.append(Finding("archive", f"{files} arquivo(s) extraídos ({human_size(nbytes)})", f"Extrator: {tool}", 0, "info"))
        return files

    # -------------------------------------------------------------- etapa estática
    def analyze_static(self, path_str: str, emit) -> StaticResult:
        """Executa a análise; se falhar ou for cancelada, apaga tudo que já tinha sido gerado."""
        try:
            return self._analyze_static(path_str, emit)
        except BaseException:
            self.cleanup()
            raise

    def _analyze_static(self, path_str: str, emit) -> StaticResult:
        self._cancel = False
        path = Path(path_str).resolve()
        self._new_workdir()
        findings: list[Finding] = []
        size = 0

        # 1. Identificação + extração segura
        emit("id", "run", "Calculando impressões digitais (SHA-256)…")
        try:
            size = path.stat().st_size
            hashes = hash_file(path)
        except OSError as e:
            if not av_blocked(e, path):
                raise
            findings.append(Finding("defender", "Bloqueado pelo antivírus em tempo real",
                                    "O Windows impediu a leitura do arquivo porque ele contém um vírus.", 90, "critical"))
            emit("id", "bad", "Acesso bloqueado pelo Microsoft Defender")
            for sid in ("vt", "def", "sig"):
                emit(sid, "skip", "")
            emit("dec", "bad", "Risco crítico")
            sr = StaticResult(path, size, "other", {"sha256": "-", "md5": "-", "sha1": "-"}, findings)
            sr.recommendation = recommend(findings, False)
            return sr
        self._check_cancel()

        magic = sniff_magic(path)
        kind = classify(path, magic)
        findings += name_tricks(path, magic)
        findings += origin_check(path)
        sr = StaticResult(path, size, kind, hashes, findings, is_archive=(kind == "archive"))

        ext_dir = self.workdir / "extracted"
        scan_targets = [path]
        if sr.is_archive:
            emit("id", "run", "Extraindo em área isolada (inclusive arquivos dentro de arquivos)…")
            sr.files_inside = self._extract_all(path, magic, ext_dir, findings)
            if sr.files_inside:
                scan_targets = [path, ext_dir]
            root, files_iter = ext_dir, [p for p in ext_dir.rglob("*") if p.is_file() and not p.is_symlink()][:MAX_FILES]
        else:
            root, files_iter = path.parent, [path]

        # Classifica o conteúdo
        pe_files: list[tuple[Path, str]] = []
        other_active: list[tuple[Path, str]] = []   # scripts, atalhos, jar, documentos...
        names_lower = [p.name.lower() for p in files_iter]
        web_like = (any(n == "package.json" for n in names_lower)
                    or (sum(n.endswith((".html", ".htm")) for n in names_lower) >= 1 and sum(n.endswith(".js") for n in names_lower) >= 2))
        active_count = 0
        unrunnable_active = False
        uninspected: list[str] = []
        unknown_types: dict[str, int] = {}
        soft_files: list[Path] = []
        has_driver = False
        for p in files_iter:
            mg = sniff_magic(p)
            k = classify(p, mg)
            if k == "archive" and sr.is_archive:
                continue  # já foi aberto
            rel = str(p.relative_to(root)) if sr.is_archive else p.name
            if p.suffix.lower() == ".sys":
                has_driver = True
            if p.suffix.lower() in SOFT_CODE_EXT and len(soft_files) < 600:
                soft_files.append(p)
            if not is_active_content(p, mg):
                if not is_inert(p, mg):  # extensão fora da lista positiva: não dá para afirmar que é só dado
                    unknown_types[p.suffix.lower() or "(sem extensão)"] = unknown_types.get(p.suffix.lower() or "(sem extensão)", 0) + 1
                continue
            active_count += 1
            if k in EXEC_KINDS.values() and not (web_like and p.suffix.lower() == ".js"):
                sr.candidates.append(Candidate(rel, k, p.stat().st_size))
            if k in _PE_KINDS or mg == "pe":
                pe_files.append((p, "lib" if k == "lib" else ("msi" if k == "msi" else "exe")))
            else:
                other_active.append((p, mg))
                if (p.suffix.lower() in INSPECT_EXT and p.suffix.lower() not in EXEC_KINDS) or k == "jar":
                    unrunnable_active = True
            if sr.is_archive:
                findings += (name_tricks(p, mg)[:1] if p != path else [])
        pe_files.sort(key=lambda t: (t[1] == "lib", t[0].stat().st_size))
        emit("id", "ok", f"{KIND_LABEL.get(kind, kind)} · {human_size(size)} · SHA-256 {hashes['sha256'][:16]}…")
        self._check_cancel()

        # Assinaturas (também priorizam a consulta ao VirusTotal)
        if pe_files:
            emit("vt", "run", "Verificando assinaturas digitais dos executáveis…")
        sig_paths = [p for p, _ in pe_files[:MAX_SIG_FILES]]
        sigs = check_signatures(sig_paths)
        status_of = {p: sigs.get(str(p), {}).get("status", "?") for p in sig_paths}

        # 2. VirusTotal
        vt = self.vt()
        if not vt:
            emit("vt", "skip", "Chave de API não configurada (Configurações). Etapa ignorada.")
            findings.append(gap("VirusTotal não consultado", "Configure a chave gratuita para ter a reputação do arquivo.", "vt"))
        else:
            emit("vt", "run", "Consultando reputação pelo hash (o arquivo não é enviado)…")
            status = lambda m: emit("vt", "run", m)
            executable = kind in EXEC_KINDS.values() or kind in ("lib", "jar")  # pacote desconhecido é normal; pesa o conteúdo
            fs, summary = vt_findings(vt.lookup(hashes["sha256"], status, self.cancelled), "", executable)
            findings += fs
            inner: list[Path] = []
            if sr.is_archive:
                unsigned = [p for p, _ in pe_files if status_of.get(p) != "Valid"]
                inner = unsigned + [p for p, _ in other_active if p.suffix.lower() in EXEC_KINDS]
                inner.sort(key=lambda p: (p.suffix.lower() == ".dll", p.stat().st_size))
            queried, unknown, clean, flagged = 0, 0, 0, 0
            for p in inner[:MAX_VT_LOOKUPS]:
                self._check_cancel()
                emit("vt", "run", f"Consultando {p.name} ({queried + 1}/{min(len(inner), MAX_VT_LOOKUPS)})…")
                try:
                    h = hash_file(p)["sha256"]
                except OSError as e:
                    if av_blocked(e, p):
                        findings.append(Finding("defender", f"{p.name}: bloqueado pelo antivírus em tempo real", "", 90, "critical"))
                    continue
                fs2, _ = vt_findings(vt.lookup(h, status, self.cancelled), p.name, True)
                queried += 1
                for f in fs2:
                    if f.trust:                # sem crédito por arquivo interno (um único crédito consolidado abaixo)
                        f.points, f.trust = 0, False
                        clean += 1
                    elif f.gap:                # desconhecido ou registro recente: sem pontos por arquivo, um único peso abaixo
                        unknown += 1
                        f.points, f.gap = 0, False
                    elif f.points > 6:
                        flagged += 1
                findings += fs2
            if unknown:
                # peso ÚNICO para o pacote (mods novos são normais); a lacuna impede "Seguro" sem reputação
                findings.append(Finding("vt", f"{unknown} arquivo(s) internos sem reputação no VirusTotal",
                                        "Desconhecidos ou vistos pela primeira vez há menos de 30 dias.", 3, "low", gap=True))
            left = max(0, len(inner) - MAX_VT_LOOKUPS)
            if left:
                findings.append(gap(f"{left} arquivo(s) internos sem consulta ao VirusTotal", f"Limite de {MAX_VT_LOOKUPS} consultas por análise (cota gratuita).", "vt"))
            if inner and queried == len(inner) and clean == queried and not unknown and not flagged:
                findings.append(Finding("vt", f"Todos os {queried} binários internos limpos no VirusTotal", "", -15, "info", trust=True))
            bad_vt = any(f.stage == "vt" and f.points >= 20 for f in findings)
            vt_err = any(f.stage == "vt" and "indisponível" in f.title for f in findings)
            emit("vt", "bad" if bad_vt else ("warn" if vt_err else "ok"), summary if not inner else f"{summary} · {queried} arquivo(s) internos consultados")
        self._check_cancel()

        # 3. Defender
        emit("def", "run", "Verificando com o Microsoft Defender…")
        threats: list[str] = []
        errors = []
        for t in scan_targets:
            res = defender_scan(t)
            threats += res.threats
            if not res.ran:
                errors.append(res.error)
        if sr.is_archive and sr.files_inside:
            left = sum(1 for p in ext_dir.rglob("*") if p.is_file())
            if left < sr.files_inside:
                threats.append(f"{sr.files_inside - left} arquivo(s) removidos pelo Defender em tempo real")
        if threats:
            findings.append(Finding("defender", "Microsoft Defender detectou ameaça", "; ".join(sorted(set(threats)))[:300], 90, "critical"))
            emit("def", "bad", threats[0][:80])
        elif errors:
            findings.append(gap("Defender não pôde verificar", errors[0]))
            emit("def", "warn", errors[0])
        else:
            findings.append(Finding("defender", "Microsoft Defender: nenhuma ameaça", "Verificação sob demanda concluída.", -5, "info"))
            emit("def", "ok", "Nenhuma ameaça encontrada")
        self._check_cancel()

        # 4. Assinatura + análise estática
        emit("sig", "run", "Analisando assinatura digital e conteúdo…")
        if pe_files:
            valid_n = sum(1 for p in sig_paths if status_of.get(p) == "Valid")
            pubs = {publisher(sigs[str(p)]["subject"]) for p in sig_paths if status_of.get(p) == "Valid"}
            all_checked = len(pe_files) <= MAX_SIG_FILES
            if not sigs:
                findings.append(gap("Assinaturas digitais não puderam ser verificadas", "O PowerShell não retornou resultado."))
            elif any(s == "HashMismatch" for s in status_of.values()):
                findings.append(Finding("signature", "Assinatura quebrada", "O arquivo foi alterado depois de assinado.", 50, "high"))
            elif valid_n == len(pe_files) and all_checked and not other_active:
                findings.append(Finding("signature", f"Todos os executáveis assinados: {', '.join(sorted(pubs))[:80]}",
                                        f"{valid_n} arquivo(s) com assinatura válida e confiável pelo Windows (inclui DLLs).", -25, "info", trust=True))
            elif valid_n == len(pe_files) and all_checked:
                # a assinatura cobre os binários, NÃO os scripts/atalhos/documentos que vieram junto
                findings.append(Finding("signature", f"Executáveis assinados ({', '.join(sorted(pubs))[:60]}), mas há outros arquivos ativos",
                                        f"{len(other_active)} script(s)/atalho(s)/documento(s) ao lado não são cobertos pela assinatura: não é crédito.", 0, "info"))
            elif valid_n:
                findings.append(Finding("signature", f"Assinatura válida em {valid_n} de {len(pe_files)} arquivos ({', '.join(sorted(pubs))[:50]})",
                                        "Os demais (ex.: DLLs ao lado de um exe assinado) não têm assinatura: isso não é crédito.", 0, "info"))
            else:
                mains = [p for p, k in pe_files if k in ("exe", "msi")]
                if any(status_of.get(p) in ("NotTrusted", "UnknownError") for p in mains):
                    findings.append(Finding("signature", "Assinatura não confiável", "Certificado desconhecido ou expirado.", 15, "medium"))
                else:
                    findings.append(Finding("signature", "Sem assinatura digital",
                                            "É o motivo do aviso do SmartScreen. Muito comum em mods e jogos indie, não prova nada sozinho.", 10, "low"))
            if not all_checked:
                findings.append(gap(f"{len(pe_files) - MAX_SIG_FILES} binário(s) sem verificação de assinatura", ""))

        heur: list[Finding] = []
        to_analyze = [p for p, _ in sorted(pe_files, key=lambda t: -t[0].stat().st_size) if status_of.get(p) != "Valid"][:MAX_PE_ANALYSIS]
        for p in to_analyze:
            self._check_cancel()
            heur += analyze_pe(p)
        for p, mg in other_active[:400]:
            fs3, inspected = analyze_content(p, mg, strong_only=(web_like and p.suffix.lower() == ".js"))
            heur += fs3
            if not inspected:
                uninspected.append(p.name)
        for p in soft_files:  # .lua/.rpy/.html/.svg: acusa só quando executam programa/baixam algo
            heur += analyze_soft(p)
        if uninspected:
            findings.append(gap("Conteúdo ativo não inspecionável", f"{len(uninspected)} arquivo(s): {', '.join(uninspected[:4])}"))
        if unknown_types:
            top = ", ".join(f"{e} ({n})" for e, n in sorted(unknown_types.items(), key=lambda t: -t[1])[:6])
            findings.append(gap("Tipos de arquivo não reconhecidos não foram inspecionados", f"{sum(unknown_types.values())} arquivo(s): {top}"))
        if has_driver:
            findings.append(gap("O pacote contém um driver do Windows (.sys)",
                                "Drivers assinados e legítimos são usados em ataques (BYOVD) e não rodam no sandbox: a assinatura não basta."))
        if unrunnable_active:
            findings.append(gap("Conteúdo ativo só inspecionado estaticamente",
                                ".jar, scripts Python, documentos com macro, .reg ou atalhos não rodam no sandbox: o comportamento real é desconhecido."))
        weak = [f for f in heur if f.points > 0 and f.severity in ("info", "low", "medium")]
        pos = sum(f.points for f in weak)
        if pos > 40:  # o teto vale só para heurísticas fracas; achados high/critical nunca são achatados
            for f in weak:
                f.points = f.points * 40 // pos
        findings += heur
        if active_count == 0 and not unknown_types and not any(f.gap and f.stage in ("archive",) for f in findings) and (not sr.is_archive or sr.files_inside):
            findings.append(Finding("static", "Sem conteúdo executável",
                                    "Nenhum programa, script, biblioteca, atalho ou documento com macro foi encontrado.", 0, "info", trust=True))
        sig_bad = any(f.stage in ("signature", "static") and f.points >= 15 for f in findings)
        emit("sig", "warn" if sig_bad else "ok",
             "Pontos de atenção encontrados" if sig_bad else ("Executáveis assinados" if any(f.stage == "signature" and f.trust for f in findings) else "Sem anomalias estruturais"))
        self._check_cancel()

        # Candidatos extras para o sandbox: DLLs sem assinatura (rundll32 dispara o DllMain)
        libs = [(p, k) for p, k in pe_files if k == "lib" and status_of.get(p) != "Valid" and p.suffix.lower() != ".sys"]
        for p, _ in sorted(libs, key=lambda t: -t[0].stat().st_size)[:8]:
            rel = str(p.relative_to(root)) if sr.is_archive else p.name
            sr.candidates.append(Candidate(rel, "dll", p.stat().st_size))
        sr.candidates.sort(key=lambda c: (_PRIORITY.get(c.kind, 9), any(w in c.rel.lower() for w in _DEPRIORITIZE), -c.size))

        # 5. Decisão
        emit("dec", "run", "Ponderando todos os sinais…")
        sr.recommendation = recommend(findings, bool(sr.candidates), static_only=unrunnable_active)
        emit("dec", "ok", f"Pontuação preliminar {compute_score(findings)}/100")
        return sr

    # -------------------------------------------------------------- sandbox
    def run_sandbox(self, sr: StaticResult, cand: Candidate, emit) -> SandboxResult:
        steps = ("sb_prep", "sb_run", "sb_collect")
        states: dict[str, str] = {}

        def tracked(sid, state, detail=""):
            states[sid] = state
            emit(sid, state, detail)

        net = bool(self.settings["sandbox_network"])
        secs = int(self.settings["sandbox_seconds"])
        self._sandbox_started = True
        try:
            if sr.is_archive:
                sample_dir, rel = self.workdir / "extracted", cand.rel
            else:
                sample_dir, rel = self.workdir / "in", sr.path.name
                tracked("sb_prep", "run", "Copiando o arquivo para a área isolada…")
                sample_dir.mkdir(exist_ok=True)
                shutil.copy2(sr.path, sample_dir / rel)
            out = sandbox.run(sample_dir, rel, cand.kind, self.workdir, net, secs, tracked, self.cancelled,
                              bool(self.settings["sandbox_protected"]))
        except InterruptedError:
            raise
        except OSError as e:
            out = sandbox.Outcome(error=f"Erro ao preparar o sandbox: {e}")

        if out.ran:
            fs = score_sandbox(out.report, net)
            inconclusive = any(f.gap for f in fs)
            bad = any(f.points >= 20 for f in fs)
            tracked("sb_collect", "bad" if bad else ("warn" if inconclusive else "ok"),
                    "Comportamento suspeito observado" if bad else ("Resultado inconclusivo" if inconclusive else "Nada suspeito observado (não prova segurança)"))
            err = next((f.title for f in fs if f.gap), "")
            return SandboxResult(not inconclusive, fs, out, err)

        first = True
        for sid in steps:
            if states.get(sid) != "ok":
                tracked(sid, "bad" if first else "skip", out.error if first else "")
                first = False
        return SandboxResult(False, [gap("Sandbox não concluído", out.error)], out, out.error)

    # -------------------------------------------------------------- limpeza
    def cleanup(self) -> int:
        """Apaga tudo que a análise gerou. Retorna bytes liberados."""
        if self._sandbox_started and sandbox.running():
            sandbox.kill()
        self._sandbox_started = False
        wd, self.workdir = self.workdir, None
        if not wd or not wd.exists():
            return 0
        freed = dir_size(wd)
        for f in wd.rglob("*"):  # arquivos somente-leitura criados pela amostra no guest não podem travar a limpeza
            try:
                os.chmod(f, stat.S_IWRITE | stat.S_IREAD)
            except OSError:
                pass

        def _unlock(func, p, _exc):
            try:
                os.chmod(p, stat.S_IWRITE)
                func(p)
            except OSError:
                pass

        for _ in range(8):
            shutil.rmtree(wd, onerror=_unlock)
            if not wd.exists():
                break
            time.sleep(0.6)
        try:
            WORK_ROOT.rmdir()  # só remove se estiver vazia
        except OSError:
            pass
        return freed if not wd.exists() else max(0, freed - dir_size(wd))

    @staticmethod
    def purge_stale(max_age_s: int = 600) -> None:
        """Remove sobras de execuções anteriores que travaram."""
        if not WORK_ROOT.exists():
            return
        for d in WORK_ROOT.iterdir():
            try:
                if time.time() - d.stat().st_mtime > max_age_s:
                    shutil.rmtree(d, ignore_errors=True)
            except OSError:
                pass
