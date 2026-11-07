"""Postura de boot/kernel na higiene (pcscan.boot_findings): o que cracks de hipervisor desligam."""
from __future__ import annotations


def run_round12(ctx) -> None:
    check = ctx.check
    from sentinela import pcscan as pc

    def titles(st):
        return [f.title for f in pc.boot_findings(st)[0]]

    ok = {"start": " NOEXECUTE=OPTIN  FVEBOOT=2666496  NOVGA", "secureboot": 1, "dg": {"vbs": 2, "cfg": [2], "run": [2]}, "managevbs": None}
    check("B1 PC saudável => nenhum achado", titles(ok) == [], str(titles(ok)))

    crack = {"start": " NOEXECUTE=OPTIN  DISABLE_INTEGRITY_CHECKS  HYPERVISORLAUNCHTYPE=OFF", "secureboot": 1,
             "dg": {"vbs": 0, "cfg": [], "run": [0]}, "managevbs": ["VBS", "HVCI", "Hypervisor"]}
    fs, _ = pc.boot_findings(crack)
    t = [f.title for f in fs]
    check("B2 DSE desligada => achado alto", any("assinatura de drivers" in x for x in t) and any(f.severity == "high" for f in fs), str(t))
    check("B2 hipervisor OFF, VBS desligado e ManageVBS aparecem", any("Hipervisor" in x for x in t) and any("VBS" in x for x in t) and any("ManageVBS" in x for x in t), str(t))
    check("B2 o que o crack desligou é listado", any("HVCI" in f.detail for f in fs if "ManageVBS" in f.title))
    check("B3 nointegritychecks em minúsculas também conta", any("assinatura" in x for x in titles(dict(ok, start="noexecute=optin nointegritychecks"))))
    check("B4 TESTSIGNING => achado alto", any("TESTSIGNING" in x for x in titles(dict(ok, start="TESTSIGNING NOEXECUTE=OPTIN"))))
    check("B5 HYPERVISORLAUNCHTYPE=AUTO não acusa", titles(dict(ok, start="HYPERVISORLAUNCHTYPE=AUTO")) == [])
    check("B6 Secure Boot desligado => achado", any("Secure Boot" in x for x in titles(dict(ok, secureboot=0))))
    _, notes = pc.boot_findings(dict(ok, secureboot=None, dg=None))
    check("B7 Secure Boot/DeviceGuard ilegíveis viram nota, não achado", titles(dict(ok, secureboot=None, dg=None)) == [] and len(notes) == 2, str(notes))
    check("B8 VBS ativado mas não rodando => achado leve", any("não está rodando" in x for x in titles(dict(ok, dg={"vbs": 1, "cfg": [2], "run": [0]}))))
    check("B9 ManageVBS vazia ainda é sinal", any("ManageVBS" in x for x in titles(dict(ok, managevbs=[]))))
    check("B10 start ausente (None) não quebra", isinstance(pc.boot_findings(dict(ok, start=None)), tuple))

    hyg = pc.boot_findings(crack)[0]
    v = pc.pc_verdict([], [], hyg, None, [])
    check("B11 configuração insegura sozinha limita o veredito a Atenção (não é prova de malware)", v.level == "caution", v.level)
