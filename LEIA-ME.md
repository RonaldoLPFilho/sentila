# Sentinela

Analisa jogos, mods e arquivos baixados **antes** de você abrir, com poucos falsos positivos.

> **Importante:** o Sentinela *reduz* o risco, não o elimina. Use o veredito como **um sinal entre outros** (origem do arquivo,
> hash no site oficial, reputação do autor). Uma auditoria independente mostrou que "nenhum alerta" nunca deve ser lido como
> "garantido seguro": por isso existe o nível **Inconclusivo**.

## Como usar

1. Dê duplo clique em **`Iniciar Sentinela.bat`** (ou instale pelo `installer\Sentinela-Setup-*.exe`).
2. Arraste o arquivo para a janela, ou clique para selecioná-lo (ou use *Analisar com Sentinela* no clique direito).
3. O app roda sozinho:
   1. **Identificação**: hashes, tipo real, origem do download e extração segura de `.zip/.rar/.7z/.iso/.cab/.msix…`, **inclusive arquivos dentro de arquivos** (até 4 níveis).
   2. **VirusTotal**: reputação pelo hash do arquivo **e de todos os binários dentro dele** (o arquivo nunca é enviado).
   3. **Microsoft Defender**: verificação sob demanda do arquivo e do conteúdo extraído.
   4. **Assinatura digital e análise estática**: assinatura de **todos** os executáveis e DLLs, empacotadores, APIs, scripts, atalhos `.lnk`, `.jar`, macros de documentos, `.reg`.
4. Ele pondera os sinais e diz se o **Windows Sandbox** é recomendado. Se for, inicia sozinho (contagem de 6 s para você poder pular).
5. No sandbox o programa roda num Windows descartável e o agente compara antes/depois: processos, arquivos, persistência, Defender, rede e arquivos-isca de ransomware.
6. Veredito final e **limpeza de tudo que a análise gerou**.
7. Só então você decide: **instalar/abrir** (o hash é conferido de novo antes de abrir), mostrar na pasta, salvar o relatório ou enviar para a Lixeira.

## O que cada veredito significa

| Veredito | Significado | O que fazer |
|---|---|---|
| **Perigoso** | Sinais fortes de malware (Defender, vários antivírus, ransomware, desativar o Defender…). É o veredito mais confiável. | Não instale. |
| **Atenção** | Pontos suspeitos que não bastam para condenar (script ofuscado, DLL com APIs de injeção, macro…). Pode ser falso positivo de trainer/mod. | Leia os motivos e confira origem e hash no site oficial. |
| **Inconclusivo** | Nenhum alerta, **mas faltou evidência ou alguma verificação** (VirusTotal sem dado, arquivo com senha, sandbox recomendado não executado, `.jar`/`.py` que só passou por análise estática…). A seção *Não verificado* mostra o quê. | Não trate como seguro. Complete as verificações ou confie só na origem. |
| **Seguro** | Nenhum alerta **e** evidência positiva, sem lacunas: (a) todos os executáveis/DLLs com assinatura válida **e nenhum script/atalho/documento ao lado**; ou (b) reputação limpa em 40+ antivírus **com o primeiro registro há mais de 30 dias**; ou (c) o pacote só tem dados conhecidos (texturas, áudio, texto…). | Risco reduzido, nunca zero. |

## Configuração (uma vez)

| Item | O que fazer |
|---|---|
| VirusTotal | Configurações → cole a chave gratuita (https://www.virustotal.com/gui/my-apikey). Fica criptografada com DPAPI. Sem a chave, quase todo arquivo sem assinatura vira *Inconclusivo*. |
| Windows Sandbox | Precisa do Windows Pro/Enterprise. Se não estiver ativo, o app mostra o botão **Ativar o Windows Sandbox** (pede administrador). Depois, **reinicie o PC**. A virtualização deve estar ligada na BIOS. |
| RAR / 7z | Instale o 7-Zip (detecção de senha e comparação de leitores de zip dependem dele). Sem ele, o app usa o `tar` do Windows. |

## Como evita falsos positivos

- O aviso do SmartScreen só significa "sem assinatura ou pouca reputação": aqui é **um sinal fraco** (+10).
- Detecções genéricas (`Heur`, `Generic`, `Unsafe`, `!ml`) de poucos antivírus viram **"provável falso positivo"**; nomes de família (AgentTesla, RedLine, Lumma…) **não** são tratados como genéricos.
- Muitas detecções genéricas (trainer compactado) dão **Atenção**, não Perigoso.
- Créditos a favor (assinatura, VirusTotal limpo, Defender) têm **teto de 20 pontos** e nunca anulam um achado grave.
- Zips de jogos HTML5/Electron (`package.json`, `.html` + `.js`) não são tratados como scripts maliciosos por usar `eval()`.
- Arquivos internos desconhecidos no VirusTotal pesam **uma vez só** (+3), não por arquivo: um mod com várias DLLs novas não vira "Atenção" por isso.
- Um arquivo recém-enviado ao VirusTotal com 0 detecções **não** ganha confiança (assinaturas de antivírus demoram dias); precisa ter mais de 30 dias de histórico.
- Reputação limpa no VirusTotal **sem assinatura digital** não basta para "Seguro" sozinha (pode ser fabricada enviando o arquivo antes): o sandbox continua recomendado.
- Zips com nomes acentuados/japoneses não são mais tratados como "ambíguos"; a comparação entre leitores usa tamanho+CRC dos arquivos.
- `.lua`, `.rpy`, `.html` e `.svg` são inspecionados: só acusam quando executam um programa ou baixam algo (usar `os.execute` para abrir o próprio jogo é comum).
- Tipos de arquivo fora da lista de dados conhecidos (texturas, áudio, texto, pacotes de jogo…) geram *Não verificado*, e `.pdf`, `.rtf`, `.rdp`, `.settingcontent-ms`, `.sh`, `.psm1` são inspecionados. Scripts ofuscados por concatenação, códigos de caractere ou variáveis encadeadas são detectados.

## Limites (leia)

- **Assinatura digital não é garantia:** certificados roubados e drivers legítimos vulneráveis (BYOVD) existem. Pacotes com driver `.sys` sempre geram *Não verificado*.
- **Zips adulterados:** se dois leitores de zip enxergam listas de arquivos diferentes (zip concatenado), o app analisa as duas visões e marca o pacote como suspeito.
- **O que o sandbox NÃO vê:** credenciais lidas sem criar arquivo (infostealers), exfiltração com a rede desligada (padrão), conexões de C2, bootkits, comportamento que só dispara depois de 60 s, e malware que detecta que está em sandbox. Por isso um sandbox "limpo" **não concede nenhum crédito**: ele só pode aumentar a pontuação.
- **Defender dentro do sandbox:** no Windows Sandbox o antivírus costuma vir desligado, então ele só observa comportamento. A verificação de assinaturas é a do Defender do seu PC.
- **Agente detectável:** malware esperto pode notar que está num sandbox (usuário `WDAGUtilityAccount`, pastas `C:\Agent`/`C:\Out`) e se comportar bem; amostras que dormem mais que o tempo de observação não são vistas.
- Se uma análise for cancelada e sobrar a VM do sandbox (processo `vmmemWindowsSandbox`), o app avisa e pede para reiniciar o computador.
- O sandbox é controlado pela amostra; o relatório dele é tratado como entrada hostil (validado e limitado) e nunca baixa o risco.
- Instaladores que pedem cliques só mostram o comportamento até a primeira tela.
- Rede **desligada** por padrão no sandbox (mais seguro, porém sem observar rede). Ligá-la deixa o programa alcançar sua rede local.
- Arquivos protegidos por senha e formatos não inspecionáveis (`.chm`…) geram *Inconclusivo*.
- `.jar`, `.py`, `.lnk` e documentos com macro são inspecionados **estaticamente** (não rodam no sandbox).
- Consulta ao VirusTotal: até 12 binários internos por análise (cota gratuita de 4/min); o restante vira *Não verificado*.
- O Windows Sandbox real não pôde ser validado de ponta a ponta no desenvolvimento (recurso desativado): o agente e o fluxo foram testados no próprio PC em modo de teste.

## Verificar processos em execução (aba "Processos")

Olha o que **já está rodando** no PC (sem precisar de administrador) e responde: há programa suspeito? algo gasta CPU/GPU sem motivo? há mineração? há indícios de botnet?

1. **Lista** os processos e confere a **assinatura digital** de cada programa (apps empacotados do Windows contam como verificados).
2. Para os **sem assinatura**, consulta a reputação no VirusTotal (só o hash; opcional, máx. 12 por verificação).
3. **Observa** CPU, GPU e conexões de rede por 30/60/120 s (recomendado 60 s: menos que isso não avalia consumo contínuo).
4. Pondera os sinais e mostra **Pontos de atenção**, **Não verificado**, **Maiores consumidores** e a lista completa. Nada é encerrado sozinho.

**O que acusa** (sempre com o motivo na tela):
- Programas que fingem ser do Windows (svchost/lsass… fora de System32, nome com letras parecidas ou invisíveis, pai errado).
- Executável apagado enquanto roda, rodando de pasta de rede, assinatura adulterada, arquivo reescrito durante a observação.
- Linha de comando perigosa (PowerShell codificado ou baixando e executando conteúdo, apagar cópias de segurança, desativar o Defender…).
- **Mineradores**: nome conhecido, parâmetros `stratum`/carteira, conexão com pool (DNS atribuído ao processo) e, só como reforço, uso contínuo de CPU/GPU por programa sem assinatura.
- Rede: varredura de outros PCs (muitas conexões sem resposta para redes diferentes nas portas 22/23/445/3389), portas de IRC/Tor, programa sem assinatura escutando conexões.
- Programas que se registram para **iniciar com o Windows** (Run, serviço, tarefa agendada, pasta Inicializar).
- Estado do Defender (tempo real desligado, assinaturas velhas, exclusões quando legíveis) e arquivo `hosts` bloqueando antivírus/atualizações.

**Como evita falso positivo:** um programa sem assinatura numa pasta de risco (Downloads, Temp…) **sozinho é só informação**; precisa de um segundo sinal (conexão externa sem janela, inicia com o Windows, comando suspeito…). Consumo alto de programa **assinado** (jogo, navegador, render) nunca pontua; só aparece em "Maiores consumidores". Se você instalou um programa sem assinatura de propósito, use **Confiar** (vale pelo SHA-256: se o arquivo mudar, deixa de valer; dá para revogar).

**O resultado nunca diz "PC limpo".** O melhor resultado é **"Sem indícios (parcial)"**; se algum programa ficou sem verificação, é **Inconclusivo** e a lista mostra quais.

**Limites (leia):** não vê rootkits de kernel, malware que só vive na memória (a assinatura vale para o arquivo, não para a imagem carregada), DLL maliciosa dentro de programa assinado, mineração dentro do navegador, mineradores que dormem ou limitam o uso, nem beacons lentos de botnet. Sem administrador, a linha de comando de processos elevados e as **exclusões do Defender** não podem ser lidas (aparecem em "Não verificado"). "Botnet" é sempre *indício*, nunca prova. Encerrar um processo **não remove** o arquivo nem a inicialização automática.

**Ações por processo:** mostrar pasta, analisar o arquivo no Sentinela, confiar, **suspender** (reversível) e **encerrar** (com confirmação; recusa processos do sistema, do Windows e o próprio app; antivírus/anticheat geram aviso). A identidade (hora de criação + caminho) é conferida no mesmo handle antes de agir, para nunca atingir outro programa que reutilizou o número do processo. O relatório salvo esconde por padrão seu nome de usuário e segredos de linhas de comando.

## Testes

```
python tests\run_regression.py     (cenários inertes: arquivos + verificação de processos)
python tests\live_procs.py         (lança cópias inofensivas com nomes suspeitos e confere a varredura real; ~1 min)
```
Executa cenários inertes derivados da auditoria (evasões, falsos positivos, relatório de sandbox forjado, processos impostores, mineração, rede…).

## Estrutura

```
sentinela/
  ui.py        interface (PySide6)
  pipeline.py  orquestra as etapas (extração recursiva, VirusTotal, Defender, assinaturas) e a limpeza
  checks.py    hash, VirusTotal, Defender, assinatura, extração, heurísticas por tipo de arquivo
  scoring.py   pontuação, lacunas, veredito e regras/saneamento do relatório do sandbox
  sandbox.py   gera o .wsb, inicia, acompanha e coleta (leituras limitadas)
  procscan.py  verificação de processos em execução (coleta, regras, amostragem, ações)
  ui_procs.py  tela "Processos"
  agent.ps1    roda DENTRO do sandbox e observa o comportamento
tests/         regressão
installer/     gera o instalador (python installer\build.py)
```
